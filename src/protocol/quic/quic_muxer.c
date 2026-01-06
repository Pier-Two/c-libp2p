#include "protocol/quic/protocol_quic.h"
#include "quic_internal.h"

#include "../../host/host_internal.h"
#include "libp2p/errors.h"
#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif
#include "libp2p/io.h"
#include "libp2p/log.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "libp2p/peerstore.h"
#include "libp2p/stream_internal.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "../../host/proto_select_internal.h"
#include "transport/muxer.h"

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picosocks.h"

#include <inttypes.h>
#include <errno.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct quic_stream_chunk
{
    struct quic_stream_chunk *next;
    size_t offset;
    size_t len;
    uint8_t data[0];
} quic_stream_chunk_t;

typedef struct quic_stream_ctx
{
    _Atomic(struct quic_muxer_ctx *) mx;  /* Atomic to allow safe teardown check */
    libp2p_stream_t *stream;
    uint64_t stream_id;
    pthread_mutex_t lock;
    quic_stream_chunk_t *head;
    quic_stream_chunk_t *tail;
    struct quic_stream_ctx *next;
    int fin_remote;
    int fin_local;
    int reset_remote;
    int stop_sending_received;  /* Peer asked us to stop sending on this stream */
    int closed;
    uint64_t deadline_ms;
    int initiator;
    int handshake_started;
    int handshake_done;
    int handshake_running;
    atomic_uint refcnt;
    libp2p_protocol_def_t proto_def;
    struct quic_push_ctx *push;
    size_t push_cap;
} quic_stream_ctx_t;

/* Simple linked list to track pending STOP_SENDING events for streams not yet created */
typedef struct pending_stop_sending
{
    uint64_t stream_id;
    struct pending_stop_sending *next;
} pending_stop_sending_t;

typedef struct quic_muxer_ctx
{
    libp2p_quic_session_t *session;
    _Atomic(struct libp2p_host *) host;  /* Atomic to allow safe teardown check */
    multiaddr_t *local;
    multiaddr_t *remote;
    pthread_mutex_t lock;
    quic_stream_ctx_t *streams_head;
    quic_stream_ctx_t *streams_tail;
    libp2p_conn_t *conn;
    int accepted_count;
    libp2p_muxer_t *owner;
    _Atomic int closed;
    atomic_uint refcnt;
    pthread_mutex_t write_mtx;
    pending_stop_sending_t *pending_stop_sending_head;  /* STOP_SENDING for unknown streams */
} quic_muxer_ctx_t;

static void quic_muxer_ctx_retain(quic_muxer_ctx_t *ctx);
static void quic_muxer_ctx_release(quic_muxer_ctx_t *ctx);

/* Add a stream ID to the pending STOP_SENDING list. Caller must hold mx->lock. */
static void quic_muxer_add_pending_stop_sending(quic_muxer_ctx_t *mx, uint64_t stream_id)
{
    pending_stop_sending_t *node = malloc(sizeof(pending_stop_sending_t));
    if (!node)
        return;
    node->stream_id = stream_id;
    node->next = mx->pending_stop_sending_head;
    mx->pending_stop_sending_head = node;
}

/* Check and remove a stream ID from the pending STOP_SENDING list.
 * Returns 1 if found (and removes it), 0 otherwise. Caller must hold mx->lock. */
static int quic_muxer_check_pending_stop_sending(quic_muxer_ctx_t *mx, uint64_t stream_id)
{
    pending_stop_sending_t **pp = &mx->pending_stop_sending_head;
    while (*pp)
    {
        if ((*pp)->stream_id == stream_id)
        {
            pending_stop_sending_t *found = *pp;
            *pp = found->next;
            free(found);
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}

/* Free all pending STOP_SENDING entries. Caller must hold mx->lock. */
static void quic_muxer_free_pending_stop_sending(quic_muxer_ctx_t *mx)
{
    pending_stop_sending_t *node = mx->pending_stop_sending_head;
    while (node)
    {
        pending_stop_sending_t *next = node->next;
        free(node);
        node = next;
    }
    mx->pending_stop_sending_head = NULL;
}

static libp2p_quic_session_t *quic_muxer_retain_session(quic_muxer_ctx_t *mx)
{
    if (!mx)
        return NULL;
    libp2p_quic_session_t *session = NULL;
    pthread_mutex_lock(&mx->lock);
    session = mx->session;
    if (session)
        libp2p__quic_session_retain(session);
    pthread_mutex_unlock(&mx->lock);
    return session;
}

static void quic_muxer_release_session(libp2p_quic_session_t *session)
{
    if (session)
        libp2p__quic_session_release(session);
}

typedef struct quic_stream_cb_task
{
    libp2p_stream_t *stream;
    quic_stream_ctx_t *st;  /* For push-mode streams, allows fallback to push ctx */
} quic_stream_cb_task_t;

typedef struct quic_handshake_task
{
    quic_muxer_ctx_t *mx;
    quic_stream_ctx_t *st;
    libp2p_stream_t *stream;
} quic_handshake_task_t;

typedef struct quic_push_ctx
{
    quic_stream_ctx_t *st;
    libp2p_protocol_def_t def;
    size_t cap;
    uint8_t *buf;
    size_t buf_sz;
} quic_push_ctx_t;

typedef struct quic_proto_open_task
{
    libp2p_protocol_def_t def;
    libp2p_stream_t *stream;
} quic_proto_open_task_t;

typedef struct quic_session_event
{
    struct quic_session_event *next;
    uint64_t stream_id;
    picoquic_call_back_event_t event;
    uint8_t *data;
    size_t len;
} quic_session_event_t;

static void quic_muxer_append_stream(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st);
static void quic_muxer_remove_stream(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st);
static ssize_t quic_stream_backend_read(void *io_ctx, void *buf, size_t len);
static ssize_t quic_stream_backend_write(void *io_ctx, const void *buf, size_t len);
static int quic_stream_backend_close(void *io_ctx);
static int quic_stream_backend_reset(void *io_ctx);
static int quic_stream_backend_set_deadline(void *io_ctx, uint64_t ms);
static const multiaddr_t *quic_stream_backend_local(void *io_ctx);
static const multiaddr_t *quic_stream_backend_remote(void *io_ctx);
static quic_stream_ctx_t *quic_accept_inbound_stream(quic_muxer_ctx_t *mx, uint64_t stream_id);
static int quic_run_inbound_handshake(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st);
static void quic_session_clear_pending(libp2p_quic_session_t *session);
static void quic_session_flush_pending(libp2p_quic_session_t *session, quic_muxer_ctx_t *mx);
static int quic_session_callback(picoquic_cnx_t *cnx,
                                 uint64_t stream_id,
                                 uint8_t *bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void *callback_ctx,
                                 void *stream_ctx);

struct libp2p_quic_session
{
    picoquic_quic_t *quic;
    _Atomic(picoquic_cnx_t *) cnx;
    quic_muxer_ctx_t *mx;
    _Atomic uint32_t refcnt;
    pthread_mutex_t lock;
    pthread_mutex_t quic_mtx_storage;  /* Storage for own mutex (used for dial sessions) */
    pthread_mutex_t *quic_mtx;         /* Pointer to active mutex (own or listener's) */
    struct libp2p_host *host;
    picoquic_packet_loop_param_t loop_param;
    picoquic_network_thread_ctx_t *loop_ctx;
    _Atomic int loop_started;
    _Atomic int loop_stop;
    quic_session_event_t *pending_head;
    quic_session_event_t *pending_tail;
};

static void quic_session_disable_cnx(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    quic_muxer_ctx_t *mx = NULL;
    pthread_mutex_lock(&session->lock);
    mx = session->mx;
    atomic_store_explicit(&session->cnx, NULL, memory_order_release);
    pthread_mutex_unlock(&session->lock);
    if (mx)
        atomic_store_explicit(&mx->closed, 1, memory_order_release);
}

static quic_push_ctx_t *quic_push_ctx_new(quic_stream_ctx_t *st, const libp2p_protocol_def_t *def, size_t cap)
{
    if (!st || !def)
        return NULL;
    quic_push_ctx_t *ctx = (quic_push_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->st = st;
    ctx->def = *def;
    ctx->cap = cap;
    ctx->buf = NULL;
    ctx->buf_sz = 0;
    return ctx;
}

static void quic_proto_open_exec(void *ud)
{
    quic_proto_open_task_t *task = (quic_proto_open_task_t *)ud;
    if (!task)
        return;
    if (task->def.on_open)
        task->def.on_open(task->stream, task->def.user_data);
    if (task->stream)
        libp2p__stream_release_async(task->stream);
    free(task);
}

static void quic_push_ctx_free(quic_push_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->buf)
    {
        free(ctx->buf);
        ctx->buf = NULL;
        ctx->buf_sz = 0;
    }
    free(ctx);
}

static void quic_push_cleanup(void *arg, libp2p_stream_t *s)
{
    (void)s;
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)arg;
    if (!st || !st->push)
        return;
    quic_push_ctx_free(st->push);
    st->push = NULL;
}

static void quic_stream_cleanup(void *arg, libp2p_stream_t *s)
{
    (void)s;
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)arg;
    if (!st)
        return;
    pthread_mutex_lock(&st->lock);
    if (st->push)
    {
        quic_push_ctx_free(st->push);
        st->push = NULL;
    }
    st->stream = NULL;
    pthread_mutex_unlock(&st->lock);
}

static void quic_push_on_readable(libp2p_stream_t *s, void *ud)
{
    quic_push_ctx_t *ctx = (quic_push_ctx_t *)ud;
    if (!ctx || !s || !ctx->st || !ctx->def.on_data)
        return;

    size_t want = 4096;
    if (ctx->cap > 0 && ctx->cap < want)
        want = ctx->cap;
    if (want == 0)
        want = 1;

    if (!ctx->buf || ctx->buf_sz < want)
    {
        uint8_t *nb = (uint8_t *)realloc(ctx->buf, want);
        if (!nb)
        {
            libp2p_stream_on_readable(s, quic_push_on_readable, ctx);
            return;
        }
        ctx->buf = nb;
        ctx->buf_sz = want;
    }
    for (;;)
    {
        ssize_t n = libp2p_stream_read(s, ctx->buf, ctx->buf_sz);
        if (n > 0)
        {
            ctx->def.on_data(s, ctx->buf, (size_t)n, ctx->def.user_data);
            continue;
        }
        if (n == 0 || n == LIBP2P_ERR_EOF)
        {
            if (ctx->def.on_eof)
                ctx->def.on_eof(s, ctx->def.user_data);
            return;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            libp2p_stream_on_readable(s, quic_push_on_readable, ctx);
            return;
        }
        if (ctx->def.on_error)
            ctx->def.on_error(s, (int)n, ctx->def.user_data);
        return;
    }
}

static void quic_attach_push(quic_stream_ctx_t *st, const libp2p_protocol_def_t *def, size_t cap)
{
    if (!st || !st->stream || !def)
        return;
    quic_push_ctx_t *ctx = quic_push_ctx_new(st, def, cap);
    if (!ctx)
        return;
    st->push = ctx;
    st->proto_def = *def;
    st->push_cap = cap;
    libp2p_stream_set_read_interest(st->stream, true);
    libp2p_stream_on_readable(st->stream, quic_push_on_readable, ctx);
    quic_push_on_readable(st->stream, ctx);
}

typedef struct
{
    quic_stream_ctx_t *st;
} quic_io_ctx_t;

static ssize_t quic_io_read(libp2p_io_t *self, void *buf, size_t len)
{
    quic_io_ctx_t *ctx = (quic_io_ctx_t *)self->ctx;
    if (!ctx || !ctx->st)
        return LIBP2P_ERR_NULL_PTR;
    return quic_stream_backend_read(ctx->st, buf, len);
}

static ssize_t quic_io_write(libp2p_io_t *self, const void *buf, size_t len)
{
    quic_io_ctx_t *ctx = (quic_io_ctx_t *)self->ctx;
    if (!ctx || !ctx->st)
        return LIBP2P_ERR_NULL_PTR;
    return quic_stream_backend_write(ctx->st, buf, len);
}

static int quic_io_set_deadline(libp2p_io_t *self, uint64_t ms)
{
    quic_io_ctx_t *ctx = (quic_io_ctx_t *)self->ctx;
    if (!ctx || !ctx->st)
        return LIBP2P_ERR_NULL_PTR;
    return quic_stream_backend_set_deadline(ctx->st, ms);
}

static const multiaddr_t *quic_io_local(libp2p_io_t *self)
{
    quic_io_ctx_t *ctx = (quic_io_ctx_t *)self->ctx;
    if (!ctx || !ctx->st)
        return NULL;
    return quic_stream_backend_local(ctx->st);
}

static const multiaddr_t *quic_io_remote(libp2p_io_t *self)
{
    quic_io_ctx_t *ctx = (quic_io_ctx_t *)self->ctx;
    if (!ctx || !ctx->st)
        return NULL;
    return quic_stream_backend_remote(ctx->st);
}

static int quic_io_close(libp2p_io_t *self)
{
    quic_io_ctx_t *ctx = (quic_io_ctx_t *)self->ctx;
    if (!ctx || !ctx->st)
        return 0;
    return quic_stream_backend_close(ctx->st);
}

static void quic_io_free(libp2p_io_t *self)
{
    if (!self)
        return;
    if (self->ctx)
        free(self->ctx);
    free(self);
}

static const libp2p_io_vtbl_t QUIC_IO_VTBL = {
    .read = quic_io_read,
    .write = quic_io_write,
    .set_deadline = quic_io_set_deadline,
    .local_addr = quic_io_local,
    .remote_addr = quic_io_remote,
    .close = quic_io_close,
    .free = quic_io_free,
};

static libp2p_io_t *quic_io_from_stream(quic_stream_ctx_t *st)
{
    if (!st)
        return NULL;
    libp2p_io_t *io = (libp2p_io_t *)calloc(1, sizeof(*io));
    quic_io_ctx_t *x = (quic_io_ctx_t *)calloc(1, sizeof(*x));
    if (!io || !x)
    {
        free(io);
        free(x);
        return NULL;
    }
    x->st = st;
    io->ctx = x;
    io->vt = &QUIC_IO_VTBL;
    return io;
}

static void quic_inbound_handshake(void *arg);

static int quic_collect_supported_protocols(libp2p_host_t *host, const char ***out_ids, size_t *out_count)
{
    if (!host || !out_ids || !out_count)
        return LIBP2P_ERR_NULL_PTR;
    *out_ids = NULL;
    *out_count = 0;

    pthread_mutex_lock(&host->mtx);
    size_t count = 0;
    for (protocol_entry_t *e = host->protocols; e; e = e->next)
        if (e->def.protocol_id)
            count++;

    const char **arr = NULL;
    if (count > 0)
    {
        arr = (const char **)calloc(count + 1, sizeof(*arr));
        if (!arr)
        {
            pthread_mutex_unlock(&host->mtx);
            return LIBP2P_ERR_INTERNAL;
        }
        size_t idx = 0;
        for (protocol_entry_t *e = host->protocols; e; e = e->next)
            if (e->def.protocol_id)
                arr[idx++] = e->def.protocol_id;
    }
    pthread_mutex_unlock(&host->mtx);

    *out_ids = arr;
    *out_count = count;
    return 0;
}

static int quic_find_protocol_def(libp2p_host_t *host, const char *incoming_id, libp2p_protocol_def_t *out_def)
{
    if (!host || !incoming_id || !out_def)
        return 0;
    libp2p_protocol_def_t chosen = {0};
    int found = 0;

    pthread_mutex_lock(&host->mtx);
    for (protocol_entry_t *e = host->protocols; e && !found; e = e->next)
    {
        if (e->def.protocol_id && strcmp(e->def.protocol_id, incoming_id) == 0)
        {
            chosen = e->def;
            found = 1;
        }
    }
    if (!found)
    {
        for (protocol_match_entry_t *m = host->matchers; m && !found; m = m->next)
        {
            if (!m->matcher.pattern)
                continue;
            switch (m->matcher.kind)
            {
                case LIBP2P_PROTO_MATCH_PREFIX:
                    if (strncmp(incoming_id, m->matcher.pattern, strlen(m->matcher.pattern)) == 0)
                    {
                        chosen = m->def;
                        found = 1;
                    }
                    break;
                case LIBP2P_PROTO_MATCH_SEMVER:
                {
                    version_triplet_t vin = {0};
                    const char *base = m->matcher.base_path;
                    if (extract_version_from_id(incoming_id, base, &vin) == 0)
                    {
                        semver_range_t range;
                        if (parse_semver_range(m->matcher.pattern, &range) == 0 && semver_in_range(&vin, &range))
                        {
                            chosen = m->def;
                            found = 1;
                        }
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }
    pthread_mutex_unlock(&host->mtx);

    if (found && out_def)
        *out_def = chosen;
    return found;
}

static size_t quic_protocol_cap(libp2p_host_t *host, const char *proto_id)
{
    if (!host || !proto_id)
        return 0;
    size_t cap = 0;
    pthread_mutex_lock(&host->mtx);
    for (proto_server_cfg_t *pc = host->proto_cfgs; pc; pc = pc->next)
    {
        if (pc->proto && strcmp(pc->proto, proto_id) == 0)
        {
            cap = pc->max_inflight_application_bytes;
            break;
        }
    }
    pthread_mutex_unlock(&host->mtx);
    return cap;
}

static int quic_protocol_requires_ident(libp2p_host_t *host, const char *proto_id)
{
    if (!host || !proto_id)
        return 0;
    int require = 0;
    pthread_mutex_lock(&host->mtx);
    for (proto_server_cfg_t *pc = host->proto_cfgs; pc; pc = pc->next)
    {
        if (pc->proto && strcmp(pc->proto, proto_id) == 0)
        {
            require = pc->require_identified_peer;
            break;
        }
    }
    pthread_mutex_unlock(&host->mtx);
    return require;
}

static int quic_peer_is_identified(libp2p_host_t *host, const peer_id_t *peer)
{
    if (!host || !peer || !host->peerstore)
        return 0;

    uint8_t *pk = NULL;
    size_t pk_len = 0;
    if (libp2p_peerstore_get_public_key(host->peerstore, peer, &pk, &pk_len) == 0)
    {
        int identified = (pk && pk_len > 0);
        if (pk)
            free(pk);
        if (identified)
            return 1;
    }

    const char **protos = NULL;
    size_t n = 0;
    if (libp2p_peerstore_get_protocols(host->peerstore, peer, &protos, &n) == 0)
    {
        int identified = (n > 0);
        libp2p_peerstore_free_protocols(protos, n);
        if (identified)
            return 1;
    }
    return 0;
}

static int quic_run_inbound_handshake(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st)
{
    if (!mx || !st || !st->stream)
        return 0;
    libp2p_host_t *host = atomic_load_explicit(&mx->host, memory_order_acquire);
    if (!host)
        return 0;
    LP_LOGI("QUIC", "run_inbound_handshake START stream_id=%llu", (unsigned long long)st->stream_id);

    if (host->opts.per_conn_max_inbound_streams > 0)
    {
        int limit_reached = 0;
        pthread_mutex_lock(&mx->lock);
        if (mx->accepted_count >= host->opts.per_conn_max_inbound_streams)
            limit_reached = 1;
        pthread_mutex_unlock(&mx->lock);
        if (limit_reached)
        {
            (void)quic_stream_backend_reset(st);
            return 0;
        }
    }

    libp2p_io_t *io = quic_io_from_stream(st);
    if (!io)
        return 0;

    const char **supported = NULL;
    size_t supported_count = 0;
    if (quic_collect_supported_protocols(host, &supported, &supported_count) != 0)
    {
        libp2p_io_free(io);
        return 0;
    }

    libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
    cfg.enable_ls = host->opts.multiselect_enable_ls;
    uint64_t effective_ms = host->opts.multiselect_handshake_timeout_ms;
    pthread_mutex_lock(&host->mtx);
    for (proto_server_cfg_t *pc = host->proto_cfgs; pc; pc = pc->next)
        if (pc->handshake_timeout_ms > 0 && (uint64_t)pc->handshake_timeout_ms > effective_ms)
            effective_ms = (uint64_t)pc->handshake_timeout_ms;
    pthread_mutex_unlock(&host->mtx);
    cfg.handshake_timeout_ms = effective_ms;

    const char *accepted = NULL;
    libp2p_multiselect_err_t ms = libp2p_multiselect_listen_io(io, supported, &cfg, &accepted);
    free((void *)supported);
    libp2p_io_free(io);

    if (ms != LIBP2P_MULTISELECT_OK || !accepted)
    {
        LP_LOGD("QUIC", "run_inbound_handshake multiselect failed ms=%d stream_id=%llu", (int)ms, (unsigned long long)st->stream_id);
        return 0;
    }
    LP_LOGI("QUIC", "run_inbound_handshake multiselect OK accepted=%s stream_id=%llu", accepted, (unsigned long long)st->stream_id);

    libp2p_stream_t *stream = st->stream;
    if (libp2p_stream_set_protocol_id(stream, accepted) != 0)
    {
        free((void *)accepted);
        return 0;
    }
    free((void *)accepted);

    if (mx->conn)
    {
        peer_id_t *peer = NULL;
        if (libp2p_quic_conn_copy_verified_peer(mx->conn, &peer) == 0 && peer)
        {
            if (libp2p_stream_set_remote_peer(stream, peer) != 0)
            {
                peer_id_destroy(peer);
                free(peer);
                return 0;
            }
        }
    }

    pthread_mutex_lock(&st->lock);
    st->handshake_done = 1;
    pthread_mutex_unlock(&st->lock);
    pthread_mutex_lock(&mx->lock);
    mx->accepted_count++;
    pthread_mutex_unlock(&mx->lock);

    const char *proto_id = libp2p_stream_protocol_id(stream);
    libp2p__emit_protocol_negotiated(host, proto_id);
    libp2p__emit_stream_opened(host, proto_id, libp2p_stream_remote_peer(stream), false);

    libp2p_protocol_def_t chosen = {0};
    int found = quic_find_protocol_def(host, proto_id, &chosen);
    LP_LOGI("QUIC", "run_inbound_handshake protocol_lookup proto=%s found=%d has_on_open=%d", proto_id, found, chosen.on_open ? 1 : 0);
    if (!found)
    {
        libp2p_stream_close(stream);
        return 0;
    }

    if (quic_protocol_requires_ident(host, proto_id))
    {
        const peer_id_t *rp = libp2p_stream_remote_peer(stream);
        if (!rp || !quic_peer_is_identified(host, rp))
        {
            libp2p_stream_close(stream);
            return 0;
        }
    }

    if (chosen.on_open)
    {
        quic_proto_open_task_t *task = (quic_proto_open_task_t *)calloc(1, sizeof(*task));
        if (task)
        {
            /* Retain the stream before queueing to the callback thread.
             * The stream will be released in quic_proto_open_exec after on_open returns. */
            if (stream && !libp2p__stream_retain_async(stream))
            {
                free(task);
            }
            else
            {
                task->def = chosen;
                task->stream = stream;
                /* Re-check host right before queueing to avoid use-after-free race */
                host = atomic_load_explicit(&mx->host, memory_order_acquire);
                if (!host)
                {
                    libp2p__stream_release_async(stream);
                    free(task);
                }
                else
                {
                    libp2p__exec_on_cb_thread(host, quic_proto_open_exec, task);
                }
            }
        }
    }

    if (chosen.read_mode == LIBP2P_READ_PUSH && chosen.on_data)
    {
        size_t cap = quic_protocol_cap(host, proto_id);
        quic_attach_push(st, &chosen, cap);
    }

    return 1;
}


#ifndef _WIN32
static int quic_multiaddr_to_sockaddr(const multiaddr_t *addr,
                                      struct sockaddr_storage *ss,
                                      socklen_t *ss_len)
{
    if (!addr || !ss || !ss_len)
        return -1;

    const size_t n = multiaddr_nprotocols(addr);
    if (n < 2)
        return -1;

    uint64_t code0 = 0;
    if (multiaddr_get_protocol_code(addr, 0, &code0) != 0)
        return -1;

    if (code0 == MULTICODEC_IP4)
    {
        uint64_t code1 = 0;
        if (multiaddr_get_protocol_code(addr, 1, &code1) != 0 || code1 != MULTICODEC_UDP)
            return -1;

        uint8_t ip[4];
        size_t ip_len = sizeof(ip);
        if (multiaddr_get_address_bytes(addr, 0, ip, &ip_len) != MULTIADDR_SUCCESS || ip_len != sizeof(ip))
            return -1;

        uint8_t pb[2];
        size_t pb_len = sizeof(pb);
        if (multiaddr_get_address_bytes(addr, 1, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != sizeof(pb))
            return -1;

        struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
        memset(v4, 0, sizeof(*v4));
        v4->sin_family = AF_INET;
#ifdef __APPLE__
        v4->sin_len = sizeof(*v4);
#endif
        memcpy(&v4->sin_addr, ip, sizeof(ip));
        v4->sin_port = htons((uint16_t)((pb[0] << 8) | pb[1]));
        *ss_len = sizeof(*v4);
        return 0;
    }

#ifdef AF_INET6
    if (code0 == MULTICODEC_IP6)
    {
        uint8_t ip6[16];
        size_t ip6_len = sizeof(ip6);
        if (multiaddr_get_address_bytes(addr, 0, ip6, &ip6_len) != MULTIADDR_SUCCESS || ip6_len != sizeof(ip6))
            return -1;

        size_t idx = 1;
        uint64_t code = 0;
        if (multiaddr_get_protocol_code(addr, idx, &code) != 0)
            return -1;

        char zonebuf[IFNAMSIZ] = {0};
        unsigned long zone_index = 0;

        if (code == MULTICODEC_IP6ZONE)
        {
            size_t zl = IFNAMSIZ - 1;
            if (multiaddr_get_address_bytes(addr, idx, (uint8_t *)zonebuf, &zl) != MULTIADDR_SUCCESS || zl == 0)
                return -1;
            zonebuf[zl] = '\0';
#ifdef __APPLE__
            zone_index = if_nametoindex(zonebuf);
#elif defined(__linux__)
            zone_index = if_nametoindex(zonebuf);
#else
            zone_index = 0;
#endif
            idx++;
            if (idx >= n || multiaddr_get_protocol_code(addr, idx, &code) != 0)
                return -1;
        }

        if (code != MULTICODEC_UDP)
            return -1;

        uint8_t pb[2];
        size_t pb_len = sizeof(pb);
        if (multiaddr_get_address_bytes(addr, idx, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != sizeof(pb))
            return -1;

        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
        memset(v6, 0, sizeof(*v6));
        v6->sin6_family = AF_INET6;
#ifdef __APPLE__
        v6->sin6_len = sizeof(*v6);
#endif
        memcpy(&v6->sin6_addr, ip6, sizeof(ip6));
        v6->sin6_port = htons((uint16_t)((pb[0] << 8) | pb[1]));
        v6->sin6_scope_id = (uint32_t)zone_index;
        *ss_len = sizeof(*v6);
        return 0;
    }
#endif /* AF_INET6 */

    return -1;
}
#endif /* !_WIN32 */

static int quic_multiaddr_udp_params(const multiaddr_t *addr, int *af_out, uint16_t *port_out)
{
    if (!addr)
        return -1;

    const size_t n = multiaddr_nprotocols(addr);
    if (n < 3)
        return -1;

    size_t idx = 0;
    uint64_t code = 0;
    if (multiaddr_get_protocol_code(addr, idx, &code) != 0)
        return -1;

    int af = AF_UNSPEC;
    if (code == MULTICODEC_IP4)
    {
        af = AF_INET;
    }
    else if (code == MULTICODEC_IP6)
    {
        af = AF_INET6;
    }
    else
    {
        return -1;
    }

    idx++;
    if (idx < n && multiaddr_get_protocol_code(addr, idx, &code) == 0 && code == MULTICODEC_IP6ZONE)
        idx++;

    if (idx >= n || multiaddr_get_protocol_code(addr, idx, &code) != 0 || code != MULTICODEC_UDP)
        return -1;

    if (af_out)
        *af_out = af;

    if (port_out)
    {
        uint8_t pb[2];
        size_t pb_len = sizeof(pb);
        if (multiaddr_get_address_bytes(addr, idx, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != 2)
            return -1;
        *port_out = (uint16_t)((pb[0] << 8) | pb[1]);
    }

    return 0;
}

/* Lock/unlock callbacks for socket loop thread synchronization.
 * These are called by the socket loop to serialize access to picoquic's
 * internal data structures (especially the cnx_wake_tree splay tree). */
static void quic_session_lock_cb(void *ctx)
{
    libp2p_quic_session_t *session = (libp2p_quic_session_t *)ctx;
    if (session && session->quic_mtx)
        pthread_mutex_lock(session->quic_mtx);
}

static void quic_session_unlock_cb(void *ctx)
{
    libp2p_quic_session_t *session = (libp2p_quic_session_t *)ctx;
    if (session && session->quic_mtx)
        pthread_mutex_unlock(session->quic_mtx);
}

void libp2p__quic_session_wake(libp2p_quic_session_t *session)
{
    if (!session)
        return;

    picoquic_network_thread_ctx_t *loop_ctx = NULL;
    pthread_mutex_lock(&session->lock);
    loop_ctx = session->loop_ctx;
    pthread_mutex_unlock(&session->lock);
    if (loop_ctx)
        (void)picoquic_wake_up_network_thread(loop_ctx);
}

static const char *quic_loop_cb_mode_name(picoquic_packet_loop_cb_enum mode)
{
    switch (mode)
    {
        case picoquic_packet_loop_ready:
            return "ready";
        case picoquic_packet_loop_after_receive:
            return "after_receive";
        case picoquic_packet_loop_after_send:
            return "after_send";
        case picoquic_packet_loop_port_update:
            return "port_update";
        case picoquic_packet_loop_time_check:
            return "time_check";
        case picoquic_packet_loop_system_call_duration:
            return "system_call_duration";
        case picoquic_packet_loop_wake_up:
            return "wake_up";
        default:
            return "unknown";
    }
}

static int quic_packet_loop_cb(picoquic_quic_t *quic,
                               picoquic_packet_loop_cb_enum cb_mode,
                               void *callback_ctx,
                               void *callback_arg)
{
    (void)quic;
    (void)callback_arg;

    libp2p_quic_session_t *session = (libp2p_quic_session_t *)callback_ctx;
    if (!session)
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;

    if (cb_mode == picoquic_packet_loop_ready && callback_arg)
    {
        picoquic_packet_loop_options_t *opts = (picoquic_packet_loop_options_t *)callback_arg;
        opts->do_time_check = 1;
    }

    if (atomic_load_explicit(&session->loop_stop, memory_order_acquire))
        return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;

    return 0;
}

int libp2p__quic_session_start_loop(libp2p_quic_session_t *session,
                                    const multiaddr_t *local_addr,
                                    const multiaddr_t *remote_addr)
{
    if (!session)
        return LIBP2P_ERR_NULL_PTR;

    /* For server-mode (inbound) connections, the listener's network thread
     * is already handling the session. We don't need to start a new loop. */
    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (cnx && !picoquic_is_client(cnx))
    {
        /* Mark as started since the listener loop is handling it */
        atomic_store_explicit(&session->loop_started, 1, memory_order_release);
        return 0;
    }

    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&session->loop_started, &expected, 1, memory_order_acq_rel, memory_order_acquire))
    {
        /* Already started */
        return 0;
    }

    if (!session->quic)
    {
        atomic_store_explicit(&session->loop_started, 0, memory_order_release);
        return LIBP2P_ERR_NULL_PTR;
    }

#ifndef _WIN32
    if (!remote_addr)
    {
        atomic_store_explicit(&session->loop_started, 0, memory_order_release);
        return LIBP2P_ERR_NULL_PTR;
    }

    int af_local = AF_UNSPEC;
    uint16_t port_local = 0;
    if (local_addr && quic_multiaddr_udp_params(local_addr, &af_local, &port_local) != 0)
    {
        af_local = AF_UNSPEC;
        port_local = 0;
    }

    int af_remote = AF_UNSPEC;
    if (quic_multiaddr_udp_params(remote_addr, &af_remote, NULL) != 0)
    {
        atomic_store_explicit(&session->loop_started, 0, memory_order_release);
        return LIBP2P_ERR_INTERNAL;
    }

    int effective_af = (af_local != AF_UNSPEC) ? af_local : (af_remote != AF_UNSPEC ? af_remote : AF_INET);
    uint16_t effective_port = port_local;

    pthread_mutex_lock(&session->lock);
    memset(&session->loop_param, 0, sizeof(session->loop_param));
    session->loop_param.local_af = effective_af;
    session->loop_param.local_port = effective_port;
    session->loop_param.dest_if = 0;
    session->loop_param.socket_buffer_size = 0;
    session->loop_param.do_not_use_gso = 0;
#ifdef __APPLE__
    if (remote_addr)
    {
        struct sockaddr_storage remote_ss;
        socklen_t remote_len = 0;
        if (quic_multiaddr_to_sockaddr(remote_addr, &remote_ss, &remote_len) == 0)
        {
            int is_loopback = 0;
            if (remote_ss.ss_family == AF_INET)
            {
                const struct sockaddr_in *v4 = (const struct sockaddr_in *)&remote_ss;
                if (v4->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
                    is_loopback = 1;
            }
#ifdef AF_INET6
            else if (remote_ss.ss_family == AF_INET6)
            {
                const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&remote_ss;
                if (IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr))
                    is_loopback = 1;
            }
#endif
            if (is_loopback)
            {
                unsigned int lo_if = if_nametoindex("lo0");
                if (lo_if != 0)
                    session->loop_param.dest_if = (int)lo_if;
            }
        }
    }
#endif
    pthread_mutex_unlock(&session->lock);

    atomic_store_explicit(&session->loop_stop, 0, memory_order_release);

    int loop_ret = 0;
    picoquic_network_thread_ctx_t *loop_ctx = picoquic_start_network_thread(session->quic,
                                                                            &session->loop_param,
                                                                            quic_packet_loop_cb,
                                                                            session,
                                                                            &loop_ret);
    if (!loop_ctx || loop_ret != 0)
    {
        LP_LOGE("QUIC", "failed to start picoquic network thread (ret=%d)", loop_ret);
        if (loop_ctx)
            picoquic_delete_network_thread(loop_ctx);
        atomic_store_explicit(&session->loop_started, 0, memory_order_release);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Set up thread synchronization callbacks to protect picoquic's internal
     * data structures (especially the cnx_wake_tree splay tree) from concurrent
     * access by the socket loop thread and worker threads (e.g., ping handler). */
    loop_ctx->lock_fn = quic_session_lock_cb;
    loop_ctx->unlock_fn = quic_session_unlock_cb;
    loop_ctx->lock_ctx = session;

    /* Wait for the network thread to be ready before returning.
     * This is necessary to ensure the socket is open and packets
     * can be sent/received before we try to use the connection. */
    uint64_t deadline = picoquic_current_time() + 2000000ULL; /* 2 seconds */
    while (!loop_ctx->thread_is_ready)
    {
        if (picoquic_current_time() > deadline)
        {
            LP_LOGE("QUIC", "network thread failed to become ready within 2 seconds");
            picoquic_delete_network_thread(loop_ctx);
            atomic_store_explicit(&session->loop_started, 0, memory_order_release);
            return LIBP2P_ERR_INTERNAL;
        }
        usleep(1000); /* 1ms */
    }

    pthread_mutex_lock(&session->lock);
    session->loop_ctx = loop_ctx;
    pthread_mutex_unlock(&session->lock);

    return 0;
#else
    int af_local = AF_UNSPEC;
    uint16_t port_local = 0;
    if (local_addr && quic_multiaddr_udp_params(local_addr, &af_local, &port_local) != 0)
    {
        af_local = AF_UNSPEC;
        port_local = 0;
    }

    int af_remote = AF_UNSPEC;
    if (remote_addr && quic_multiaddr_udp_params(remote_addr, &af_remote, NULL) != 0)
        af_remote = AF_UNSPEC;

    int effective_af = (af_local != AF_UNSPEC) ? af_local : (af_remote != AF_UNSPEC ? af_remote : AF_INET);
    uint16_t effective_port = port_local;

    pthread_mutex_lock(&session->lock);
    memset(&session->loop_param, 0, sizeof(session->loop_param));
    session->loop_param.local_af = effective_af;
    session->loop_param.local_port = effective_port;
    session->loop_param.dest_if = 0;
    session->loop_param.socket_buffer_size = 0;
    session->loop_param.do_not_use_gso = 0;
    pthread_mutex_unlock(&session->lock);

    atomic_store_explicit(&session->loop_stop, 0, memory_order_release);

    int loop_ret = 0;
    picoquic_network_thread_ctx_t *loop_ctx = picoquic_start_network_thread(session->quic,
                                                                            &session->loop_param,
                                                                            quic_packet_loop_cb,
                                                                            session,
                                                                            &loop_ret);
    if (!loop_ctx || loop_ret != 0)
    {
        LP_LOGE("QUIC", "failed to start picoquic network thread (ret=%d)", loop_ret);
        if (loop_ctx)
            picoquic_delete_network_thread(loop_ctx);
        atomic_store_explicit(&session->loop_started, 0, memory_order_release);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Set up thread synchronization callbacks to protect picoquic's internal
     * data structures (especially the cnx_wake_tree splay tree) from concurrent
     * access by the socket loop thread and worker threads (e.g., ping handler). */
    loop_ctx->lock_fn = quic_session_lock_cb;
    loop_ctx->unlock_fn = quic_session_unlock_cb;
    loop_ctx->lock_ctx = session;

    /* Wait for the network thread to be ready before returning.
     * This is necessary to ensure the socket is open and packets
     * can be sent/received before we try to use the connection. */
    uint64_t deadline = picoquic_current_time() + 2000000ULL; /* 2 seconds */
    while (!loop_ctx->thread_is_ready)
    {
        if (picoquic_current_time() > deadline)
        {
            LP_LOGE("QUIC", "network thread failed to become ready within 2 seconds");
            picoquic_delete_network_thread(loop_ctx);
            atomic_store_explicit(&session->loop_started, 0, memory_order_release);
            return LIBP2P_ERR_INTERNAL;
        }
        usleep(1000); /* 1ms */
    }

    pthread_mutex_lock(&session->lock);
    session->loop_ctx = loop_ctx;
    pthread_mutex_unlock(&session->lock);

    return 0;
#endif /* _WIN32 */
}

void libp2p__quic_session_stop_loop(libp2p_quic_session_t *session)
{
    if (!session)
        return;

    if (atomic_load_explicit(&session->loop_started, memory_order_acquire) == 0)
        return;

    atomic_store_explicit(&session->loop_stop, 1, memory_order_release);

    picoquic_network_thread_ctx_t *loop_ctx = NULL;

    pthread_mutex_lock(&session->lock);
    loop_ctx = session->loop_ctx;
    session->loop_ctx = NULL;
    pthread_mutex_unlock(&session->lock);

    if (loop_ctx)
    {
        (void)picoquic_wake_up_network_thread(loop_ctx);
        picoquic_delete_network_thread(loop_ctx);
    }

    atomic_store_explicit(&session->loop_started, 0, memory_order_release);
}

void libp2p__quic_session_attach_thread(libp2p_quic_session_t *session,
                                        picoquic_network_thread_ctx_t *thread_ctx)
{
    if (!session)
        return;
    pthread_mutex_lock(&session->lock);
    session->loop_ctx = thread_ctx;
    pthread_mutex_unlock(&session->lock);
}

static quic_stream_chunk_t *quic_chunk_new(const uint8_t *data, size_t len)
{
    quic_stream_chunk_t *chunk = (quic_stream_chunk_t *)malloc(sizeof(*chunk) + len);
    if (!chunk)
        return NULL;
    chunk->next = NULL;
    chunk->offset = 0;
    chunk->len = len;
    if (len && data)
        memcpy(chunk->data, data, len);
    return chunk;
}

static void quic_chunk_consume(quic_stream_ctx_t *ctx, quic_stream_chunk_t *chunk, size_t consumed)
{
    if (!ctx || !chunk)
        return;
    chunk->offset += consumed;
    chunk->len -= consumed;
    if (chunk->len == 0)
    {
        if (ctx->head == chunk)
            ctx->head = chunk->next;
        if (ctx->tail == chunk)
            ctx->tail = chunk->next;
        free(chunk);
    }
}

static void quic_stream_free_chunks(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    quic_stream_chunk_t *cur = ctx->head;
    while (cur)
    {
        quic_stream_chunk_t *next = cur->next;
        free(cur);
        cur = next;
    }
    ctx->head = ctx->tail = NULL;
}

static void quic_stream_ctx_destroy(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    quic_stream_free_chunks(ctx);
    if (ctx->push)
    {
        quic_push_ctx_free(ctx->push);
        ctx->push = NULL;
    }
    quic_muxer_ctx_t *mx = atomic_load_explicit(&ctx->mx, memory_order_acquire);
    if (mx)
    {
        atomic_store_explicit(&ctx->mx, NULL, memory_order_release);
        quic_muxer_ctx_release(mx);
    }
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

static void quic_stream_ctx_retain(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    atomic_fetch_add_explicit(&ctx->refcnt, 1U, memory_order_relaxed);
}

static void quic_stream_ctx_release(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    unsigned int old = atomic_fetch_sub_explicit(&ctx->refcnt, 1U, memory_order_acq_rel);
    if (old == 1U)
        quic_stream_ctx_destroy(ctx);
}

static void quic_muxer_ctx_retain(quic_muxer_ctx_t *ctx)
{
    if (!ctx)
        return;
    atomic_fetch_add_explicit(&ctx->refcnt, 1U, memory_order_relaxed);
}

static void quic_muxer_ctx_release(quic_muxer_ctx_t *ctx)
{
    if (!ctx)
        return;
    unsigned int old = atomic_fetch_sub_explicit(&ctx->refcnt, 1U, memory_order_acq_rel);
    if (old == 1U)
        free(ctx);
}

static quic_session_event_t *quic_session_event_new(uint64_t stream_id,
                                                    const uint8_t *bytes,
                                                    size_t len,
                                                    picoquic_call_back_event_t event)
{
    quic_session_event_t *ev = (quic_session_event_t *)calloc(1, sizeof(*ev));
    if (!ev)
        return NULL;
    ev->stream_id = stream_id;
    ev->event = event;
    ev->len = len;
    if (len > 0 && bytes)
    {
        ev->data = (uint8_t *)malloc(len);
        if (!ev->data)
        {
            free(ev);
            return NULL;
        }
        memcpy(ev->data, bytes, len);
    }
    return ev;
}

static void quic_session_event_free(quic_session_event_t *ev)
{
    if (!ev)
        return;
    free(ev->data);
    free(ev);
}

static void quic_session_pending_append_locked(libp2p_quic_session_t *session,
                                               quic_session_event_t *ev)
{
    if (!session || !ev)
        return;
    ev->next = NULL;
    if (!session->pending_tail)
    {
        session->pending_head = session->pending_tail = ev;
    }
    else
    {
        session->pending_tail->next = ev;
        session->pending_tail = ev;
    }
}

static quic_session_event_t *quic_session_pending_detach_locked(libp2p_quic_session_t *session)
{
    if (!session)
        return NULL;
    quic_session_event_t *head = session->pending_head;
    session->pending_head = session->pending_tail = NULL;
    return head;
}

static void quic_session_clear_pending(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    pthread_mutex_lock(&session->lock);
    quic_session_event_t *cur = quic_session_pending_detach_locked(session);
    pthread_mutex_unlock(&session->lock);
    while (cur)
    {
        quic_session_event_t *next = cur->next;
        quic_session_event_free(cur);
        cur = next;
    }
}

libp2p_quic_session_t *libp2p__quic_session_wrap(picoquic_quic_t *quic, picoquic_cnx_t *cnx)
{
    if (!cnx)
        return NULL;
    libp2p_quic_session_t *session = (libp2p_quic_session_t *)calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    session->quic = quic;
    atomic_store_explicit(&session->cnx, cnx, memory_order_release);
   session->mx = NULL;
   session->host = NULL;
   atomic_store(&session->refcnt, 1);
    memset(&session->loop_param, 0, sizeof(session->loop_param));
    session->loop_ctx = NULL;
    atomic_store(&session->loop_started, 0);
    atomic_store(&session->loop_stop, 0);
    if (pthread_mutex_init(&session->lock, NULL) != 0)
    {
        free(session);
        return NULL;
    }
    if (pthread_mutex_init(&session->quic_mtx_storage, NULL) != 0)
    {
        pthread_mutex_destroy(&session->lock);
        free(session);
        return NULL;
    }
    /* By default, use the session's own mutex storage.
     * For listener sessions, this will be overwritten to point to the listener's mutex. */
    session->quic_mtx = &session->quic_mtx_storage;
    if (cnx)
        picoquic_set_callback(cnx, quic_session_callback, session);
    return session;
}

void libp2p__quic_session_retain(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    atomic_fetch_add_explicit(&session->refcnt, 1, memory_order_relaxed);
}

void libp2p__quic_session_release(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    if (atomic_fetch_sub_explicit(&session->refcnt, 1, memory_order_acq_rel) == 1)
    {
        libp2p__quic_session_stop_loop(session);
        quic_session_clear_pending(session);
        pthread_mutex_destroy(&session->lock);
        /* Only destroy the storage mutex if we own it (not using listener's mutex) */
        if (session->quic_mtx == &session->quic_mtx_storage)
            pthread_mutex_destroy(&session->quic_mtx_storage);
        free(session);
    }
}

void libp2p__quic_session_set_host(libp2p_quic_session_t *session, struct libp2p_host *host)
{
    if (!session)
        return;
    pthread_mutex_lock(&session->lock);
    session->host = host;
    pthread_mutex_unlock(&session->lock);
}

void libp2p__quic_session_set_quic_mtx(libp2p_quic_session_t *session, pthread_mutex_t *mtx)
{
    if (!session)
        return;
    /* For listener sessions, use the listener's mutex instead of our own.
     * This is safe because the session is being created/configured before any
     * concurrent access can occur. */
    if (mtx) {
        /* We no longer need our own mutex storage since we'll use the external one */
        pthread_mutex_destroy(&session->quic_mtx_storage);
        session->quic_mtx = mtx;
    }
}

pthread_mutex_t *libp2p__quic_session_get_quic_mtx(libp2p_quic_session_t *session)
{
    return session ? session->quic_mtx : NULL;
}

picoquic_cnx_t *libp2p__quic_session_native(libp2p_quic_session_t *session)
{
    return session ? atomic_load_explicit(&session->cnx, memory_order_acquire) : NULL;
}

picoquic_quic_t *libp2p__quic_session_quic(libp2p_quic_session_t *session)
{
    return session ? session->quic : NULL;
}

static void quic_session_attach_muxer(libp2p_quic_session_t *session, quic_muxer_ctx_t *mx)
{
    if (!session)
        return;
    pthread_mutex_lock(&session->lock);
    session->mx = mx;
    pthread_mutex_unlock(&session->lock);
}

static quic_muxer_ctx_t *quic_session_muxer(libp2p_quic_session_t *session)
{
    if (!session)
        return NULL;
    pthread_mutex_lock(&session->lock);
    quic_muxer_ctx_t *mx = session->mx;
    pthread_mutex_unlock(&session->lock);
    return mx;
}

static void quic_muxer_append_stream(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st)
{
    if (!mx || !st)
        return;
    st->next = NULL;
    if (!mx->streams_head)
    {
        mx->streams_head = mx->streams_tail = st;
    }
    else
    {
        mx->streams_tail->next = st;
        mx->streams_tail = st;
    }
}

static void quic_muxer_remove_stream(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st)
{
    if (!mx || !st)
        return;
    quic_stream_ctx_t *prev = NULL;
    quic_stream_ctx_t *cur = mx->streams_head;
    while (cur)
    {
        if (cur == st)
        {
            if (prev)
                prev->next = cur->next;
            else
                mx->streams_head = cur->next;
            if (mx->streams_tail == cur)
                mx->streams_tail = prev;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    st->next = NULL;
}

static quic_stream_ctx_t *quic_muxer_find_stream(quic_muxer_ctx_t *mx, uint64_t stream_id)
{
    if (!mx)
        return NULL;
    pthread_mutex_lock(&mx->lock);
    quic_stream_ctx_t *cur = mx->streams_head;
    while (cur)
    {
        if (cur->stream_id == stream_id)
        {
            quic_stream_ctx_retain(cur);
            pthread_mutex_unlock(&mx->lock);
            return cur;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&mx->lock);
    return NULL;
}

static void quic_stream_fire_readable(void *arg)
{
    quic_stream_cb_task_t *task = (quic_stream_cb_task_t *)arg;
    if (!task || !task->stream)
    {
        free(task);
        return;
    }
    
    /* First try the one-shot callback mechanism */
    libp2p_on_readable_fn cb = NULL;
    void *ud = NULL;
    int has_cb = libp2p__stream_consume_on_readable(task->stream, &cb, &ud);
    if (has_cb && cb)
    {
        cb(task->stream, ud);
        libp2p__stream_release_async(task->stream);
        free(task);
        return;
    }
    
    /* For push-mode streams: if no one-shot callback, try the push context.
     * This handles the case where multiple fire_readable events are queued
     * but the callback was already consumed by an earlier event. */
    quic_stream_ctx_t *st = task->st;
    if (st && st->push && st->push->def.on_data)
    {
        quic_push_on_readable(task->stream, st->push);
    }
    
    libp2p__stream_release_async(task->stream);
    free(task);
}

static void quic_stream_fire_writable(void *arg)
{
    quic_stream_cb_task_t *task = (quic_stream_cb_task_t *)arg;
    if (!task || !task->stream)
    {
        free(task);
        return;
    }
    libp2p_on_writable_fn cb = NULL;
    void *ud = NULL;
    if (libp2p__stream_consume_on_writable(task->stream, &cb, &ud) && cb)
        cb(task->stream, ud);
    libp2p__stream_release_async(task->stream);
    free(task);
}

static void quic_stream_schedule_readable(quic_stream_ctx_t *ctx, quic_muxer_ctx_t *mx, libp2p_stream_t *stream)
{
    if (!ctx || !stream || !mx)
        return;
    /* Use the passed-in muxer and stream instead of reloading from ctx to avoid
     * race conditions where ctx->mx or ctx->stream change between dispatch and here. */
    struct libp2p_host *host = atomic_load_explicit(&mx->host, memory_order_acquire);
    if (!host)
        return;
    if (!libp2p__stream_retain_async(stream))
        return;
    quic_stream_cb_task_t *task = (quic_stream_cb_task_t *)calloc(1, sizeof(*task));
    if (!task)
    {
        libp2p__stream_release_async(stream);
        return;
    }
    task->stream = stream;
    task->st = ctx;  /* Store stream ctx for push-mode fallback */
    /* Re-check host right before queueing to avoid use-after-free race */
    host = atomic_load_explicit(&mx->host, memory_order_acquire);
    if (!host)
    {
        libp2p__stream_release_async(stream);
        free(task);
        return;
    }
    libp2p__exec_on_cb_thread(host, quic_stream_fire_readable, task);
}

static void quic_stream_schedule_writable(quic_stream_ctx_t *ctx)
{
    if (!ctx || !ctx->stream)
        return;
    /* Atomically load muxer to avoid use-after-free during teardown */
    quic_muxer_ctx_t *mx = atomic_load_explicit(&ctx->mx, memory_order_acquire);
    if (!mx)
        return;
    /* Atomically load host to avoid use-after-free during teardown */
    struct libp2p_host *host = atomic_load_explicit(&mx->host, memory_order_acquire);
    if (!host)
        return;
    libp2p_stream_t *stream = ctx->stream;
    if (!libp2p__stream_retain_async(stream))
        return;
    quic_stream_cb_task_t *task = (quic_stream_cb_task_t *)calloc(1, sizeof(*task));
    if (!task)
    {
        libp2p__stream_release_async(stream);
        return;
    }
    task->stream = stream;
    /* Re-check muxer and host right before queueing to avoid use-after-free race */
    mx = atomic_load_explicit(&ctx->mx, memory_order_acquire);
    if (!mx)
    {
        libp2p__stream_release_async(stream);
        free(task);
        return;
    }
    host = atomic_load_explicit(&mx->host, memory_order_acquire);
    if (!host)
    {
        libp2p__stream_release_async(stream);
        free(task);
        return;
    }
    libp2p__exec_on_cb_thread(host, quic_stream_fire_writable, task);
}

static void quic_stream_handshake_exec(void *arg)
{
    quic_handshake_task_t *task = (quic_handshake_task_t *)arg;
    if (!task)
        return;
    quic_muxer_ctx_t *mx = task->mx;
    quic_stream_ctx_t *st = task->st;
    libp2p_stream_t *stream = task->stream;
    free(task);

    if (!st)
    {
        if (stream)
            libp2p__stream_release_async(stream);
        return;
    }

    int ok = 0;
    libp2p_quic_session_t *session = quic_muxer_retain_session(mx);
    libp2p_host_t *host = mx ? atomic_load_explicit(&mx->host, memory_order_acquire) : NULL;
    if (mx && host && session)
        ok = quic_run_inbound_handshake(mx, st);

    if (!ok)
    {
        if (session)
        {
            picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
            if (cnx && session->quic_mtx)
            {
                pthread_mutex_lock(session->quic_mtx);
                picoquic_set_app_stream_ctx(cnx, st->stream_id, NULL);
                pthread_mutex_unlock(session->quic_mtx);
            }
        }
        libp2p_stream_t *stream = NULL;
        pthread_mutex_lock(&st->lock);
        stream = st->stream;
        if (stream)
            st->stream = NULL;
        pthread_mutex_unlock(&st->lock);
        int host_tearing_down = 0;
        /* Re-load host pointer atomically for teardown check */
        host = mx ? atomic_load_explicit(&mx->host, memory_order_acquire) : NULL;
        if (host)
        {
            pthread_mutex_lock(&host->mtx);
            host_tearing_down = host->tearing_down;
            pthread_mutex_unlock(&host->mtx);
        }
        else
        {
            host_tearing_down = 1;
        }
        if (stream && !host_tearing_down)
        {
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
        }
    }
    else
    {
        /* Capture stream pointer while holding lock to avoid race condition */
        libp2p_stream_t *stream_for_readable = NULL;
        pthread_mutex_lock(&st->lock);
        stream_for_readable = st->stream;
        pthread_mutex_unlock(&st->lock);
        if (stream_for_readable)
            quic_stream_schedule_readable(st, mx, stream_for_readable);
    }
    quic_muxer_release_session(session);

    pthread_mutex_lock(&st->lock);
    st->handshake_running = 0;
    if (!ok && !st->handshake_done)
        st->handshake_done = 1;
    pthread_mutex_unlock(&st->lock);

    quic_muxer_ctx_release(mx);
    quic_stream_ctx_release(st);
    if (stream)
        libp2p__stream_release_async(stream);
}

static void quic_stream_start_handshake(quic_muxer_ctx_t *mx, quic_stream_ctx_t *st, libp2p_stream_t *stream_for_handshake)
{
    if (!st)
        return;
    if (!stream_for_handshake)
    {
        pthread_mutex_lock(&st->lock);
        st->handshake_running = 0;
        if (!st->handshake_done)
            st->handshake_done = 1;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    libp2p_host_t *host = mx ? atomic_load_explicit(&mx->host, memory_order_acquire) : NULL;
    if (!mx || !host)
    {
        pthread_mutex_lock(&st->lock);
        st->handshake_running = 0;
        if (!st->handshake_done)
            st->handshake_done = 1;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    quic_handshake_task_t *task = (quic_handshake_task_t *)calloc(1, sizeof(*task));
    if (!task)
    {
        pthread_mutex_lock(&st->lock);
        st->handshake_running = 0;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    task->mx = mx;
    task->st = st;
    task->stream = stream_for_handshake;
    quic_stream_ctx_retain(st);
    quic_muxer_ctx_retain(mx);
    int retained = 0;
    pthread_mutex_lock(&st->lock);
    if (st->stream == stream_for_handshake)
        retained = libp2p__stream_retain_async(stream_for_handshake);
    pthread_mutex_unlock(&st->lock);
    if (task->stream && !retained)
    {
        quic_muxer_ctx_release(mx);
        quic_stream_ctx_release(st);
        free(task);
        pthread_mutex_lock(&st->lock);
        st->handshake_running = 0;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    /* Re-check host pointer right before queueing to avoid use-after-free race.
     * Between loading the host pointer and reaching this point, the host may have
     * been torn down and freed. Re-load atomically to check. */
    host = atomic_load_explicit(&mx->host, memory_order_acquire);
    if (!host)
    {
        /* Host was freed, clean up */
        if (task->stream)
            libp2p__stream_release_async(task->stream);
        quic_muxer_ctx_release(mx);
        quic_stream_ctx_release(st);
        free(task);
        pthread_mutex_lock(&st->lock);
        st->handshake_running = 0;
        if (!st->handshake_done)
            st->handshake_done = 1;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    pthread_mutex_lock(&st->lock);
    if (st->stream != stream_for_handshake)
    {
        pthread_mutex_unlock(&st->lock);
        if (task->stream)
            libp2p__stream_release_async(task->stream);
        quic_muxer_ctx_release(mx);
        quic_stream_ctx_release(st);
        free(task);
        pthread_mutex_lock(&st->lock);
        st->handshake_running = 0;
        if (!st->handshake_done)
            st->handshake_done = 1;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    pthread_mutex_unlock(&st->lock);
    libp2p__exec_on_cb_thread(host, quic_stream_handshake_exec, task);
}

static void quic_stream_push_bytes(quic_stream_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || !len)
        return;
    quic_stream_chunk_t *chunk = quic_chunk_new(data, len);
    if (!chunk)
    {
        LP_LOGE("QUIC", "stream %" PRIu64 " failed to allocate chunk (%zu bytes)", ctx->stream_id, len);
        return;
    }
    if (!ctx->head)
        ctx->head = ctx->tail = chunk;
    else
    {
        ctx->tail->next = chunk;
        ctx->tail = chunk;
    }
}

static void quic_stream_mark_fin(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    ctx->fin_remote = 1;
}

static void quic_stream_mark_reset(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    ctx->reset_remote = 1;
}

static void quic_stream_mark_stop_sending(quic_stream_ctx_t *ctx)
{
    if (!ctx)
        return;
    ctx->stop_sending_received = 1;
}

static int quic_session_dispatch(libp2p_quic_session_t *session,
                                 quic_muxer_ctx_t *mx,
                                 picoquic_cnx_t *cnx,
                                 uint64_t stream_id,
                                 uint8_t *bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void *stream_ctx)
{
    (void)session;
    (void)cnx;
    (void)stream_ctx;
    if (!mx)
        return 0;

    LP_LOGI("QUIC", "muxer_stream_event stream_id=%llu event=%d length=%zu",
            (unsigned long long)stream_id, (int)event, length);

    quic_stream_ctx_t *st = quic_muxer_find_stream(mx, stream_id);
    switch (event)
    {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            if (!st)
            {
                LP_LOGI("QUIC", "accepting inbound stream stream_id=%llu", (unsigned long long)stream_id);
                st = quic_accept_inbound_stream(mx, stream_id);
            }
            if (st)
            {
                int schedule_handshake = 0;
                int handshake_done_now = 0;
                int already_fin = 0;
                libp2p_stream_t *stream_for_readable = NULL;
                libp2p_stream_t *stream_for_handshake = NULL;
                pthread_mutex_lock(&st->lock);
                /* Check if FIN was already received - if so, a duplicate FIN event
                 * with no data is a late-arriving notification that should be ignored
                 * to avoid spurious EOF returns to higher layers. */
                already_fin = st->fin_remote;
                if (length && bytes)
                    quic_stream_push_bytes(st, bytes, length);
                if (event == picoquic_callback_stream_fin && !already_fin)
                    quic_stream_mark_fin(st);
                handshake_done_now = st->handshake_done;
                if (!st->handshake_done && !st->handshake_running)
                {
                    st->handshake_started = 1;
                    st->handshake_running = 1;
                    schedule_handshake = 1;
                }
                /* Capture stream pointer while holding lock to avoid race condition */
                stream_for_readable = st->stream;
                stream_for_handshake = st->stream;
                pthread_mutex_unlock(&st->lock);

                if (schedule_handshake)
                    quic_stream_start_handshake(mx, st, stream_for_handshake);

                /* Only schedule readable if there's new data or this is the first FIN.
                 * A duplicate FIN with no data should not trigger a spurious readable event. */
                if (handshake_done_now && stream_for_readable && (length > 0 || !already_fin))
                    quic_stream_schedule_readable(st, mx, stream_for_readable);
            }
            else
            {
                LP_LOGW("QUIC", "data event for unknown stream %" PRIu64, stream_id);
            }
            break;
        case picoquic_callback_stream_reset:
            if (!st)
                st = quic_accept_inbound_stream(mx, stream_id);
            if (st)
            {
                libp2p_stream_t *stream_for_readable = NULL;
                pthread_mutex_lock(&st->lock);
                quic_stream_mark_reset(st);
                /* Capture stream pointer while holding lock to avoid race condition */
                stream_for_readable = st->stream;
                pthread_mutex_unlock(&st->lock);
                quic_stream_schedule_readable(st, mx, stream_for_readable);
            }
            else
            {
                LP_LOGW("QUIC", "reset event for unknown stream %" PRIu64, stream_id);
            }
            break;
        case picoquic_callback_stop_sending:
            /* Peer sent STOP_SENDING frame - they don't want to receive more data on this stream.
             * Mark the stream so we stop trying to write to it.
             * Note: picoquic already sets stream->stop_sending_received, which causes
             * picoquic_add_to_stream to return -1. By marking it here, we allow higher
             * layers (like gossipsub) to detect this state and stop retrying writes. */
            if (st)
            {
                pthread_mutex_lock(&st->lock);
                quic_stream_mark_stop_sending(st);
                pthread_mutex_unlock(&st->lock);
                LP_LOGI("QUIC", "stop_sending received for stream %" PRIu64, stream_id);
            }
            else
            {
                /* Stream doesn't exist yet - record this STOP_SENDING so we can apply it
                 * when the stream is created. This handles the race condition where
                 * STOP_SENDING arrives before the stream's initial data. */
                LP_LOGW("QUIC", "stop_sending event for unknown stream %" PRIu64 ", queueing for later", stream_id);
                pthread_mutex_lock(&mx->lock);
                quic_muxer_add_pending_stop_sending(mx, stream_id);
                pthread_mutex_unlock(&mx->lock);
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Not using active send callbacks yet. */
            break;
        default:
            break;
    }
    if (st)
        quic_stream_ctx_release(st);
    return 0;
}

static void quic_session_replay_events(libp2p_quic_session_t *session,
                                       quic_muxer_ctx_t *mx,
                                       picoquic_cnx_t *cnx,
                                       quic_session_event_t *events)
{
    quic_session_event_t *cur = events;
    while (cur)
    {
        quic_session_event_t *next = cur->next;
        quic_session_dispatch(session,
                              mx,
                              cnx,
                              cur->stream_id,
                              cur->data,
                              cur->len,
                              cur->event,
                              NULL);
        quic_session_event_free(cur);
        cur = next;
    }
}

static void quic_session_flush_pending(libp2p_quic_session_t *session, quic_muxer_ctx_t *mx)
{
    if (!session)
        return;
    /* Maintain consistent lock ordering with the socket-loop callbacks: always
     * acquire quic_mtx before session->lock to avoid deadlock. */
    pthread_mutex_t *quic_mtx = session->quic_mtx;
    if (quic_mtx)
        pthread_mutex_lock(quic_mtx);

    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    int mx_from_session = 0;
    pthread_mutex_lock(&session->lock);
    if (!mx)
    {
        mx = session->mx;
        mx_from_session = 1;
    }
    if (mx && mx_from_session)
        quic_muxer_ctx_retain(mx);
    quic_session_event_t *pending = quic_session_pending_detach_locked(session);
    pthread_mutex_unlock(&session->lock);

    if (pending)
    {
        quic_session_replay_events(session, mx, cnx, pending);
    }

    if (mx && mx_from_session)
        quic_muxer_ctx_release(mx);

    if (quic_mtx)
        pthread_mutex_unlock(quic_mtx);
}

static int quic_session_callback(picoquic_cnx_t *cnx,
                                 uint64_t stream_id,
                                 uint8_t *bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void *callback_ctx,
                                 void *stream_ctx)
{
    libp2p_quic_session_t *session = (libp2p_quic_session_t *)callback_ctx;
    if (!session)
        return 0;

    int closing_event = (event == picoquic_callback_close ||
                         event == picoquic_callback_application_close ||
                         event == picoquic_callback_stateless_reset);

    if (closing_event)
        quic_session_disable_cnx(session);

    int bufferable = (event == picoquic_callback_stream_data ||
                      event == picoquic_callback_stream_fin ||
                      event == picoquic_callback_stream_reset ||
                      event == picoquic_callback_stop_sending);

    quic_muxer_ctx_t *mx = NULL;
    quic_session_event_t *pending = NULL;

    pthread_mutex_lock(&session->lock);
    mx = session->mx;
    if (!mx)
    {
        if (bufferable)
        {
            quic_session_event_t *ev = quic_session_event_new(stream_id, bytes, length, event);
            if (ev)
                quic_session_pending_append_locked(session, ev);
        }
        pthread_mutex_unlock(&session->lock);
        return 0;
    }
    /* Retain muxer before releasing session lock to prevent use-after-free.
     * The muxer could be freed by another thread after we release the lock. */
    quic_muxer_ctx_retain(mx);
    pending = quic_session_pending_detach_locked(session);
    pthread_mutex_unlock(&session->lock);

    if (pending)
        quic_session_replay_events(session, mx, cnx, pending);

    int ret = quic_session_dispatch(session, mx, cnx, stream_id, bytes, length, event, stream_ctx);
    quic_muxer_ctx_release(mx);
    return ret;
}

static ssize_t quic_stream_backend_read(void *io_ctx, void *buf, size_t len)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st || !buf)
        return LIBP2P_ERR_NULL_PTR;
    if (len == 0)
        return 0;
    ssize_t copied = 0;
    pthread_mutex_lock(&st->lock);
    if (st->reset_remote)
    {
        pthread_mutex_unlock(&st->lock);
        return LIBP2P_ERR_RESET;
    }
    while (st->head && copied < (ssize_t)len)
    {
        quic_stream_chunk_t *chunk = st->head;
        size_t remaining = len - (size_t)copied;
        size_t take = chunk->len < remaining ? chunk->len : remaining;
        if (take > 0)
        {
            memcpy((uint8_t *)buf + copied, chunk->data + chunk->offset, take);
            copied += (ssize_t)take;
            quic_chunk_consume(st, chunk, take);
        }
        if (take == 0)
            break;
    }
    if (copied == 0)
    {
        if (st->fin_remote)
        {
            pthread_mutex_unlock(&st->lock);
            return 0;
        }
        pthread_mutex_unlock(&st->lock);
        return LIBP2P_ERR_AGAIN;
    }
    pthread_mutex_unlock(&st->lock);
    return copied;
}

static ssize_t quic_stream_backend_write(void *io_ctx, const void *buf, size_t len)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st || !buf)
        return LIBP2P_ERR_NULL_PTR;
    quic_muxer_ctx_t *mx = atomic_load_explicit(&st->mx, memory_order_acquire);
    if (!mx)
        return LIBP2P_ERR_INTERNAL;
    /* Fast path bail out if muxer already marked closed. */
    if (atomic_load_explicit(&mx->closed, memory_order_acquire))
        return LIBP2P_ERR_CLOSED;
    /* Fast path bail out if peer sent STOP_SENDING for this stream. */
    if (st->stop_sending_received)
        return LIBP2P_ERR_CLOSED;
    if (len == 0)
        return 0;
    libp2p_quic_session_t *session = quic_muxer_retain_session(mx);
    if (!session)
        return LIBP2P_ERR_CLOSED;
    /* Snapshot cnx before taking write lock; session->cnx is nulled during close. */
    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (!cnx)
    {
        LP_LOGW("QUIC",
                "stream_backend_write drop ctx=%p stream_id=%" PRIu64 " reason=dead-session",
                (void *)st,
                st->stream_id);
        quic_muxer_release_session(session);
        return LIBP2P_ERR_CLOSED;
    }
    picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx);
    /* Avoid writing into a connection that is already closing/disconnected. */
    if (cnx_state >= picoquic_state_disconnected || cnx_state == picoquic_state_closing ||
        cnx_state == picoquic_state_closing_received)
    {
        LP_LOGW("QUIC",
                "stream_backend_write drop ctx=%p stream_id=%" PRIu64 " state=%s(%d)",
                (void *)st,
                st->stream_id,
                libp2p__quic_state_name(cnx_state),
                (int)cnx_state);
        quic_muxer_release_session(session);
        return LIBP2P_ERR_CLOSED;
    }
    LP_LOGD("QUIC",
            "stream_backend_write ctx=%p cnx=%p stream_id=%" PRIu64 " len=%zu",
            (void *)st,
            (void *)cnx,
            st->stream_id,
            len);
    pthread_mutex_lock(&mx->write_mtx);
    /* Re-check closed/connection after acquiring write lock to narrow race on shutdown. */
    int mx_closed = atomic_load_explicit(&mx->closed, memory_order_acquire);
    picoquic_cnx_t *current_cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (mx_closed || current_cnx != cnx)
    {
        pthread_mutex_unlock(&mx->write_mtx);
        quic_muxer_release_session(session);
        return LIBP2P_ERR_CLOSED;
    }
    /* Acquire quic_mtx to synchronize with the socket loop thread.
     * This prevents concurrent access to picoquic's internal data structures
     * (especially the cnx_wake_tree splay tree) which are not thread-safe. */
    pthread_mutex_lock(session->quic_mtx);
    int rc = picoquic_add_to_stream(cnx, st->stream_id, (const uint8_t *)buf, len, 0);
    pthread_mutex_unlock(session->quic_mtx);
    pthread_mutex_unlock(&mx->write_mtx);
    if (rc != 0)
    {
        LP_LOGW("QUIC",
                "stream_backend_write result ctx=%p cnx=%p stream_id=%" PRIu64 " rc=%d",
                (void *)st,
                (void *)cnx,
                st->stream_id,
                rc);
    }
    libp2p__quic_session_wake(session);
    if (rc == 0)
    {
        quic_stream_schedule_writable(st);
        quic_muxer_release_session(session);
        return (ssize_t)len;
    }
    ssize_t err = LIBP2P_ERR_INTERNAL;
    if (rc == PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL)
    {
        err = LIBP2P_ERR_AGAIN;
        /* Schedule writable callback so higher layers (gossipsub) can retry
         * when the stream becomes writable again after backpressure clears. */
        quic_stream_schedule_writable(st);
    }
    else if (rc == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED)
        err = LIBP2P_ERR_CLOSED;
    else if (rc == PICOQUIC_ERROR_INVALID_STREAM_ID)
        err = LIBP2P_ERR_INTERNAL;
    else if (rc == -1)
    {
        /* picoquic returns -1 when stream->reset_sent or stream->stop_sending_received is set.
         * Mark the stream as having received stop_sending so we bail out early on future writes. */
        st->stop_sending_received = 1;
        err = LIBP2P_ERR_CLOSED;
    }
    quic_muxer_release_session(session);
    return err;
}

static int quic_stream_backend_close(void *io_ctx)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    quic_muxer_ctx_t *mx = atomic_load_explicit(&st->mx, memory_order_acquire);
    if (!mx)
        return LIBP2P_ERR_NULL_PTR;
    if (atomic_load_explicit(&mx->closed, memory_order_acquire))
        return LIBP2P_ERR_CLOSED;
    if (st->fin_local)
        return 0;
    libp2p_quic_session_t *session = quic_muxer_retain_session(mx);
    if (!session)
        return LIBP2P_ERR_CLOSED;
    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (!cnx)
    {
        quic_muxer_release_session(session);
        return LIBP2P_ERR_CLOSED;
    }
    pthread_mutex_lock(&mx->write_mtx);
    /* Acquire quic_mtx to synchronize with the socket loop thread.
     * This prevents concurrent access to picoquic's internal data structures
     * (especially the cnx_wake_tree splay tree) which are not thread-safe. */
    if (session->quic_mtx)
        pthread_mutex_lock(session->quic_mtx);
    int rc = picoquic_add_to_stream(cnx, st->stream_id, NULL, 0, 1);
    if (session->quic_mtx)
        pthread_mutex_unlock(session->quic_mtx);
    pthread_mutex_unlock(&mx->write_mtx);
    libp2p__quic_session_wake(session);
    quic_muxer_release_session(session);
    if (rc == 0)
    {
        st->fin_local = 1;
        return 0;
    }
    if (rc == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED)
        return 0;
    return LIBP2P_ERR_INTERNAL;
}

/* Half-close: send FIN on the write side while keeping read open.
 * This is essentially the same as close at QUIC level since QUIC streams
 * support half-close natively (close just sets fin_local, doesn't affect reads). */
static int quic_stream_backend_shutdown_write(void *io_ctx)
{
    return quic_stream_backend_close(io_ctx);
}

static int quic_stream_backend_reset(void *io_ctx)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    quic_muxer_ctx_t *mx = atomic_load_explicit(&st->mx, memory_order_acquire);
    if (!mx)
        return LIBP2P_ERR_NULL_PTR;
    if (atomic_load_explicit(&mx->closed, memory_order_acquire))
        return LIBP2P_ERR_CLOSED;
    libp2p_quic_session_t *session = quic_muxer_retain_session(mx);
    if (!session)
        return LIBP2P_ERR_CLOSED;
    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (!cnx)
    {
        quic_muxer_release_session(session);
        return LIBP2P_ERR_CLOSED;
    }
    pthread_mutex_lock(&mx->write_mtx);
    /* Acquire quic_mtx to synchronize with the socket loop thread.
     * This prevents concurrent access to picoquic's internal data structures
     * (especially the cnx_wake_tree splay tree) which are not thread-safe. */
    if (session->quic_mtx)
        pthread_mutex_lock(session->quic_mtx);
    int rc = picoquic_reset_stream(cnx, st->stream_id, 0);
    if (session->quic_mtx)
        pthread_mutex_unlock(session->quic_mtx);
    pthread_mutex_unlock(&mx->write_mtx);
    libp2p__quic_session_wake(session);
    quic_muxer_release_session(session);
    if (rc == 0)
    {
        pthread_mutex_lock(&st->lock);
        quic_stream_mark_reset(st);
        pthread_mutex_unlock(&st->lock);
        return 0;
    }
    if (rc == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED)
        return 0;
    return LIBP2P_ERR_INTERNAL;
}

static int quic_stream_backend_set_deadline(void *io_ctx, uint64_t ms)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&st->lock);
    st->deadline_ms = ms;
    pthread_mutex_unlock(&st->lock);
    return 0;
}

static const multiaddr_t *quic_stream_backend_local(void *io_ctx)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return NULL;
    quic_muxer_ctx_t *mx = atomic_load_explicit(&st->mx, memory_order_acquire);
    return mx ? mx->local : NULL;
}

static const multiaddr_t *quic_stream_backend_remote(void *io_ctx)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return NULL;
    quic_muxer_ctx_t *mx = atomic_load_explicit(&st->mx, memory_order_acquire);
    return mx ? mx->remote : NULL;
}

static int quic_stream_backend_is_writable(void *io_ctx)
{
    (void)io_ctx;
    return 1;
}

static int quic_stream_backend_has_readable(void *io_ctx)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return -1;
    pthread_mutex_lock(&st->lock);
    int ready = (st->head != NULL) || st->fin_remote || st->reset_remote;
    pthread_mutex_unlock(&st->lock);
    return ready ? 1 : 0;
}

static void quic_stream_backend_free(void *io_ctx)
{
    quic_stream_ctx_t *st = (quic_stream_ctx_t *)io_ctx;
    if (!st)
        return;
    quic_muxer_ctx_t *mx = atomic_load_explicit(&st->mx, memory_order_acquire);
    libp2p_quic_session_t *session = quic_muxer_retain_session(mx);
    LP_LOGD("QUIC",
            "backend_free ctx=%p stream_id=%" PRIu64 " mx=%p session=%p",
            (void *)st,
            st->stream_id,
            (void *)mx,
            (void *)session);
    quic_muxer_release_session(session);
    if (mx)
    {
        pthread_mutex_lock(&mx->lock);
        quic_muxer_remove_stream(mx, st);
        pthread_mutex_unlock(&mx->lock);
    }
    pthread_mutex_lock(&st->lock);
    st->stream = NULL;
    pthread_mutex_unlock(&st->lock);
    quic_stream_ctx_release(st);
}

static const libp2p_stream_backend_ops_t QUIC_STREAM_OPS = {
    .read = quic_stream_backend_read,
    .write = quic_stream_backend_write,
    .close = quic_stream_backend_close,
    .shutdown_write = quic_stream_backend_shutdown_write,
    .reset = quic_stream_backend_reset,
    .set_deadline = quic_stream_backend_set_deadline,
    .local_addr = quic_stream_backend_local,
    .remote_addr = quic_stream_backend_remote,
    .is_writable = quic_stream_backend_is_writable,
    .has_readable = quic_stream_backend_has_readable,
    .free_ctx = quic_stream_backend_free,
};

static quic_stream_ctx_t *quic_accept_inbound_stream(quic_muxer_ctx_t *mx, uint64_t stream_id)
{
    if (!mx)
        return NULL;
    libp2p_quic_session_t *session = quic_muxer_retain_session(mx);
    if (!session)
        return NULL;

    quic_stream_ctx_t *st = (quic_stream_ctx_t *)calloc(1, sizeof(*st));
    if (!st)
    {
        quic_muxer_release_session(session);
        return NULL;
    }

    atomic_init(&st->mx, mx);
    quic_muxer_ctx_retain(mx);
    st->stream = NULL;
    st->stream_id = stream_id;
    st->head = st->tail = NULL;
    st->next = NULL;
    st->fin_remote = 0;
    st->fin_local = 0;
    st->reset_remote = 0;
    st->closed = 0;
    st->deadline_ms = 0;
    st->initiator = 0;
    st->handshake_started = 0;
    st->handshake_done = 0;
    st->handshake_running = 0;
    atomic_init(&st->refcnt, 1U);
    st->push = NULL;
    st->push_cap = 0;
    if (pthread_mutex_init(&st->lock, NULL) != 0)
    {
        quic_muxer_ctx_release(mx);
        free(st);
        quic_muxer_release_session(session);
        return NULL;
    }

    pthread_mutex_lock(&mx->lock);
    quic_muxer_append_stream(mx, st);
    /* Check if we received STOP_SENDING for this stream before it was created */
    int had_pending_stop = quic_muxer_check_pending_stop_sending(mx, stream_id);
    pthread_mutex_unlock(&mx->lock);

    if (had_pending_stop)
    {
        pthread_mutex_lock(&st->lock);
        st->stop_sending_received = 1;
        pthread_mutex_unlock(&st->lock);
        LP_LOGI("QUIC", "applied pending stop_sending for stream %" PRIu64, stream_id);
    }

    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (!cnx)
    {
        pthread_mutex_lock(&mx->lock);
        quic_muxer_remove_stream(mx, st);
        pthread_mutex_unlock(&mx->lock);
        quic_stream_ctx_release(st);
        quic_muxer_release_session(session);
        return NULL;
    }

    /* NOTE: Do NOT lock quic_mtx here - this function is called from the dispatch callback
     * which runs inside the socket loop. The socket loop already holds quic_mtx via lock_fn.
     * Trying to lock here causes a deadlock. */
    picoquic_set_app_stream_ctx(cnx, stream_id, st);

    libp2p_host_t *host = atomic_load_explicit(&mx->host, memory_order_acquire);
    libp2p_stream_t *stream = libp2p_stream_from_ops(host, st, &QUIC_STREAM_OPS, NULL, 0, NULL);
    if (!stream)
    {
        pthread_mutex_lock(&mx->lock);
        quic_muxer_remove_stream(mx, st);
        pthread_mutex_unlock(&mx->lock);
        /* NOTE: No quic_mtx lock - already held by socket loop */
        picoquic_set_app_stream_ctx(cnx, stream_id, NULL);
        quic_stream_ctx_release(st);
        quic_muxer_release_session(session);
        return NULL;
    }

    pthread_mutex_lock(&st->lock);
    st->stream = stream;
    pthread_mutex_unlock(&st->lock);
    libp2p__stream_set_cleanup(stream, quic_stream_cleanup, st);
    if (mx->owner)
        libp2p_stream_set_parent(stream, NULL, mx->owner, 0);

    pthread_mutex_lock(&st->lock);
    st->handshake_started = 1;
    st->handshake_running = 1;
    pthread_mutex_unlock(&st->lock);
    quic_stream_start_handshake(mx, st, stream);
    quic_stream_ctx_retain(st);
    quic_muxer_release_session(session);
    return st;
}

static libp2p_muxer_err_t quic_muxer_negotiate(libp2p_muxer_t *mx, libp2p_conn_t *c, uint64_t timeout_ms, bool inbound)
{
    (void)mx;
    (void)c;
    (void)timeout_ms;
    (void)inbound;
    return LIBP2P_MUXER_OK;
}

static libp2p_muxer_err_t quic_muxer_open_stream(libp2p_muxer_t *mx, const uint8_t *name, size_t name_len, libp2p_stream_t **out)
{
    (void)name;
    (void)name_len;
    if (!mx || !out)
        return LIBP2P_MUXER_ERR_NULL_PTR;
    quic_muxer_ctx_t *ctx = (quic_muxer_ctx_t *)mx->ctx;
    if (!ctx)
        return LIBP2P_MUXER_ERR_INTERNAL;
    libp2p_quic_session_t *session = quic_muxer_retain_session(ctx);
    if (!session)
        return LIBP2P_MUXER_ERR_INTERNAL;
    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (!cnx)
    {
        /* Connection was closed/destroyed - cannot open new streams */
        quic_muxer_release_session(session);
        return LIBP2P_MUXER_ERR_INTERNAL;
    }
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    if (stream_id == UINT64_MAX)
    {
        quic_muxer_release_session(session);
        return LIBP2P_MUXER_ERR_INTERNAL;
    }

    quic_stream_ctx_t *st = (quic_stream_ctx_t *)calloc(1, sizeof(*st));
    if (!st)
    {
        quic_muxer_release_session(session);
        return LIBP2P_MUXER_ERR_INTERNAL;
    }
    atomic_init(&st->mx, ctx);
    quic_muxer_ctx_retain(ctx);
    st->stream = NULL;
    st->stream_id = stream_id;
    st->head = st->tail = NULL;
    st->next = NULL;
    st->fin_remote = 0;
    st->fin_local = 0;
    st->reset_remote = 0;
    st->closed = 0;
    st->deadline_ms = 0;
    st->initiator = 1;
    st->handshake_started = 1;
    st->handshake_done = 1;
    st->handshake_running = 0;
    atomic_init(&st->refcnt, 1U);
    st->push = NULL;
    st->push_cap = 0;
    if (pthread_mutex_init(&st->lock, NULL) != 0)
    {
        quic_muxer_ctx_release(ctx);
        free(st);
        quic_muxer_release_session(session);
        return LIBP2P_MUXER_ERR_INTERNAL;
    }

    pthread_mutex_lock(&ctx->lock);
    quic_muxer_append_stream(ctx, st);
    pthread_mutex_unlock(&ctx->lock);

    if (session->quic_mtx)
        pthread_mutex_lock(session->quic_mtx);
    picoquic_set_app_stream_ctx(cnx, stream_id, st);
    if (session->quic_mtx)
        pthread_mutex_unlock(session->quic_mtx);

    libp2p_host_t *host = atomic_load_explicit(&ctx->host, memory_order_acquire);
    libp2p_stream_t *stream = libp2p_stream_from_ops(host, st, &QUIC_STREAM_OPS, NULL, 1, NULL);
    if (!stream)
    {
        if (session->quic_mtx)
            pthread_mutex_lock(session->quic_mtx);
        picoquic_set_app_stream_ctx(cnx, stream_id, NULL);
        if (session->quic_mtx)
            pthread_mutex_unlock(session->quic_mtx);
        pthread_mutex_lock(&ctx->lock);
        quic_muxer_remove_stream(ctx, st);
        pthread_mutex_unlock(&ctx->lock);
        quic_stream_ctx_release(st);
        quic_muxer_release_session(session);
        return LIBP2P_MUXER_ERR_INTERNAL;
    }

    st->stream = stream;
    libp2p__stream_set_cleanup(stream, quic_stream_cleanup, st);
    libp2p_stream_set_parent(stream, NULL, mx, 0);
    *out = stream;
    quic_muxer_release_session(session);
    return LIBP2P_MUXER_OK;
}

static ssize_t quic_muxer_stream_read(libp2p_stream_t *s, void *buf, size_t len)
{
    (void)s;
    (void)buf;
    (void)len;
    return LIBP2P_ERR_UNSUPPORTED;
}

static ssize_t quic_muxer_stream_write(libp2p_stream_t *s, const void *buf, size_t len)
{
    (void)s;
    (void)buf;
    (void)len;
    return LIBP2P_ERR_UNSUPPORTED;
}

static void quic_muxer_stream_close(libp2p_stream_t *s)
{
    (void)s;
}

static void quic_muxer_free(libp2p_muxer_t *mx)
{
    if (!mx)
        return;
    quic_muxer_ctx_t *ctx = (quic_muxer_ctx_t *)mx->ctx;
    if (ctx)
    {
        /* Clear host pointer FIRST to prevent use-after-free in stream callbacks
         * that may fire from the listener's packet loop during teardown */
        atomic_store_explicit(&ctx->host, NULL, memory_order_release);

        quic_stream_ctx_t *streams = NULL;
        pthread_mutex_lock(&ctx->lock);
        streams = ctx->streams_head;
        ctx->streams_head = ctx->streams_tail = NULL;
        quic_muxer_free_pending_stop_sending(ctx);
        pthread_mutex_unlock(&ctx->lock);
        while (streams)
        {
            quic_stream_ctx_t *next = streams->next;
            if (streams->stream)
            {
                libp2p_stream_t *stream = NULL;
                pthread_mutex_lock(&streams->lock);
                stream = streams->stream;
                streams->stream = NULL;
                pthread_mutex_unlock(&streams->lock);
                if (stream)
                {
                    libp2p__stream_mark_deferred(stream);
                    libp2p_stream_close(stream);
                    libp2p_stream_free(stream);
                }
                else
                {
                    quic_stream_ctx_release(streams);
                }
            }
            else
            {
                quic_stream_ctx_release(streams);
            }
            streams = next;
        }
        multiaddr_free(ctx->local);
        ctx->local = NULL;
        multiaddr_free(ctx->remote);
        ctx->remote = NULL;
        libp2p_quic_session_t *session = NULL;
        pthread_mutex_lock(&ctx->lock);
        session = ctx->session;
        ctx->session = NULL;
        pthread_mutex_unlock(&ctx->lock);
        if (session)
        {
            picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
            if (cnx)
                picoquic_set_callback(cnx, NULL, NULL);
            quic_session_attach_muxer(session, NULL);
            libp2p__quic_session_release(session);
        }
        /* host was already cleared atomically at function start */
        ctx->owner = NULL;
        ctx->conn = NULL;
        pthread_mutex_destroy(&ctx->write_mtx);
        pthread_mutex_destroy(&ctx->lock);
        quic_muxer_ctx_release(ctx);
    }
    free(mx);
}

static const libp2p_muxer_vtbl_t QUIC_MUXER_VTBL = {
    .negotiate = quic_muxer_negotiate,
    .open_stream = quic_muxer_open_stream,
    .stream_read = quic_muxer_stream_read,
    .stream_write = quic_muxer_stream_write,
    .stream_close = quic_muxer_stream_close,
    .free = quic_muxer_free,
};

libp2p_muxer_t *libp2p_quic_muxer_new(struct libp2p_host *host,
                                      libp2p_quic_session_t *session,
                                      const multiaddr_t *local,
                                      const multiaddr_t *remote,
                                      libp2p_conn_t *conn)
{
    if (!session)
        return NULL;

    libp2p_muxer_t *mx = (libp2p_muxer_t *)calloc(1, sizeof(*mx));
    quic_muxer_ctx_t *ctx = (quic_muxer_ctx_t *)calloc(1, sizeof(*ctx));
    int lock_initialized = 0;
    int write_lock_initialized = 0;
    if (!mx || !ctx)
    {
        free(mx);
        free(ctx);
        return NULL;
    }

    int err = 0;
    ctx->local = local ? multiaddr_copy(local, &err) : NULL;
    if (local && (!ctx->local || err != 0))
        goto fail;
    err = 0;
    ctx->remote = remote ? multiaddr_copy(remote, &err) : NULL;
    if (remote && (!ctx->remote || err != 0))
        goto fail;

    ctx->session = session;
    atomic_init(&ctx->host, host);
    ctx->streams_head = ctx->streams_tail = NULL;
    ctx->pending_stop_sending_head = NULL;
    ctx->conn = conn;
    ctx->accepted_count = 0;
    ctx->owner = mx;
    atomic_store(&ctx->closed, 0);
    atomic_init(&ctx->refcnt, 1U);
    if (pthread_mutex_init(&ctx->lock, NULL) != 0)
        goto fail;
    lock_initialized = 1;
    if (pthread_mutex_init(&ctx->write_mtx, NULL) != 0)
        goto fail;
    write_lock_initialized = 1;

    libp2p__quic_session_retain(session);
    quic_session_attach_muxer(session, ctx);
    if (host)
        libp2p__quic_session_set_host(session, host);
    picoquic_cnx_t *cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (cnx)
        picoquic_set_callback(cnx, quic_session_callback, session);
    quic_session_flush_pending(session, ctx);
    cnx = atomic_load_explicit(&session->cnx, memory_order_acquire);
    if (cnx)
    {
        /* Acquire quic_mtx before mark_active_stream - it may call reinsert_by_wake_time
         * which modifies the splay tree. Must be synchronized with socket loop thread. */
        if (session->quic_mtx)
            pthread_mutex_lock(session->quic_mtx);
        (void)picoquic_mark_active_stream(cnx, 0, 1, NULL);
        if (session->quic_mtx)
            pthread_mutex_unlock(session->quic_mtx);
    }

    if (libp2p__quic_session_start_loop(session, ctx->local, ctx->remote) != 0)
        goto fail_with_session;

    mx->vt = &QUIC_MUXER_VTBL;
    mx->ctx = ctx;
    return mx;

fail_with_session:
    {
        picoquic_cnx_t *cnx_fail = atomic_load_explicit(&session->cnx, memory_order_acquire);
        if (cnx_fail)
            picoquic_set_callback(cnx_fail, NULL, NULL);
    }
    quic_session_attach_muxer(session, NULL);
    libp2p__quic_session_release(session);
fail:
    if (ctx)
    {
        if (write_lock_initialized)
            pthread_mutex_destroy(&ctx->write_mtx);
        if (lock_initialized)
            pthread_mutex_destroy(&ctx->lock);
        multiaddr_free(ctx->local);
        multiaddr_free(ctx->remote);
        free(ctx);
    }
    free(mx);
    return NULL;
}
