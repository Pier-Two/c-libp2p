#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "host_internal.h"
#include "proto_select_internal.h"

#include "libp2p/error_map.h"
#include "libp2p/events.h"
#include "libp2p/io.h"
#include "libp2p/log.h"
#include "libp2p/lpmsg.h"
#include "libp2p/peerstore.h"
#include "libp2p/stream.h"
#include "libp2p/protocol_listen.h"
#include "libp2p/runtime.h"
#include "libp2p/stream_internal.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/muxer/mplex/mplex_io_adapter.h"
#include "protocol/muxer/mplex/mplex_stream_adapter.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/muxer/yamux/yamux_io_adapter.h"
#include "protocol/muxer/yamux/yamux_stream_adapter.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/quic/protocol_quic.h"
#include "transport/transport.h"
#include "transport/upgrader.h"

/* generic readiness helpers are provided by stream internals */

/* Single-thread executor task for protocol on_open */
typedef struct proto_on_open_task
{
    libp2p_stream_t *s;
    libp2p_protocol_def_t def;
} proto_on_open_task_t;

static void cbexec_proto_on_open(void *ud)
{
    proto_on_open_task_t *t = (proto_on_open_task_t *)ud;
    if (t && t->def.on_open)
        t->def.on_open(t->s, t->def.user_data);
    free(t);
}

/* no watchdog – runtime stops on io error/close */

/* Minimal runtime callback context for inbound yamux session */
typedef struct yamux_cb_ctx
{
    libp2p_runtime_t *rt;
    libp2p_host_t *host;
    libp2p_yamux_ctx_t *yctx;
    libp2p_conn_t *secured;
    /* First stream gets this exact peer pointer; subsequent streams use peer_template */
    peer_id_t *first_peer;   /* owned by session until claimed; protect with mtx */
    int accepted_count;      /* number of accepted substreams on this connection */
    peer_id_t peer_template; /* a copy to duplicate for subsequent streams */
    /* Runtime-driven stream readiness (push-mode + on_writable) */
    pthread_mutex_t mtx;
    struct push_stream_node *streams; /* singly-linked */
} yamux_cb_ctx_t;

static void inbound_yamux_on_io(int _fd, short events, void *ud);
static void *inbound_substream_worker(void *arg);

/* Forward declaration for listener thread */
static void *listener_accept_thread(void *arg);

/* Per-session push-mode stream tracking */
typedef struct push_stream_node
{
    libp2p_stream_t *s;
    libp2p_protocol_def_t def; /* valid when read_mode == PUSH and on_data set */
    size_t cap;                /* optional inflight cap */
    uint8_t *buf;              /* reusable buffer */
    size_t buf_sz;
    struct push_stream_node *next;
} push_stream_node_t;

static void cbctx_stream_cleanup(void *ctx, libp2p_stream_t *s);

/* Detach the listener list under the host mutex and optionally duplicate it into
 * an array for indexed processing. Falls back to list processing when memory
 * allocation fails, avoiding null-pointer dereferences during shutdown. */
static void detach_listeners(libp2p_host_t *host, listener_node_t ***out_arr, size_t *out_len, listener_node_t **out_head)
{
    if (!host || !out_arr || !out_len || !out_head)
        return;
    *out_arr = NULL;
    *out_len = 0;
    *out_head = NULL;

    pthread_mutex_lock(&host->mtx);
    listener_node_t *head = host->listeners;
    size_t count = 0;
    for (listener_node_t *it = head; it; it = it->next)
        count++;

    listener_node_t **arr = NULL;
    if (count > 0)
    {
        arr = (listener_node_t **)calloc(count, sizeof(*arr));
        if (arr)
        {
            size_t idx = 0;
            for (listener_node_t *it = head; it && idx < count; it = it->next)
                arr[idx++] = it;
            count = idx;
        }
    }

    host->listeners = NULL;
    pthread_mutex_unlock(&host->mtx);

    *out_arr = arr;
    *out_len = count;
    *out_head = head;
}

/* Free per-session yamux callback context and any retained tracking nodes. */
static void yamux_cb_ctx_free(yamux_cb_ctx_t *c)
{
    if (!c)
        return;
    /* Detach list under lock to safely free after unlock */
    pthread_mutex_lock(&c->mtx);
    struct push_stream_node *it = c->streams;
    c->streams = NULL;
    pthread_mutex_unlock(&c->mtx);
    while (it)
    {
        struct push_stream_node *next = it->next;
        if (it->buf)
            free(it->buf);
        /* Do not touch it->s; streams are closed elsewhere */
        free(it);
        it = next;
    }
    if (c->first_peer)
        peer_id_destroy(c->first_peer);
    if (c->peer_template.bytes)
        peer_id_destroy(&c->peer_template);
    pthread_mutex_destroy(&c->mtx);
    free(c);
}

/* Bridge readable notifications directly to a protocol's on_data handler for
 * push-mode streams. This complements the periodic cbctx_service_push pump to
 * ensure timely delivery without polling. */
typedef struct push_bridge_ctx
{
    libp2p_protocol_def_t def;
    yamux_cb_ctx_t *c;
} push_bridge_ctx_t;

static void push_bridge_on_readable(libp2p_stream_t *s, void *ud)
{
    push_bridge_ctx_t *ctx = (push_bridge_ctx_t *)ud;
    if (!ctx || !s || !ctx->def.on_data)
        return;
    /* Reuse the per-stream buffer managed by push_stream_node to avoid
     * per-callback allocations. Allocate once on the node if missing. */
    uint8_t *buf = NULL;
    size_t buf_sz = 0;

    if (!ctx->c)
        return;

    pthread_mutex_lock(&ctx->c->mtx);
    push_stream_node_t *node = NULL;
    for (push_stream_node_t *it = ctx->c->streams; it; it = it->next)
    {
        if (it->s == s)
        {
            node = it;
            break;
        }
    }

    if (!node)
    {
        /* Stream not tracked (race or teardown). Re-arm and try later. */
        pthread_mutex_unlock(&ctx->c->mtx);
        libp2p_stream_on_readable(s, push_bridge_on_readable, ctx);
        return;
    }

    /* Ensure buffer exists on node */
    size_t want = node->buf_sz > 0 ? node->buf_sz : 4096;
    if (node->cap > 0 && node->cap < want)
        want = node->cap;
    if (want == 0)
        want = 1;
    if (!node->buf || node->buf_sz < want)
    {
        uint8_t *nb = (uint8_t *)realloc(node->buf, want);
        if (nb)
        {
            node->buf = nb;
            node->buf_sz = want;
        }
        else
        {
            /* Allocation failed; unlock and re-arm to retry later. */
            pthread_mutex_unlock(&ctx->c->mtx);
            libp2p_stream_on_readable(s, push_bridge_on_readable, ctx);
            return;
        }
    }

    buf = node->buf;
    buf_sz = node->buf_sz;

    for (;;)
    {
        ssize_t n = libp2p_stream_read(s, buf, buf_sz);
        if (n > 0)
        {
            ctx->def.on_data(s, buf, (size_t)n, ctx->def.user_data);
            continue;
        }
        if (n == 0)
        {
            if (ctx->def.on_eof)
                ctx->def.on_eof(s, ctx->def.user_data);
            pthread_mutex_unlock(&ctx->c->mtx);
            free(ctx);
            return;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            /* Re-arm for next readability */
            pthread_mutex_unlock(&ctx->c->mtx);
            libp2p_stream_on_readable(s, push_bridge_on_readable, ctx);
            return;
        }
        /* Error */
        if (ctx->def.on_error)
            ctx->def.on_error(s, (int)n, ctx->def.user_data);
        pthread_mutex_unlock(&ctx->c->mtx);
        free(ctx);
        return;
    }
}

static void cbctx_register_stream(yamux_cb_ctx_t *c, libp2p_stream_t *s)
{
    if (!c || !s)
        return;
    push_stream_node_t *n = (push_stream_node_t *)calloc(1, sizeof(*n));
    if (!n)
        return;
    n->s = s;
    pthread_mutex_lock(&c->mtx);
    n->next = c->streams;
    c->streams = n;
    pthread_mutex_unlock(&c->mtx);
    libp2p__stream_set_cleanup(s, cbctx_stream_cleanup, c);
}

static void cbctx_configure_push(yamux_cb_ctx_t *c, libp2p_stream_t *s, const libp2p_protocol_def_t *def, size_t cap)
{
    if (!c || !s || !def)
        return;
    pthread_mutex_lock(&c->mtx);
    for (push_stream_node_t *it = c->streams; it; it = it->next)
    {
        if (it->s == s)
        {
            it->def = *def;
            it->cap = cap;
            size_t want = 4096;
            if (cap > 0 && cap < want)
                want = cap;
            if (want == 0)
                want = 1;
            if (!it->buf || it->buf_sz < want)
            {
                uint8_t *nb = (uint8_t *)realloc(it->buf, want);
                if (nb)
                {
                    it->buf = nb;
                    it->buf_sz = want;
                }
            }
            break;
        }
    }
    pthread_mutex_unlock(&c->mtx);
}

static void cbctx_remove_stream(yamux_cb_ctx_t *c, libp2p_stream_t *s)
{
    if (!c || !s)
        return;
    pthread_mutex_lock(&c->mtx);
    push_stream_node_t **pp = (push_stream_node_t **)&c->streams;
    while (*pp)
    {
        if ((*pp)->s == s)
        {
            push_stream_node_t *victim = *pp;
            *pp = victim->next;
            if (victim->buf)
                free(victim->buf);
            free(victim);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&c->mtx);
}

static void cbctx_stream_cleanup(void *ctx, libp2p_stream_t *s)
{
    if (!ctx || !s)
        return;
    yamux_cb_ctx_t *c = (yamux_cb_ctx_t *)ctx;
    cbctx_remove_stream(c, s);
}

static void cbctx_service_push(yamux_cb_ctx_t *c)
{
    if (!c)
        return;
    pthread_mutex_lock(&c->mtx);
    push_stream_node_t **pp = (push_stream_node_t **)&c->streams;
    while (*pp)
    {
        push_stream_node_t *it = *pp;
        if (!it->def.on_data || !it->buf || it->buf_sz == 0)
        {
            pp = &(*pp)->next;
            continue;
        }
        int remove = 0;
        for (;;)
        {
            ssize_t n = libp2p_stream_read(it->s, it->buf, it->buf_sz);
            if (n > 0)
            {
                it->def.on_data(it->s, it->buf, (size_t)n, it->def.user_data);
                continue;
            }
            if (n == 0)
            {
                if (it->def.on_eof)
                    it->def.on_eof(it->s, it->def.user_data);
                remove = 1;
                break;
            }
            if (n == LIBP2P_ERR_AGAIN)
            {
                /* No more data for now */
                break;
            }
            if (it->def.on_error)
                it->def.on_error(it->s, (int)n, it->def.user_data);
            remove = 1;
            break;
        }
        if (remove)
        {
            *pp = it->next;
            if (it->buf)
                free(it->buf);
            free(it);
        }
        else
        {
            pp = &(*pp)->next;
        }
    }
    pthread_mutex_unlock(&c->mtx);
}

static void cbctx_service_writable(yamux_cb_ctx_t *c)
{
    if (!c)
        return;
    pthread_mutex_lock(&c->mtx);
    for (push_stream_node_t *it = c->streams; it; it = it->next)
    {
        libp2p_on_writable_fn cb = NULL;
        void *ud = NULL;
        int ok = libp2p__stream_is_writable(it->s);
        if (ok == 1)
        {
            if (libp2p__stream_consume_on_writable(it->s, &cb, &ud) && cb)
                cb(it->s, ud);
        }
    }
    pthread_mutex_unlock(&c->mtx);
}

static void cbctx_service_readable(yamux_cb_ctx_t *c)
{
    if (!c)
        return;
    pthread_mutex_lock(&c->mtx);
    for (push_stream_node_t *it = c->streams; it; it = it->next)
    {
        /* Only notify for pull-mode interest */
        libp2p_on_readable_fn cb = NULL;
        void *ud = NULL;
        int has = libp2p__stream_has_readable(it->s);
        if (has == 1 && libp2p__stream_has_read_interest(it->s))
        {
            if (libp2p__stream_consume_on_readable(it->s, &cb, &ud) && cb)
                cb(it->s, ud);
        }
    }
    pthread_mutex_unlock(&c->mtx);
}

/* Snapshot registered protocol IDs into a NULL-terminated array suitable for
 * multistream-select. Returns 0 on success or a libp2p error code. */
static int collect_supported_protocols(libp2p_host_t *host, const char ***out_ids, size_t *out_count)
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
        {
            if (e->def.protocol_id)
                arr[idx++] = e->def.protocol_id;
        }
    }
    pthread_mutex_unlock(&host->mtx);

    *out_ids = arr;
    *out_count = count;
    return 0;
}

/* Removed old push pump scaffolding (unused). Readability delivery is handled
 * via cbctx_service_push and push_bridge_on_readable without dedicated pumps. */

/* Inbound yamux session handler: processes frames and accepts true substreams */
typedef struct inbound_session_ctx
{
    libp2p_host_t *host;
    libp2p_conn_t *conn;   /* secured conn owned by session */
    libp2p_muxer_t *mx;    /* per-connection muxer owned by session */
    peer_id_t *peer;       /* owned by session; transferred to streams */
    session_node_t *snode; /* tracking node registered on host */
} inbound_session_ctx_t;

/* Auto-identify context and worker (file-scope) */
typedef struct
{
    libp2p_host_t *host;
    libp2p_yamux_ctx_t *yctx;
    peer_id_t peer;
} aid_ctx_t;
static void *aid_thread(void *a)
{
    aid_ctx_t *c = (aid_ctx_t *)a;
    /* Open substream */
    uint32_t sid = 0;
    if (!c->yctx || libp2p_yamux_stream_open(c->yctx, &sid) != LIBP2P_YAMUX_OK)
        goto aid_out;
    libp2p_io_t *io = libp2p_io_from_yamux(c->yctx, sid);
    if (!io)
        goto aid_out;
    const char *accepted = NULL;
    const char *prop[2] = {LIBP2P_IDENTIFY_PROTO_ID, NULL};
    libp2p_multiselect_err_t ms = libp2p_multiselect_dial_io(io, prop, c->host->opts.multiselect_handshake_timeout_ms, &accepted);
    if (ms == LIBP2P_MULTISELECT_OK)
    {
        uint8_t *buf = (uint8_t *)malloc(64 * 1024);
        if (buf)
        {
            ssize_t n = libp2p_lp_recv_io_timeout(io, buf, 64 * 1024,
                                                (c->host->opts.handshake_timeout_ms > 0) ? (uint64_t)c->host->opts.handshake_timeout_ms : 0);
            if (n > 0)
            {
                libp2p_identify_t *id = NULL;
                if (libp2p_identify_message_decode(buf, (size_t)n, &id) == 0 && id)
                {
                    if (c->host->peerstore)
                    {
                        if (id->public_key && id->public_key_len)
                            (void)libp2p_peerstore_set_public_key(c->host->peerstore, &c->peer, id->public_key, id->public_key_len);
                        if (id->num_protocols && id->protocols)
                        {
                            if (libp2p_peerstore_set_protocols(c->host->peerstore, &c->peer, (const char *const *)id->protocols, id->num_protocols) == 0)
                                libp2p__notify_peer_protocols_updated(c->host, &c->peer, (const char *const *)id->protocols, id->num_protocols);
                        }
                        for (size_t i = 0; i < id->num_listen_addrs; i++)
                        {
                            const uint8_t *astr = id->listen_addrs[i];
                            size_t alen = id->listen_addrs_lens[i];
                            if (!astr || !alen)
                                continue;
                            char *saddr = (char *)malloc(alen + 1);
                            if (!saddr)
                                continue;
                            memcpy(saddr, astr, alen);
                            saddr[alen] = '\0';
                            int ma_err = 0;
                            multiaddr_t *ma = multiaddr_new_from_str(saddr, &ma_err);
                            free(saddr);
                            if (ma)
                            {
                                (void)libp2p_peerstore_add_addr(c->host->peerstore, &c->peer, ma, 10 * 60 * 1000);
                                multiaddr_free(ma);
                            }
                        }
                    }
                    if (id->observed_addr && id->observed_addr_len)
                    {
                        char *ostr = (char *)malloc(id->observed_addr_len + 1);
                        if (ostr)
                        {
                            memcpy(ostr, id->observed_addr, id->observed_addr_len);
                            ostr[id->observed_addr_len] = '\0';
                            libp2p_event_t evt = {0};
                            evt.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE;
                            evt.u.new_external_addr_candidate.addr = ostr;
                            libp2p_event_publish(c->host, &evt);
                            free(ostr);
                        }
                    }
                    libp2p_identify_free(id);
                }
            }
            free(buf);
        }
    }
    libp2p_io_free(io);
aid_out:
    if (c->peer.bytes)
        peer_id_destroy(&c->peer);
    if (c && c->host)
        libp2p__worker_dec(c->host);
    free(c);
    return NULL;
}

static void *inbound_session_thread(void *arg)
{
    inbound_session_ctx_t *ictx = (inbound_session_ctx_t *)arg;
    if (!ictx)
        return NULL;
    libp2p_host_t *host = ictx->host;
    libp2p_muxer_t *mx = ictx->mx;
    libp2p_conn_t *secured = ictx->conn;
    peer_id_t *remote_peer = ictx->peer;
    libp2p_yamux_ctx_t *yctx = (libp2p_yamux_ctx_t *)mx->ctx;

    (void)libp2p_yamux_enable_keepalive(yctx, 15000);
    /* Allow substream recv to opportunistically pump a single frame when the
     * central runtime loop is idle. This matches other impls and avoids
     * handshake stalls without concurrent reads (guarded by loop_active). */
    if (yctx)
        yctx->pump_in_recv = 1;

    /* Create a minimal runtime and watch the underlying fd */
    libp2p_runtime_t *rt = libp2p_runtime_new();
    if (!rt)
    {
        if (remote_peer)
            peer_id_destroy(remote_peer);
        libp2p_conn_free(secured);
        libp2p_muxer_free(mx);
        free(ictx);
        return NULL;
    }
    int fd = -1;
    if (secured && secured->vt && secured->vt->get_fd)
        fd = secured->vt->get_fd(secured);

    yamux_cb_ctx_t *cbctx = (yamux_cb_ctx_t *)calloc(1, sizeof(*cbctx));
    if (!cbctx)
    {
        if (remote_peer)
            peer_id_destroy(remote_peer);
        libp2p_conn_free(secured);
        libp2p_muxer_free(mx);
        libp2p_runtime_free(rt);
        free(ictx);
        return NULL;
    }
    cbctx->rt = rt;
    cbctx->host = host;
    cbctx->yctx = yctx;
    cbctx->secured = secured;
    cbctx->first_peer = NULL;
    cbctx->accepted_count = 0;
    memset(&cbctx->peer_template, 0, sizeof(cbctx->peer_template));
    pthread_mutexattr_t mtx_attr;
    pthread_mutexattr_init(&mtx_attr);
    pthread_mutexattr_settype(&mtx_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&cbctx->mtx, &mtx_attr);
    pthread_mutexattr_destroy(&mtx_attr);
    /* Keep a copy of the remote peer id to duplicate for subsequent streams */
    if (remote_peer && remote_peer->bytes && remote_peer->size)
    {
        /* Transfer ownership of the first peer pointer into cbctx so that
         * substream workers can safely claim it under the mutex without
         * racing on a stack-resident pointer. */
        cbctx->first_peer = remote_peer; /* claimed by first stream or freed on exit */
        /* Keep a template copy for subsequent streams */
        cbctx->peer_template.bytes = (uint8_t *)malloc(remote_peer->size);
        if (cbctx->peer_template.bytes)
        {
            memcpy(cbctx->peer_template.bytes, remote_peer->bytes, remote_peer->size);
            cbctx->peer_template.size = remote_peer->size;
        }
        /* Prevent double free of original pointer below */
        remote_peer = NULL;
    }
    if (fd >= 0)
        libp2p_runtime_add_fd(rt, fd, 1, 1, inbound_yamux_on_io, cbctx);

    /* Publish runtime into session node so host_stop can stop/join it */
    if (ictx->snode)
    {
        pthread_mutex_lock(&ictx->snode->ready_mtx);
        ictx->snode->rt = rt;
        ictx->snode->yctx = yctx;
        if (yctx)
            atomic_fetch_add_explicit(&yctx->refcnt, 1, memory_order_acq_rel);
        ictx->snode->mx = mx;
        ictx->snode->conn = secured;
        ictx->snode->yamux_cb = cbctx;
        pthread_cond_broadcast(&ictx->snode->ready_cv);
        pthread_mutex_unlock(&ictx->snode->ready_mtx);
    }

    /* Kick once in case data already queued */
    inbound_yamux_on_io(fd, 0x1, cbctx);

    /* Runtime timers available if needed */

    /* Inbound auto-identify when enabled */
    if (remote_peer && host->opts.flags & LIBP2P_HOST_F_AUTO_IDENTIFY_INBOUND)
    {
        aid_ctx_t *c = (aid_ctx_t *)calloc(1, sizeof(*c));
        if (c)
        {
            c->host = host;
            c->yctx = yctx;
            c->peer.bytes = (uint8_t *)malloc(remote_peer->size);
            if (c->peer.bytes)
            {
                memcpy(c->peer.bytes, remote_peer->bytes, remote_peer->size);
                c->peer.size = remote_peer->size;
                pthread_t th;
                if (host)
                    libp2p__worker_inc(host);
                if (pthread_create(&th, NULL, aid_thread, c) == 0)
                    pthread_detach(th);
                else
                {
                    if (host)
                        libp2p__worker_dec(host);
                    peer_id_destroy(&c->peer);
                    free(c);
                }
            }
            else
            {
                free(c);
            }
        }
    }

    (void)libp2p_runtime_run(rt);

    /* Note: cbctx (and its streams list) is intentionally kept alive to avoid
     * races with detached substream workers still referencing it. It will be
     * reclaimed indirectly when the process exits; future refactoring can
     * attach it to session_node for coordinated teardown. */
    /* Hand off connection and muxer lifecycle to host_stop via session node. */
    /* Do not free rt here; host_stop() owns stopping/joining and will free it
     * after joining the session thread to avoid races/use-after-free. */
    /* Session node is retained for host_stop() to stop/join and free. */
    free(ictx);
    return NULL;
}

/* --- Mplex inbound: runtime-driven frame processing + event-driven substream acceptance --- */
typedef struct mplex_cb_ctx
{
    libp2p_runtime_t *rt;
    libp2p_host_t *host;
    libp2p_mplex_ctx_t *mctx;
    libp2p_conn_t *secured;
    /* First stream gets this exact peer pointer; subsequent streams use peer_template */
    peer_id_t *first_peer; /* owned by session until claimed; protect with mtx */
    int accepted_count;
    peer_id_t peer_template;
    pthread_mutex_t mtx;
    struct push_stream_node *streams;
} mplex_cb_ctx_t;

static void inbound_mplex_on_io(int _fd, short events, void *ud)
{
    mplex_cb_ctx_t *c = (mplex_cb_ctx_t *)ud;
    if (!c || !c->mctx)
        return;
    if (events & 0x1) /* READ */
    {
        int rc = libp2p_mplex_on_readable(c->mctx);
        if (rc != LIBP2P_MPLEX_OK && rc != LIBP2P_MPLEX_ERR_AGAIN)
        {
            libp2p_runtime_stop(c->rt);
            return;
        }
    }
    if (events & 0x2) /* WRITE */
    {
        int rc = libp2p_mplex_on_writable(c->mctx);
        if (rc != LIBP2P_MPLEX_OK && rc != LIBP2P_MPLEX_ERR_AGAIN)
        {
            libp2p_runtime_stop(c->rt);
            return;
        }
    }
    /* Service push-mode and readiness notifications */
    cbctx_service_push((yamux_cb_ctx_t *)c); /* reuse helpers (same layout subset) */
    cbctx_service_readable((yamux_cb_ctx_t *)c);
    cbctx_service_writable((yamux_cb_ctx_t *)c);
}

static void mplex_stream_event_cb(libp2p_mplex_stream_t *stream, libp2p_mplex_event_t ev, void *ud)
{
    mplex_cb_ctx_t *c = (mplex_cb_ctx_t *)ud;
    if (!c || !stream)
        return;
    if (ev == LIBP2P_MPLEX_STREAM_OPENED)
    {
        /* Enforce per-connection inbound streams cap if configured */
        if (c->host && c->host->opts.per_conn_max_inbound_streams > 0 &&
            c->accepted_count >= c->host->opts.per_conn_max_inbound_streams)
        {
            /* Reset the stream to signal refusal and free resources */
            (void)libp2p_mplex_stream_reset(stream);
            return;
        }
        /* Negotiate protocol over the new stream */
        libp2p_io_t *subio = libp2p_io_from_mplex(stream);
        if (!subio)
            return;
        const char **supported = NULL;
        size_t count = 0;
        int sp_rc = collect_supported_protocols(c->host, &supported, &count);
        if (sp_rc != 0)
        {
            (void)libp2p_mplex_stream_reset(stream);
            libp2p_io_free(subio);
            return;
        }

        libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
        cfg.enable_ls = c->host->opts.multiselect_enable_ls;
        uint64_t effective_ms = c->host->opts.multiselect_handshake_timeout_ms;
        pthread_mutex_lock(&c->host->mtx);
        for (proto_server_cfg_t *pc = c->host->proto_cfgs; pc; pc = pc->next)
            if (pc->handshake_timeout_ms > 0 && (uint64_t)pc->handshake_timeout_ms > effective_ms)
                effective_ms = (uint64_t)pc->handshake_timeout_ms;
        pthread_mutex_unlock(&c->host->mtx);
        cfg.handshake_timeout_ms = effective_ms;

        const char *accepted_heap = NULL;
        libp2p_multiselect_err_t ms = libp2p_multiselect_listen_io(subio, supported, &cfg, &accepted_heap);
        free((void *)supported);
        if (ms != LIBP2P_MULTISELECT_OK)
        {
            /* Reset the stream on negotiation failure to avoid dangling state */
            (void)libp2p_mplex_stream_reset(stream);
            libp2p_io_free(subio);
            return;
        }
        /* Build libp2p_stream wrapper */
        peer_id_t *peer_for_stream = NULL;
        /* First accepted stream claims the exact peer pointer, subsequent ones duplicate */
        pthread_mutex_lock(&c->mtx);
        if (c->first_peer)
        {
            peer_for_stream = c->first_peer;
            c->first_peer = NULL;
        }
        pthread_mutex_unlock(&c->mtx);
        if (!peer_for_stream && c->peer_template.bytes && c->peer_template.size)
        {
            peer_for_stream = (peer_id_t *)calloc(1, sizeof(*peer_for_stream));
            if (peer_for_stream)
            {
                peer_for_stream->bytes = (uint8_t *)malloc(c->peer_template.size);
                if (peer_for_stream->bytes)
                {
                    memcpy(peer_for_stream->bytes, c->peer_template.bytes, c->peer_template.size);
                    peer_for_stream->size = c->peer_template.size;
                }
                else
                {
                    free(peer_for_stream);
                    peer_for_stream = NULL;
                }
            }
        }

        /* Resource manager removed: no admission gating */

        libp2p_stream_t *stream_pub = libp2p_stream_from_mplex(c->host, c->mctx, stream, accepted_heap, 0, peer_for_stream);
        free((void *)accepted_heap);
        libp2p_io_free(subio);
        if (!stream_pub)
        {
            if (peer_for_stream)
                peer_id_destroy(peer_for_stream);
            return;
        }

        c->accepted_count++;
        /* Events */
        libp2p__emit_protocol_negotiated(c->host, libp2p_stream_protocol_id(stream_pub));
        libp2p__emit_stream_opened(c->host, libp2p_stream_protocol_id(stream_pub), libp2p_stream_remote_peer(stream_pub), false);

        /* Register for runtime-driven readiness */
        cbctx_register_stream((yamux_cb_ctx_t *)c, stream_pub);

        /* Dispatch to server */
        libp2p_protocol_def_t chosen = {0};
        int found = 0;
        const char *incoming_id = libp2p_stream_protocol_id(stream_pub);
        pthread_mutex_lock(&c->host->mtx);
        for (protocol_entry_t *e = c->host->protocols; e && !found; e = e->next)
        {
            if (e->def.protocol_id && strcmp(e->def.protocol_id, incoming_id) == 0)
            {
                chosen = e->def;
                found = 1;
            }
        }
        if (!found)
        {
            for (protocol_match_entry_t *m = c->host->matchers; m && !found; m = m->next)
            {
                if (!incoming_id || !m->matcher.pattern)
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
        pthread_mutex_unlock(&c->host->mtx);
        /* Enforce require_identified_peer before dispatching handlers if configured */
        if (found)
        {
            int require_ident = 0;
            pthread_mutex_lock(&c->host->mtx);
            for (proto_server_cfg_t *pc = c->host->proto_cfgs; pc; pc = pc->next)
            {
                if (pc->proto && incoming_id && strcmp(pc->proto, incoming_id) == 0)
                {
                    require_ident = pc->require_identified_peer;
                    break;
                }
            }
            pthread_mutex_unlock(&c->host->mtx);
            if (require_ident)
            {
                int identified = 0;
                const peer_id_t *rp = libp2p_stream_remote_peer(stream_pub);
                if (rp && c->host->peerstore)
                {
                    uint8_t *pk = NULL;
                    size_t pk_len = 0;
                    if (libp2p_peerstore_get_public_key(c->host->peerstore, rp, &pk, &pk_len) == 0)
                    {
                        if (pk && pk_len > 0)
                            identified = 1;
                        if (pk)
                            free(pk);
                    }
                    if (!identified)
                    {
                        const char **protos = NULL;
                        size_t n = 0;
                        if (libp2p_peerstore_get_protocols(c->host->peerstore, rp, &protos, &n) == 0)
                        {
                            if (n > 0)
                                identified = 1;
                            libp2p_peerstore_free_protocols(protos, n);
                        }
                    }
                }
                if (!identified)
                {
                    /* Deny dispatch; close and unregister stream */
                    cbctx_remove_stream((yamux_cb_ctx_t *)c, stream_pub);
                    libp2p_stream_close(stream_pub);
                    return; /* do not dispatch */
                }
            }
        }
        if (found && chosen.on_open)
        {
            proto_on_open_task_t *t = (proto_on_open_task_t *)calloc(1, sizeof(*t));
            if (t)
            {
                t->s = stream_pub;
                t->def = chosen; /* shallow copy of callbacks + user_data */
                libp2p__exec_on_cb_thread(c->host, cbexec_proto_on_open, t);
            }
        }
        else if (chosen.read_mode == LIBP2P_READ_PUSH && chosen.on_data)
        {
            size_t cap = 0;
            pthread_mutex_lock(&c->host->mtx);
            const char *pid = libp2p_stream_protocol_id(stream_pub);
            for (proto_server_cfg_t *pc = c->host->proto_cfgs; pc; pc = pc->next)
                if (pc->proto && pid && strcmp(pc->proto, pid) == 0)
                {
                    cap = pc->max_inflight_application_bytes;
                    break;
                }
            pthread_mutex_unlock(&c->host->mtx);
            cbctx_configure_push((yamux_cb_ctx_t *)c, stream_pub, &chosen, cap);
            /* Service once immediately to deliver any buffered data */
            cbctx_service_push((yamux_cb_ctx_t *)c);
        }
    }
}

static void *inbound_mplex_session_thread(void *arg)
{
    inbound_session_ctx_t *ictx = (inbound_session_ctx_t *)arg;
    if (!ictx)
        return NULL;
    libp2p_host_t *host = ictx->host;
    libp2p_muxer_t *mx = ictx->mx;
    libp2p_conn_t *secured = ictx->conn;
    peer_id_t *remote_peer = ictx->peer;
    libp2p_mplex_ctx_t *mctx = (libp2p_mplex_ctx_t *)mx->ctx;

    /* Build a runtime */
    libp2p_runtime_t *rt = libp2p_runtime_new();
    int fd = libp2p_conn_get_fd(secured);

    /* Prepare callback context (must exist before add_fd so its pointer is valid) */
    mplex_cb_ctx_t cb = {0};
    cb.rt = rt;
    cb.host = host;
    cb.mctx = mctx;
    cb.secured = secured;
    cb.accepted_count = 0;
    cb.first_peer = remote_peer; /* owned by session until claimed */

    if (fd >= 0)
        libp2p_runtime_add_fd(rt, fd, 1, 1, inbound_mplex_on_io, &cb);
    /* Keep a template copy for subsequent streams */
    memset(&cb.peer_template, 0, sizeof(cb.peer_template));
    if (remote_peer && remote_peer->bytes && remote_peer->size)
    {
        cb.peer_template.bytes = (uint8_t *)malloc(remote_peer->size);
        if (cb.peer_template.bytes)
        {
            memcpy(cb.peer_template.bytes, remote_peer->bytes, remote_peer->size);
            cb.peer_template.size = remote_peer->size;
        }
        /* Prevent double free of original pointer below */
        remote_peer = NULL;
    }
    pthread_mutex_init(&cb.mtx, NULL);
    if (rt && fd >= 0)
        libp2p_runtime_mod_fd(rt, fd, 1, 1);

    /* Copy remote_peer for template */
    if (remote_peer && remote_peer->bytes && remote_peer->size)
    {
        cb.peer_template.bytes = (uint8_t *)malloc(remote_peer->size);
        if (cb.peer_template.bytes)
        {
            memcpy(cb.peer_template.bytes, remote_peer->bytes, remote_peer->size);
            cb.peer_template.size = remote_peer->size;
        }
    }

    /* Register event callbacks */
    libp2p_mplex_event_callbacks_t ev = {0};
    ev.on_stream_event = mplex_stream_event_cb;
    ev.on_error = NULL;
    ev.user_data = &cb;
    (void)libp2p_mplex_set_event_callbacks(mctx, &ev);

    /* Publish runtime into session node so host_stop can stop/join it */
    if (ictx->snode)
    {
        pthread_mutex_lock(&ictx->snode->ready_mtx);
        ictx->snode->rt = rt;
        ictx->snode->mx = mx;
        ictx->snode->conn = secured;
        pthread_cond_broadcast(&ictx->snode->ready_cv);
        pthread_mutex_unlock(&ictx->snode->ready_mtx);
    }

    /* Run runtime loop */
    (void)libp2p_runtime_run(rt);

    /* Cleanup */
    if (remote_peer)
        peer_id_destroy(remote_peer);
    if (cb.peer_template.bytes)
        peer_id_destroy(&cb.peer_template);

    /* Hand off connection and muxer lifecycle to host_stop via session node. */
    /* Runtime freed by host_stop after joining the session thread. */

    if (ictx && ictx->snode)
    {
        pthread_mutex_lock(&host->mtx);
        /* snode already removed on host_stop; nothing else */
        pthread_mutex_unlock(&host->mtx);
    }
    free(ictx);
    return NULL;
}

/* Runtime callback: handle connection readability and accept substreams */
static void inbound_yamux_on_io(int _fd, short events, void *ud)
{
    (void)_fd;
    (void)events;
    yamux_cb_ctx_t *c = (yamux_cb_ctx_t *)ud;
    /* Pump yamux frames until EAGAIN or error */
    if (c && c->yctx)
        atomic_store_explicit(&c->yctx->loop_active, true, memory_order_release);
    for (;;)
    {
        libp2p_yamux_err_t pr = libp2p_yamux_process_one(c->yctx);
        if (pr == LIBP2P_YAMUX_ERR_AGAIN)
            break;
        if (pr != LIBP2P_YAMUX_OK)
        {
            if (c && c->yctx)
                atomic_store_explicit(&c->yctx->loop_active, false, memory_order_release);
            libp2p_runtime_stop(c->rt);
            return;
        }
    }
    if (c && c->yctx)
        atomic_store_explicit(&c->yctx->loop_active, false, memory_order_release);

    /* Drain accepted inbound substreams */
    for (;;)
    {
        libp2p_yamux_stream_t *yst = NULL;
        if (libp2p_yamux_accept_stream(c->yctx, &yst) != LIBP2P_YAMUX_OK || !yst)
            break;

        uint32_t sid = yst->id;
        /* Enforce per-connection inbound streams cap if configured */
        if (c->host && c->host->opts.per_conn_max_inbound_streams > 0 && c->accepted_count >= c->host->opts.per_conn_max_inbound_streams)
        {
            (void)libp2p_yamux_close_stream(c->yctx->conn, sid);
            continue;
        }
        /* Handle substream in a detached worker to keep IO loop responsive. */
        typedef struct
        {
            yamux_cb_ctx_t *ctx;
            uint32_t sid;
            int heap;
        } sub_work_t;
        sub_work_t *work = (sub_work_t *)calloc(1, sizeof(*work));
        if (!work)
            continue;
        work->ctx = c;
        work->sid = sid;
        work->heap = 1;
        pthread_t th;
        if (c && c->host)
            libp2p__worker_inc(c->host);
        if (pthread_create(&th, NULL, inbound_substream_worker, work) == 0)
        {
            pthread_detach(th);
        }
        else
        {
            if (c && c->host)
                libp2p__worker_dec(c->host);
            free(work);
        }
    }

    /* Service push-mode streams (deliver on_data/on_eof/on_error) */
    cbctx_service_push(c);

    /* If writable flagged, service one-shot on_writable callbacks */
    if (events & 0x2)
        cbctx_service_writable(c);

    /* After pumping frames, notify pull-mode listeners that data is ready */
    cbctx_service_readable(c);
}

/* Handle a single inbound substream: run multistream-select and dispatch. */
static void *inbound_substream_worker(void *arg)
{
    typedef struct
    {
        yamux_cb_ctx_t *ctx;
        uint32_t sid;
        int heap;
    } sub_work_t;
    sub_work_t *sw = (sub_work_t *)arg;
    if (!sw || !sw->ctx)
        return NULL;
    yamux_cb_ctx_t *c = sw->ctx;
    /* substream id captured; I/O via yamux adapter */
    uint32_t sid = sw->sid;
    int heap_alloc = sw->heap;
    /* free the work envelope if heap-allocated */
    if (heap_alloc)
        free(sw);

    /* Take a temporary reference on the yamux context to protect against
     * concurrent teardown while negotiating or resetting the substream. */
    libp2p_yamux_ctx_t *yref = c ? c->yctx : NULL;
    if (yref)
        atomic_fetch_add_explicit(&yref->refcnt, 1, memory_order_acq_rel);

    /* Snapshot supported protocols */
    const char **supported = NULL;
    size_t count = 0;
    int sp_rc = collect_supported_protocols(c->host, &supported, &count);
    if (sp_rc != 0)
    {
        if (yref)
            (void)libp2p_yamux_stream_reset(yref, sid);
        if (c && c->host)
            libp2p__worker_dec(c->host);
        if (yref)
            libp2p_yamux_ctx_free(yref);
        return NULL;
    }
    LP_LOGD("HOST", "inbound_substream: supported_count=%zu", count);
    if (supported)
    {
        for (size_t i = 0; i < count; i++)
            LP_LOGD("HOST", "supported[%zu]=%s", i, supported[i] ? supported[i] : "(null)");
    }

    libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
    cfg.enable_ls = c->host->opts.multiselect_enable_ls;
    /* Derive effective handshake timeout: host default overridden by any per-protocol server opts */
    uint64_t effective_ms = c->host->opts.multiselect_handshake_timeout_ms;
    pthread_mutex_lock(&c->host->mtx);
    for (proto_server_cfg_t *pc = c->host->proto_cfgs; pc; pc = pc->next)
    {
        if (pc->handshake_timeout_ms > 0 && (uint64_t)pc->handshake_timeout_ms > effective_ms)
            effective_ms = (uint64_t)pc->handshake_timeout_ms;
    }
    pthread_mutex_unlock(&c->host->mtx);
    cfg.handshake_timeout_ms = effective_ms;
    const char *accepted_heap = NULL;
    libp2p_io_t *subio = libp2p_io_from_yamux(c->yctx, sid);
    libp2p_multiselect_err_t ms = subio ? libp2p_multiselect_listen_io(subio, supported, &cfg, &accepted_heap) : LIBP2P_MULTISELECT_ERR_INTERNAL;
    /* No manual pumping here; rely on substream recv’s opportunistic pump. */
    LP_LOGD("HOST", "multiselect_listen rc=%d accepted=%s", (int)ms, accepted_heap ? accepted_heap : "(null)");
    free((void *)supported);
    if (ms != LIBP2P_MULTISELECT_OK)
    {
        /* On negotiation failure or timeout, actively reset the substream to
         * release resources and signal the peer. Leaving the stream open here
         * can leak state and cause later races. */
        if (yref)
            (void)libp2p_yamux_stream_reset(yref, sid);
        if (subio)
            libp2p_io_free(subio);
        free((void *)accepted_heap);
        if (c && c->host)
            libp2p__worker_dec(c->host);
        if (yref)
            libp2p_yamux_ctx_free(yref);
        return NULL;
    }

    extern libp2p_stream_t *libp2p_stream_from_conn(libp2p_host_t * host, libp2p_conn_t * c, const char *protocol_id, int initiator,
                                                    peer_id_t *remote_peer);
    peer_id_t *peer_for_stream = NULL;
    /* hand off the original peer id to the first stream only, safely */
    pthread_mutex_lock(&c->mtx);
    if (c->first_peer)
    {
        peer_for_stream = c->first_peer;
        c->first_peer = NULL;
    }
    pthread_mutex_unlock(&c->mtx);
    if (!peer_for_stream && c->peer_template.bytes && c->peer_template.size)
    {
        peer_for_stream = (peer_id_t *)calloc(1, sizeof(*peer_for_stream));
        if (peer_for_stream)
        {
            peer_for_stream->bytes = (uint8_t *)malloc(c->peer_template.size);
            if (peer_for_stream->bytes)
            {
                memcpy(peer_for_stream->bytes, c->peer_template.bytes, c->peer_template.size);
                peer_for_stream->size = c->peer_template.size;
            }
            else
            {
                free(peer_for_stream);
                peer_for_stream = NULL;
            }
        }
    }

    /* Resource manager removed: no admission gating */

    libp2p_stream_t *stream = libp2p_stream_from_yamux(c->host, yref, sid, accepted_heap, 0, peer_for_stream);
    free((void *)accepted_heap);
    if (!stream)
    {
        if (subio)
            libp2p_io_free(subio);
        if (peer_for_stream)
            peer_id_destroy(peer_for_stream);
        if (c && c->host)
            libp2p__worker_dec(c->host);
        if (yref)
            libp2p_yamux_ctx_free(yref);
        return NULL;
    }
    if (subio)
        libp2p_io_free(subio);
    c->accepted_count++;

    libp2p__emit_protocol_negotiated(c->host, libp2p_stream_protocol_id(stream));
    libp2p__emit_stream_opened(c->host, libp2p_stream_protocol_id(stream), libp2p_stream_remote_peer(stream), false);

    /* Register stream with session for runtime-driven readiness */
    cbctx_register_stream(c, stream);

    /* Drop our temporary yctx reference; the stream holds its own ref now */
    if (yref)
        libp2p_yamux_ctx_free(yref);

    /* Dispatch */
    libp2p_protocol_def_t chosen = {0};
    int found = 0;
    const char *incoming_id = libp2p_stream_protocol_id(stream);
    LP_LOGD("HOST", "inbound negotiated protocol_id=%s", incoming_id ? incoming_id : "(null)");
    pthread_mutex_lock(&c->host->mtx);
    for (protocol_entry_t *e = c->host->protocols; e && !found; e = e->next)
    {
        if (e->def.protocol_id && strcmp(e->def.protocol_id, incoming_id) == 0)
        {
            chosen = e->def;
            found = 1;
        }
    }
    if (!found)
    {
        LP_LOGD("HOST", "no exact match for %s; trying matchers", incoming_id ? incoming_id : "(null)");
        for (protocol_match_entry_t *m = c->host->matchers; m && !found; m = m->next)
        {
            if (!incoming_id || !m->matcher.pattern)
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
    pthread_mutex_unlock(&c->host->mtx);
    if (!found)
    {
        LP_LOGD("HOST", "dispatch miss for %s; showing registered protocols", incoming_id ? incoming_id : "(null)");
        pthread_mutex_lock(&c->host->mtx);
        for (protocol_entry_t *e = c->host->protocols; e; e = e->next)
        {
            if (e->def.protocol_id)
                LP_LOGD("HOST", "registered: %s", e->def.protocol_id);
        }
        /* newline not needed with structured logging */
        pthread_mutex_unlock(&c->host->mtx);
    }

    /* Enforce require_identified_peer before dispatching handlers if configured */
    if (found)
    {
        int require_ident = 0;
        pthread_mutex_lock(&c->host->mtx);
        for (proto_server_cfg_t *pc = c->host->proto_cfgs; pc; pc = pc->next)
        {
            if (pc->proto && incoming_id && strcmp(pc->proto, incoming_id) == 0)
            {
                require_ident = pc->require_identified_peer;
                break;
            }
        }
        pthread_mutex_unlock(&c->host->mtx);
        if (require_ident)
        {
            int identified = 0;
            const peer_id_t *rp = libp2p_stream_remote_peer(stream);
            if (rp && c->host->peerstore)
            {
                uint8_t *pk = NULL;
                size_t pk_len = 0;
                if (libp2p_peerstore_get_public_key(c->host->peerstore, rp, &pk, &pk_len) == 0)
                {
                    if (pk && pk_len > 0)
                        identified = 1;
                    if (pk)
                        free(pk);
                }
                if (!identified)
                {
                    const char **protos = NULL;
                    size_t n = 0;
                    if (libp2p_peerstore_get_protocols(c->host->peerstore, rp, &protos, &n) == 0)
                    {
                        if (n > 0)
                            identified = 1;
                        libp2p_peerstore_free_protocols(protos, n);
                    }
                }
            }
            if (!identified)
            {
                /* Deny dispatch; close and unregister stream */
                cbctx_remove_stream(c, stream);
                libp2p_stream_close(stream);
                if (c && c->host)
                    libp2p__worker_dec(c->host);
                return NULL;
            }
        }
    }

    if (found && chosen.on_open)
    {
        proto_on_open_task_t *t = (proto_on_open_task_t *)calloc(1, sizeof(*t));
        if (t)
        {
            t->s = stream;
            t->def = chosen; /* shallow copy of callbacks + user_data */
            libp2p__exec_on_cb_thread(c->host, cbexec_proto_on_open, t);
        }
    }
    else if (chosen.read_mode == LIBP2P_READ_PUSH && chosen.on_data)
    {
        size_t cap = 0;
        /* Look up per-protocol inflight cap if configured */
        pthread_mutex_lock(&c->host->mtx);
        const char *incoming_id2 = libp2p_stream_protocol_id(stream);
        for (proto_server_cfg_t *pc = c->host->proto_cfgs; pc; pc = pc->next)
        {
            if (pc->proto && incoming_id2 && strcmp(pc->proto, incoming_id2) == 0)
            {
                cap = pc->max_inflight_application_bytes;
                break;
            }
        }
        pthread_mutex_unlock(&c->host->mtx);
        cbctx_configure_push(c, stream, &chosen, cap);
        /* Service once immediately to deliver any buffered data */
        cbctx_service_push(c);
        /* Additionally, bridge readable notifications directly to on_data to
         * ensure timely delivery without relying on subsequent IO callbacks. */
        libp2p_stream_set_read_interest(stream, true);
        push_bridge_ctx_t *pbc = (push_bridge_ctx_t *)calloc(1, sizeof(*pbc));
        if (pbc)
        {
            pbc->def = chosen;
            pbc->c = c;
            libp2p_stream_on_readable(stream, push_bridge_on_readable, pbc);
        }
    }
    if (c && c->host)
        libp2p__worker_dec(c->host);
    return NULL;
}

int libp2p_host_start(libp2p_host_t *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    atomic_store_explicit(&host->running, 1, memory_order_release);
    for (size_t i = 0; i < host->opts.num_listen_addrs; i++)
    {
        const char *a = host->opts.listen_addrs[i];
        if (!a)
            continue;
        int ma_err = 0;
        multiaddr_t *addr = multiaddr_new_from_str(a, &ma_err);
        if (!addr)
            continue;
        libp2p_listener_t *lst = NULL;
        libp2p_transport_t *t = libp2p__host_select_transport(host, addr);
        if (!t || libp2p_transport_listen(t, addr, &lst) != LIBP2P_TRANSPORT_OK)
        {
            multiaddr_free(addr);
            continue;
        }
        multiaddr_free(addr);
        listener_node_t *node = (listener_node_t *)calloc(1, sizeof(*node));
        if (!node)
        {
            libp2p_listener_close(lst);
            libp2p_listener_free(lst);
            continue;
        }
        node->lst = lst;
        node->host = host;
        node->thread_running = 1;

        /* Precompute and cache the bound address string before starting the
         * thread so subsequent events always have a non-NULL addr. */
        multiaddr_t *bound = NULL;
        if (libp2p_listener_local_addr(lst, &bound) == 0 && bound)
        {
            int str_err2 = 0;
            char *s2 = multiaddr_to_str(bound, &str_err2);
            if (s2)
            {
                if (!node->addr_str)
                    node->addr_str = strdup(s2);
                /* Emit LISTEN_ADDR_ADDED for initially bound listeners */
                libp2p_event_t evt2 = {0};
                evt2.kind = LIBP2P_EVT_LISTEN_ADDR_ADDED;
                evt2.u.listen_addr_added.addr = s2;
                libp2p_event_publish(host, &evt2);
                free(s2);
            }
            multiaddr_free(bound);
        }
        if (!node->addr_str)
            node->addr_str = strdup(""); /* guard against NULL */

        pthread_mutex_lock(&host->mtx);
        node->next = host->listeners;
        host->listeners = node;
        pthread_mutex_unlock(&host->mtx);
        if (pthread_create(&node->thread, NULL, listener_accept_thread, node) == 0)
            node->thread_started = 1;
    }
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_HOST_STARTED;
    libp2p_event_publish(host, &evt);
    return 0;
}

int libp2p_host_stop(libp2p_host_t *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    LP_LOGD("HOST_STOP", "begin");
    /* Defer freeing yamux session callback contexts until after all
     * detached substream workers have exited to avoid races. */
    yamux_cb_ctx_t **yamux_cbs = NULL;
    libp2p_stream_t **pending_streams = NULL;
    size_t pending_stream_count = 0;
    size_t yamux_cb_count = 0, yamux_cb_cap = 0;
    libp2p_conn_t **deferred_conns = NULL;
    size_t deferred_conn_count = 0, deferred_conn_cap = 0;
    /* Idempotent: if already stopped, return immediately. */
    if (!atomic_load_explicit(&host->running, memory_order_acquire))
        return 0;
    /* Enter teardown mode: event dispatch enqueue becomes non-blocking to
     * prevent subscriber stalls from delaying shutdown. */
    pthread_mutex_lock(&host->mtx);
    host->tearing_down = 1;
    pthread_mutex_unlock(&host->mtx);
    atomic_store_explicit(&host->running, 0, memory_order_release);
    /* Stop internal publish service to avoid new async work during teardown */
    libp2p_publish_service_stop(host);
    LP_LOGD("HOST_STOP", "unsubscribed internal subs; closing active streams");
    /* Proactively close any remaining active streams to unblock protocol workers
     * before stopping sessions. */
    {
        pthread_mutex_lock(&host->mtx);
        size_t scount = 0;
        for (stream_entry_t *se = host->active_streams; se; se = se->next)
            scount++;
        libp2p_stream_t **streams = scount ? (libp2p_stream_t **)calloc(scount, sizeof(*streams)) : NULL;
        pending_streams = streams;
        size_t si = 0;
        for (stream_entry_t *se = host->active_streams; se && streams; se = se->next)
            streams[si++] = se->s;
        pending_stream_count = streams ? si : 0;
        pthread_mutex_unlock(&host->mtx);
        LP_LOGD("HOST_STOP", "closing %zu active streams", (size_t)pending_stream_count);
        for (size_t i = 0; i < pending_stream_count; i++)
            if (pending_streams[i])
            {
                libp2p__stream_mark_deferred(pending_streams[i]);
                libp2p_stream_close(pending_streams[i]);
            }
    }
    LP_LOGD("HOST_STOP", "streams closed; proceeding to stop/join sessions");
    /* Stop and join per-connection session threads first (no new sessions can appear
     * because host->running was set to 0 above). */
    /* Now stop and join per-connection session threads after no new sessions can appear */
    pthread_mutex_lock(&host->mtx);
    size_t sess_count_dbg = 0;
    for (session_node_t *it = host->sessions; it; it = it->next)
        sess_count_dbg++;
    pthread_mutex_unlock(&host->mtx);
    LP_LOGD("HOST_STOP", "stopping sessions; count=%zu", sess_count_dbg);
    for (;;)
    {
        pthread_mutex_lock(&host->mtx);
        session_node_t *sn = host->sessions;
        if (sn)
        {
            /* detach from list head; joining outside lock */
            host->sessions = sn->next;
        }
        pthread_mutex_unlock(&host->mtx);
        if (!sn)
            break;
        /* Wait for the session to publish its thread and runtime without polling. */
        if (!sn->is_quic)
        {
            pthread_mutex_lock(&sn->ready_mtx);
            if (!sn->thread || !sn->rt)
            {
                struct timespec now;
                clock_gettime(CLOCK_REALTIME, &now);
                struct timespec abs;
                abs.tv_sec = now.tv_sec + 1;
                abs.tv_nsec = now.tv_nsec; /* up to ~1s */
                while ((!sn->thread || !sn->rt))
                {
                    int w = pthread_cond_timedwait(&sn->ready_cv, &sn->ready_mtx, &abs);
                    if (w == ETIMEDOUT)
                        break;
                }
            }
            pthread_mutex_unlock(&sn->ready_mtx);
            LP_LOGD("HOST_STOP", "stopping session thread %p (rt=%p)", (void *)sn->thread, (void *)sn->rt);
            /* Take a temporary reference to the yamux context to avoid races with
             * the session thread freeing it while we signal shutdown. */
            libp2p_yamux_ctx_t *yref = sn->yctx;
            if (yref)
                atomic_fetch_add_explicit(&yref->refcnt, 1, memory_order_acq_rel);
            /* Proactively signal muxer shutdown before stopping the runtime to
             * expedite unblocking of any pending operations. */
            if (yref)
                libp2p_yamux_stop(yref);
            if (sn->rt)
                libp2p_runtime_stop(sn->rt);
            if (sn->thread)
                pthread_join(sn->thread, NULL);
            if (yref)
                libp2p_yamux_ctx_free(yref);
        }
        else
        {
            LP_LOGD("HOST_STOP", "stopping QUIC session (mx=%p conn=%p)", (void *)sn->mx, (void *)sn->conn);
        }
        /* Free per-session resources now that the thread has exited. */
        /* Save yamux cbctx for deferred free after worker threads drain. */
        if (sn->yamux_cb)
        {
            if (yamux_cb_count == yamux_cb_cap)
            {
                size_t ncap = yamux_cb_cap ? (yamux_cb_cap * 2) : 8;
                void *np = realloc(yamux_cbs, ncap * sizeof(*yamux_cbs));
                if (np)
                {
                    yamux_cbs = (yamux_cb_ctx_t **)np;
                    yamux_cb_cap = ncap;
                }
            }
            if (yamux_cb_count < yamux_cb_cap)
                yamux_cbs[yamux_cb_count++] = sn->yamux_cb;
            else
                LP_LOGD("HOST_STOP", "dropping yamux_cb (OOM during tracking)");
            sn->yamux_cb = NULL;
        }
        if (sn->rt)
        {
            libp2p_runtime_free(sn->rt);
            sn->rt = NULL;
        }
        if (sn->yctx)
        {
            libp2p_yamux_ctx_t *base = sn->yctx;
            libp2p_yamux_ctx_free(base);
            sn->yctx = NULL;
        }
        if (!sn->is_quic && sn->conn)
        {
            /* Close immediately to unblock any pending I/O, but defer freeing
             * until worker threads (identify push, ping, etc.) have drained. */
            libp2p_conn_close(sn->conn);
            if (deferred_conn_count == deferred_conn_cap)
            {
                size_t ncap = deferred_conn_cap ? (deferred_conn_cap * 2) : 8;
                void *np = realloc(deferred_conns, ncap * sizeof(*deferred_conns));
                if (np)
                {
                    deferred_conns = (libp2p_conn_t **)np;
                    deferred_conn_cap = ncap;
                }
            }
            if (deferred_conn_count < deferred_conn_cap)
            {
                deferred_conns[deferred_conn_count++] = sn->conn;
            }
            else
            {
                LP_LOGD("HOST_STOP", "deferring conn free failed (OOM); leaking for safety");
            }
            sn->conn = NULL;
        }
        if (sn->is_quic && sn->conn)
        {
            libp2p_quic_conn_detach_session(sn->conn);
        }
        if (sn->mx)
        {
            libp2p_muxer_free(sn->mx);
            sn->mx = NULL;
        }
        if (sn->is_quic && sn->conn)
        {
            libp2p_conn_free(sn->conn);
            sn->conn = NULL;
        }
        /* destroy ready primitives and free */
        pthread_mutex_destroy(&sn->ready_mtx);
        pthread_cond_destroy(&sn->ready_cv);
        free(sn);
    }
    if (pending_streams)
    {
        for (size_t i = 0; i < pending_stream_count; i++)
            pending_streams[i] = NULL;
    }
    LP_LOGD("HOST_STOP", "sessions stopped; notifying stopped");
    /* Now close listeners and join accept threads */
    LP_LOGD("HOST_STOP", "closing listeners");
    listener_node_t **ls = NULL;
    listener_node_t *listener_head = NULL;
    size_t lcount = 0;
    detach_listeners(host, &ls, &lcount, &listener_head);

    /* Emit EXPIRED_LISTEN_ADDR for each listener about to be closed.
       Use the cached address string captured at listen time to avoid
       racing with transport internals during shutdown. */
    if (ls)
    {
        for (size_t i = 0; i < lcount; i++)
        {
            listener_node_t *ln = ls[i];
            if (!ln)
                continue;
            if (ln->addr_str)
            {
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_EXPIRED_LISTEN_ADDR;
                evt.u.listen_addr_added.addr = ln->addr_str;
                libp2p_event_publish(host, &evt);
            }
        }
    }
    else
    {
        for (listener_node_t *ln = listener_head; ln; ln = ln->next)
        {
            if (ln->addr_str)
            {
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_EXPIRED_LISTEN_ADDR;
                evt.u.listen_addr_added.addr = ln->addr_str;
                libp2p_event_publish(host, &evt);
            }
        }
    }

    if (ls)
    {
        for (size_t i = 0; i < lcount; i++)
        {
            listener_node_t *ln = ls[i];
            if (!ln)
                continue;
            LP_LOGD("HOST_STOP", "closing listener node=%p", (void *)ln);
            if (ln->lst)
                libp2p_listener_close(ln->lst);
            ln->thread_running = 0;
        }
        for (size_t i = 0; i < lcount; i++)
        {
            listener_node_t *ln = ls[i];
            if (!ln)
                continue;
            LP_LOGD("HOST_STOP", "joining listener thread node=%p", (void *)ln);
            if (ln->thread_started)
                pthread_join(ln->thread, NULL);
            LP_LOGD("HOST_STOP", "joined listener thread node=%p", (void *)ln);
            if (ln->lst)
                libp2p_listener_free(ln->lst);
            if (ln->addr_str)
                free(ln->addr_str);
            free(ln);
        }
        free(ls);
    }
    else
    {
        for (listener_node_t *ln = listener_head; ln; ln = ln->next)
        {
            LP_LOGD("HOST_STOP", "closing listener node=%p", (void *)ln);
            if (ln->lst)
                libp2p_listener_close(ln->lst);
            ln->thread_running = 0;
        }
        listener_node_t *ln = listener_head;
        while (ln)
        {
            listener_node_t *next = ln->next;
            LP_LOGD("HOST_STOP", "joining listener thread node=%p", (void *)ln);
            if (ln->thread_started)
                pthread_join(ln->thread, NULL);
            LP_LOGD("HOST_STOP", "joined listener thread node=%p", (void *)ln);
            if (ln->lst)
                libp2p_listener_free(ln->lst);
            if (ln->addr_str)
                free(ln->addr_str);
            free(ln);
            ln = next;
        }
    }
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_HOST_STOPPED;
    libp2p_event_publish(host, &evt);

    /* Wait for detached workers (identify, ping, substream handlers) to finish without polling. */
    pthread_mutex_lock(&host->mtx);
    while (atomic_load(&host->worker_count) > 0)
    {
        pthread_cond_wait(&host->worker_cv, &host->mtx);
    }
    pthread_mutex_unlock(&host->mtx);
    /* Now it is safe to free deferred yamux cbctx objects. */
    for (size_t i = 0; i < pending_stream_count; i++)
        if (pending_streams[i])
        {
            libp2p__stream_destroy(pending_streams[i]);
            pending_streams[i] = NULL;
        }
    free(pending_streams);
    for (size_t i = 0; i < yamux_cb_count; i++)
        yamux_cb_ctx_free(yamux_cbs[i]);
    free(yamux_cbs);
    for (size_t i = 0; i < deferred_conn_count; i++)
        libp2p_conn_free(deferred_conns[i]);
    free(deferred_conns);
    LP_LOGD("HOST_STOP", "end");
    /* Do not force-reset worker_count here; host_free waits for it to reach 0. */
    return 0;
}

int libp2p_host_listen(libp2p_host_t *host, const char *multiaddr_str)
{
    if (!host || !multiaddr_str)
        return LIBP2P_ERR_NULL_PTR;
    int ma_err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(multiaddr_str, &ma_err);
    if (!addr)
        return LIBP2P_ERR_UNSUPPORTED;
    libp2p_listener_t *lst = NULL;
    libp2p_transport_t *t = libp2p__host_select_transport(host, addr);
    int rc = t ? libp2p_transport_listen(t, addr, &lst) : LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    if (rc != LIBP2P_TRANSPORT_OK)
    {
        multiaddr_free(addr);
        return libp2p_error_from_transport(rc);
    }
    listener_node_t *node = (listener_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        multiaddr_free(addr);
        return LIBP2P_ERR_INTERNAL;
    }
    node->lst = lst;
    node->host = host;
    node->thread_running = 1;

    /* Cache address string early for subsequent events; fall back to input */
    int str_err = 0;
    char *s = multiaddr_to_str(addr, &str_err);
    if (s)
    {
        if (!node->addr_str)
            node->addr_str = strdup(s);
        libp2p_event_t evt = (libp2p_event_t){0};
        evt.kind = LIBP2P_EVT_LISTEN_ADDR_ADDED;
        evt.u.listen_addr_added.addr = s;
        libp2p_event_publish(host, &evt);
        free(s);
    }
    if (!node->addr_str)
        node->addr_str = strdup(multiaddr_str ? multiaddr_str : "");

    pthread_mutex_lock(&host->mtx);
    node->next = host->listeners;
    host->listeners = node;
    pthread_mutex_unlock(&host->mtx);
    if (atomic_load_explicit(&host->running, memory_order_acquire))
    {
        if (pthread_create(&node->thread, NULL, listener_accept_thread, node) == 0)
            node->thread_started = 1;
    }
    multiaddr_free(addr);
    return 0;
}

int libp2p_host_listen_ma(libp2p_host_t *host, const multiaddr_t *addr)
{
    if (!host || !addr)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_listener_t *lst = NULL;
    libp2p_transport_t *t = libp2p__host_select_transport(host, addr);
    int rc = t ? libp2p_transport_listen(t, addr, &lst) : LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    if (rc != LIBP2P_TRANSPORT_OK)
        return libp2p_error_from_transport(rc);
    listener_node_t *node = (listener_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        return LIBP2P_ERR_INTERNAL;
    }
    node->lst = lst;
    node->host = host;
    node->thread_running = 1;

    /* Cache address string early for subsequent events */
    int str_err = 0;
    char *s = multiaddr_to_str(addr, &str_err);
    if (s)
    {
        if (!node->addr_str)
            node->addr_str = strdup(s);
        libp2p_event_t evt = (libp2p_event_t){0};
        evt.kind = LIBP2P_EVT_LISTEN_ADDR_ADDED;
        evt.u.listen_addr_added.addr = s;
        libp2p_event_publish(host, &evt);
        free(s);
    }
    if (!node->addr_str)
        node->addr_str = strdup("");

    pthread_mutex_lock(&host->mtx);
    node->next = host->listeners;
    host->listeners = node;
    pthread_mutex_unlock(&host->mtx);
    if (atomic_load_explicit(&host->running, memory_order_acquire))
    {
        if (pthread_create(&node->thread, NULL, listener_accept_thread, node) == 0)
            node->thread_started = 1;
    }
    return 0;
}

static void *listener_accept_thread(void *arg)
{
    listener_node_t *node = (listener_node_t *)arg;
    libp2p_host_t *host = node->host;
    /* Ensure addr_str is initialized for subsequent events */
    if (!node->addr_str)
    {
        multiaddr_t *bound = NULL;
        if (node->lst && libp2p_listener_local_addr(node->lst, &bound) == 0 && bound)
        {
            int se = 0;
            char *s = multiaddr_to_str(bound, &se);
            if (s)
            {
                node->addr_str = strdup(s);
                free(s);
            }
            multiaddr_free(bound);
        }
        if (!node->addr_str)
            node->addr_str = strdup("");
    }
    for (;;)
    {
        /* Early-exit when host_stop requested shutdown for this listener. */
        if (!node->thread_running)
            break;
        libp2p_conn_t *raw = NULL;
        libp2p_listener_err_t rc = libp2p_listener_accept(node->lst, &raw);
        if (rc == LIBP2P_LISTENER_ERR_AGAIN ||
            rc == LIBP2P_LISTENER_ERR_TIMEOUT ||
            rc == LIBP2P_LISTENER_ERR_BACKOFF)
            continue; /* rely on listener internals to block efficiently */
        if (rc != LIBP2P_LISTENER_OK)
        {
            if (rc == LIBP2P_LISTENER_ERR_CLOSED)
            {
                /* Notify subscribers the listener closed (once) */
                if (!node->emitted_closed)
                {
                    libp2p_event_t evt = (libp2p_event_t){0};
                    evt.kind = LIBP2P_EVT_LISTENER_CLOSED;
                    evt.u.listener_closed.addr = node->addr_str;
                    evt.u.listener_closed.reason = libp2p_error_from_listener(rc);
                    libp2p_event_publish(host, &evt);
                    node->emitted_closed = 1;
                }
                break;
            }
            /* Other listener error. During shutdown, suppress spurious errors */
            if (!node->emitted_error && atomic_load_explicit(&host->running, memory_order_acquire) && node->thread_running)
            {
                libp2p_event_t evt = (libp2p_event_t){0};
                evt.kind = LIBP2P_EVT_LISTENER_ERROR;
                evt.u.listener_error.addr = node->addr_str;
                evt.u.listener_error.code = libp2p_error_from_listener(rc);
                evt.u.listener_error.msg = "listener accept error";
                libp2p_event_publish(host, &evt);
                node->emitted_error = 1;
            }
            continue;
        }
        /* Reset error emission gate on successful accept */
        node->emitted_error = 0;
        if (!raw)
            continue;

        /* Upgrade inbound connection (Noise + muxer) via shared helper */
        libp2p_uconn_t *uc = NULL;
        int uprci = 0;
        if (libp2p_quic_conn_session(raw) != NULL)
        {
            uprci = libp2p__host_upgrade_inbound_quic(host, raw, &uc);
        }
        else
        {
            uprci = libp2p__host_upgrade_inbound(host, raw, /*allow_mplex=*/1, &uc);
        }
        if (uprci != 0 || !uc)
            continue;
        libp2p_conn_t *secured = uc->conn;
        peer_id_t *remote_peer = uc->remote_peer;
        libp2p_muxer_t *mx = (libp2p_muxer_t *)uc->muxer;
        free(uc);

        /* Enforce inbound connection limits and optional conn manager high-water */
        {
            int reject = 0;
            /* Hard cap from options */
            if (host->opts.max_inbound_conns > 0)
            {
                size_t count = 0;
                pthread_mutex_lock(&host->mtx);
                for (session_node_t *itc = host->sessions; itc; itc = itc->next)
                    count++;
                pthread_mutex_unlock(&host->mtx);
                if (count >= (size_t)host->opts.max_inbound_conns)
                    reject = 1;
            }
            /* Conn manager high-water */
            if (!reject && host->conn_mgr)
            {
                int lw = 0, hw = 0, gm = 0;
                (void)gm;
                if (libp2p_conn_mgr_get_params(host->conn_mgr, &lw, &hw, NULL) == 0 && hw > 0)
                {
                    size_t count = 0;
                    pthread_mutex_lock(&host->mtx);
                    for (session_node_t *itc = host->sessions; itc; itc = itc->next)
                        count++;
                    pthread_mutex_unlock(&host->mtx);
                    if ((int)count >= hw)
                        reject = 1;
                }
            }
            if (reject)
            {
                libp2p_conn_free(secured);
                if (remote_peer)
                    peer_id_destroy(remote_peer);
                if (mx)
                    libp2p_muxer_free(mx);
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_INCOMING_CONNECTION_ERROR;
                evt.u.incoming_conn_error.peer = NULL;
                evt.u.incoming_conn_error.code = LIBP2P_ERR_AGAIN;
                evt.u.incoming_conn_error.msg = "too many inbound connections";
                libp2p_event_publish(host, &evt);
                continue;
            }
        }

        if (host->gater_fn)
        {
            int str_err = 0;
            char *addr_str = NULL;
            const multiaddr_t *raddr = libp2p_conn_remote_addr(secured);
            if (raddr)
                addr_str = multiaddr_to_str(raddr, &str_err);
            libp2p_gater_decision_t gd = host->gater_fn(addr_str ? addr_str : "", remote_peer, host->gater_ud);
            if (addr_str)
                free(addr_str);
            if (gd == LIBP2P_GATER_DECISION_REJECT)
            {
                libp2p_conn_free(secured);
                if (remote_peer)
                    peer_id_destroy(remote_peer);
                if (mx)
                    libp2p_muxer_free(mx);
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_INCOMING_CONNECTION_ERROR;
                evt.u.incoming_conn_error.peer = remote_peer;
                evt.u.incoming_conn_error.code = LIBP2P_ERR_UNSUPPORTED;
                evt.u.incoming_conn_error.msg = "connection gated/rejected";
                libp2p_event_publish(host, &evt);
                continue;
            }
        }

        libp2p__emit_conn_opened(host, true, remote_peer, libp2p_conn_remote_addr(secured));

        int is_quic = libp2p_quic_conn_session(secured) ? 1 : 0;

        if (is_quic)
        {
            session_node_t *snode = (session_node_t *)calloc(1, sizeof(*snode));
            if (snode)
            {
                snode->is_quic = 1;
                pthread_mutex_init(&snode->ready_mtx, NULL);
                pthread_cond_init(&snode->ready_cv, NULL);
                pthread_mutex_lock(&host->mtx);
                snode->next = host->sessions;
                host->sessions = snode;
                pthread_mutex_unlock(&host->mtx);
                pthread_mutex_lock(&snode->ready_mtx);
                snode->mx = mx;
                snode->conn = secured;
                pthread_cond_broadcast(&snode->ready_cv);
                pthread_mutex_unlock(&snode->ready_mtx);
                LP_LOGD("HOST", "registered inbound QUIC session node=%p", (void *)snode);
            }
            if (remote_peer)
            {
                peer_id_destroy(remote_peer);
                free(remote_peer);
                remote_peer = NULL;
            }
            continue;
        }

        /* Spawn per-connection session thread to process frames and accept substreams */

        inbound_session_ctx_t *ictx = calloc(1, sizeof(*ictx));
        if (!ictx)
        {
            libp2p_conn_free(secured);
            libp2p_muxer_free(mx);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            continue;
        }
        /* register this session so host_stop can stop/join it */
        session_node_t *snode = (session_node_t *)calloc(1, sizeof(*snode));
        if (snode)
        {
            snode->is_quic = 0;
            /* init ready signaling primitives */
            pthread_mutex_init(&snode->ready_mtx, NULL);
            pthread_cond_init(&snode->ready_cv, NULL);
            pthread_mutex_lock(&host->mtx);
            snode->next = host->sessions;
            host->sessions = snode;
            pthread_mutex_unlock(&host->mtx);
            LP_LOGD("HOST", "registered inbound session node=%p", (void *)snode);
        }
        ictx->host = host;
        ictx->conn = secured;
        ictx->mx = mx;
        ictx->peer = remote_peer;
        ictx->snode = snode;
        remote_peer = NULL;
        pthread_t th;
        /* Heuristic: if muxer vtable has open_stream, assume yamux; otherwise mplex */
        if (mx && mx->vt && mx->vt->open_stream)
        {
            if (pthread_create(&th, NULL, inbound_session_thread, ictx) == 0)
            {
                if (snode)
                {
                    /* publish thread handle and signal readiness */
                    pthread_mutex_lock(&snode->ready_mtx);
                    snode->thread = th;
                    pthread_cond_broadcast(&snode->ready_cv);
                    pthread_mutex_unlock(&snode->ready_mtx);
                }
                else
                    pthread_detach(th);
            }
            else
            {
                free(ictx);
                libp2p_conn_free(secured);
                libp2p_muxer_free(mx);
                if (remote_peer)
                    peer_id_destroy(remote_peer);
                if (snode)
                {
                    pthread_mutex_lock(&host->mtx);
                    session_node_t **pp = &host->sessions;
                    while (*pp && *pp != snode)
                        pp = &(*pp)->next;
                    if (*pp == snode)
                        *pp = snode->next;
                    pthread_mutex_unlock(&host->mtx);
                    pthread_mutex_destroy(&snode->ready_mtx);
                    pthread_cond_destroy(&snode->ready_cv);
                    free(snode);
                }
            }
        }
        else
        {
            if (pthread_create(&th, NULL, inbound_mplex_session_thread, ictx) == 0)
            {
                if (snode)
                {
                    pthread_mutex_lock(&snode->ready_mtx);
                    snode->thread = th;
                    pthread_cond_broadcast(&snode->ready_cv);
                    pthread_mutex_unlock(&snode->ready_mtx);
                }
                else
                    pthread_detach(th);
            }
            else
            {
                free(ictx);
                libp2p_conn_free(secured);
                libp2p_muxer_free(mx);
                if (remote_peer)
                    peer_id_destroy(remote_peer);
                if (snode)
                {
                    pthread_mutex_lock(&host->mtx);
                    session_node_t **pp = &host->sessions;
                    while (*pp && *pp != snode)
                        pp = &(*pp)->next;
                    if (*pp == snode)
                        *pp = snode->next;
                    pthread_mutex_unlock(&host->mtx);
                    pthread_mutex_destroy(&snode->ready_mtx);
                    pthread_cond_destroy(&snode->ready_cv);
                    free(snode);
                }
            }
        }
        /* Already handed off to session thread */
        continue;
    }
    return NULL;
}
