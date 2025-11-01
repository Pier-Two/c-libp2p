#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "host_internal.h"
#include "libp2p/debug_trace.h"
#include "libp2p/errors.h"
#include "libp2p/lpmsg.h"
#include "libp2p/peerstore.h"
#include "libp2p/protocol_introspect.h"
#include "libp2p/protocol_listen.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id_ecdsa.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_rsa.h"
#include "peer_id/peer_id_secp256k1.h"
#include "protocol/identify/protocol_identify.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"

typedef struct identify_srv_ctx
{
    libp2p_stream_t *s;
    struct libp2p_host *host;
} identify_srv_ctx_t;

static void identify_srv_handle(identify_srv_ctx_t *ctx)
{
    if (!ctx)
        return;
    libp2p_stream_t *s = ctx->s;
    struct libp2p_host *host = ctx->host;
    const peer_id_t *remote = libp2p_stream_remote_peer(s);
    char peer_buf[128] = {0};
    if (remote && peer_id_to_string(remote, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf)) < 0)
        peer_buf[0] = '\0';
    const char *proto_id = libp2p_stream_protocol_id(s);
    LIBP2P_TRACE("identify", "serving identify stream=%p peer=%s proto=%s", (void *)s, peer_buf, proto_id ? proto_id : "(unknown)");

    uint8_t *buf = NULL;
    size_t blen = 0;
    if (libp2p_identify_encode_local(host, s, 1, &buf, &blen) == 0 && buf && blen > 0)
    {
        ssize_t written = libp2p_lp_send(s, buf, blen);
        if (written < 0)
        {
            LIBP2P_TRACE("identify", "lp_send failed stream=%p rc=%zd proto=%s", (void *)s, written, proto_id ? proto_id : "(unknown)");
        }
        else
        {
            LIBP2P_TRACE("identify", "lp_send ok stream=%p bytes=%zd peer=%s", (void *)s, written, peer_buf);
        }
    }
    else
    {
        LIBP2P_TRACE("identify", "encode failed stream=%p peer=%s", (void *)s, peer_buf);
    }
    free(buf);
    (void)libp2p_stream_close(s);
    libp2p__stream_release_async(s);
    if (host)
        libp2p__worker_dec(host);
    free(ctx);
}

static void identify_on_open(libp2p_stream_t *s, void *ud)
{
    identify_srv_ctx_t *ctx = (identify_srv_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return;
    ctx->s = s;
    ctx->host = (struct libp2p_host *)ud;
    if (!libp2p__stream_retain_async(s))
    {
        free(ctx);
        if (s)
        {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }
    if (ctx->host)
        libp2p__worker_inc(ctx->host);
    identify_srv_handle(ctx);
}

int libp2p_identify_service_start(struct libp2p_host *host, libp2p_protocol_server_t **out_server)
{
    if (!host || !out_server)
        return -1;
    libp2p_protocol_def_t def = {
        .protocol_id = LIBP2P_IDENTIFY_PROTO_ID,
        .read_mode = LIBP2P_READ_PULL,
        .on_open = identify_on_open,
        .on_data = NULL,
        .on_eof = NULL,
        .on_close = NULL,
        .on_error = NULL,
        .user_data = host,
    };
    return libp2p_host_listen_protocol(host, &def, out_server);
}

int libp2p_identify_service_stop(struct libp2p_host *host, libp2p_protocol_server_t *server)
{
    if (!host || !server)
        return -1;
    return libp2p_host_unlisten(host, server);
}

/* ======================= Identify Push ======================= */

typedef struct identify_push_state
{
    struct libp2p_host *host;
    /* LP header accumulation */
    uint8_t hdr[10];
    size_t hdr_used;
    int header_done;
    uint64_t need;
    /* Payload accumulation */
    uint8_t *payload;
    size_t got;
    int done;
} identify_push_state_t;

typedef struct identify_push_thread_ctx
{
    libp2p_stream_t *stream;
    struct libp2p_host *host;
} identify_push_thread_ctx_t;

/* Bound Identify Push payload to avoid excessive allocations on malformed inputs. */
#ifndef LIBP2P_IDENTIFY_PUSH_MAX_FRAME
#define LIBP2P_IDENTIFY_PUSH_MAX_FRAME (16 * 1024)
#endif

static void identify_push_process_full(libp2p_stream_t *s, identify_push_state_t *st)
{
    if (!s || !st || !st->host || !st->payload)
        return;

    libp2p_identify_t *id = NULL;
    if (libp2p_identify_message_decode(st->payload, st->got, &id) != 0 || !id)
    {
        LIBP2P_TRACE("identify_push", "decode failed got=%zu", st->got);
        return;
    }

    const peer_id_t *remote = libp2p_stream_remote_peer(s);
    peer_id_t remote_copy = {0};
    if (remote && remote->bytes && remote->size)
    {
        uint8_t *dup = (uint8_t *)malloc(remote->size);
        if (dup)
        {
            memcpy(dup, remote->bytes, remote->size);
            remote_copy.bytes = dup;
            remote_copy.size = remote->size;
            remote = &remote_copy;
        }
        else
        {
            remote = NULL; /* fallback to derived id below */
        }
    }
    const peer_id_t *target = remote;
    peer_id_t derived = {0};
    int derived_valid = 0;
    if (id->public_key && id->public_key_len &&
        peer_id_create_from_public_key(id->public_key, id->public_key_len, &derived) == PEER_ID_SUCCESS)
    {
        derived_valid = 1;
        if (!target || !target->bytes || target->size == 0 || peer_id_equals(target, &derived) != 1)
            target = &derived;
    }

    if (st->host->peerstore && target)
    {
        char pid_buf[128];
        if (peer_id_to_string(target, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
            snprintf(pid_buf, sizeof(pid_buf), "<unknown>");
        LIBP2P_TRACE("identify_push", "apply target=%s remote=%p protocols=%zu", pid_buf, (void *)remote, id->num_protocols);
        if (id->num_protocols && id->protocols)
        {
            if (libp2p_peerstore_set_protocols(st->host->peerstore, target, (const char *const *)id->protocols, id->num_protocols) == 0)
            {
                libp2p__notify_peer_protocols_updated(st->host, target, (const char *const *)id->protocols, id->num_protocols);
                LIBP2P_TRACE("identify_push", "protocols updated count=%zu", id->num_protocols);
            }
        }

        if (id->public_key && id->public_key_len)
            (void)libp2p_peerstore_set_public_key(st->host->peerstore, target, id->public_key, id->public_key_len);

        for (size_t i = 0; i < id->num_listen_addrs; i++)
        {
            const uint8_t *bytes = id->listen_addrs[i];
            size_t blen = id->listen_addrs_lens[i];
            if (!bytes || !blen)
                continue;
            int ma_err = 0;
            multiaddr_t *ma = multiaddr_new_from_bytes(bytes, blen, &ma_err);
            if (ma)
            {
                (void)libp2p_peerstore_add_addr(st->host->peerstore, target, ma, 10 * 60 * 1000);
                int serr = 0;
                char *astr = multiaddr_to_str(ma, &serr);
                if (astr && serr == MULTIADDR_SUCCESS)
                {
                    libp2p_event_t evt2 = (libp2p_event_t){0};
                    evt2.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER;
                    evt2.u.new_external_addr_of_peer.peer = target;
                    evt2.u.new_external_addr_of_peer.addr = astr;
                    libp2p_event_publish(st->host, &evt2);
                    free(astr);
                }
                multiaddr_free(ma);
            }
        }
    }

    if (derived_valid)
        peer_id_destroy(&derived);
    if (remote_copy.bytes)
        peer_id_destroy(&remote_copy);

    if (id->observed_addr && id->observed_addr_len)
    {
        int ma_err = 0;
        multiaddr_t *oma = multiaddr_new_from_bytes(id->observed_addr, id->observed_addr_len, &ma_err);
        if (oma)
        {
            int serr = 0;
            char *ostr = multiaddr_to_str(oma, &serr);
            if (ostr && serr == MULTIADDR_SUCCESS)
            {
                libp2p_event_t evt = (libp2p_event_t){0};
                evt.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE;
                evt.u.new_external_addr_candidate.addr = ostr;
                libp2p_event_publish(st->host, &evt);
                free(ostr);
            }
            multiaddr_free(oma);
        }
    }

    libp2p_identify_free(id);
}

static void identify_push_on_close(libp2p_stream_t *s, void *ud);

static void identify_push_close_and_signal(libp2p_stream_t *s, identify_push_state_t *st)
{
    if (st)
        st->done = 1;
    libp2p_stream_close(s);
}

static void identify_push_feed(libp2p_stream_t *s, const uint8_t *data, size_t len, void *ud)
{
    identify_push_state_t *st = (identify_push_state_t *)libp2p_stream_get_user_data(s);
    if (!st)
    {
        /* Lazy-init state on first data callback when on_open is not used. */
        st = (identify_push_state_t *)calloc(1, sizeof(*st));
        if (!st)
        {
            identify_push_close_and_signal(s, NULL);
            return;
        }
        st->host = (struct libp2p_host *)ud;
        libp2p_stream_set_user_data(s, st);
    }
    if (!st || !data || len == 0)
        return;
    size_t off = 0;
    while (off < len)
    {
        if (!st->header_done)
        {
            size_t room = sizeof(st->hdr) - st->hdr_used;
            size_t to_copy = (len - off < room) ? (len - off) : room;
            memcpy(st->hdr + st->hdr_used, data + off, to_copy);
            st->hdr_used += to_copy;
            off += to_copy;
            uint64_t need = 0;
            size_t consumed = 0;
            if (unsigned_varint_decode(st->hdr, st->hdr_used, &need, &consumed) == UNSIGNED_VARINT_OK)
            {
                st->need = need;
                /* If we decoded a zero-length frame, ignore it and keep waiting
                 * for the next frame instead of treating it as a complete
                 * Identify Push. Closing on a zero-length frame can race with
                 * the sender still delivering the actual payload, causing data
                 * loss. */
                if (st->need == 0)
                {
                    /* Reset header state to look for the next frame header. */
                    st->hdr_used = 0;
                    st->got = 0;
                    /* Do not mark header_done; continue accumulating. */
                    /* Note: any excess bytes (should be 0 here) will be
                     * handled by the outer loop since off already advanced. */
                }
                else
                {
                    if (st->need > (uint64_t)LIBP2P_IDENTIFY_PUSH_MAX_FRAME)
                    {
                        /* Frame too large: close defensively */
                        identify_push_close_and_signal(s, st);
                        return;
                    }
                    st->header_done = 1;
                    st->payload = (uint8_t *)malloc((size_t)need);
                    if (!st->payload)
                    { /* OOM: close */
                        identify_push_close_and_signal(s, st);
                        return;
                    }
                    size_t excess = st->hdr_used - consumed;
                    if (excess > 0)
                    {
                        size_t take = excess > st->need ? (size_t)st->need : excess;
                        memcpy(st->payload, st->hdr + consumed, take);
                        st->got = take;
                    }
                }
            }
            else if (st->hdr_used == sizeof(st->hdr))
            {
                /* malformed header */
                identify_push_close_and_signal(s, st);
                return;
            }
        }
        else
        {
            size_t want = (size_t)(st->need - st->got);
            size_t to_copy = (len - off < want) ? (len - off) : want;
            memcpy(st->payload + st->got, data + off, to_copy);
            st->got += to_copy;
            off += to_copy;
            if (st->need > 0 && st->got == st->need)
            {
        identify_push_process_full(s, st);
        st->done = 1;
        LIBP2P_TRACE("identify_push", "frame complete need=%llu", (unsigned long long)st->need);
        return;
            }
        }
    }
}

static void identify_push_on_close(libp2p_stream_t *s, void *ud)
{
    (void)ud;
    identify_push_state_t *st = (identify_push_state_t *)libp2p_stream_get_user_data(s);
    if (st)
    {
        LIBP2P_TRACE("identify_push", "on_close stream=%p", (void *)s);
        if (st->payload)
            free(st->payload);
        free(st);
        libp2p_stream_set_user_data(s, NULL);
    }
}
static void *identify_push_thread(void *arg)
{
    identify_push_thread_ctx_t *ctx = (identify_push_thread_ctx_t *)arg;
    if (!ctx)
        return NULL;
    libp2p_stream_t *s = ctx->stream;
    struct libp2p_host *host = ctx->host;
    identify_push_state_t *st = (identify_push_state_t *)calloc(1, sizeof(*st));
    if (!s || !st)
    {
        if (host)
            libp2p__worker_dec(host);
        free(st);
        free(ctx);
        return NULL;
    }
    st->host = host;
    libp2p_stream_set_user_data(s, st);

    uint8_t buf[4096];
    int status = 0;
    while (1)
    {
        ssize_t n = libp2p_stream_read(s, buf, sizeof(buf));
        if (n > 0)
        {
            identify_push_feed(s, buf, (size_t)n, host);
            LIBP2P_TRACE("identify_push", "read bytes=%zd header_done=%d need=%llu got=%zu stream=%p",
                         n,
                         st->header_done,
                         (unsigned long long)st->need,
                         st->got,
                         (void *)s);
            if (st->done)
                break;
            continue;
        }
        if (n == 0)
        {
            LIBP2P_TRACE("identify_push", "stream EOF stream=%p", (void *)s);
            break;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            if (st->done)
            {
                LIBP2P_TRACE("identify_push", "done flagged after AGAIN stream=%p", (void *)s);
                break;
            }
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
            nanosleep(&ts, NULL);
            continue;
        }
        status = (int)n;
        LIBP2P_TRACE("identify_push", "read error=%d stream=%p", status, (void *)s);
        break;
    }

    if (!st->done)
        LIBP2P_TRACE("identify_push", "exit without payload status=%d stream=%p", status, (void *)s);

    int close_rc = libp2p_stream_close(s);
    identify_push_on_close(s, host);
    if (close_rc != 0)
    {
        LIBP2P_TRACE("identify_push", "stream_close rc=%d stream=%p", close_rc, (void *)s);
    }
    libp2p__stream_release_async(s);

    if (host)
        libp2p__worker_dec(host);
    free(ctx);
    return NULL;
}

static void identify_push_on_open(libp2p_stream_t *s, void *ud)
{
    identify_push_thread_ctx_t *ctx = (identify_push_thread_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return;
    ctx->stream = s;
    ctx->host = (struct libp2p_host *)ud;
    if (!libp2p__stream_retain_async(s))
    {
        if (ctx->host)
            libp2p__worker_dec(ctx->host);
        free(ctx);
        if (s)
        {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }
    if (ctx->host)
        libp2p__worker_inc(ctx->host);
    libp2p_stream_set_read_interest(s, true);
    pthread_t th;
    if (pthread_create(&th, NULL, identify_push_thread, ctx) == 0)
    {
        pthread_detach(th);
        LIBP2P_TRACE("identify_push", "thread started stream=%p", (void *)s);
    }
    else
    {
        if (ctx->host)
            libp2p__worker_dec(ctx->host);
        free(ctx);
        LIBP2P_TRACE("identify_push", "thread spawn failed stream=%p", (void *)s);
        if (s)
        {
            libp2p_stream_close(s);
            libp2p__stream_release_async(s);
        }
    }
}

int libp2p_identify_push_service_start(struct libp2p_host *host, libp2p_protocol_server_t **out_server)
{
    if (!host || !out_server)
        return -1;
    libp2p_protocol_def_t def = {
        .protocol_id = LIBP2P_IDENTIFY_PUSH_PROTO_ID,
        .read_mode = LIBP2P_READ_PULL,
        .on_open = identify_push_on_open,
        .on_data = NULL,
        .on_eof = NULL,
        .on_close = identify_push_on_close,
        .on_error = NULL,
        .user_data = host,
    };
    return libp2p_host_listen_protocol(host, &def, out_server);
}

int libp2p_identify_push_service_stop(struct libp2p_host *host, libp2p_protocol_server_t *server)
{
    if (!host || !server)
        return -1;
    return libp2p_host_unlisten(host, server);
}

int libp2p_identify_encode_local(struct libp2p_host *host, libp2p_stream_t *s, int include_observed, uint8_t **out_buf, size_t *out_len)
{
    if (!host || !out_buf || !out_len)
        return -1;
    libp2p_identify_t msg = (libp2p_identify_t){0};
    msg.protocol_version = strdup("libp2p/1.0.0");
    msg.agent_version = strdup("c-libp2p");

    /* Public key */
    if (host->have_identity && host->identity_key && host->identity_key_len > 0)
    {
        uint8_t *pubkey_pb = NULL;
        size_t pubkey_pb_len = 0;
        uint8_t *tmp = (uint8_t *)malloc(host->identity_key_len);
        if (tmp)
        {
            memcpy(tmp, host->identity_key, host->identity_key_len);
            peer_id_error_t perr = PEER_ID_E_INVALID_PROTOBUF;
            switch (host->identity_type)
            {
                case 1:
                    perr = peer_id_create_from_private_key_ed25519(tmp, host->identity_key_len, &pubkey_pb, &pubkey_pb_len);
                    break;
                case 2:
                    perr = peer_id_create_from_private_key_secp256k1(tmp, host->identity_key_len, &pubkey_pb, &pubkey_pb_len);
                    break;
                case 0:
                    perr = peer_id_create_from_private_key_rsa(tmp, host->identity_key_len, &pubkey_pb, &pubkey_pb_len);
                    break;
                case 3:
                    perr = peer_id_create_from_private_key_ecdsa(tmp, host->identity_key_len, &pubkey_pb, &pubkey_pb_len);
                    break;
                default:
                    perr = PEER_ID_E_INVALID_PROTOBUF;
                    break;
            }
            free(tmp);
            if (perr == PEER_ID_SUCCESS && pubkey_pb)
            {
                msg.public_key = pubkey_pb;
                msg.public_key_len = pubkey_pb_len;
                /* ownership moved into msg for free path */
            }
        }
    }

    /* listenAddrs: encode as binary multiaddr bytes per spec */
    pthread_mutex_lock(&host->mtx);
    for (listener_node_t *ln = host->listeners; ln; ln = ln->next)
    {
        multiaddr_t *ma = NULL;
        if (ln->lst && libp2p_listener_local_addr(ln->lst, &ma) == LIBP2P_LISTENER_OK && ma)
        {
            uint8_t tmp[512];
            int wrote = multiaddr_get_bytes(ma, tmp, sizeof(tmp));
            if (wrote == MULTIADDR_ERR_BUFFER_TOO_SMALL)
            {
                size_t cap = 4096;
                uint8_t *heap = (uint8_t *)malloc(cap);
                if (heap)
                {
                    int w2 = multiaddr_get_bytes(ma, heap, cap);
                    if (w2 > 0)
                    {
                        uint8_t **new_addrs = (uint8_t **)realloc(msg.listen_addrs, (msg.num_listen_addrs + 1) * sizeof(uint8_t *));
                        size_t *new_lens = (size_t *)realloc(msg.listen_addrs_lens, (msg.num_listen_addrs + 1) * sizeof(size_t));
                        if (new_addrs && new_lens)
                        {
                            msg.listen_addrs = new_addrs;
                            msg.listen_addrs_lens = new_lens;
                            msg.listen_addrs[msg.num_listen_addrs] = (uint8_t *)malloc((size_t)w2);
                            if (msg.listen_addrs[msg.num_listen_addrs])
                            {
                                memcpy(msg.listen_addrs[msg.num_listen_addrs], heap, (size_t)w2);
                                msg.listen_addrs_lens[msg.num_listen_addrs] = (size_t)w2;
                                msg.num_listen_addrs++;
                            }
                        }
                    }
                    free(heap);
                }
            }
            else if (wrote > 0)
            {
                uint8_t **new_addrs = (uint8_t **)realloc(msg.listen_addrs, (msg.num_listen_addrs + 1) * sizeof(uint8_t *));
                size_t *new_lens = (size_t *)realloc(msg.listen_addrs_lens, (msg.num_listen_addrs + 1) * sizeof(size_t));
                if (new_addrs && new_lens)
                {
                    msg.listen_addrs = new_addrs;
                    msg.listen_addrs_lens = new_lens;
                    msg.listen_addrs[msg.num_listen_addrs] = (uint8_t *)malloc((size_t)wrote);
                    if (msg.listen_addrs[msg.num_listen_addrs])
                    {
                        memcpy(msg.listen_addrs[msg.num_listen_addrs], tmp, (size_t)wrote);
                        msg.listen_addrs_lens[msg.num_listen_addrs] = (size_t)wrote;
                        msg.num_listen_addrs++;
                    }
                }
            }
            multiaddr_free(ma);
        }
    }
    pthread_mutex_unlock(&host->mtx);

    if (msg.num_listen_addrs == 0 && host->opts.num_listen_addrs && host->opts.listen_addrs)
    {
        for (size_t i = 0; i < host->opts.num_listen_addrs; i++)
        {
            const char *astr = host->opts.listen_addrs[i];
            if (!astr)
                continue;
            int ma_err = 0;
            multiaddr_t *ma = multiaddr_new_from_str(astr, &ma_err);
            if (!ma)
                continue;
            uint8_t tmp[512];
            int wrote = multiaddr_get_bytes(ma, tmp, sizeof(tmp));
            if (wrote == MULTIADDR_ERR_BUFFER_TOO_SMALL)
            {
                size_t cap = 4096;
                uint8_t *heap = (uint8_t *)malloc(cap);
                if (heap)
                {
                    int w2 = multiaddr_get_bytes(ma, heap, cap);
                    if (w2 > 0)
                    {
                        uint8_t **new_addrs = (uint8_t **)realloc(msg.listen_addrs, (msg.num_listen_addrs + 1) * sizeof(uint8_t *));
                        size_t *new_lens = (size_t *)realloc(msg.listen_addrs_lens, (msg.num_listen_addrs + 1) * sizeof(size_t));
                        if (new_addrs && new_lens)
                        {
                            msg.listen_addrs = new_addrs;
                            msg.listen_addrs_lens = new_lens;
                            msg.listen_addrs[msg.num_listen_addrs] = (uint8_t *)malloc((size_t)w2);
                            if (msg.listen_addrs[msg.num_listen_addrs])
                            {
                                memcpy(msg.listen_addrs[msg.num_listen_addrs], heap, (size_t)w2);
                                msg.listen_addrs_lens[msg.num_listen_addrs] = (size_t)w2;
                                msg.num_listen_addrs++;
                            }
                        }
                    }
                    free(heap);
                }
            }
            else if (wrote > 0)
            {
                uint8_t **new_addrs = (uint8_t **)realloc(msg.listen_addrs, (msg.num_listen_addrs + 1) * sizeof(uint8_t *));
                size_t *new_lens = (size_t *)realloc(msg.listen_addrs_lens, (msg.num_listen_addrs + 1) * sizeof(size_t));
                if (new_addrs && new_lens)
                {
                    msg.listen_addrs = new_addrs;
                    msg.listen_addrs_lens = new_lens;
                    msg.listen_addrs[msg.num_listen_addrs] = (uint8_t *)malloc((size_t)wrote);
                    if (msg.listen_addrs[msg.num_listen_addrs])
                    {
                        memcpy(msg.listen_addrs[msg.num_listen_addrs], tmp, (size_t)wrote);
                        msg.listen_addrs_lens[msg.num_listen_addrs] = (size_t)wrote;
                        msg.num_listen_addrs++;
                    }
                }
            }
            multiaddr_free(ma);
        }
    }

    if (include_observed && s)
    {
        const multiaddr_t *rma = libp2p_stream_remote_addr(s);
        if (rma)
        {
            uint8_t tmp[512];
            int wrote = multiaddr_get_bytes(rma, tmp, sizeof(tmp));
            if (wrote == MULTIADDR_ERR_BUFFER_TOO_SMALL)
            {
                size_t cap = 4096;
                uint8_t *heap = (uint8_t *)malloc(cap);
                if (heap)
                {
                    int w2 = multiaddr_get_bytes(rma, heap, cap);
                    if (w2 > 0)
                    {
                        msg.observed_addr = (uint8_t *)malloc((size_t)w2);
                        if (msg.observed_addr)
                        {
                            memcpy(msg.observed_addr, heap, (size_t)w2);
                            msg.observed_addr_len = (size_t)w2;
                        }
                    }
                    free(heap);
                }
            }
            else if (wrote > 0)
            {
                msg.observed_addr = (uint8_t *)malloc((size_t)wrote);
                if (msg.observed_addr)
                {
                    memcpy(msg.observed_addr, tmp, (size_t)wrote);
                    msg.observed_addr_len = (size_t)wrote;
                }
            }
        }
    }

    const char **ids = NULL;
    size_t n_ids = 0;
    if (libp2p_host_supported_protocols(host, &ids, &n_ids) == 0 && n_ids > 0)
    {
        msg.protocols = (char **)calloc(n_ids, sizeof(char *));
        if (msg.protocols)
        {
            for (size_t i = 0; i < n_ids; i++)
                msg.protocols[i] = ids[i] ? (char *)ids[i] : NULL;
            msg.num_protocols = n_ids;
        }
    }

    int rc = libp2p_identify_message_encode(&msg, out_buf, out_len);
    libp2p_host_free_supported_protocols(ids, n_ids);
    free(msg.protocols);
    if (msg.public_key)
        free(msg.public_key);
    if (msg.listen_addrs)
    {
        for (size_t i = 0; i < msg.num_listen_addrs; i++)
            free(msg.listen_addrs[i]);
        free(msg.listen_addrs);
    }
    if (msg.listen_addrs_lens)
        free(msg.listen_addrs_lens);
    if (msg.observed_addr)
        free(msg.observed_addr);
    free(msg.protocol_version);
    free(msg.agent_version);
    return rc;
}
