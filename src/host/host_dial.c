#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_internal.h"
#include "proto_select_internal.h"

#include "libp2p/dial.h"
#include "libp2p/host.h"
#include "libp2p/log.h"
#include "libp2p/protocol_dial.h"
#include "libp2p/protocol_introspect.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/muxer/mplex/mplex_io_adapter.h"
#include "protocol/muxer/mplex/mplex_stream_adapter.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/muxer/yamux/yamux_io_adapter.h"
#include "protocol/muxer/yamux/yamux_stream_adapter.h"
#include "protocol/noise/protocol_noise.h"
#include "transport/connection.h"
#include "transport/transport.h"
#include "transport/upgrader.h"
#include "libp2p/cancel.h"
#include "libp2p/error_map.h"
#include "libp2p/io.h"
#include "libp2p/lpmsg.h"
#include "libp2p/peerstore.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/tcp/protocol_tcp_util.h" /* now_mono_ms */
#include "multiformats/multicodec/multicodec_codes.h"

/* ================= Outbound yamux session loop (event-driven) ================= */

typedef struct
{
    libp2p_yamux_ctx_t *yctx;
} ob_loop_ctx_t;

static void *outbound_yamux_loop(void *arg)
{
    ob_loop_ctx_t *ctx = (ob_loop_ctx_t *)arg;
    if (!ctx)
        return NULL;
    if (ctx->yctx)
    {
        (void)libp2p_yamux_enable_keepalive(ctx->yctx, 15000);
        (void)libp2p_yamux_process_loop(ctx->yctx);
    }
    free(ctx);
    return NULL;
}

/* Single-thread executor helper: dial on_open wrapper */
typedef struct dial_on_open_task
{
    libp2p_on_stream_open_fn cb;
    libp2p_stream_t *s;
    void *ud;
    int err;
} dial_on_open_task_t;

static void cbexec_dial_on_open(void *ud)
{
    dial_on_open_task_t *t = (dial_on_open_task_t *)ud;
    if (t && t->cb)
        t->cb(t->s, t->ud, t->err);
    free(t);
}

static void schedule_dial_on_open(libp2p_host_t *host, libp2p_on_stream_open_fn cb, libp2p_stream_t *s, void *ud, int err)
{
    if (!host || !cb)
        return;
    dial_on_open_task_t *t = (dial_on_open_task_t *)calloc(1, sizeof(*t));
    if (!t)
        return;
    t->cb = cb;
    t->s = s;
    t->ud = ud;
    t->err = err;
    libp2p__exec_on_cb_thread(host, cbexec_dial_on_open, t);
}

static size_t count_outbound_conns(libp2p_host_t *host)
{
    size_t c = 0;
    if (!host)
        return 0;
    pthread_mutex_lock(&host->mtx);
    for (stream_entry_t *it = host->active_streams; it; it = it->next)
    {
        if (it->initiator)
            c++;
    }
    pthread_mutex_unlock(&host->mtx);
    return c;
}

/* === Auto-Identify (request on new connections) === */
typedef struct auto_identify_ctx
{
    libp2p_host_t *host;
    libp2p_yamux_ctx_t *yctx;
    peer_id_t peer; /* owned copy */
} auto_identify_ctx_t;

/* Simple LP receive directly on a conn (configurable stall timeout). */
static ssize_t lp_recv_conn(libp2p_conn_t *c, uint8_t *buf, size_t max_len, uint64_t stall_timeout_ms)
{
    if (!c || !buf)
        return LIBP2P_ERR_NULL_PTR;
    const uint64_t slow_ms = (stall_timeout_ms > 0) ? stall_timeout_ms : 2000;
    uint8_t hdr[10];
    size_t used = 0;
    uint64_t need = 0;
    size_t consumed = 0;
    uint64_t start = now_mono_ms();
    while (used < sizeof(hdr))
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (used > 0 && remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        if (remain)
            libp2p_conn_set_deadline(c, remain);
        ssize_t n = libp2p_conn_read(c, &hdr[used], 1);
        if (n == 1)
        {
            used++;
            start = now_mono_ms();
            if (unsigned_varint_decode(hdr, used, &need, &consumed) == UNSIGNED_VARINT_OK)
                break;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            if (used == 0)
                return LIBP2P_ERR_AGAIN;
            continue;
        }
        return (ssize_t)n;
    }
    if (used == sizeof(hdr) && unsigned_varint_decode(hdr, used, &need, &consumed) != UNSIGNED_VARINT_OK)
        return LIBP2P_ERR_INTERNAL;
    if (need > max_len)
    {
        size_t to_discard = (size_t)need;
        uint8_t tmp[4096];
        start = now_mono_ms();
        while (to_discard > 0)
        {
            uint64_t elapsed = now_mono_ms() - start;
            uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
            if (remain == 0)
                return LIBP2P_ERR_TIMEOUT;
            libp2p_conn_set_deadline(c, remain);
            size_t want = to_discard > sizeof(tmp) ? sizeof(tmp) : to_discard;
            ssize_t n = libp2p_conn_read(c, tmp, want);
            if (n > 0)
            {
                to_discard -= (size_t)n;
                start = now_mono_ms();
                continue;
            }
            if (n == LIBP2P_CONN_ERR_AGAIN)
            {
                continue;
            }
            return (ssize_t)n;
        }
        return LIBP2P_ERR_MSG_TOO_LARGE;
    }
    size_t got = 0;
    start = now_mono_ms();
    while (got < need)
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        libp2p_conn_set_deadline(c, remain);
        ssize_t n = libp2p_conn_read(c, buf + got, (size_t)need - got);
        if (n > 0)
        {
            got += (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            continue;
        }
        return (ssize_t)n;
    }
    return (ssize_t)got;
}

/* Run a one-shot Identify request on a new session (synchronous). */
static void auto_identify_run(libp2p_host_t *host, libp2p_yamux_ctx_t *yctx, const peer_id_t *peer)
{
    if (!host || !yctx || !peer)
        return;
    uint32_t sid = 0;
    if (libp2p_yamux_stream_open(yctx, &sid) != LIBP2P_YAMUX_OK)
        return;
    libp2p_io_t *io = libp2p_io_from_yamux(yctx, sid);
    if (!io)
    {
        (void)libp2p_yamux_stream_close(yctx, sid);
        return;
    }

    const char *accepted = NULL;
    const char *prop[2] = {LIBP2P_IDENTIFY_PROTO_ID, NULL};
    uint8_t *buf = NULL;

    libp2p_multiselect_err_t ms = libp2p_multiselect_dial_io(io, prop, host->opts.multiselect_handshake_timeout_ms, &accepted);
    if (ms != LIBP2P_MULTISELECT_OK)
        goto cleanup;

    buf = (uint8_t *)malloc(64 * 1024);
    if (!buf)
        goto cleanup;

    ssize_t n = libp2p_lp_recv_io_timeout(io, buf, 64 * 1024,
                                          (host->opts.handshake_timeout_ms > 0) ? (uint64_t)host->opts.handshake_timeout_ms : 0);
    if (n > 0)
    {
        libp2p_identify_t *id = NULL;
        if (libp2p_identify_message_decode(buf, (size_t)n, &id) == 0 && id)
        {
            if (host->peerstore)
            {
                if (id->public_key && id->public_key_len)
                    (void)libp2p_peerstore_set_public_key(host->peerstore, peer, id->public_key, id->public_key_len);
                if (id->num_protocols && id->protocols)
                {
                    if (libp2p_peerstore_set_protocols(host->peerstore, peer, (const char *const *)id->protocols, id->num_protocols) == 0)
                        libp2p__notify_peer_protocols_updated(host, peer, (const char *const *)id->protocols, id->num_protocols);
                }
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
                        (void)libp2p_peerstore_add_addr(host->peerstore, peer, ma, 10 * 60 * 1000);
                        multiaddr_free(ma);
                    }
                }
            }
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
                        libp2p_event_t evt = {0};
                        evt.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE;
                        evt.u.new_external_addr_candidate.addr = ostr;
                        libp2p_event_publish(host, &evt);
                        free(ostr);
                    }
                    multiaddr_free(oma);
                }
            }
            libp2p_identify_free(id);
        }
    }

cleanup:
    if (buf)
        free(buf);
    if (accepted)
        free((void *)accepted);
    libp2p_io_close_free(io);
}

static int peer_id_clone_simple(const peer_id_t *in, peer_id_t *out)
{
    if (!in || !in->bytes || in->size == 0 || !out)
        return -1;
    out->bytes = (uint8_t *)malloc(in->size);
    if (!out->bytes)
        return -1;
    memcpy(out->bytes, in->bytes, in->size);
    out->size = in->size;
    return 0;
}

static void *auto_identify_thread(void *arg)
{
    auto_identify_ctx_t *ctx = (auto_identify_ctx_t *)arg;
    if (!ctx)
        return NULL;
    libp2p_host_t *host = ctx->host;
    libp2p_yamux_ctx_t *yctx = ctx->yctx;
    auto_identify_run(host, yctx, &ctx->peer);
    if (ctx->peer.bytes)
        peer_id_destroy(&ctx->peer);
    free(ctx);
    return NULL;
}

typedef struct ls_ctx
{
    const char **ids;
    size_t n;
    int done;
    int err;
} ls_ctx_t;

static void host_collect_ls_cb(const char *const *ids, size_t n, int err, void *ud)
{
    ls_ctx_t *c = (ls_ctx_t *)ud;
    c->err = err;
    c->done = 1;
    c->n = n;
    c->ids = NULL;
    if (err != 0 || !ids || n == 0)
        return;
    const char **arr = (const char **)calloc(n, sizeof(*arr));
    if (!arr)
    {
        c->err = LIBP2P_ERR_INTERNAL;
        return;
    }
    for (size_t i = 0; i < n; i++)
        arr[i] = ids[i] ? strdup(ids[i]) : NULL;
    c->ids = arr;
}

/* multiselect mapping provided by libp2p_error_from_multiselect() */

static bool addr_is_quic(const multiaddr_t *addr)
{
    if (!addr)
        return false;
    size_t n = multiaddr_nprotocols(addr);
    if (n < 3)
        return false;
    size_t idx = 1;
    uint64_t code = 0;
    if (multiaddr_get_protocol_code(addr, idx, &code) != 0)
        return false;
    if (code == MULTICODEC_IP6ZONE)
    {
        idx++;
        if (idx >= n || multiaddr_get_protocol_code(addr, idx, &code) != 0)
            return false;
    }
    if (code != MULTICODEC_UDP)
        return false;
    if (idx + 1 >= n)
        return false;
    uint64_t next = 0;
    if (multiaddr_get_protocol_code(addr, idx + 1, &next) != 0)
        return false;
    return (next == MULTICODEC_QUIC_V1 || next == MULTICODEC_QUIC);
}

static int do_dial_and_select(libp2p_host_t *host, const char *remote_multiaddr, const char *const proposals[], int dial_timeout_ms,
                              const char **accepted_out, libp2p_stream_t **out_stream, const libp2p_cancel_token_t *cancel)
{
    if (!host || !remote_multiaddr || !proposals || !out_stream)
        return LIBP2P_ERR_NULL_PTR;

    if (cancel && libp2p_cancel_token_is_canceled(cancel))
        return LIBP2P_ERR_CANCELED;

    /* Enforce outbound connection limits (hard cap and optional conn manager) */
    {
        int reject = 0;
        if (host->opts.max_outbound_conns > 0)
        {
            if (count_outbound_conns(host) >= (size_t)host->opts.max_outbound_conns)
                reject = 1;
        }
        if (!reject && host->conn_mgr)
        {
            int lw = 0, hw = 0;
            if (libp2p_conn_mgr_get_params(host->conn_mgr, &lw, &hw, NULL) == 0 && hw > 0)
            {
                if ((int)count_outbound_conns(host) >= hw)
                    reject = 1;
            }
        }
        if (reject)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_AGAIN;
            evt.u.outgoing_conn_error.msg = "too many outbound connections";
            libp2p_event_publish(host, &evt);
            return LIBP2P_ERR_AGAIN;
        }
    }

    /* Emit DIALING event before attempting to connect */
    libp2p__emit_dialing(host, remote_multiaddr);

    int ma_err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(remote_multiaddr, &ma_err);
    if (!addr)
    {
        /* Invalid multiaddr string */
        libp2p__emit_outgoing_error(host, LIBP2P_ERR_UNSUPPORTED, "invalid multiaddr");
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (host->gater_fn)
    {
        libp2p_gater_decision_t gd = host->gater_fn(remote_multiaddr, NULL, host->gater_ud);
        if (gd == LIBP2P_GATER_DECISION_REJECT)
        {
            multiaddr_free(addr);
            /* Emit outgoing connection error for gater rejection */
            libp2p__emit_outgoing_error(host, LIBP2P_ERR_UNSUPPORTED, "connection gated/rejected");
            return LIBP2P_ERR_UNSUPPORTED;
        }
    }

    libp2p_conn_t *raw = NULL;
    int is_quic = addr_is_quic(addr) ? 1 : 0;
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        multiaddr_free(addr);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_transport_t *t = libp2p__host_select_transport(host, addr);
    libp2p_transport_err_t d_rc = t ? libp2p_transport_dial(t, addr, &raw) : LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    if (d_rc != LIBP2P_TRANSPORT_OK || !raw)
    {
        multiaddr_free(addr);
        /* Emit outgoing connection error */
        libp2p__emit_outgoing_error(host, libp2p_error_from_transport(d_rc), "transport dial failed");
        return libp2p_error_from_transport(d_rc);
    }
    multiaddr_free(addr);

    /* QUIC: bypass upgrader; stream support comes in Phase 2. */
    if (is_quic)
    {
        libp2p_uconn_t *uc_q = NULL;
        int qrc = libp2p__host_upgrade_outbound_quic(host, raw, &uc_q);
        if (qrc != 0 || !uc_q)
            return qrc ? qrc : LIBP2P_ERR_INTERNAL;

        libp2p_conn_t *secured = uc_q->conn;
        peer_id_t *remote_peer = uc_q->remote_peer;
        libp2p_muxer_t *mx = (libp2p_muxer_t *)uc_q->muxer;
        libp2p_stream_t *dial_stream = NULL;
        libp2p_io_t *subio = NULL;
        const char *accepted = NULL;
        int take_ownership = 1;
        int rc = 0;

        if (cancel && libp2p_cancel_token_is_canceled(cancel))
        {
            rc = LIBP2P_ERR_CANCELED;
            goto quic_fail;
        }

        if (!mx || !mx->vt || !mx->vt->open_stream)
        {
            rc = LIBP2P_ERR_INTERNAL;
            goto quic_fail;
        }

        if (mx->vt->open_stream(mx, NULL, 0, &dial_stream) != LIBP2P_MUXER_OK || !dial_stream)
        {
            rc = LIBP2P_ERR_INTERNAL;
            goto quic_fail;
        }

        if (cancel && libp2p_cancel_token_is_canceled(cancel))
        {
            rc = LIBP2P_ERR_CANCELED;
            goto quic_fail;
        }

        subio = libp2p_io_from_stream(dial_stream);
        if (!subio)
        {
            rc = LIBP2P_ERR_INTERNAL;
            goto quic_fail;
        }

        if (cancel && libp2p_cancel_token_is_canceled(cancel))
        {
            rc = LIBP2P_ERR_CANCELED;
            goto quic_fail;
        }

        libp2p_multiselect_err_t ms = libp2p_multiselect_dial_io(subio, proposals, host->opts.multiselect_handshake_timeout_ms, &accepted);
        if (ms != LIBP2P_MULTISELECT_OK)
        {
            rc = libp2p_error_from_multiselect(ms);
            {
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
                evt.u.outgoing_conn_error.peer = NULL;
                evt.u.outgoing_conn_error.code = rc;
                evt.u.outgoing_conn_error.msg = "multistream negotiation failed";
                libp2p_event_publish(host, &evt);
            }
            goto quic_fail;
        }

        libp2p_io_free(subio);
        subio = NULL;

        if (accepted)
        {
            const char *dup = strdup(accepted);
            free((void *)accepted);
            accepted = dup;
            if (!accepted)
            {
                rc = LIBP2P_ERR_INTERNAL;
                goto quic_fail;
            }
            if (libp2p_stream_set_protocol_id(dial_stream, accepted) != 0)
            {
                rc = LIBP2P_ERR_INTERNAL;
                goto quic_fail;
            }
        }

        if (remote_peer)
        {
            if (libp2p_stream_set_remote_peer(dial_stream, remote_peer) != 0)
            {
                remote_peer = NULL;
                rc = LIBP2P_ERR_INTERNAL;
                goto quic_fail;
            }
            remote_peer = NULL;
        }

        if (accepted && strcmp(accepted, LIBP2P_IDENTIFY_PUSH_PROTO_ID) == 0)
            take_ownership = 0;

        libp2p_stream_set_parent(dial_stream, secured, mx, take_ownership);
        free(uc_q);

        *out_stream = dial_stream;
        (void)dial_timeout_ms;
        if (accepted_out)
            *accepted_out = accepted;
        libp2p__emit_protocol_negotiated(host, accepted);
        libp2p__emit_stream_opened(host, libp2p_stream_protocol_id(dial_stream), libp2p_stream_remote_peer(dial_stream), true);
        libp2p__emit_conn_opened(host, false, libp2p_stream_remote_peer(dial_stream), libp2p_stream_remote_addr(dial_stream));
        if (!accepted_out && accepted)
            free((void *)accepted);
        return 0;

    quic_fail:
        if (subio)
            libp2p_io_close_free(subio);
        if (dial_stream)
            libp2p_stream_reset(dial_stream);
        if (remote_peer)
        {
            peer_id_destroy(remote_peer);
            free(remote_peer);
        }
        if (mx)
            libp2p_muxer_free(mx);
        if (secured)
            libp2p_conn_free(secured);
        free(uc_q);
        if (accepted && !accepted_out)
            free((void *)accepted);
        return rc ? rc : LIBP2P_ERR_INTERNAL;
    }

    /* Upgrade raw connection using shared helper (Noise + muxer). */
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_conn_free(raw);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_uconn_t *uc = NULL;
    int uprc = libp2p__host_upgrade_outbound(host, raw, NULL, /*allow_mplex=*/1, &uc);
    if (uprc != 0 || !uc)
        return uprc ? uprc : LIBP2P_ERR_INTERNAL;
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        if (uc && uc->conn)
            libp2p_conn_free(uc->conn);
        if (uc && uc->remote_peer)
            peer_id_destroy(uc->remote_peer);
        if (uc)
            free(uc);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_conn_t *secured = uc->conn;
    peer_id_t *remote_peer = uc->remote_peer;
    libp2p_muxer_t *mx = (libp2p_muxer_t *)uc->muxer;
    /* Open a true substream and perform multistream-select on it */
    libp2p_yamux_ctx_t *yctx = (mx && mx->vt && mx->vt->open_stream) ? (libp2p_yamux_ctx_t *)mx->ctx : NULL;
    libp2p_mplex_stream_t *mps = NULL;
    uint32_t sid = 0;
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        free(uc);
        return LIBP2P_ERR_CANCELED;
    }
    if (yctx)
    {
        if (libp2p_yamux_stream_open(yctx, &sid) != LIBP2P_YAMUX_OK)
        {
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            free(uc);
            return LIBP2P_ERR_INTERNAL;
        }
    }
    else
    {
        /* Open mplex stream with empty name to avoid any implementation-specific
         * assumptions about stream naming. Protocol negotiation runs inside. */
        const uint8_t *name = NULL;
        size_t name_len = 0;
        if (libp2p_mplex_stream_open((libp2p_mplex_ctx_t *)mx->ctx, name, name_len, &mps) != LIBP2P_MPLEX_OK || !mps)
        {
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            free(uc);
            return LIBP2P_ERR_INTERNAL;
        }
        /* Ensure the mplex context is being driven by a background event loop
         * so that substream negotiations and subsequent protocol I/O can make
         * progress without polling. */
        (void)libp2p_mplex_start_event_loop_thread((libp2p_mplex_ctx_t *)mx->ctx);
    }
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        free(uc);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_io_t *subio = yctx ? libp2p_io_from_yamux(yctx, sid) : libp2p_io_from_mplex(mps);
    if (!subio)
    {
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        return LIBP2P_ERR_INTERNAL;
    }
    const char *accepted = NULL;
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_io_close_free(subio);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        free(uc);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_multiselect_err_t ms = libp2p_multiselect_dial_io(subio, proposals, host->opts.multiselect_handshake_timeout_ms, &accepted);
    if (ms != LIBP2P_MULTISELECT_OK)
    {
        libp2p_io_close_free(subio);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        free(uc);
        /* Emit protocol negotiation error */
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL; /* peer exists but stream not built yet */
        evt.u.outgoing_conn_error.code = libp2p_error_from_multiselect(ms);
        evt.u.outgoing_conn_error.msg = "multistream negotiation failed";
        libp2p_event_publish(host, &evt);
        return libp2p_error_from_multiselect(ms);
    }

    /* At this point, multistream-select succeeded and `accepted` is a heap string
       owned by us. Duplicate it so subsequent users (stream wrapper, events,
       and optional caller return via accepted_out) are decoupled from the
       original allocation source. */
    if (accepted)
    {
        const char *dup = strdup(accepted);
        free((void *)accepted);
        accepted = dup;
    }

    /* Resource manager removed: no admission gating for outbound streams */

    /* Kick off auto-identify synchronously (avoid lingering thread) unless dialing identify-push */
    if (yctx)
    {
        if (remote_peer && (host->opts.flags & LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND) &&
            !(accepted && strcmp(accepted, LIBP2P_IDENTIFY_PUSH_PROTO_ID) == 0))
        {
            auto_identify_run(host, (libp2p_yamux_ctx_t *)mx->ctx, remote_peer);
        }
    }
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_io_close_free(subio);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        free(uc);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_stream_t *ss = yctx ? libp2p_stream_from_yamux(host, yctx, sid, accepted, 1, remote_peer)
                               : libp2p_stream_from_mplex(host, (libp2p_mplex_ctx_t *)mx->ctx, mps, accepted, 1, remote_peer);
    if (!ss)
    {
        libp2p_io_close_free(subio);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "failed to wrap stream";
        libp2p_event_publish(host, &evt);
        return LIBP2P_ERR_INTERNAL;
    }
    /* For most single-stream dials, we own the parent session so closing the
       stream tears down the underlying connection/muxer. However, for
       Identify Push we avoid tearing down the parent immediately to ensure
       the remote peer can drain the push payload before the session goes
       away. */
    int take_ownership = 1;
    libp2p_stream_set_parent(ss, secured, mx, take_ownership);
    libp2p_io_free(subio);
    free(uc); /* parent now owns secured+mx; remote_peer moved into stream */
    *out_stream = ss;
    /* Accounting for outbound taken care of by resource manager admit above */
    (void)dial_timeout_ms;
    if (accepted_out)
        *accepted_out = accepted;
    /* Emit protocol negotiated, stream opened, and conn opened events */
    libp2p__emit_protocol_negotiated(host, accepted);
    libp2p__emit_stream_opened(host, libp2p_stream_protocol_id(ss), libp2p_stream_remote_peer(ss), true);
    libp2p__emit_conn_opened(host, false, libp2p_stream_remote_peer(ss), libp2p_stream_remote_addr(ss));
    /* If caller didn't request accepted_out, free our heap copy now */
    if (!accepted_out && accepted)
        free((void *)accepted);

    /* If this is a long‑lived outbound yamux session (e.g., Identify Push where
     * the parent is not torn down with the stream), start a lightweight
     * event‑driven loop to process frames so progress does not rely on
     * opportunistic pumping from stream reads. Register it in host->sessions
     * for coordinated shutdown. */
    if (yctx && take_ownership == 0)
    {
        session_node_t *snode = (session_node_t *)calloc(1, sizeof(*snode));
        if (snode)
        {
            pthread_mutex_init(&snode->ready_mtx, NULL);
            pthread_cond_init(&snode->ready_cv, NULL);
            /* Publish into host list so host_stop can stop/join. */
            pthread_mutex_lock(&host->mtx);
            snode->next = host->sessions;
            host->sessions = snode;
            pthread_mutex_unlock(&host->mtx);

            /* Stash owning references for teardown (parent not owned by stream). */
            snode->yctx = yctx;
            snode->mx = mx;
            snode->conn = secured;

            ob_loop_ctx_t *ctx = (ob_loop_ctx_t *)calloc(1, sizeof(*ctx));
            if (ctx)
            {
                ctx->yctx = yctx;
                pthread_t th;
                if (pthread_create(&th, NULL, outbound_yamux_loop, ctx) == 0)
                {
                    pthread_mutex_lock(&snode->ready_mtx);
                    snode->thread = th;
                    pthread_cond_broadcast(&snode->ready_cv);
                    pthread_mutex_unlock(&snode->ready_mtx);
                }
                else
                {
                    /* If thread creation fails, keep session usable via recv pumping. */
                    free(ctx);
                }
            }
        }
    }
    return 0;
}

static int do_dial_upgrade_only(libp2p_host_t *host, const char *remote_multiaddr, int dial_timeout_ms, libp2p_stream_t **out_stream,
                                const libp2p_cancel_token_t *cancel)
{
    if (!host || !remote_multiaddr || !out_stream)
        return LIBP2P_ERR_NULL_PTR;

    /* Enforce outbound connection limits (hard cap and optional conn manager) */
    {
        int reject = 0;
        if (host->opts.max_outbound_conns > 0)
        {
            if (count_outbound_conns(host) >= (size_t)host->opts.max_outbound_conns)
                reject = 1;
        }
        if (!reject && host->conn_mgr)
        {
            int lw = 0, hw = 0;
            if (libp2p_conn_mgr_get_params(host->conn_mgr, &lw, &hw, NULL) == 0 && hw > 0)
            {
                if ((int)count_outbound_conns(host) >= hw)
                    reject = 1;
            }
        }
        if (reject)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_AGAIN;
            evt.u.outgoing_conn_error.msg = "too many outbound connections";
            libp2p_event_publish(host, &evt);
            return LIBP2P_ERR_AGAIN;
        }
    }

    /* Emit DIALING event */
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
        return LIBP2P_ERR_CANCELED;
    libp2p__emit_dialing(host, remote_multiaddr);

    int ma_err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(remote_multiaddr, &ma_err);
    if (!addr)
    {
        libp2p__emit_outgoing_error(host, LIBP2P_ERR_UNSUPPORTED, "invalid multiaddr");
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (host->gater_fn)
    {
        libp2p_gater_decision_t gd = host->gater_fn(remote_multiaddr, NULL, host->gater_ud);
        if (gd == LIBP2P_GATER_DECISION_REJECT)
        {
            multiaddr_free(addr);
            libp2p__emit_outgoing_error(host, LIBP2P_ERR_UNSUPPORTED, "connection gated/rejected");
            return LIBP2P_ERR_UNSUPPORTED;
        }
    }

    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_conn_t *raw = NULL;
    int is_quic = addr_is_quic(addr) ? 1 : 0;
    libp2p_transport_t *t = libp2p__host_select_transport(host, addr);
    libp2p_transport_err_t d_rc = t ? libp2p_transport_dial(t, addr, &raw) : LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    if (d_rc != LIBP2P_TRANSPORT_OK || !raw)
    {
        multiaddr_free(addr);
        libp2p__emit_outgoing_error(host, libp2p_error_from_transport(d_rc), "transport dial failed");
        return libp2p_error_from_transport(d_rc);
    }
    multiaddr_free(addr);

    if (is_quic)
    {
        libp2p_uconn_t *uc_q = NULL;
        int qrc = libp2p__host_upgrade_outbound_quic(host, raw, &uc_q);
        if (qrc != 0 || !uc_q)
            return qrc ? qrc : LIBP2P_ERR_INTERNAL;

        libp2p_conn_t *secured = uc_q->conn;
        peer_id_t *remote_peer = uc_q->remote_peer;
        libp2p_muxer_t *mx = (libp2p_muxer_t *)uc_q->muxer;
        uc_q->conn = NULL;
        uc_q->remote_peer = NULL;
        uc_q->muxer = NULL;
        free(uc_q);

        if (!mx)
        {
            if (remote_peer)
                peer_id_destroy(remote_peer);
            if (secured)
                libp2p_conn_free(secured);
            libp2p__emit_outgoing_error(host, LIBP2P_ERR_INTERNAL, "quic muxer unavailable");
            return LIBP2P_ERR_INTERNAL;
        }

        if (cancel && libp2p_cancel_token_is_canceled(cancel))
        {
            libp2p_muxer_free(mx);
            if (secured)
                libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            return LIBP2P_ERR_CANCELED;
        }

        libp2p_stream_t *ss = libp2p_stream_from_conn(host, secured, NULL, 1, remote_peer);
        if (!ss)
        {
            libp2p_muxer_free(mx);
            if (secured)
                libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "failed to wrap stream";
            libp2p_event_publish(host, &evt);
            return LIBP2P_ERR_INTERNAL;
        }

        libp2p_stream_set_parent(ss, secured, mx, 1);
        libp2p__emit_conn_opened(host, false, libp2p_stream_remote_peer(ss), libp2p_stream_remote_addr(ss));
        (void)dial_timeout_ms;
        *out_stream = ss;
        return 0;
    }

    /* Upgrade using shared helper */
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_conn_free(raw);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_uconn_t *uc2 = NULL;
    int uprc2 = libp2p__host_upgrade_outbound(host, raw, NULL, /*allow_mplex=*/0, &uc2);
    if (uprc2 != 0 || !uc2)
        return uprc2 ? uprc2 : LIBP2P_ERR_INTERNAL;
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        if (uc2 && uc2->conn)
            libp2p_conn_free(uc2->conn);
        if (uc2 && uc2->remote_peer)
            peer_id_destroy(uc2->remote_peer);
        if (uc2)
            free(uc2);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_conn_t *secured = uc2->conn;
    peer_id_t *remote_peer = uc2->remote_peer;
    libp2p_muxer_t *mx2 = (libp2p_muxer_t *)uc2->muxer;

    extern libp2p_stream_t *libp2p_stream_from_conn(libp2p_host_t * host, libp2p_conn_t * c, const char *protocol_id, int initiator,
                                                    peer_id_t *remote_peer);
    if (cancel && libp2p_cancel_token_is_canceled(cancel))
    {
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        free(uc2);
        return LIBP2P_ERR_CANCELED;
    }
    libp2p_stream_t *ss = libp2p_stream_from_conn(host, secured, NULL, 1, remote_peer);
    if (!ss)
    {
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "failed to wrap stream";
        libp2p_event_publish(host, &evt);
        return LIBP2P_ERR_INTERNAL;
    }
    /* Auto-identify synchronously to avoid lingering background threads */
    if (remote_peer && (host->opts.flags & LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND))
    {
        auto_identify_run(host, (libp2p_yamux_ctx_t *)mx2->ctx, remote_peer);
    }
    (void)dial_timeout_ms;
    *out_stream = ss;
    return 0;
}

int libp2p_host_dial_protocol_blocking(libp2p_host_t *host, const char *remote_multiaddr, const char *protocol_id, int timeout_ms,
                                       libp2p_stream_t **out)
{
    if (!host || !remote_multiaddr || !protocol_id || !out)
        return LIBP2P_ERR_NULL_PTR;
    const char *proposals[2] = {protocol_id, NULL};
    const char *accepted = NULL;
    libp2p_stream_t *s = NULL;
    int rc = do_dial_and_select(host, remote_multiaddr, proposals, timeout_ms, &accepted, &s, NULL);
    if (accepted)
        free((void *)accepted);
    if (rc)
        return rc;
    *out = s;
    return 0;
}

int libp2p_host_dial_protocol(libp2p_host_t *host, const char *remote_multiaddr, const char *protocol_id, libp2p_on_stream_open_fn on_open,
                              void *user_data)
{
    libp2p_stream_t *s = NULL;
    int rc = libp2p_host_dial_protocol_blocking(host, remote_multiaddr, protocol_id, host->opts.dial_timeout_ms, &s);
    if (on_open)
        schedule_dial_on_open(host, on_open, s, user_data, rc);
    return rc;
}

int libp2p_host_open_stream(libp2p_host_t *host, const peer_id_t *peer, const char *protocol_id, libp2p_on_stream_open_fn on_open, void *user_data)
{
    if (!host || !peer || !protocol_id)
    {
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, user_data, LIBP2P_ERR_NULL_PTR);
        return LIBP2P_ERR_NULL_PTR;
    }
    if (!host->peerstore)
    {
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, user_data, LIBP2P_ERR_INTERNAL);
        return LIBP2P_ERR_INTERNAL;
    }
    const multiaddr_t **addrs = NULL;
    size_t n = 0;
    if (libp2p_peerstore_get_addrs(host->peerstore, peer, &addrs, &n) != 0 || n == 0)
    {
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, user_data, LIBP2P_ERR_INTERNAL);
        return LIBP2P_ERR_INTERNAL;
    }
    libp2p_stream_t *s = NULL;
    int rc = LIBP2P_ERR_INTERNAL;
    /* Build EXACT selector for target protocol */
    libp2p_proto_selector_t sel = {
        .kind = LIBP2P_PROTO_SELECT_EXACT,
        .exact_id = protocol_id,
        .id_list = NULL,
        .id_list_len = 0,
        .prefix = NULL,
        .base_path = NULL,
        .semver_range = NULL,
    };
    for (size_t i = 0; i < n; i++)
    {
        int serr = 0;
        char *maddr = multiaddr_to_str(addrs[i], &serr);
        if (!maddr)
            continue;
        rc = libp2p_host_dial_selected_blocking(host, maddr, &sel, host->opts.dial_timeout_ms, &s);
        free(maddr);
        if (rc == 0 && s)
            break;
    }
    libp2p_peerstore_free_addrs(addrs, n);
    if (on_open)
        schedule_dial_on_open(host, on_open, s, user_data, rc);
    return rc;
}

typedef struct open_async_ctx
{
    libp2p_host_t *host;
    peer_id_t peer;    /* deep copy */
    char *protocol_id; /* heap string */
    libp2p_on_stream_open_fn cb;
    void *user_data;
} open_async_ctx_t;

static void *open_stream_async_thread(void *arg)
{
    open_async_ctx_t *ctx = (open_async_ctx_t *)arg;
    if (!ctx)
        return NULL;
    libp2p_host_t *host = ctx->host;
    const char *protocol_id = ctx->protocol_id;
    libp2p_on_stream_open_fn on_open = ctx->cb;
    void *ud = ctx->user_data;

    if (!host || !host->peerstore || !protocol_id || !on_open)
    {
        LP_LOGD("IDENTIFY_PUB", "[open_async] early fail: host=%p peerstore=%p proto=%s on_open=%p",
                (void *)host, host ? (void *)host->peerstore : NULL, protocol_id ? protocol_id : "(null)", (void *)on_open);
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, ud, LIBP2P_ERR_NULL_PTR);
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx->protocol_id);
        if (ctx->host)
            libp2p__worker_dec(ctx->host);
        free(ctx);
        return NULL;
    }

    const multiaddr_t **addrs = NULL;
    size_t n = 0;
    if (libp2p_peerstore_get_addrs(host->peerstore, &ctx->peer, &addrs, &n) != 0 || n == 0)
    {
        LP_LOGD("IDENTIFY_PUB", "[open_async] no peerstore addrs (n=%zu)", n);
        schedule_dial_on_open(host, on_open, NULL, ud, LIBP2P_ERR_INTERNAL);
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx->protocol_id);
        if (ctx->host)
            libp2p__worker_dec(ctx->host);
        free(ctx);
        return NULL;
    }

    libp2p_stream_t *s = NULL;
    int rc = LIBP2P_ERR_INTERNAL;

    /* Prefer reuse: if an active stream already exists for any address */
    LP_LOGD("IDENTIFY_PUB", "[open_async] have %zu addr(s) for peer dial", n);
    for (size_t i = 0; i < n; i++)
    {
        int serr = 0;
        char *maddr = multiaddr_to_str(addrs[i], &serr);
        if (!maddr)
            continue;
        LP_LOGD("IDENTIFY_PUB", "[open_async] try reuse %s", maddr);
        pthread_mutex_lock(&host->mtx);
        for (stream_entry_t *ent = host->active_streams; ent; ent = ent->next)
        {
            if (ent->remote_addr && ent->protocol_id && strcmp(ent->protocol_id, protocol_id) == 0 && strcmp(ent->remote_addr, maddr) == 0)
            {
                s = ent->s;
                rc = 0;
                break;
            }
        }
        pthread_mutex_unlock(&host->mtx);
        if (s)
        {
            free(maddr);
            schedule_dial_on_open(host, on_open, s, ud, rc);
            goto out_cleanup;
        }
        free(maddr);
    }

    /* No reuse path hit; dial using selector (blocking call inside this thread) */
    libp2p_proto_selector_t sel = {
        .kind = LIBP2P_PROTO_SELECT_EXACT,
        .exact_id = protocol_id,
        .id_list = NULL,
        .id_list_len = 0,
        .prefix = NULL,
        .base_path = NULL,
        .semver_range = NULL,
    };
    for (size_t i = 0; i < n; i++)
    {
        int serr = 0;
        char *maddr = multiaddr_to_str(addrs[i], &serr);
        if (!maddr)
            continue;
        LP_LOGD("IDENTIFY_PUB", "[open_async] dialing %s", maddr);
        s = NULL;
        rc = libp2p_host_dial_selected_blocking(host, maddr, &sel, host->opts.dial_timeout_ms, &s);
        free(maddr);
        if (rc == 0 && s)
            break;
    }
    schedule_dial_on_open(host, on_open, s, ud, rc);

out_cleanup:
    libp2p_peerstore_free_addrs(addrs, n);
    if (ctx->peer.bytes)
        peer_id_destroy(&ctx->peer);
    free(ctx->protocol_id);
    if (ctx->host)
        libp2p__worker_dec(ctx->host);
    free(ctx);
    return NULL;
}

int libp2p_host_open_stream_async(libp2p_host_t *host, const peer_id_t *peer, const char *protocol_id, libp2p_on_stream_open_fn on_open,
                                  void *user_data)
{
    if (!host || !peer || !protocol_id || !on_open)
        return LIBP2P_ERR_NULL_PTR;
    open_async_ctx_t *ctx = (open_async_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return LIBP2P_ERR_INTERNAL;
    ctx->host = host;
    if (peer->bytes && peer->size)
    {
        ctx->peer.bytes = (uint8_t *)malloc(peer->size);
        if (!ctx->peer.bytes)
        {
            free(ctx);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(ctx->peer.bytes, peer->bytes, peer->size);
        ctx->peer.size = peer->size;
    }
    ctx->protocol_id = strdup(protocol_id);
    if (!ctx->protocol_id)
    {
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx);
        return LIBP2P_ERR_INTERNAL;
    }
    ctx->cb = on_open;
    ctx->user_data = user_data;
    pthread_t th;
    libp2p__worker_inc(host);
    if (pthread_create(&th, NULL, open_stream_async_thread, ctx) != 0)
    {
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx->protocol_id);
        libp2p__worker_dec(host);
        free(ctx);
        return LIBP2P_ERR_INTERNAL;
    }
    pthread_detach(th);
    return 0;
}

int libp2p_host_dial_selected_blocking(libp2p_host_t *host, const char *remote_multiaddr, const libp2p_proto_selector_t *selector, int timeout_ms,
                                       libp2p_stream_t **out)
{
    if (!host || !remote_multiaddr || !selector || !out)
        return LIBP2P_ERR_NULL_PTR;
    const char **proposals = NULL;
    size_t proposals_len = 0;
    int is_dynamic = 0;
    int rc = build_proposals_from_selector(host, selector, &proposals, &proposals_len, &is_dynamic);
    if (rc)
        return rc;
    const char *accepted = NULL;
    libp2p_stream_t *s = NULL;
    rc = do_dial_and_select(host, remote_multiaddr, (const char *const *)proposals, timeout_ms, &accepted, &s, NULL);
    if (is_dynamic && proposals)
        free((void *)proposals);
    if (accepted)
        free((void *)accepted);
    if (rc)
        return rc;
    *out = s;
    return 0;
}

int libp2p_host_dial_selected(libp2p_host_t *host, const char *remote_multiaddr, const libp2p_proto_selector_t *selector,
                              const libp2p_proto_dial_opts_t *opts, libp2p_on_stream_open_fn on_open, void *user_data)
{
    if (!host || !remote_multiaddr || !selector)
    {
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, user_data, LIBP2P_ERR_NULL_PTR);
        return LIBP2P_ERR_NULL_PTR;
    }

    int timeout = host->opts.dial_timeout_ms;
    int prefer_ls = (opts && opts->prefer_ls_probe) ? 1 : 0;
    int max_attempts = (opts && opts->max_attempts > 0) ? opts->max_attempts : 0;
    int allow_reuse = (opts && opts->allow_reuse_existing_stream) ? 1 : 0;

    const char **proposals = NULL;
    size_t num = 0;
    int is_dynamic = 0;
    int rc = 0;
    libp2p_stream_t *s = NULL;

    /* Optionally reuse an existing negotiated stream that matches selector */
    if (allow_reuse)
    {
        pthread_mutex_lock(&host->mtx);
        for (stream_entry_t *it = host->active_streams; it; it = it->next)
        {
            if (!it->remote_addr || !it->protocol_id)
                continue;
            if (strcmp(it->remote_addr, remote_multiaddr) != 0)
                continue;
            int match = 0;
            switch (selector->kind)
            {
                case LIBP2P_PROTO_SELECT_EXACT:
                    match = (selector->exact_id && strcmp(selector->exact_id, it->protocol_id) == 0);
                    break;
                case LIBP2P_PROTO_SELECT_LIST:
                    if (selector->id_list && selector->id_list_len > 0)
                    {
                        for (size_t i = 0; i < selector->id_list_len; i++)
                        {
                            if (selector->id_list[i] && strcmp(selector->id_list[i], it->protocol_id) == 0)
                            {
                                match = 1;
                                break;
                            }
                        }
                    }
                    break;
                case LIBP2P_PROTO_SELECT_PREFIX:
                    if (selector->prefix)
                        match = (strncmp(it->protocol_id, selector->prefix, strlen(selector->prefix)) == 0);
                    break;
                case LIBP2P_PROTO_SELECT_SEMVER:
                    if (selector->base_path && selector->semver_range)
                    {
                        version_triplet_t vtmp = {0};
                        if (strncmp(it->protocol_id, selector->base_path, strlen(selector->base_path)) == 0 &&
                            extract_version_from_id(it->protocol_id, selector->base_path, &vtmp) == 0)
                        {
                            semver_range_t rng;
                            if (parse_semver_range(selector->semver_range, &rng) == 0)
                                match = semver_in_range(&vtmp, &rng);
                        }
                    }
                    break;
                default:
                    break;
            }
            if (match)
            {
                s = it->s;
                pthread_mutex_unlock(&host->mtx);
                if (on_open)
                    schedule_dial_on_open(host, on_open, s, user_data, 0);
                return 0;
            }
        }
        pthread_mutex_unlock(&host->mtx);
    }

    if (prefer_ls && host->opts.multiselect_enable_ls &&
        (selector->kind == LIBP2P_PROTO_SELECT_PREFIX || selector->kind == LIBP2P_PROTO_SELECT_SEMVER))
    {
        ls_ctx_t ctx = {0};
        (void)libp2p_protocol_ls(host, remote_multiaddr, host_collect_ls_cb, &ctx);
        if (ctx.done && ctx.err == 0 && ctx.ids && ctx.n > 0)
        {
            const char *accepted = NULL;
            int accepted_has_v = 0;
            version_triplet_t accepted_v = {0};
            semver_range_t rng = {0};
            int have_range = 0;
            if (selector->kind == LIBP2P_PROTO_SELECT_SEMVER && selector->semver_range)
                have_range = (parse_semver_range(selector->semver_range, &rng) == 0);
            for (size_t i = 0; i < ctx.n; i++)
            {
                const char *id = ctx.ids[i];
                if (!id)
                    continue;
                if (selector->kind == LIBP2P_PROTO_SELECT_PREFIX)
                {
                    if (!selector->prefix || strncmp(id, selector->prefix, strlen(selector->prefix)) != 0)
                        continue;
                    version_triplet_t vtmp = {0};
                    int has_v = (extract_version_from_id(id, selector->prefix, &vtmp) == 0);
                    if (!accepted)
                    {
                        accepted = id;
                        accepted_has_v = has_v;
                        accepted_v = vtmp;
                    }
                    else if (has_v && accepted_has_v)
                    {
                        if (vtmp.major > accepted_v.major || (vtmp.major == accepted_v.major && vtmp.minor > accepted_v.minor) ||
                            (vtmp.major == accepted_v.major && vtmp.minor == accepted_v.minor && vtmp.patch > accepted_v.patch))
                        {
                            accepted = id;
                            accepted_v = vtmp;
                        }
                    }
                    else if (has_v && !accepted_has_v)
                    {
                        accepted = id;
                        accepted_has_v = 1;
                        accepted_v = vtmp;
                    }
                    else if (!has_v && !accepted_has_v)
                    {
                        if (strcmp(id, accepted) > 0)
                            accepted = id;
                    }
                }
                else if (selector->kind == LIBP2P_PROTO_SELECT_SEMVER)
                {
                    if (!selector->base_path || !have_range)
                        continue;
                    if (strncmp(id, selector->base_path, strlen(selector->base_path)) != 0)
                        continue;
                    version_triplet_t vtmp = {0};
                    if (extract_version_from_id(id, selector->base_path, &vtmp) != 0)
                        continue;
                    if (!semver_in_range(&vtmp, &rng))
                        continue;
                    if (!accepted)
                    {
                        accepted = id;
                        accepted_has_v = 1;
                        accepted_v = vtmp;
                    }
                    else
                    {
                        if (vtmp.major > accepted_v.major || (vtmp.major == accepted_v.major && vtmp.minor > accepted_v.minor) ||
                            (vtmp.major == accepted_v.major && vtmp.minor == accepted_v.minor && vtmp.patch > accepted_v.patch))
                        {
                            accepted = id;
                            accepted_v = vtmp;
                        }
                    }
                }
            }
            if (accepted)
            {
                const char *arr[2] = {accepted, NULL};
                rc = do_dial_and_select(host, remote_multiaddr, arr, timeout, NULL, &s, NULL);
                for (size_t i = 0; i < ctx.n; i++)
                    free((void *)ctx.ids[i]);
                free((void *)ctx.ids);
                if (on_open)
                    schedule_dial_on_open(host, on_open, s, user_data, rc);
                return rc;
            }
            for (size_t i = 0; i < ctx.n; i++)
                free((void *)ctx.ids[i]);
            free((void *)ctx.ids);
        }
    }

    rc = build_proposals_from_selector(host, selector, &proposals, &num, &is_dynamic);
    if (rc)
    {
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, user_data, rc);
        return rc;
    }

    if (selector->kind == LIBP2P_PROTO_SELECT_LIST && max_attempts > 0 && (size_t)max_attempts < num)
    {
        num = (size_t)max_attempts;
        if (is_dynamic)
            proposals[num] = NULL;
    }

    rc = do_dial_and_select(host, remote_multiaddr, (const char *const *)proposals, timeout, NULL, &s, NULL);
    if (is_dynamic && proposals)
        free((void *)proposals);
    if (on_open)
        schedule_dial_on_open(host, on_open, s, user_data, rc);
    return rc;
}

int libp2p_host_dial_opts(libp2p_host_t *host, const libp2p_dial_opts_t *opts, libp2p_on_stream_open_fn on_open, void *user_data)
{
    if (!host || !opts || opts->struct_size == 0)
        return LIBP2P_ERR_NULL_PTR;
    int timeout = opts->timeout_ms > 0 ? opts->timeout_ms : host->opts.dial_timeout_ms;
    int rc = 0;
    libp2p_stream_t *s = NULL;
    if (opts->protocol_id && opts->protocol_id[0] != '\0')
    {
        libp2p_proto_selector_t sel = {
            .kind = LIBP2P_PROTO_SELECT_EXACT,
            .exact_id = opts->protocol_id,
            .id_list = NULL,
            .id_list_len = 0,
            .prefix = NULL,
            .base_path = NULL,
            .semver_range = NULL,
        };
        rc = libp2p_host_dial_selected_blocking(host, opts->remote_multiaddr, &sel, timeout, &s);
    }
    else
    {
        rc = do_dial_upgrade_only(host, opts->remote_multiaddr, timeout, &s, NULL);
    }
    if (on_open)
        schedule_dial_on_open(host, on_open, s, user_data, rc);
    return rc;
}

int libp2p_host_dial_opts_cancellable(libp2p_host_t *host, const libp2p_dial_opts_t *opts, struct libp2p_cancel_token *cancel,
                                      libp2p_on_stream_open_fn on_open, void *user_data)
{
    if (!host || !opts || opts->struct_size == 0)
        return LIBP2P_ERR_NULL_PTR;

    if (cancel && libp2p_cancel_token_is_canceled((const libp2p_cancel_token_t *)cancel))
    {
        if (on_open)
            schedule_dial_on_open(host, on_open, NULL, user_data, LIBP2P_ERR_CANCELED);
        return LIBP2P_ERR_CANCELED;
    }

    int timeout = opts->timeout_ms > 0 ? opts->timeout_ms : host->opts.dial_timeout_ms;
    int rc = 0;
    libp2p_stream_t *s = NULL;

    if (opts->protocol_id && opts->protocol_id[0] != '\0')
    {
        const char *proposals[2] = {opts->protocol_id, NULL};
        const char *accepted = NULL;
        rc = do_dial_and_select(host, opts->remote_multiaddr, proposals, timeout, &accepted, &s, (const libp2p_cancel_token_t *)cancel);
        if (accepted)
            free((void *)accepted);
    }
    else
    {
        rc = do_dial_upgrade_only(host, opts->remote_multiaddr, timeout, &s, (const libp2p_cancel_token_t *)cancel);
    }
    if (on_open)
        schedule_dial_on_open(host, on_open, s, user_data, rc);
    return rc;
}

int libp2p_protocol_ls(libp2p_host_t *host, const char *remote_multiaddr, libp2p_on_protocol_list_fn on_list, void *ud)
{
    if (!host || !remote_multiaddr || !on_list)
        return LIBP2P_ERR_NULL_PTR;
    if (!host->opts.multiselect_enable_ls)
    {
        on_list(NULL, 0, LIBP2P_ERR_UNSUPPORTED, ud);
        return LIBP2P_ERR_UNSUPPORTED;
    }
    /* Emit DIALING for ls probe */
    libp2p__emit_dialing(host, remote_multiaddr);
    int ma_err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(remote_multiaddr, &ma_err);
    if (!addr)
    {
        libp2p__emit_outgoing_error(host, LIBP2P_ERR_UNSUPPORTED, "invalid multiaddr");
        on_list(NULL, 0, LIBP2P_ERR_UNSUPPORTED, ud);
        return LIBP2P_ERR_UNSUPPORTED;
    }
    libp2p_conn_t *raw = NULL;
    libp2p_transport_t *t = libp2p__host_select_transport(host, addr);
    libp2p_transport_err_t d_rc = t ? libp2p_transport_dial(t, addr, &raw) : LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    if (d_rc != LIBP2P_TRANSPORT_OK || !raw)
    {
        multiaddr_free(addr);
        libp2p__emit_outgoing_error(host, libp2p_error_from_transport(d_rc), "transport dial failed");
        on_list(NULL, 0, libp2p_error_from_transport(d_rc), ud);
        return libp2p_error_from_transport(d_rc);
    }
    multiaddr_free(addr);
    /* Upgrade using shared helper */
    libp2p_uconn_t *uc3 = NULL;
    int uprc3 = libp2p__host_upgrade_outbound(host, raw, NULL, /*allow_mplex=*/0, &uc3);
    if (uprc3 != 0 || !uc3)
    {
        on_list(NULL, 0, uprc3 ? uprc3 : LIBP2P_ERR_INTERNAL, ud);
        return uprc3 ? uprc3 : LIBP2P_ERR_INTERNAL;
    }
    libp2p_conn_t *secured = uc3->conn;
    peer_id_t *remote_peer = uc3->remote_peer;
    free(uc3); /* we own secured and remote_peer now */
    const char *hdr = LIBP2P_MULTISELECT_PROTO_ID;
    uint8_t var[10];
    size_t vlen = 0;
    unsigned_varint_encode(strlen(hdr) + 1, var, sizeof(var), &vlen);
    size_t frame_len = vlen + strlen(hdr) + 1;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "multistream header alloc failed";
        libp2p_event_publish(host, &evt);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(frame, var, vlen);
    memcpy(frame + vlen, hdr, strlen(hdr));
    frame[vlen + strlen(hdr)] = '\n';
    if (libp2p_conn_write(secured, frame, frame_len) < 0)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "multistream header send failed";
        libp2p_event_publish(host, &evt);
        free(frame);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
        return LIBP2P_ERR_INTERNAL;
    }
    free(frame);
    char *msg = NULL;
    {
        uint8_t v[10];
        size_t used = 0;
        uint64_t plen = 0;
        size_t consumed = 0;
        while (used < sizeof(v))
        {
            ssize_t n = libp2p_conn_read(secured, &v[used], 1);
            if (n <= 0)
                break;
            used += 1;
            if (unsigned_varint_decode(v, used, &plen, &consumed) == UNSIGNED_VARINT_OK)
                break;
        }
        uint8_t *payload = (uint8_t *)malloc(plen);
        if (!payload)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "multistream header decode failed";
            libp2p_event_publish(host, &evt);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        size_t got = 0;
        while (got < plen)
        {
            ssize_t n = libp2p_conn_read(secured, payload + got, plen - got);
            if (n <= 0)
            {
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
                evt.u.outgoing_conn_error.peer = NULL;
                evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
                evt.u.outgoing_conn_error.msg = "multistream header read failed";
                libp2p_event_publish(host, &evt);
                free(payload);
                libp2p_conn_free(secured);
                if (remote_peer)
                    peer_id_destroy(remote_peer);
                on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
                return LIBP2P_ERR_INTERNAL;
            }
            got += (size_t)n;
        }
        if (plen == 0 || payload[plen - 1] != '\n')
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "multistream header decode failed";
            libp2p_event_publish(host, &evt);
            free(payload);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        payload[plen - 1] = '\0';
        msg = (char *)payload;
    }
    if (strcmp(msg, LIBP2P_MULTISELECT_PROTO_ID) != 0)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "multistream header mismatch";
        libp2p_event_publish(host, &evt);
        free(msg);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
        return LIBP2P_ERR_INTERNAL;
    }
    free(msg);
    const char *ls = LIBP2P_MULTISELECT_LS;
    uint8_t var2[10];
    size_t vlen2 = 0;
    unsigned_varint_encode(strlen(ls) + 1, var2, sizeof(var2), &vlen2);
    size_t frame_len2 = vlen2 + strlen(ls) + 1;
    uint8_t *frame2 = (uint8_t *)malloc(frame_len2);
    if (!frame2)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "ls request alloc failed";
        libp2p_event_publish(host, &evt);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(frame2, var2, vlen2);
    memcpy(frame2 + vlen2, ls, strlen(ls));
    frame2[vlen2 + strlen(ls)] = '\n';
    if (libp2p_conn_write(secured, frame2, frame_len2) < 0)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "ls request send failed";
        libp2p_event_publish(host, &evt);
        free(frame2);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
        return LIBP2P_ERR_INTERNAL;
    }
    free(frame2);
    uint8_t vbuf[10];
    size_t used = 0;
    uint64_t outer_len = 0;
    size_t consumed = 0;
    while (used < sizeof(vbuf))
    {
        ssize_t n = libp2p_conn_read(secured, &vbuf[used], 1);
        if (n <= 0)
            break;
        used++;
        if (unsigned_varint_decode(vbuf, used, &outer_len, &consumed) == UNSIGNED_VARINT_OK)
            break;
    }
    uint8_t *outer = outer_len ? (uint8_t *)malloc(outer_len) : NULL;
    if (!outer)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "ls response decode failed";
        libp2p_event_publish(host, &evt);
        libp2p_conn_free(secured);
        if (remote_peer)
            peer_id_destroy(remote_peer);
        on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
        return LIBP2P_ERR_INTERNAL;
    }
    size_t got = 0;
    while (got < outer_len)
    {
        ssize_t n = libp2p_conn_read(secured, outer + got, outer_len - got);
        if (n <= 0)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "ls response read failed";
            libp2p_event_publish(host, &evt);
            free(outer);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        got += (size_t)n;
    }
    const char **ids = NULL;
    size_t nids = 0, cap = 0;
    size_t off = 0;
    while (off < outer_len)
    {
        if (outer[off] == '\n')
        {
            off++;
            break;
        }
        uint64_t inner_len = 0;
        size_t vbytes = 0;
        if (unsigned_varint_decode(outer + off, outer_len - off, &inner_len, &vbytes) != UNSIGNED_VARINT_OK)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "ls response decode failed";
            libp2p_event_publish(host, &evt);
            free(outer);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        off += vbytes;
        if (inner_len == 0 || off + inner_len > outer_len)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "ls response decode failed";
            libp2p_event_publish(host, &evt);
            free(outer);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        if (outer[off + inner_len - 1] != '\n')
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "ls response decode failed";
            libp2p_event_publish(host, &evt);
            free(outer);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        size_t slen = inner_len - 1;
        char *s = (char *)malloc(slen + 1);
        if (!s)
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
            evt.u.outgoing_conn_error.peer = NULL;
            evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
            evt.u.outgoing_conn_error.msg = "ls response decode failed";
            libp2p_event_publish(host, &evt);
            free(outer);
            libp2p_conn_free(secured);
            if (remote_peer)
                peer_id_destroy(remote_peer);
            on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(s, outer + off, slen);
        s[slen] = '\0';
        off += inner_len;
        if (nids == cap)
        {
            size_t ncap = cap ? cap * 2 : 8;
            const char **tmp = (const char **)realloc((void *)ids, ncap * sizeof(*tmp));
            if (!tmp)
            {
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
                evt.u.outgoing_conn_error.peer = NULL;
                evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
                evt.u.outgoing_conn_error.msg = "ls response decode failed";
                libp2p_event_publish(host, &evt);
                free(s);
                free(outer);
                libp2p_conn_free(secured);
                if (remote_peer)
                    peer_id_destroy(remote_peer);
                on_list(NULL, 0, LIBP2P_ERR_INTERNAL, ud);
                return LIBP2P_ERR_INTERNAL;
            }
            ids = tmp;
            cap = ncap;
        }
        ids[nids++] = s;
    }
    free(outer);
    libp2p_conn_free(secured);
    if (remote_peer)
        peer_id_destroy(remote_peer);
    on_list(ids, nids, 0, ud);
    for (size_t i = 0; i < nids; i++)
        free((void *)ids[i]);
    free((void *)ids);
    return 0;
}
