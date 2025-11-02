#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p/dial.h"
#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/muxer.h"
#include "libp2p/stream.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"
#include "protocol/quic/protocol_quic.h"

#include "src/host/host_internal.h"

struct stub_quic_transport_ctx;

/* Provide a minimal session definition so we can track lifetime hooks. */
struct libp2p_quic_session
{
    struct stub_quic_transport_ctx *owner;
    int closed;
    int freed;
};

typedef struct stub_quic_transport_ctx
{
    int dial_count;
    int session_closed;
    int session_freed;
} stub_quic_transport_ctx_t;

static void stub_session_close(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    session->closed = 1;
    if (session->owner)
        session->owner->session_closed = 1;
}

static void stub_session_free(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    session->freed = 1;
    if (session->owner)
        session->owner->session_freed = 1;
    free(session);
}

static bool stub_quic_can_handle(const multiaddr_t *addr)
{
    (void)addr;
    return true;
}

static libp2p_transport_err_t stub_quic_listen(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out)
{
    (void)self;
    (void)addr;
    (void)out;
    return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
}

static libp2p_transport_err_t stub_quic_close(libp2p_transport_t *self)
{
    (void)self;
    return LIBP2P_TRANSPORT_OK;
}

static void stub_quic_transport_free(libp2p_transport_t *self)
{
    if (!self)
        return;
    free(self->ctx);
    free(self);
}

static libp2p_transport_err_t stub_quic_dial(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out)
{
    if (!self || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_INTERNAL;

    stub_quic_transport_ctx_t *ctx = (stub_quic_transport_ctx_t *)self->ctx;
    if (!ctx)
        return LIBP2P_TRANSPORT_ERR_INTERNAL;

    libp2p_quic_session_t *session = (libp2p_quic_session_t *)calloc(1, sizeof(*session));
    if (!session)
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    session->owner = ctx;

    peer_id_t *peer = (peer_id_t *)calloc(1, sizeof(*peer));
    if (!peer)
    {
        free(session);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    if (peer_id_create_from_string("12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E", peer) != PEER_ID_SUCCESS)
    {
        peer_id_destroy(peer);
        free(peer);
        free(session);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p_conn_t *conn = libp2p_quic_conn_new(NULL, addr, session, stub_session_close, stub_session_free, peer);
    if (!conn)
    {
        peer_id_destroy(peer);
        free(peer);
        free(session);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    ctx->dial_count += 1;
    *out = conn;
    return LIBP2P_TRANSPORT_OK;
}

static const libp2p_transport_vtbl_t STUB_TRANSPORT_VTBL = {
    .can_handle = stub_quic_can_handle,
    .dial = stub_quic_dial,
    .listen = stub_quic_listen,
    .close = stub_quic_close,
    .free = stub_quic_transport_free,
};

typedef struct stub_muxer_ctx
{
    int free_called;
} stub_muxer_ctx_t;

static libp2p_muxer_err_t stub_muxer_negotiate(libp2p_muxer_t *mx, libp2p_conn_t *c, uint64_t timeout_ms, bool inbound)
{
    (void)mx;
    (void)c;
    (void)timeout_ms;
    (void)inbound;
    return LIBP2P_MUXER_OK;
}

static libp2p_muxer_err_t stub_muxer_open_stream(libp2p_muxer_t *mx, const uint8_t *name, size_t name_len, libp2p_stream_t **out)
{
    (void)mx;
    (void)name;
    (void)name_len;
    (void)out;
    return LIBP2P_MUXER_ERR_INTERNAL;
}

static ssize_t stub_muxer_stream_read(libp2p_stream_t *s, void *buf, size_t len)
{
    (void)s;
    (void)buf;
    (void)len;
    return LIBP2P_ERR_UNSUPPORTED;
}

static ssize_t stub_muxer_stream_write(libp2p_stream_t *s, const void *buf, size_t len)
{
    (void)s;
    (void)buf;
    (void)len;
    return LIBP2P_ERR_UNSUPPORTED;
}

static void stub_muxer_stream_close(libp2p_stream_t *s)
{
    (void)s;
}

static void stub_muxer_free(libp2p_muxer_t *mx)
{
    if (!mx)
        return;
    if (mx->ctx)
        free(mx->ctx);
    free(mx);
}

static const libp2p_muxer_vtbl_t STUB_MUXER_VTBL = {
    .negotiate = stub_muxer_negotiate,
    .open_stream = stub_muxer_open_stream,
    .stream_read = stub_muxer_stream_read,
    .stream_write = stub_muxer_stream_write,
    .stream_close = stub_muxer_stream_close,
    .free = stub_muxer_free,
};

static int muxer_factory_called = 0;
static libp2p_host_t *muxer_factory_host = NULL;
static libp2p_quic_session_t *muxer_factory_session = NULL;

static libp2p_muxer_t *stub_muxer_factory(libp2p_host_t *host,
                                          libp2p_quic_session_t *session,
                                          const multiaddr_t *local,
                                          const multiaddr_t *remote,
                                          libp2p_conn_t *conn)
{
    (void)local;
    (void)remote;
    (void)conn;
    muxer_factory_called += 1;
    muxer_factory_host = host;
    muxer_factory_session = session;

    libp2p_muxer_t *mx = (libp2p_muxer_t *)calloc(1, sizeof(*mx));
    if (!mx)
        return NULL;
    stub_muxer_ctx_t *ctx = (stub_muxer_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        free(mx);
        return NULL;
    }
    mx->vt = &STUB_MUXER_VTBL;
    mx->ctx = ctx;
    return mx;
}

typedef struct callback_state
{
    atomic_int called;
    int err;
    libp2p_stream_t *stream;
} callback_state_t;

static void on_open_cb(libp2p_stream_t *s, void *user_data, int err)
{
    callback_state_t *st = (callback_state_t *)user_data;
    st->err = err;
    st->stream = s;
    atomic_store(&st->called, 1);
}

static int wait_for_callback(callback_state_t *state)
{
    struct timespec ts = {0, 10000000}; /* 10ms */
    for (int i = 0; i < 200; i++)
    {
        if (atomic_load(&state->called))
            return 1;
        nanosleep(&ts, NULL);
    }
    return 0;
}

static int drain_conn_opened(libp2p_host_t *host)
{
    for (int i = 0; i < 50; i++)
    {
        libp2p_event_t evt = {0};
        if (libp2p_host_next_event(host, 100, &evt) == 1)
        {
            int ok = (evt.kind == LIBP2P_EVT_CONN_OPENED);
            libp2p_event_free(&evt);
            if (ok)
                return 1;
        }
    }
    return 0;
}

static int fail_msg(const char *msg)
{
    fprintf(stderr, "%s\n", msg ? msg : "test failure");
    return 1;
}

int main(void)
{
    libp2p_host_options_t opts;
    if (libp2p_host_options_default(&opts) != 0)
        return fail_msg("host options default failed");

    const char *transports[] = {"quic"};
    opts.transport_names = transports;
    opts.num_transport_names = 1;

    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&opts, &host) != 0 || !host)
        return fail_msg("libp2p_host_new failed");

    /* Replace transport list with stubbed QUIC transport */
    if (host->transports)
    {
        for (size_t i = 0; i < host->num_transports; i++)
            libp2p_transport_free(host->transports[i]);
        free(host->transports);
    }
    libp2p_transport_t *stub_transport = (libp2p_transport_t *)calloc(1, sizeof(*stub_transport));
    if (!stub_transport)
    {
        libp2p_host_free(host);
        return fail_msg("alloc stub transport failed");
    }
    stub_quic_transport_ctx_t *tctx = (stub_quic_transport_ctx_t *)calloc(1, sizeof(*tctx));
    if (!tctx)
    {
        free(stub_transport);
        libp2p_host_free(host);
        return fail_msg("alloc transport ctx failed");
    }
    stub_transport->vt = &STUB_TRANSPORT_VTBL;
    stub_transport->ctx = tctx;
    host->transports = (libp2p_transport_t **)calloc(1, sizeof(*host->transports));
    if (!host->transports)
    {
        stub_quic_transport_free(stub_transport);
        libp2p_host_free(host);
        return fail_msg("alloc transport array failed");
    }
    host->transports[0] = stub_transport;
    host->num_transports = 1;

    libp2p__host_set_quic_muxer_factory(stub_muxer_factory);

    const char *remote_addr = "/ip4/127.0.0.1/udp/4242/quic-v1";
    libp2p_dial_opts_t dial_opts = {0};
    dial_opts.struct_size = sizeof(dial_opts);
    dial_opts.remote_multiaddr = remote_addr;
    dial_opts.timeout_ms = 2000;

    callback_state_t cb_state = {0};
    atomic_store(&cb_state.called, 0);
    cb_state.err = -1;
    cb_state.stream = NULL;

    int rc = libp2p_host_dial_opts(host, &dial_opts, on_open_cb, &cb_state);
    if (rc != 0)
    {
        char buf[128];
        snprintf(buf, sizeof(buf), "libp2p_host_dial_opts returned error %d", rc);
        for (int i = 0; i < 5; i++)
        {
            libp2p_event_t evt = {0};
            if (libp2p_host_next_event(host, 100, &evt) != 1)
                break;
            if (evt.kind == LIBP2P_EVT_OUTGOING_CONNECTION_ERROR)
            {
                fprintf(stderr, "event kind=%d msg=%s code=%d\n", (int)evt.kind,
                        evt.u.outgoing_conn_error.msg ? evt.u.outgoing_conn_error.msg : "",
                        evt.u.outgoing_conn_error.code);
            }
            else
            {
                fprintf(stderr, "event kind=%d\n", (int)evt.kind);
            }
            libp2p_event_free(&evt);
        }
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg(buf);
    }
    if (!wait_for_callback(&cb_state))
    {
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("dial callback not invoked");
    }
    if (cb_state.err != 0 || !cb_state.stream)
    {
        if (cb_state.stream)
        {
            libp2p_stream_close(cb_state.stream);
            libp2p_stream_free(cb_state.stream);
        }
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("callback returned error");
    }

    const peer_id_t *rpeer = libp2p_stream_remote_peer(cb_state.stream);
    if (!rpeer)
    {
        libp2p_stream_close(cb_state.stream);
        libp2p_stream_free(cb_state.stream);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("remote peer missing");
    }
    peer_id_t expected_peer = {0};
    if (peer_id_create_from_string("12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E", &expected_peer) != PEER_ID_SUCCESS)
    {
        libp2p_stream_close(cb_state.stream);
        libp2p_stream_free(cb_state.stream);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("expected peer parse failed");
    }
    int same_peer = peer_id_equals(rpeer, &expected_peer);
    peer_id_destroy(&expected_peer);
    if (same_peer != 1)
    {
        libp2p_stream_close(cb_state.stream);
        libp2p_stream_free(cb_state.stream);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("unexpected remote peer");
    }

    const multiaddr_t *raddr = libp2p_stream_remote_addr(cb_state.stream);
    int ok_addr = 0;
    if (raddr)
    {
        int serr = 0;
        char *addr_str = multiaddr_to_str(raddr, &serr);
        if (addr_str && serr == 0 && strcmp(addr_str, remote_addr) == 0)
            ok_addr = 1;
        free(addr_str);
    }
    if (!ok_addr)
    {
        libp2p_stream_close(cb_state.stream);
        libp2p_stream_free(cb_state.stream);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("remote multiaddr mismatch");
    }

    if (!drain_conn_opened(host))
    {
        libp2p_stream_close(cb_state.stream);
        libp2p_stream_free(cb_state.stream);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("conn opened event not observed");
    }

    libp2p_stream_close(cb_state.stream);
    libp2p_stream_free(cb_state.stream);

    if (muxer_factory_called != 1 || muxer_factory_host != host || muxer_factory_session == NULL)
    {
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("muxer factory expectations failed");
    }

    if (tctx->dial_count != 1 || tctx->session_closed != 1 || tctx->session_freed != 1)
    {
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return fail_msg("transport expectations failed");
    }

    libp2p__host_set_quic_muxer_factory(NULL);
    libp2p_host_free(host);
    return 0;
}
