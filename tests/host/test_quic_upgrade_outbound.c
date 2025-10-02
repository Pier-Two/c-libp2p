#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/host.h"
#include "peer_id/peer_id.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "libp2p/muxer.h"
#include "protocol/quic/protocol_quic.h"

#include "src/host/host_internal.h"

/* Provide a minimal definition so we can allocate a session handle for testing. */
struct libp2p_quic_session
{
    int dummy;
};

static int factory_called = 0;
static libp2p_host_t *factory_host = NULL;
static libp2p_quic_session_t *factory_session = NULL;
static const multiaddr_t *factory_local = NULL;
static const multiaddr_t *factory_remote = NULL;

static int stub_muxer_free_called = 0;

typedef struct stub_quic_muxer
{
    libp2p_muxer_t base;
} stub_quic_muxer_t;

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
    stub_muxer_free_called++;
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

static libp2p_muxer_t *test_muxer_factory(libp2p_host_t *host,
                                          libp2p_quic_session_t *session,
                                          const multiaddr_t *local,
                                          const multiaddr_t *remote,
                                          libp2p_conn_t *conn)
{
    factory_called++;
    factory_host = host;
    factory_session = session;
    factory_local = local;
    factory_remote = remote;
    (void)conn;

    stub_quic_muxer_t *stub = (stub_quic_muxer_t *)calloc(1, sizeof(*stub));
    if (!stub)
        return NULL;
    stub->base.vt = &STUB_MUXER_VTBL;
    stub->base.ctx = NULL;
    return &stub->base;
}

static int session_free_called = 0;

static void stub_session_close(libp2p_quic_session_t *session)
{
    (void)session;
}

static void stub_session_free(libp2p_quic_session_t *session)
{
    session_free_called++;
    free(session);
}

static int check(int cond, const char *msg)
{
    if (!cond)
        fprintf(stderr, "FAIL: %s\n", msg);
    return cond;
}

int main(void)
{
    int ok = 1;

    libp2p_host_options_t opts;
    if (libp2p_host_options_default(&opts) != 0)
        return 1;
    const char *transports[] = {"quic"};
    opts.transport_names = transports;
    opts.num_transport_names = 1;

    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&opts, &host) != 0 || !host)
        return 1;

    libp2p__host_set_quic_muxer_factory(test_muxer_factory);

    libp2p_quic_session_t *session = (libp2p_quic_session_t *)calloc(1, sizeof(*session));
    if (!session)
    {
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }

    int ma_err = 0;
    multiaddr_t *remote_addr = multiaddr_new_from_str("/ip4/127.0.0.1/udp/4242/quic", &ma_err);
    if (!remote_addr || ma_err != 0)
    {
        free(session);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }

    peer_id_t expected_peer = {0};
    if (peer_id_create_from_string("12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E", &expected_peer) != PEER_ID_SUCCESS)
    {
        multiaddr_free(remote_addr);
        free(session);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }

    peer_id_t *conn_peer = (peer_id_t *)calloc(1, sizeof(*conn_peer));
    if (!conn_peer)
    {
        peer_id_destroy(&expected_peer);
        multiaddr_free(remote_addr);
        free(session);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }
    if (peer_id_create_from_string("12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E", conn_peer) != PEER_ID_SUCCESS)
    {
        peer_id_destroy(&expected_peer);
        free(conn_peer);
        multiaddr_free(remote_addr);
        free(session);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }

    libp2p_conn_t *conn = libp2p_quic_conn_new(NULL, remote_addr, session, stub_session_close, stub_session_free, conn_peer);
    if (!conn)
    {
        peer_id_destroy(&expected_peer);
        multiaddr_free(remote_addr);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }

    libp2p_uconn_t *uc = NULL;
    int rc = libp2p__host_upgrade_outbound_quic(host, conn, &uc);
    ok &= check(rc == 0 && uc != NULL, "upgrade success");
    if (!ok || !uc)
    {
        libp2p_conn_free(conn);
        peer_id_destroy(&expected_peer);
        multiaddr_free(remote_addr);
        libp2p__host_set_quic_muxer_factory(NULL);
        libp2p_host_free(host);
        return 1;
    }

    ok &= check(factory_called == 1, "factory invoked once");
    ok &= check(factory_host == host, "factory received host");
    ok &= check(factory_session == session, "factory received session");

    ok &= check(uc->remote_peer != NULL, "uc remote peer non-null");
    ok &= check(uc->remote_peer != conn_peer, "remote peer cloned");
    if (uc->remote_peer)
        ok &= check(peer_id_equals(&expected_peer, uc->remote_peer) == 1, "remote peer matches input");

    ok &= check(uc->muxer != NULL, "muxer populated");

    char *factory_remote_str = NULL;
    if (factory_remote)
        factory_remote_str = multiaddr_to_str(factory_remote, NULL);
    ok &= check(factory_remote_str != NULL, "factory remote str");
    if (factory_remote_str)
    {
        ok &= check(strcmp(factory_remote_str, "/ip4/127.0.0.1/udp/4242/quic") == 0, "factory remote matches input");
        free(factory_remote_str);
    }

    ok &= check(stub_muxer_free_called == 0, "muxer not yet freed");

    libp2p_muxer_free((libp2p_muxer_t *)uc->muxer);
    ok &= check(stub_muxer_free_called == 1, "muxer free called once");

    if (uc->remote_peer)
    {
        peer_id_destroy(uc->remote_peer);
        free(uc->remote_peer);
        uc->remote_peer = NULL;
    }
    libp2p_conn_free(uc->conn);
    free(uc);

    ok &= check(session_free_called == 1, "session free called once");

    peer_id_destroy(&expected_peer);
    multiaddr_free(remote_addr);

    libp2p__host_set_quic_muxer_factory(NULL);
    libp2p_host_free(host);

    return ok ? 0 : 1;
}
