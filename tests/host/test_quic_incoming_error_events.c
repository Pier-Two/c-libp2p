#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/muxer.h"
#include "protocol/quic/protocol_quic.h"

#include "src/host/host_internal.h"

struct libp2p_quic_session
{
    int closed;
    int freed;
};

static int stub_factory_called = 0;

static libp2p_muxer_t *stub_muxer_factory(libp2p_host_t *host,
                                          libp2p_quic_session_t *session,
                                          const multiaddr_t *local,
                                          const multiaddr_t *remote,
                                          libp2p_conn_t *conn)
{
    (void)host;
    (void)local;
    (void)remote;
    (void)session;
    (void)conn;
    stub_factory_called++;
    return NULL;
}

static void stub_session_close(libp2p_quic_session_t *session)
{
    if (session)
        session->closed = 1;
}

static void stub_session_free(libp2p_quic_session_t *session)
{
    if (session)
    {
        session->freed = 1;
    }
}

static int expect_incoming_error(libp2p_host_t *host,
                                 libp2p_err_t expected_code,
                                 const char *expected_substr,
                                 int timeout_ms)
{
    const int step_ms = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(host, step_ms, &evt);
        if (got == 1)
        {
            int ok = (evt.kind == LIBP2P_EVT_INCOMING_CONNECTION_ERROR) &&
                     (evt.u.incoming_conn_error.code == expected_code);
            if (ok && expected_substr && evt.u.incoming_conn_error.msg)
                ok = strstr(evt.u.incoming_conn_error.msg, expected_substr) != NULL;
            libp2p_event_free(&evt);
            if (ok)
                return 1;
        }
        waited += step_ms;
    }
    return 0;
}

int main(void)
{
    libp2p_host_options_t opts;
    if (libp2p_host_options_default(&opts) != 0)
        return 1;

    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&opts, &host) != 0 || !host)
        return 1;

    libp2p_quic_session_t *session = (libp2p_quic_session_t *)calloc(1, sizeof(*session));
    if (!session)
    {
        libp2p_host_free(host);
        return 1;
    }

    peer_id_t *conn_peer = (peer_id_t *)calloc(1, sizeof(*conn_peer));
    if (!conn_peer)
    {
        free(session);
        libp2p_host_free(host);
        return 1;
    }
    if (peer_id_create_from_string("12D3KooWSgVg7Ha9r8wB6L6scR8Db1wUwYUyJYEdpjXD2qH5A5X9", conn_peer) != PEER_ID_SUCCESS)
    {
        peer_id_destroy(conn_peer);
        free(conn_peer);
        free(session);
        libp2p_host_free(host);
        return 1;
    }

    libp2p__host_set_quic_muxer_factory(stub_muxer_factory);

    libp2p_conn_t *conn = libp2p_quic_conn_new(NULL, NULL, session,
                                               stub_session_close,
                                               stub_session_free,
                                               conn_peer);
    if (!conn)
    {
        libp2p__host_set_quic_muxer_factory(NULL);
        peer_id_destroy(conn_peer);
        free(conn_peer);
        free(session);
        libp2p_host_free(host);
        return 1;
    }

    libp2p_uconn_t *uc = NULL;
    int rc = libp2p__host_upgrade_inbound_quic(host, conn, &uc);

    libp2p__host_set_quic_muxer_factory(NULL);

    int ok = 1;
    ok &= (rc == LIBP2P_ERR_INTERNAL);
    ok &= (uc == NULL);
    ok &= (stub_factory_called == 1);
    ok &= expect_incoming_error(host, LIBP2P_ERR_INTERNAL, "quic muxer unavailable", 4000);
    ok &= (session->freed == 1);

    libp2p_host_free(host);
    free(session);
    return ok ? 0 : 1;
}
