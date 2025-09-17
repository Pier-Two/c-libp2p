#include <stdio.h>
#include <string.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/events.h"
#include "libp2p/protocol_introspect.h"

typedef struct ls_cb_ctx
{
    int done;
    int err;
} ls_cb_ctx_t;

static void ls_cb(const char *const *ids, size_t n, int err, void *ud)
{
    (void)ids;
    (void)n;
    ls_cb_ctx_t *c = (ls_cb_ctx_t *)ud;
    if (c)
    {
        c->err = err;
        c->done = 1;
    }
}

static int wait_for_kind_and_capture(libp2p_host_t *h, libp2p_event_kind_t k, int timeout_ms, libp2p_event_t *out)
{
    const int step_ms = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step_ms, &evt);
        if (got == 1)
        {
            if (evt.kind == k)
            {
                if (out)
                    *out = evt; /* shallow move; caller must free */
                else
                    libp2p_event_free(&evt);
                return 1;
            }
            libp2p_event_free(&evt);
        }
        waited += step_ms;
    }
    return 0;
}

static int test_ls_invalid_multiaddr(void)
{
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    (void)libp2p_host_builder_muxer(b, "yamux");
    (void)libp2p_host_builder_multistream(b, 5000, true); /* enable ls */

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(b, &host) != 0 || !host)
    {
        libp2p_host_builder_free(b);
        return 1;
    }

    ls_cb_ctx_t ctx = {0};
    const char *bad_addr = "not-a-multiaddr";
    (void)libp2p_protocol_ls(host, bad_addr, ls_cb, &ctx);

    int saw_dialing = wait_for_kind_and_capture(host, LIBP2P_EVT_DIALING, 1000, NULL);
    libp2p_event_t err_evt = {0};
    int saw_err = wait_for_kind_and_capture(host, LIBP2P_EVT_OUTGOING_CONNECTION_ERROR, 1000, &err_evt);

    int ok = 1;
    if (!saw_dialing || !saw_err)
        ok = 0;
    else
    {
        /* Expect precise mapping and message */
        if (err_evt.u.outgoing_conn_error.code != LIBP2P_ERR_UNSUPPORTED)
            ok = 0;
        if (!err_evt.u.outgoing_conn_error.msg || strcmp(err_evt.u.outgoing_conn_error.msg, "invalid multiaddr") != 0)
            ok = 0;
    }
    libp2p_event_free(&err_evt);

    /* Callback should have been invoked with same error */
    if (!ctx.done || ctx.err != LIBP2P_ERR_UNSUPPORTED)
        ok = 0;

    libp2p_host_free(host);
    libp2p_host_builder_free(b);
    return ok ? 0 : 1;
}

static int test_ls_transport_dial_failure(void)
{
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    (void)libp2p_host_builder_muxer(b, "yamux");
    (void)libp2p_host_builder_multistream(b, 5000, true);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(b, &host) != 0 || !host)
    {
        libp2p_host_builder_free(b);
        return 1;
    }

    ls_cb_ctx_t ctx = {0};
    /* Localhost, very likely closed port to trigger connection refusal */
    const char *unreachable = "/ip4/127.0.0.1/tcp/1";
    (void)libp2p_protocol_ls(host, unreachable, ls_cb, &ctx);

    int saw_dialing = wait_for_kind_and_capture(host, LIBP2P_EVT_DIALING, 1500, NULL);
    libp2p_event_t err_evt = {0};
    int saw_err = wait_for_kind_and_capture(host, LIBP2P_EVT_OUTGOING_CONNECTION_ERROR, 3000, &err_evt);

    int ok = 1;
    if (!saw_dialing || !saw_err)
        ok = 0;
    else
    {
        /* Expect mapped code and precise message for transport failure */
        if (err_evt.u.outgoing_conn_error.code != LIBP2P_ERR_INTERNAL)
            ok = 0;
        if (!err_evt.u.outgoing_conn_error.msg || strcmp(err_evt.u.outgoing_conn_error.msg, "transport dial failed") != 0)
            ok = 0;
    }
    libp2p_event_free(&err_evt);

    if (!ctx.done || ctx.err != LIBP2P_ERR_INTERNAL)
        ok = 0;

    libp2p_host_free(host);
    libp2p_host_builder_free(b);
    return ok ? 0 : 1;
}

int main(void)
{
    int rc1 = test_ls_invalid_multiaddr();
    int rc2 = test_ls_transport_dial_failure();
    return (rc1 == 0 && rc2 == 0) ? 0 : 1;
}

