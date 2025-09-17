#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/protocol.h"
#include "libp2p/protocol_dial.h"
#include "libp2p/events.h"

#define TEST_PROTO_ID "/test/1.0.0"

static void on_open_cb(libp2p_stream_t *s, void *user_data)
{
    (void)s;
    (void)user_data;
}

static int wait_for_kinds(libp2p_host_t *h, const libp2p_event_kind_t *kinds, size_t nkinds, int timeout_ms)
{
    int seen[16] = {0};
    if (nkinds > 16) return 0;
    const int step_ms = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step_ms, &evt);
        if (got == 1)
        {
            fprintf(stderr, "[events] kind=%d\n", (int)evt.kind);
            for (size_t i = 0; i < nkinds; i++)
                if (evt.kind == kinds[i])
                    seen[i] = 1;
            libp2p_event_free(&evt);
        }
        int all = 1;
        for (size_t i = 0; i < nkinds; i++)
            if (!seen[i]) all = 0;
        if (all) return 1;
        waited += step_ms;
    }
    return 0;
}

int main(void)
{
    /* Build and start server host with ephemeral listen */
    libp2p_host_builder_t *srv_b = libp2p_host_builder_new();
    if (!srv_b) return 1;
    (void)libp2p_host_builder_listen_addr(srv_b, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_transport(srv_b, "tcp");
    (void)libp2p_host_builder_security(srv_b, "noise");
    (void)libp2p_host_builder_muxer(srv_b, "yamux");
    (void)libp2p_host_builder_multistream(srv_b, 5000, true);

    libp2p_host_t *srv = NULL;
    if (libp2p_host_builder_build(srv_b, &srv) != 0 || !srv)
    { libp2p_host_builder_free(srv_b); return 1; }

    libp2p_protocol_def_t def = {0};
    def.protocol_id = TEST_PROTO_ID;
    def.read_mode = LIBP2P_READ_PULL;
    def.on_open = on_open_cb;
    if (libp2p_register_protocol(srv, &def) != 0)
    { libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }

    if (libp2p_host_start(srv) != 0)
    { libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }

    /* Capture bound address from LISTEN_ADDR_ADDED */
    char bound_addr[256] = {0};
    {
        int got_addr = 0;
        for (int i = 0; i < 40 && !got_addr; i++)
        {
            libp2p_event_t evt = {0};
            int got = libp2p_host_next_event(srv, 100, &evt);
            if (got == 1)
            {
                if (evt.kind == LIBP2P_EVT_LISTEN_ADDR_ADDED && evt.u.listen_addr_added.addr)
                {
                    snprintf(bound_addr, sizeof(bound_addr), "%s", evt.u.listen_addr_added.addr);
                    got_addr = 1;
                }
                libp2p_event_free(&evt);
            }
        }
        if (!got_addr)
        { libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }
    }

    /* Build client host */
    libp2p_host_builder_t *cli_b = libp2p_host_builder_new();
    if (!cli_b)
    { libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }
    (void)libp2p_host_builder_transport(cli_b, "tcp");
    (void)libp2p_host_builder_security(cli_b, "noise");
    (void)libp2p_host_builder_muxer(cli_b, "yamux");
    (void)libp2p_host_builder_multistream(cli_b, 5000, true);
    libp2p_host_t *cli = NULL;
    if (libp2p_host_builder_build(cli_b, &cli) != 0 || !cli)
    { libp2p_host_free(srv); libp2p_host_builder_free(srv_b); libp2p_host_builder_free(cli_b); return 1; }

    /* Dial and expect client events */
    /* Use selector API to exercise do_dial_and_select (ensures success events emitted) */
    libp2p_proto_selector_t sel = {0};
    sel.kind = LIBP2P_PROTO_SELECT_EXACT;
    sel.exact_id = TEST_PROTO_ID;
    libp2p_stream_t *stream = NULL;
    if (libp2p_host_dial_selected_blocking(cli, bound_addr, &sel, 5000, &stream) != 0 || !stream)
    { libp2p_host_free(cli); libp2p_host_builder_free(cli_b); libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }

    const libp2p_event_kind_t need_cli[] = {
        LIBP2P_EVT_PROTOCOL_NEGOTIATED,
        LIBP2P_EVT_STREAM_OPENED,
        LIBP2P_EVT_CONN_OPENED
    };
    if (!wait_for_kinds(cli, need_cli, 3, 5000))
    { libp2p_stream_close(stream); libp2p_host_free(cli); libp2p_host_builder_free(cli_b); libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }

    const libp2p_event_kind_t need_srv[] = {
        LIBP2P_EVT_CONN_OPENED,
        LIBP2P_EVT_PROTOCOL_NEGOTIATED,
        LIBP2P_EVT_STREAM_OPENED
    };
    if (!wait_for_kinds(srv, need_srv, 3, 5000))
    { libp2p_stream_close(stream); libp2p_host_free(cli); libp2p_host_builder_free(cli_b); libp2p_host_free(srv); libp2p_host_builder_free(srv_b); return 1; }

    /* Close on client and ensure client sees stream/conn closed */
    libp2p_stream_close(stream);
    const libp2p_event_kind_t need_cli_close[] = {
        LIBP2P_EVT_STREAM_CLOSED,
        LIBP2P_EVT_CONN_CLOSED
    };
    int ok_close = wait_for_kinds(cli, need_cli_close, 2, 5000);

    libp2p_host_free(cli);
    libp2p_host_builder_free(cli_b);
    libp2p_host_stop(srv);
    libp2p_host_free(srv);
    libp2p_host_builder_free(srv_b);

    return ok_close ? 0 : 1;
}
