#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/protocol.h"
#include "libp2p/events.h"

#define TEST_PROTO_ID "/test/1.0.0"

static void on_open_noop(libp2p_stream_t *s, void *ud, int err)
{
    (void)s; (void)ud; (void)err;
}

/* Helper: wait until we get a LISTEN_ADDR_ADDED and copy it */
static int capture_listen_addr(libp2p_host_t *h, char *out, size_t out_len)
{
    for (int i = 0; i < 50; i++)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, 100, &evt);
        if (got == 1)
        {
            if (evt.kind == LIBP2P_EVT_LISTEN_ADDR_ADDED && evt.u.listen_addr_added.addr)
            {
                snprintf(out, out_len, "%s", evt.u.listen_addr_added.addr);
                libp2p_event_free(&evt);
                return 1;
            }
            libp2p_event_free(&evt);
        }
    }
    return 0;
}

int main(void)
{
    /* Start a server with a simple protocol */
    libp2p_host_builder_t *srvb = libp2p_host_builder_new();
    if (!srvb) return 1;
    (void)libp2p_host_builder_listen_addr(srvb, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_transport(srvb, "tcp");
    (void)libp2p_host_builder_security(srvb, "noise");
    (void)libp2p_host_builder_muxer(srvb, "yamux");
    libp2p_host_t *srv = NULL;
    if (libp2p_host_builder_build(srvb, &srv) != 0 || !srv)
    { libp2p_host_builder_free(srvb); return 1; }
    libp2p_protocol_def_t def = {0};
    def.protocol_id = TEST_PROTO_ID;
    def.read_mode = LIBP2P_READ_PULL;
    def.on_open = (void(*)(libp2p_stream_t*,void*))on_open_noop;
    if (libp2p_register_protocol(srv, &def) != 0)
    { libp2p_host_free(srv); libp2p_host_builder_free(srvb); return 1; }
    if (libp2p_host_start(srv) != 0)
    { libp2p_host_free(srv); libp2p_host_builder_free(srvb); return 1; }
    char addr[256] = {0};
    if (!capture_listen_addr(srv, addr, sizeof(addr)))
    { libp2p_host_free(srv); libp2p_host_builder_free(srvb); return 1; }

    /* Build a client with max_outbound_conns=1 and attempt two dials */
    libp2p_host_builder_t *clib = libp2p_host_builder_new();
    if (!clib)
    { libp2p_host_free(srv); libp2p_host_builder_free(srvb); return 1; }
    (void)libp2p_host_builder_transport(clib, "tcp");
    (void)libp2p_host_builder_security(clib, "noise");
    (void)libp2p_host_builder_muxer(clib, "yamux");
    (void)libp2p_host_builder_max_conns(clib, 0, 1);
    libp2p_host_t *cli = NULL;
    if (libp2p_host_builder_build(clib, &cli) != 0 || !cli)
    { libp2p_host_free(srv); libp2p_host_builder_free(srvb); libp2p_host_builder_free(clib); return 1; }

    /* First dial should succeed */
    libp2p_stream_t *s1 = NULL;
    if (libp2p_host_dial_protocol_blocking(cli, addr, TEST_PROTO_ID, 5000, &s1) != 0 || !s1)
    { libp2p_host_free(cli); libp2p_host_builder_free(clib); libp2p_host_free(srv); libp2p_host_builder_free(srvb); return 1; }

    /* Give a moment for registration (defensive) */
    usleep(1000 * 50);
    /* Second dial should be rejected locally due to limit */
    libp2p_stream_t *s2 = NULL;
    int rc2 = libp2p_host_dial_protocol_blocking(cli, addr, TEST_PROTO_ID, 1000, &s2);
    int ok = (rc2 != 0 && s2 == NULL);

    /* Cleanup */
    if (s1)
    {
        libp2p_stream_close(s1);
        libp2p_stream_free(s1);
    }
    libp2p_host_free(cli);
    libp2p_host_builder_free(clib);
    libp2p_host_stop(srv);
    libp2p_host_free(srv);
    libp2p_host_builder_free(srvb);
    return ok ? 0 : 1;
}
