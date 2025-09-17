#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/events.h"

static int wait_for_event_kind(libp2p_host_t *h, libp2p_event_kind_t k, int timeout_ms)
{
    const int step_ms = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step_ms, &evt);
        if (got == 1)
        {
            int match = (evt.kind == k);
            libp2p_event_free(&evt);
            if (match)
                return 1;
        }
        waited += step_ms;
    }
    return 0;
}

int main(void)
{
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    (void)libp2p_host_builder_muxer(b, "yamux");
    (void)libp2p_host_builder_multistream(b, 5000, false);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(b, &host) != 0 || !host)
    {
        libp2p_host_builder_free(b);
        return 1;
    }

    /* Invalid multiaddr string to trigger parse error path */
    const char *bad_addr = "not-a-multiaddr";
    libp2p_stream_t *s = NULL;
    (void)s;
    (void)libp2p_host_dial_protocol_blocking(host, bad_addr, "/test/1.0.0", 1000, &s);

    int saw_dialing = wait_for_event_kind(host, LIBP2P_EVT_DIALING, 1000);
    int saw_error = wait_for_event_kind(host, LIBP2P_EVT_OUTGOING_CONNECTION_ERROR, 1000);

    libp2p_host_free(host);
    libp2p_host_builder_free(b);

    return (saw_dialing && saw_error) ? 0 : 1;
}

