#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/events.h"

static int collect_until(libp2p_host_t *h, int timeout_ms,
                         int *saw_started, int *saw_listen_added,
                         int *saw_expired, int *saw_listener_closed, int *saw_stopped)
{
    int waited = 0;
    const int step_ms = 50;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step_ms, &evt);
        if (got == 1)
        {
            switch (evt.kind)
            {
                case LIBP2P_EVT_HOST_STARTED: *saw_started = 1; break;
                case LIBP2P_EVT_LISTEN_ADDR_ADDED: *saw_listen_added = 1; break;
                case LIBP2P_EVT_EXPIRED_LISTEN_ADDR: *saw_expired = 1; break;
                case LIBP2P_EVT_LISTENER_CLOSED: *saw_listener_closed = 1; break;
                case LIBP2P_EVT_HOST_STOPPED: *saw_stopped = 1; break;
                default: break;
            }
            libp2p_event_free(&evt);
        }

        /* Success criteria for this test: host started and listen addr added observed */
        if (*saw_started && *saw_listen_added)
            return 1;

        waited += step_ms;
    }
    return 0;
}

int main(void)
{
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    (void)libp2p_host_builder_listen_addr(b, "/ip4/127.0.0.1/tcp/0");
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

    if (libp2p_host_start(host) != 0)
    {
        libp2p_host_free(host);
        libp2p_host_builder_free(b);
        return 1;
    }

    /* Allow initial events to queue */
    usleep(1000 * 50);

    int saw_started = 0, saw_listen_added = 0, saw_expired = 0, saw_listener_closed = 0, saw_stopped = 0;
    int ok = collect_until(host, 3000, &saw_started, &saw_listen_added, &saw_expired, &saw_listener_closed, &saw_stopped);

    /* Stop host and then ensure we observe EXPIRED_LISTEN_ADDR, LISTENER_CLOSED and HOST_STOPPED */
    (void)libp2p_host_stop(host);

    const int step_ms = 50;
    int waited = 0;
    while (waited < 3000 && !(saw_expired && saw_listener_closed && saw_stopped))
    {
        libp2p_event_t evt = (libp2p_event_t){0};
        int got = libp2p_host_next_event(host, step_ms, &evt);
        if (got == 1)
        {
            switch (evt.kind)
            {
                case LIBP2P_EVT_EXPIRED_LISTEN_ADDR: saw_expired = 1; break;
                case LIBP2P_EVT_LISTENER_CLOSED: saw_listener_closed = 1; break;
                case LIBP2P_EVT_HOST_STOPPED: saw_stopped = 1; break;
                default: break;
            }
            libp2p_event_free(&evt);
        }
        waited += step_ms;
    }

    libp2p_host_free(host);
    libp2p_host_builder_free(b);
    return (ok && saw_expired && saw_listener_closed && saw_stopped) ? 0 : 1;
}
