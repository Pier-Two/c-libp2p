#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/host_builder.h"
#include "libp2p/host.h"
#include "libp2p/events.h"
#include "peer_id/peer_id.h"

static peer_id_t make_dummy_peer(void)
{
    peer_id_t pid = {0};
    pid.size = 3;
    pid.bytes = (uint8_t *)malloc(pid.size);
    if (pid.bytes)
    {
        pid.bytes[0] = 1;
        pid.bytes[1] = 2;
        pid.bytes[2] = 3;
    }
    return pid;
}

static int expect_next(libp2p_host_t *h, libp2p_event_kind_t k, libp2p_event_t *out)
{
    for (int i = 0; i < 20; i++)
    {
        libp2p_event_t evt = (libp2p_event_t){0};
        int got = libp2p_host_next_event(h, 50, &evt);
        if (got == 1)
        {
            if (evt.kind == k)
            {
                *out = evt;
                return 1;
            }
            /* not our event; free and continue */
            libp2p_event_free(&evt);
        }
    }
    return 0;
}

int main(void)
{
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    libp2p_host_t *h = NULL;
    if (libp2p_host_builder_build(b, &h) != 0 || !h)
    {
        libp2p_host_builder_free(b);
        return 1;
    }

    /* Prepare a dummy peer for events that include peer IDs */
    peer_id_t pid = make_dummy_peer();

    /* 1) LISTEN_ADDR_ADDED */
    {
        const char *addr = "/ip4/127.0.0.1/tcp/1234";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_LISTEN_ADDR_ADDED;
        e.u.listen_addr_added.addr = addr;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_LISTEN_ADDR_ADDED, &got))
            goto fail;
        if (!got.u.listen_addr_added.addr || got.u.listen_addr_added.addr == addr)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.listen_addr_added.addr != NULL)
            goto fail; /* must be nulled */
    }

    /* 2) LISTENER_ERROR */
    {
        const char *addr = "/ip4/0.0.0.0/tcp/0";
        const char *msg = "bind failed";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_LISTENER_ERROR;
        e.u.listener_error.addr = addr;
        e.u.listener_error.msg = msg;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_LISTENER_ERROR, &got))
            goto fail;
        if (!got.u.listener_error.addr || !got.u.listener_error.msg || got.u.listener_error.addr == addr || got.u.listener_error.msg == msg)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.listener_error.addr || got.u.listener_error.msg)
            goto fail;
    }

    /* 3) DIALING */
    {
        const char *addr = "/ip4/127.0.0.1/tcp/4001";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_DIALING;
        e.u.dialing.peer = &pid;
        e.u.dialing.addr = addr;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_DIALING, &got))
            goto fail;
        if (!got.u.dialing.peer || !got.u.dialing.addr)
        { libp2p_event_free(&got); goto fail; }
        if (got.u.dialing.peer == &pid || got.u.dialing.addr == addr)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.dialing.peer || got.u.dialing.addr)
            goto fail;
    }

    /* 4) OUTGOING_CONNECTION_ERROR */
    {
        const char *msg = "connect failed";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        e.u.outgoing_conn_error.peer = &pid;
        e.u.outgoing_conn_error.code = -1;
        e.u.outgoing_conn_error.msg = msg;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_OUTGOING_CONNECTION_ERROR, &got))
            goto fail;
        if (!got.u.outgoing_conn_error.peer || !got.u.outgoing_conn_error.msg)
        { libp2p_event_free(&got); goto fail; }
        if (got.u.outgoing_conn_error.peer == &pid || got.u.outgoing_conn_error.msg == msg)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.outgoing_conn_error.peer || got.u.outgoing_conn_error.msg)
            goto fail;
    }

    /* 5) NEW_EXTERNAL_ADDR_CANDIDATE */
    {
        const char *addr = "/ip4/198.51.100.1/tcp/1234";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE;
        e.u.new_external_addr_candidate.addr = addr;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE, &got))
            goto fail;
        if (!got.u.new_external_addr_candidate.addr || got.u.new_external_addr_candidate.addr == addr)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.new_external_addr_candidate.addr)
            goto fail;
    }

    /* 6) NEW_EXTERNAL_ADDR_OF_PEER */
    {
        const char *addr = "/ip4/203.0.113.1/tcp/4001";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER;
        e.u.new_external_addr_of_peer.peer = &pid;
        e.u.new_external_addr_of_peer.addr = addr;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER, &got))
            goto fail;
        if (!got.u.new_external_addr_of_peer.peer || !got.u.new_external_addr_of_peer.addr)
        { libp2p_event_free(&got); goto fail; }
        if (got.u.new_external_addr_of_peer.peer == &pid || got.u.new_external_addr_of_peer.addr == addr)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.new_external_addr_of_peer.peer || got.u.new_external_addr_of_peer.addr)
            goto fail;
    }

    /* 7) CONN_OPENED */
    {
        const char *addr = "/ip4/127.0.0.1/tcp/4002";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_CONN_OPENED;
        e.u.conn_opened.peer = &pid;
        e.u.conn_opened.addr = addr;
        e.u.conn_opened.inbound = 0;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_CONN_OPENED, &got))
            goto fail;
        if (!got.u.conn_opened.peer || !got.u.conn_opened.addr)
        { libp2p_event_free(&got); goto fail; }
        if (got.u.conn_opened.peer == &pid || got.u.conn_opened.addr == addr)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.conn_opened.peer || got.u.conn_opened.addr)
            goto fail;
    }

    /* 8) CONN_CLOSED */
    {
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_CONN_CLOSED;
        e.u.conn_closed.peer = &pid;
        e.u.conn_closed.reason = 0;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_CONN_CLOSED, &got))
            goto fail;
        if (!got.u.conn_closed.peer)
        { libp2p_event_free(&got); goto fail; }
        if (got.u.conn_closed.peer == &pid)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.conn_closed.peer)
            goto fail;
    }

    /* 9) PROTOCOL_NEGOTIATED */
    {
        const char *pid_str = "/test/1.0.0";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_PROTOCOL_NEGOTIATED;
        e.u.protocol_negotiated.protocol_id = pid_str;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_PROTOCOL_NEGOTIATED, &got))
            goto fail;
        if (!got.u.protocol_negotiated.protocol_id || got.u.protocol_negotiated.protocol_id == pid_str)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.protocol_negotiated.protocol_id)
            goto fail;
    }

    /* 10) STREAM_OPENED */
    {
        const char *pid_str = "/ping/1.0.0";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_STREAM_OPENED;
        e.u.stream_opened.protocol_id = pid_str;
        e.u.stream_opened.peer = &pid;
        e.u.stream_opened.initiator = 1;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_STREAM_OPENED, &got))
            goto fail;
        if (!got.u.stream_opened.peer || !got.u.stream_opened.protocol_id)
        { libp2p_event_free(&got); goto fail; }
        if (got.u.stream_opened.peer == &pid || got.u.stream_opened.protocol_id == pid_str)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.stream_opened.peer || got.u.stream_opened.protocol_id)
            goto fail;
    }

    /* 11) ERROR */
    {
        const char *msg = "generic error";
        libp2p_event_t e = {0};
        e.kind = LIBP2P_EVT_ERROR;
        e.u.error.code = -123;
        e.u.error.msg = msg;
        libp2p_event_publish(h, &e);

        libp2p_event_t got = {0};
        if (!expect_next(h, LIBP2P_EVT_ERROR, &got))
            goto fail;
        if (!got.u.error.msg || got.u.error.msg == msg)
        { libp2p_event_free(&got); goto fail; }
        libp2p_event_free(&got);
        if (got.u.error.msg)
            goto fail;
    }

    /* cleanup */
    if (pid.bytes)
        free(pid.bytes);
    libp2p_host_free(h);
    libp2p_host_builder_free(b);
    return 0;

fail:
    if (pid.bytes)
        free(pid.bytes);
    libp2p_host_free(h);
    libp2p_host_builder_free(b);
    return 1;
}
