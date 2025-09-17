#include "host_internal.h"
#include "libp2p/debug_trace.h"
#include "libp2p/events.h"
#include "libp2p/peer.h"
#include "multiformats/multiaddr/multiaddr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void libp2p__emit_dialing(libp2p_host_t *host, const char *addr)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_DIALING;
    evt.u.dialing.peer = NULL;
    evt.u.dialing.addr = addr;
    libp2p_event_publish(host, &evt);
}

void libp2p__emit_outgoing_error(libp2p_host_t *host, libp2p_err_t code, const char *msg)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
    evt.u.outgoing_conn_error.peer = NULL;
    evt.u.outgoing_conn_error.code = code;
    evt.u.outgoing_conn_error.msg = msg;
    libp2p_event_publish(host, &evt);
}

void libp2p__emit_incoming_error(libp2p_host_t *host, libp2p_err_t code, const char *msg)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_INCOMING_CONNECTION_ERROR;
    evt.u.incoming_conn_error.peer = NULL;
    evt.u.incoming_conn_error.code = code;
    evt.u.incoming_conn_error.msg = msg;
    libp2p_event_publish(host, &evt);
}

void libp2p__emit_incoming_error_with_peer(libp2p_host_t *host, const peer_id_t *peer, libp2p_err_t code, const char *msg)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_INCOMING_CONNECTION_ERROR;
    evt.u.incoming_conn_error.peer = (peer_id_t *)peer;
    evt.u.incoming_conn_error.code = code;
    evt.u.incoming_conn_error.msg = msg;
    libp2p_event_publish(host, &evt);
}

void libp2p__emit_conn_opened(libp2p_host_t *host, bool inbound, const peer_id_t *peer, const multiaddr_t *addr)
{
    if (!host)
        return;
    int serr = 0;
    char *addr_str = addr ? multiaddr_to_str(addr, &serr) : NULL;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_CONN_OPENED;
    evt.u.conn_opened.peer = (peer_id_t *)peer;
    evt.u.conn_opened.addr = addr_str;
    evt.u.conn_opened.inbound = inbound;
    libp2p_event_publish(host, &evt);
    if (addr_str)
        free(addr_str);
}

void libp2p__emit_protocol_negotiated(libp2p_host_t *host, const char *protocol_id)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_PROTOCOL_NEGOTIATED;
    evt.u.protocol_negotiated.protocol_id = protocol_id;
    libp2p_event_publish(host, &evt);
}

void libp2p__emit_stream_opened(libp2p_host_t *host, const char *protocol_id, const peer_id_t *peer, bool initiator)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_STREAM_OPENED;
    evt.u.stream_opened.protocol_id = protocol_id;
    evt.u.stream_opened.peer = (peer_id_t *)peer;
    evt.u.stream_opened.initiator = initiator;
    libp2p_event_publish(host, &evt);
}

void libp2p__notify_peer_protocols_updated(libp2p_host_t *host, const peer_id_t *peer, const char *const *protocols, size_t num_protocols)
{
    if (!host || !peer)
        return;

    char **list = NULL;
    size_t list_len = 0;
    if (protocols && num_protocols > 0)
    {
        list = (char **)calloc(num_protocols, sizeof(*list));
        if (!list)
        {
            num_protocols = 0;
        }
        else
        {
            for (size_t i = 0; i < num_protocols; i++)
            {
                const char *p = protocols[i];
                if (!p)
                    continue;
                char *dup = strdup(p);
                if (!dup)
                {
                    for (size_t j = 0; j < list_len; j++)
                        free(list[j]);
                    free(list);
                    list = NULL;
                    list_len = 0;
                    num_protocols = 0;
                    break;
                }
                list[list_len++] = dup;
            }
            if (list && list_len == 0)
            {
                free(list);
                list = NULL;
            }
        }
    }

    libp2p_event_t evt = (libp2p_event_t){0};
    evt.kind = LIBP2P_EVT_PEER_PROTOCOLS_UPDATED;
    evt.u.peer_protocols_updated.peer = (peer_id_t *)peer;
    evt.u.peer_protocols_updated.protocols = (const char **)list;
    evt.u.peer_protocols_updated.num_protocols = list_len;

    char pid_buf[128];
    if (peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
        snprintf(pid_buf, sizeof(pid_buf), "<unknown>");
    LIBP2P_TRACE("idpush", "event peer protocols updated peer=%s count=%zu", pid_buf, list_len);
    libp2p_event_publish(host, &evt);

    if (list)
    {
        for (size_t i = 0; i < list_len; i++)
            free(list[i]);
        free(list);
    }
}
