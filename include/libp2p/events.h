#ifndef LIBP2P_EVENTS_H
#define LIBP2P_EVENTS_H

#include <stdbool.h>
#include <stddef.h>

#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct libp2p_host;

typedef enum
{
    LIBP2P_EVT_HOST_STARTED,
    LIBP2P_EVT_HOST_STOPPED,
    LIBP2P_EVT_LISTEN_ADDR_ADDED,
    LIBP2P_EVT_EXPIRED_LISTEN_ADDR,
    LIBP2P_EVT_LISTENER_CLOSED,
    LIBP2P_EVT_LISTENER_ERROR,
    LIBP2P_EVT_DIALING,
    LIBP2P_EVT_OUTGOING_CONNECTION_ERROR,
    LIBP2P_EVT_INCOMING_CONNECTION_ERROR,
    LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE,
    LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED,
    LIBP2P_EVT_EXTERNAL_ADDR_EXPIRED,
    LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER,
    LIBP2P_EVT_LOCAL_PROTOCOLS_UPDATED,
    LIBP2P_EVT_PEER_PROTOCOLS_UPDATED,
    LIBP2P_EVT_CONN_OPENED,
    LIBP2P_EVT_CONN_CLOSED,
    LIBP2P_EVT_STREAM_OPENED,
    LIBP2P_EVT_STREAM_CLOSED,
    LIBP2P_EVT_PROTOCOL_NEGOTIATED,
    LIBP2P_EVT_ERROR
} libp2p_event_kind_t;

typedef struct
{
    const char *addr;
} libp2p_evt_listen_addr_added_t;
typedef struct
{
    const char *addr;
    int reason;
} libp2p_evt_listener_closed_t;
typedef struct
{
    const char *addr;
    int code;
    const char *msg;
} libp2p_evt_listener_error_t;
typedef struct
{
    const peer_id_t *peer;
    const char *addr;
} libp2p_evt_dialing_t;
typedef struct
{
    const peer_id_t *peer;
    int code;
    const char *msg;
} libp2p_evt_conn_error_t;
typedef struct
{
    const char *addr;
} libp2p_evt_external_addr_t;
typedef struct
{
    const peer_id_t *peer;
    const char *addr;
} libp2p_evt_external_addr_of_peer_t;
typedef struct
{
    const peer_id_t *peer;
    const char **protocols;
    size_t num_protocols;
} libp2p_evt_peer_protocols_updated_t;
typedef struct
{
    const peer_id_t *peer;
    const char *addr;
    bool inbound;
} libp2p_evt_conn_opened_t;
typedef struct
{
    const peer_id_t *peer;
    int reason;
} libp2p_evt_conn_closed_t;
typedef struct
{
    const char *protocol_id;
    const peer_id_t *peer;
    bool initiator;
} libp2p_evt_stream_opened_t;
typedef struct
{
    int reason;
} libp2p_evt_stream_closed_t;
typedef struct
{
    const char *protocol_id;
} libp2p_evt_protocol_negotiated_t;
typedef struct
{
    int code;
    const char *msg;
} libp2p_evt_error_t;

typedef struct
{
    libp2p_event_kind_t kind;
    union
    {
        libp2p_evt_listen_addr_added_t listen_addr_added;
        libp2p_evt_listener_closed_t listener_closed;
        libp2p_evt_listener_error_t listener_error;
        libp2p_evt_dialing_t dialing;
        libp2p_evt_conn_error_t outgoing_conn_error;
        libp2p_evt_conn_error_t incoming_conn_error;
        libp2p_evt_external_addr_t new_external_addr_candidate;
        libp2p_evt_external_addr_t external_addr_confirmed;
        libp2p_evt_external_addr_t external_addr_expired;
        libp2p_evt_external_addr_of_peer_t new_external_addr_of_peer;
        libp2p_evt_peer_protocols_updated_t peer_protocols_updated;
        libp2p_evt_conn_opened_t conn_opened;
        libp2p_evt_conn_closed_t conn_closed;
        libp2p_evt_stream_opened_t stream_opened;
        libp2p_evt_stream_closed_t stream_closed;
        libp2p_evt_protocol_negotiated_t protocol_negotiated;
        libp2p_evt_error_t error;
    } u;
} libp2p_event_t;

typedef void (*libp2p_event_cb)(const libp2p_event_t *evt, void *user_data);
typedef struct libp2p_subscription libp2p_subscription_t;
int libp2p_event_subscribe(struct libp2p_host *host, libp2p_event_cb cb, void *user_data, libp2p_subscription_t **sub);
void libp2p_event_unsubscribe(struct libp2p_host *host, libp2p_subscription_t *sub);

/* Publish an event: enqueue for pull APIs and dispatch asynchronously to
 * subscribers via a dedicated dispatcher thread. Thread-safe and race-free
 * with respect to subscription list mutations. */
void libp2p_event_publish(struct libp2p_host *host, const libp2p_event_t *evt);

/* Pull-based polling */
int libp2p_host_next_event(struct libp2p_host *host, int timeout_ms, libp2p_event_t *out_evt);
void libp2p_event_free(libp2p_event_t *evt);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_EVENTS_H */
