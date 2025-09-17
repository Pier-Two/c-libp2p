#ifndef PROTOCOL_PING_H
#define PROTOCOL_PING_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "libp2p/host.h"
#include "libp2p/protocol_listen.h"
#include "libp2p/stream.h"
#include "transport/connection.h"
#include <stdint.h>

#define LIBP2P_PING_PROTO_ID "/ipfs/ping/1.0.0"

typedef enum
{
    LIBP2P_PING_OK = 0,
    LIBP2P_PING_ERR_NULL_PTR = -1,
    LIBP2P_PING_ERR_TIMEOUT = -2,
    LIBP2P_PING_ERR_IO = -3,
    LIBP2P_PING_ERR_UNEXPECTED = -4
} libp2p_ping_err_t;

libp2p_ping_err_t libp2p_ping_roundtrip(libp2p_conn_t *conn, uint64_t timeout_ms, uint64_t *rtt_ms);

libp2p_ping_err_t libp2p_ping_serve(libp2p_conn_t *conn);

/* Stream-based helpers */
libp2p_ping_err_t libp2p_ping_roundtrip_stream(struct libp2p_stream *s, uint64_t timeout_ms, uint64_t *rtt_ms);
libp2p_ping_err_t libp2p_ping_serve_stream(struct libp2p_stream *s);

/* Convenience service registration */
int libp2p_ping_service_start(struct libp2p_host *host, libp2p_protocol_server_t **out_server);
int libp2p_ping_service_stop(struct libp2p_host *host, libp2p_protocol_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_PING_H */
