#ifndef PROTOCOL_TCP_H
#define PROTOCOL_TCP_H

/**
 * @file protocol_tcp.h
 * @brief TCP transport for C-libp2p.
 *
 * This module instantiates a concrete @ref libp2p_transport_t whose v-table
 * speaks plain TCP sockets on IPv4 and IPv6.
 */

#include "transport/transport.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @struct libp2p_tcp_config_t
 * @brief User-tunable knobs for the TCP transport.
 *
 * Use @ref libp2p_tcp_config_default() first, then tweak what you need.
 */
typedef struct
{
    bool nodelay;                /**< Disable Nagle (TCP_NODELAY).                 */
    bool reuse_port;             /**< Enable SO_REUSE{ADDR,PORT}.                  */
    bool keepalive;              /**< Enable TCP keep-alives.                      */
    uint32_t recv_buffer;        /**< SO_RCVBUF (0 → kernel default).              */
    uint32_t send_buffer;        /**< SO_SNDBUF (0 → kernel default).              */
    int listen_backlog;          /**< Listen backlog (≤0 → OS default).            */
    uint32_t ttl_ms;             /**< Initial IP TTL / hop-limit in ms (0 → OS default). */
    uint32_t connect_timeout_ms; /**< Dial timeout in milliseconds.           */
    uint32_t accept_poll_ms;     /**< accept() poll period in milliseconds (0 → library default 1000). */
    uint32_t close_timeout_ms;   /**< Listener close timeout in milliseconds (0 → immediate, UINT32_MAX → wait forever, library default 5000). */
} libp2p_tcp_config_t;

/**
 * @brief Return the canonical default configuration.
 *
 *  * `nodelay      = true`
 *  * `reuse_port   = true`
 *  * `keepalive    = true`
 *  * `recv_buffer  = 0`
 *  * `send_buffer  = 0`
 *  * `listen_backlog = 128`
 *  * `ttl_ms       = 0`
 *  * `close_timeout_ms = 5000`
 */
static inline libp2p_tcp_config_t libp2p_tcp_config_default(void)
{
    return (libp2p_tcp_config_t){
        .nodelay = true,
        .reuse_port = true,
        .keepalive = true,
        .recv_buffer = 0,
        .send_buffer = 0,
        .listen_backlog = 128,
        .ttl_ms = 0,
        .connect_timeout_ms = 30000,
        .accept_poll_ms = 1000,  /* 1 s default */
        .close_timeout_ms = 5000 /* 5 s default */
    };
}

/**
 * @brief Create a new TCP transport.
 *
 * @param cfg  Optional configuration (NULL → defaults).
 * @return     A heap-allocated @ref libp2p_transport_t or NULL on OOM.
 *
 * Free with @ref libp2p_transport_free().
 */
libp2p_transport_t *libp2p_tcp_transport_new(const libp2p_tcp_config_t *cfg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_TCP_H */