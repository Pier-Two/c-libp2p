#ifndef TRANSPORT_H
#define TRANSPORT_H

/**
 * @file transport.h
 * @brief Raw transport abstraction for C-libp2p (TCP, QUIC, uTP, …).
 *
 * A **transport** only creates raw bidirectional byte pipes.  Security,
 * multiplexing, and protocol negotiation are layered on top by the upgrader.
 *
 *        ┌──────────────────┐
 *        │   Stream API     │
 *        └────────┬─────────┘
 *                 │   (muxer)
 *        ┌────────┴─────────┐
 *        │  Secure channel  │
 *        └────────┬─────────┘
 *                 │   (upgrader)
 *                 ┌────────┴─────────┐
 *                 │  Raw transport   │  (TCP / UDP / QUIC / uTP / …)
 *                 └──────────────────┘
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "transport/connection.h"
#include "transport/listener.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct libp2p_transport;
typedef struct libp2p_transport libp2p_transport_t;

/**
 * @enum libp2p_transport_err_t
 * @brief Return codes for all transport operations.
 */
typedef enum
{
    LIBP2P_TRANSPORT_OK = 0,               /**< No error.                              */
    LIBP2P_TRANSPORT_ERR_NULL_PTR = -1,    /**< Required pointer was NULL.             */
    LIBP2P_TRANSPORT_ERR_UNSUPPORTED = -2, /**< Transport cannot handle the addr.      */
    LIBP2P_TRANSPORT_ERR_DIAL_FAIL = -3,   /**< Dial() failed (network/proto error).   */
    LIBP2P_TRANSPORT_ERR_LISTEN_FAIL = -4, /**< Listen() failed.                       */
    LIBP2P_TRANSPORT_ERR_CLOSED = -5,      /**< Operation on a closed transport.       */
    LIBP2P_TRANSPORT_ERR_INTERNAL = -6,    /**< Unexpected internal failure.           */
    LIBP2P_TRANSPORT_ERR_TIMEOUT = -7,     /**< Operation timed out.                  */
    /** @brief setsockopt: The specified option is not supported by the protocol (maps to ENOPROTOOPT). */
    LIBP2P_TRANSPORT_ERR_SOCKOPT_OPT_NOT_SUPPORTED = -8,
    /** @brief setsockopt: Permission denied (maps to EACCES, EPERM). */
    LIBP2P_TRANSPORT_ERR_SOCKOPT_PERMISSION = -9,
    /** @brief setsockopt: Invalid argument provided for the option (maps to EINVAL). */
    LIBP2P_TRANSPORT_ERR_SOCKOPT_INVALID_ARG = -10,
    /** @brief setsockopt: Insufficient resources or buffer space (maps to ENOBUFS). */
    LIBP2P_TRANSPORT_ERR_SOCKOPT_NO_RESOURCES = -11,
    /** @brief setsockopt: Other unspecified error occurred during a setsockopt call. */
    LIBP2P_TRANSPORT_ERR_SOCKOPT_OTHER_FAIL = -12,
    /** @brief Invalid argument provided for the option (maps to EINVAL). */
    LIBP2P_TRANSPORT_ERR_INVALID_ARG = -13,
} libp2p_transport_err_t;

/**
 * @brief Dispatch table every concrete transport must implement.
 *
 * All methods must be **thread-safe**; higher layers may call them from
 * multiple threads concurrently.
 */
typedef struct
{
    /* Capability check */
    bool (*can_handle)(const multiaddr_t *addr);

    /* Active side */
    libp2p_transport_err_t (*dial)(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out);

    /* Passive side */
    libp2p_transport_err_t (*listen)(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out);

    /* Lifecycle management */
    libp2p_transport_err_t (*close)(libp2p_transport_t *self);
    void (*free)(libp2p_transport_t *self);

} libp2p_transport_vtbl_t;

/**
 * @brief Transport handle with method table and implementation context.
 */
struct libp2p_transport
{
    const libp2p_transport_vtbl_t *vt; /**< Pointer to method table.   */
    void *ctx;                         /**< Implementation private data.*/
};

/* Convenience inline wrappers */

/**
 * @brief Check whether the transport can handle an address.
 *
 * @param t     Transport instance.
 * @param addr  Multiaddress to test.
 * @return true if supported, false otherwise.
 */
static inline bool libp2p_transport_can_handle(const libp2p_transport_t *t, const multiaddr_t *addr)
{
    return t && t->vt && t->vt->can_handle ? t->vt->can_handle(addr) : false;
}

/**
 * @brief Dial a remote address.
 *
 * @param t     Transport instance.
 * @param addr  Destination multiaddress.
 * @param out   On success, receives a new connection.
 * @return LIBP2P_TRANSPORT_OK or an error code.
 */
static inline libp2p_transport_err_t libp2p_transport_dial(libp2p_transport_t *t, const multiaddr_t *addr, libp2p_conn_t **out)
{
    if (!t || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    return t->vt->dial(t, addr, out);
}

/**
 * @brief Start listening on the given address.
 *
 * @param t     Transport instance.
 * @param addr  Address to bind.
 * @param out   On success, receives a new listener.
 * @return LIBP2P_TRANSPORT_OK or an error code.
 */
static inline libp2p_transport_err_t libp2p_transport_listen(libp2p_transport_t *t, const multiaddr_t *addr, libp2p_listener_t **out)
{
    if (!t || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    return t->vt->listen(t, addr, out);
}

/**
 * @brief Close the transport instance.
 *
 * @param t Transport instance.
 * @return LIBP2P_TRANSPORT_OK or an error code.
 */
static inline libp2p_transport_err_t libp2p_transport_close(libp2p_transport_t *t) { return t ? t->vt->close(t) : LIBP2P_TRANSPORT_ERR_NULL_PTR; }

/**
 * @brief Free a transport instance.
 *
 * @param t Transport instance (may be NULL).
 */
static inline void libp2p_transport_free(libp2p_transport_t *t)
{
    if (t && t->vt && t->vt->free)
        t->vt->free(t);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TRANSPORT_H */