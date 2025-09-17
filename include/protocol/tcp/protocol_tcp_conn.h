#ifndef PROTOCOL_TCP_CONN_H
#define PROTOCOL_TCP_CONN_H
/**
 * @file protocol_tcp_conn.h
 * @brief Public interface for a single TCP connection.
 *
 * This header exposes the full connection context structure along with
 * helper functions and the vtable. No I/O is performed here; the
 * implementation resides in tcp_conn.c.
 *
 * These symbols are primarily intended for libp2p’s own transports and
 * tests. Treat the layout as semi-stable rather than a strict ABI
 * commitment.
 */

#include <stdatomic.h> /* atomic_bool             */
#include <stddef.h>    /* size_t                  */
#include <stdint.h>    /* uint64_t                */

#include "multiformats/multiaddr/multiaddr.h"
#include "transport/connection.h" /* libp2p_conn_t / vtbl / err enum   */

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @struct tcp_conn_ctx
 * @brief Context for a single TCP connection.
 *
 * Exposed so callers can fetch the raw file descriptor or cached
 * multiaddrs without additional system calls.
 */
typedef struct tcp_conn_ctx
{
    int fd;                      /**< non-blocking, close-on-exec socket  */
    multiaddr_t *local;          /**< cached local multiaddr              */
    multiaddr_t *remote;         /**< cached peer multiaddr (nullable)    */
    atomic_bool closed;          /**< fast-path closed check              */
    atomic_uint_fast64_t deadline_at; /**< 0 = none; monotonic ms          */
} tcp_conn_ctx_t;

/**
 * @brief Read from a TCP connection.
 *
 * @param c   Connection to read from.
 * @param buf Buffer to fill.
 * @param len Size of @p buf in bytes.
 * @return Bytes read or -1 on error.
 */
ssize_t tcp_conn_read(libp2p_conn_t *c, void *buf, size_t len);

/**
 * @brief Write to a TCP connection.
 *
 * @param c   Connection to write to.
 * @param buf Data to send.
 * @param len Number of bytes in @p buf.
 * @return Bytes written or -1 on error.
 */
ssize_t tcp_conn_write(libp2p_conn_t *c, const void *buf, size_t len);

/**
 * @brief Set a read/write deadline on the connection.
 *
 * @param c  Connection to configure.
 * @param ms Deadline in monotonic milliseconds (0 disables).
 * @return LIBP2P_CONN_SUCCESS on success or an error code.
 */
libp2p_conn_err_t tcp_conn_set_deadline(libp2p_conn_t *c, uint64_t ms);

/**
 * @brief Return the cached local multiaddress.
 *
 * @param c Connection to inspect.
 * @return Pointer to the local multiaddr.
 */
const multiaddr_t *tcp_conn_local(libp2p_conn_t *c);

/**
 * @brief Return the cached remote multiaddress.
 *
 * @param c Connection to inspect.
 * @return Pointer to the remote multiaddr or NULL.
 */
const multiaddr_t *tcp_conn_remote(libp2p_conn_t *c);

/**
 * @brief Close a TCP connection.
 *
 * @param c Connection to close.
 * @return LIBP2P_CONN_SUCCESS on success or an error code.
 */
libp2p_conn_err_t tcp_conn_close(libp2p_conn_t *c);

/**
 * @brief Free a TCP connection and its resources.
 *
 * @param c Connection to destroy.
 */
void tcp_conn_free(libp2p_conn_t *c);

/**
 * @brief Pre-wired connection vtable defined in tcp_conn.c.
 */
extern const libp2p_conn_vtbl_t TCP_CONN_VTBL;

/**
 * Wrap an existing, already-connected (or connecting) TCP socket
 * descriptor into a libp2p connection object.
 *
 * The FD **must** be:
 *   • valid (≥ 0)
 *   • non-blocking
 *   • FD_CLOEXEC set (if platform supports it)
 *
 * On success, ownership of the FD transfers to the returned object and
 * will be closed via `tcp_conn_free()`.  Returns NULL on allocation
 * failure or if address conversion fails.
 */
libp2p_conn_t *make_tcp_conn(int fd);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_TCP_CONN_H */
