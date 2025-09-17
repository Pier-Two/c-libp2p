#ifndef CONNECTION_H
#define CONNECTION_H

/**
 * @file connection.h
 * @brief Opaque raw-connection handle for C-libp2p.
 *
 * A **connection** is a bidirectional byte pipe supplied by a transport
 * (TCP socket, QUIC stream, …) *before* any security or multiplexing is
 * applied.  Higher layers treat it like a POSIX socket with a little
 * extra metadata.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "multiformats/multiaddr/multiaddr.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct libp2p_connection;
typedef struct libp2p_connection libp2p_conn_t;

/**
 * @enum libp2p_conn_err_t
 * @brief Return codes for connection operations.
 *
 * Positive values are valid byte counts; non-zero negatives are errors.
 */
typedef enum
{
    LIBP2P_CONN_OK = 0,            /**< No error (unused—success is byte count). */
    LIBP2P_CONN_ERR_NULL_PTR = -1, /**< Required pointer was NULL.               */
    LIBP2P_CONN_ERR_AGAIN = -2,    /**< Would block (EAGAIN / EWOULDBLOCK).      */
    LIBP2P_CONN_ERR_EOF = -3,      /**< Remote closed the connection.            */
    LIBP2P_CONN_ERR_CLOSED = -4,   /**< Operation after libp2p_conn_close().     */
    LIBP2P_CONN_ERR_TIMEOUT = -5,  /**< Deadline expired.                        */
    LIBP2P_CONN_ERR_INTERNAL = -6  /**< Unspecified internal failure.            */
} libp2p_conn_err_t;

/**
 * @brief Virtual table for connection operations.
 */

typedef struct
{
    /* I/O operations */
    /**
     * @brief Read up to @p len bytes into @p buf.
     *
     * @return Positive byte count, or a negative libp2p_conn_err_t.
     */
    ssize_t (*read)(libp2p_conn_t *self, void *buf, size_t len);

    /**
     * @brief Write up to @p len bytes from @p buf.
     *
     * @return Positive byte count, or a negative libp2p_conn_err_t.
     */
    ssize_t (*write)(libp2p_conn_t *self, const void *buf, size_t len);

    /**
     * @brief Set a combined read/write deadline in milliseconds from now.
     *        Pass 0 to clear any existing deadline.
     */
    libp2p_conn_err_t (*set_deadline)(libp2p_conn_t *self, uint64_t ms);

    /* Metadata accessors */

    const multiaddr_t *(*local_addr)(libp2p_conn_t *self);
    const multiaddr_t *(*remote_addr)(libp2p_conn_t *self);

    /* Lifecycle management */

    libp2p_conn_err_t (*close)(libp2p_conn_t *self);
    void (*free)(libp2p_conn_t *self);

    /**
     * @brief Get the underlying file descriptor for the connection.
     *        This is intended for use with event loops (epoll, kqueue, etc.).
     * @return The file descriptor, or -1 on error.
     */
    int (*get_fd)(libp2p_conn_t *self);

} libp2p_conn_vtbl_t;

/**
 * @brief Opaque connection structure.
 */

struct libp2p_connection
{
    const libp2p_conn_vtbl_t *vt;
    void *ctx; /**< Transport-specific state. */
};

/* Convenience inline wrappers */

/**
 * @brief Read from a connection.
 *
 * @param c   Connection handle.
 * @param buf Buffer to fill with received bytes.
 * @param len Maximum number of bytes to read.
 * @return Positive byte count, or a negative @ref libp2p_conn_err_t.
 */
static inline ssize_t libp2p_conn_read(libp2p_conn_t *c, void *buf, size_t len)
{
    return c && c->vt ? c->vt->read(c, buf, len) : LIBP2P_CONN_ERR_NULL_PTR;
}

/**
 * @brief Write to a connection.
 *
 * @param c   Connection handle.
 * @param buf Bytes to send.
 * @param len Number of bytes available in @p buf.
 * @return Positive byte count, or a negative @ref libp2p_conn_err_t.
 */
static inline ssize_t libp2p_conn_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    return c && c->vt ? c->vt->write(c, buf, len) : LIBP2P_CONN_ERR_NULL_PTR;
}

/**
 * @brief Set a combined read/write deadline.
 *
 * Passing @p ms == 0 clears any existing deadline.
 *
 * @param c  Connection handle.
 * @param ms Deadline in milliseconds from now.
 * @return LIBP2P_CONN_OK on success or a negative error code.
 */
static inline libp2p_conn_err_t libp2p_conn_set_deadline(libp2p_conn_t *c, uint64_t ms)
{
    return c && c->vt ? c->vt->set_deadline(c, ms) : LIBP2P_CONN_ERR_NULL_PTR;
}

/**
 * @brief Get the local endpoint address.
 *
 * @param c Connection handle.
 * @return Pointer to the local multiaddress or NULL on error.
 */
static inline const multiaddr_t *libp2p_conn_local_addr(libp2p_conn_t *c) { return c && c->vt ? c->vt->local_addr(c) : NULL; }

/**
 * @brief Get the remote endpoint address.
 *
 * @param c Connection handle.
 * @return Pointer to the remote multiaddress or NULL on error.
 */
static inline const multiaddr_t *libp2p_conn_remote_addr(libp2p_conn_t *c) { return c && c->vt ? c->vt->remote_addr(c) : NULL; }

/**
 * @brief Close the connection.
 *
 * @param c Connection handle.
 * @return LIBP2P_CONN_OK on success or a negative error code.
 */
static inline libp2p_conn_err_t libp2p_conn_close(libp2p_conn_t *c) { return c && c->vt ? c->vt->close(c) : LIBP2P_CONN_ERR_NULL_PTR; }

/**
 * @brief Free a connection and its resources.
 *
 * Safe to call with NULL or on a half-initialized object.
 *
 * @param c Connection handle.
 */
static inline void libp2p_conn_free(libp2p_conn_t *c)
{
    if (c && c->vt && c->vt->free)
        c->vt->free(c);
}

/**
 * @brief Get the underlying file descriptor, if available.
 *
 * This is intended for integration with event loops (epoll, kqueue, etc.).
 * Implementations that do not expose an fd should return -1.
 */
static inline int libp2p_conn_get_fd(libp2p_conn_t *c) { return c && c->vt && c->vt->get_fd ? c->vt->get_fd(c) : -1; }

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CONNECTION_H */
