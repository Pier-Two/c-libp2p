#ifndef LIBP2P_MPLEX_CONN_H
#define LIBP2P_MPLEX_CONN_H

#include "transport/connection.h"
#include <stdatomic.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Non-blocking connection context for Mplex
 */
typedef struct mplex_conn_ctx
{
    int fd;                    /**< File descriptor */
    atomic_bool closed;        /**< Connection closed flag */
    atomic_size_t read_bytes;  /**< Total bytes read */
    atomic_size_t write_bytes; /**< Total bytes written */
} mplex_conn_ctx_t;

/**
 * @brief Creates a new non-blocking connection wrapper
 * @param fd The file descriptor to wrap
 * @return New connection object or NULL on failure
 * @note The FD is set to non-blocking mode
 */
libp2p_conn_t *mplex_conn_new(int fd);

/**
 * @brief Frees a connection created by mplex_conn_new
 * @param conn The connection to free
 */
void mplex_conn_free(libp2p_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MPLEX_CONN_H */
