#ifndef LIBP2P_CONN_UTIL_H
#define LIBP2P_CONN_UTIL_H

/**
 * @file conn_util.h
 * @brief Helper routines for reliable read/write on a non-blocking libp2p_conn_t.
 *
 * These helpers hide the common “retry until all bytes sent / received” loops
 * that were copy-pasted in the YAMUX and MPLEX implementations.  They operate
 * purely on the generic connection layer and therefore can be reused by any
 * higher-level protocol without pulling additional dependencies.
 */

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "protocol/tcp/protocol_tcp_util.h" /* now_mono_ms() */
#include "transport/connection.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Write the entire buffer, retrying short writes until @p len bytes have
 *        been delivered or a fatal connection error / soft timeout occurs.
 *
 * The function returns immediately on any connection-layer error other than
 * LIBP2P_CONN_ERR_AGAIN.  When the connection would block it spins until
 * @p slow_ms milliseconds have elapsed without forward progress, in which case
 * LIBP2P_CONN_ERR_TIMEOUT is returned.
 *
 * @param c        Connection handle (must not be NULL).
 * @param buf      Data to send.
 * @param len      Number of bytes in @p buf.
 * @param slow_ms  Maximum stall time in milliseconds before timing out.
 *                 Pass 0 to use the default (1000ms).
 * @return LIBP2P_CONN_OK on success or a negative libp2p_conn_err_t on failure.
 */
libp2p_conn_err_t libp2p_conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len, uint64_t slow_ms);

/**
 * @brief Read exactly @p len bytes from the connection.
 *
 * The call keeps retrying when the connection would block (AGAIN) until all
 * requested bytes are available or a fatal connection error occurs.
 *
 * @param c   Connection handle.
 * @param buf Destination buffer (size >= @p len).
 * @param len Number of bytes to read.
 * @return LIBP2P_CONN_OK on success or a negative libp2p_conn_err_t on failure.
 */
libp2p_conn_err_t libp2p_conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len);

/**
 * @brief Read exactly @p len bytes with a stall timeout.
 *
 * Behaves like libp2p_conn_read_exact(), but if the connection repeatedly
 * reports AGAIN without making forward progress for @p slow_ms milliseconds,
 * returns LIBP2P_CONN_ERR_TIMEOUT instead of spinning indefinitely.
 *
 * @param c       Connection handle.
 * @param buf     Destination buffer (size >= @p len).
 * @param len     Number of bytes to read.
 * @param slow_ms Maximum stall time in milliseconds (0 = default 1000ms).
 * @return LIBP2P_CONN_OK on success or a negative libp2p_conn_err_t.
 */
libp2p_conn_err_t libp2p_conn_read_exact_timed(libp2p_conn_t *c, uint8_t *buf, size_t len, uint64_t slow_ms);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBP2P_CONN_UTIL_H */
