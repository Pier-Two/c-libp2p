#include "transport/conn_util.h"
#include <errno.h>
#include <time.h>
#include <unistd.h>

/* Busy-wait backoffs removed: rely on per-call deadlines in the connection
 * implementation to block efficiently until readable/writable. */

libp2p_conn_err_t libp2p_conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len, uint64_t slow_ms)
{
    if (!c || !buf)
        return LIBP2P_CONN_ERR_NULL_PTR;

    if (slow_ms == 0)
        slow_ms = 1000; /* default 1 s */

    uint64_t start = now_mono_ms();

    while (len)
    {
        /* Arm/refresh a per-chunk deadline to avoid spinning. */
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_CONN_ERR_TIMEOUT;
        (void)libp2p_conn_set_deadline(c, remain);

        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            /* Try again; deadline blocks until writable or timeout. */
            continue;
        }
        /* propagate EOF / CLOSED / INTERNAL / TIMEOUT */
        return (libp2p_conn_err_t)n;
    }
    /* Clear deadline */
    (void)libp2p_conn_set_deadline(c, 0);
    return LIBP2P_CONN_OK;
}

libp2p_conn_err_t libp2p_conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
{
    if (!c || !buf)
        return LIBP2P_CONN_ERR_NULL_PTR;

    while (len)
    {
        /* If the caller did not set a deadline, use a modest per-iteration
         * wait to avoid spinning. This blocks in the transport via poll(). */
        (void)libp2p_conn_set_deadline(c, 1000);

        ssize_t n = libp2p_conn_read(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            /* Try again; deadline blocks until readable. */
            continue;
        }
        /* bubble up real error */
        (void)libp2p_conn_set_deadline(c, 0);
        return (libp2p_conn_err_t)n;
    }
    (void)libp2p_conn_set_deadline(c, 0);
    return LIBP2P_CONN_OK;
}

libp2p_conn_err_t libp2p_conn_read_exact_timed(libp2p_conn_t *c, uint8_t *buf, size_t len, uint64_t slow_ms)
{
    if (!c || !buf)
        return LIBP2P_CONN_ERR_NULL_PTR;

    if (slow_ms == 0)
        slow_ms = 1000; /* default 1 s */

    uint64_t start = now_mono_ms();

    while (len)
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_CONN_ERR_TIMEOUT;
        (void)libp2p_conn_set_deadline(c, remain);

        ssize_t n = libp2p_conn_read(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            /* Try again; deadline blocks until readable. */
            continue;
        }
        (void)libp2p_conn_set_deadline(c, 0);
        return (libp2p_conn_err_t)n; /* EOF / CLOSED / INTERNAL / TIMEOUT */
    }
    (void)libp2p_conn_set_deadline(c, 0);
    return LIBP2P_CONN_OK;
}
