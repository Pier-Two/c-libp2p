#include "libp2p/lpmsg.h"
#include "libp2p/io.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/tcp/protocol_tcp_util.h" /* now_mono_ms */
#include <string.h>
#include <time.h>

ssize_t libp2p_lp_send(libp2p_stream_t *s, const uint8_t *data, size_t len)
{
    if (!s || !data)
        return LIBP2P_ERR_NULL_PTR;
    uint8_t hdr[10];
    size_t hlen = 0;
    if (unsigned_varint_encode(len, hdr, sizeof(hdr), &hlen) != UNSIGNED_VARINT_OK)
        return LIBP2P_ERR_INTERNAL;

    const uint64_t slow_ms = 2000;
    uint64_t start = now_mono_ms();

    /* Write header fully with EAGAIN tolerance */
    size_t sent = 0;
    while (sent < hlen)
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        (void)libp2p_stream_set_deadline(s, remain);

        ssize_t n = libp2p_stream_write(s, hdr + sent, hlen - sent);
        if (n > 0)
        {
            sent += (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
            continue;
        return n; /* fatal */
    }

    /* Write payload fully with EAGAIN tolerance */
    sent = 0;
    start = now_mono_ms();
    while (sent < len)
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        (void)libp2p_stream_set_deadline(s, remain);

        ssize_t n = libp2p_stream_write(s, data + sent, len - sent);
        if (n > 0)
        {
            sent += (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
            continue;
        return n;
    }
    (void)libp2p_stream_set_deadline(s, 0);
    return (ssize_t)(hlen + len);
}

ssize_t libp2p_lp_recv(libp2p_stream_t *s, uint8_t *buf, size_t max_len)
{
    if (!s || !buf)
        return LIBP2P_ERR_NULL_PTR;

    /* Default stall timeout per stage (header/payload). */
    const uint64_t slow_ms = 2000;

    uint8_t hdr[10];
    size_t used = 0;
    uint64_t need = 0;
    size_t consumed = 0;
    uint64_t start = now_mono_ms();

    /* Read varint header byte-by-byte; tolerate EAGAIN while making progress. */
    while (used < sizeof(hdr))
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (used > 0 && remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        if (remain)
            (void)libp2p_stream_set_deadline(s, remain);

        ssize_t n = libp2p_stream_read(s, &hdr[used], 1);
        if (n == 1)
        {
            used += 1;
            start = now_mono_ms();
            if (unsigned_varint_decode(hdr, used, &need, &consumed) == UNSIGNED_VARINT_OK)
                break; /* got full length */
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            if (used == 0)
                return LIBP2P_ERR_AGAIN; /* no progress yet; let caller interleave */
            continue;                    /* keep blocking until header complete or timeout */
        }
        /* EOF or fatal */
        return (ssize_t)n;
    }

    if (used == sizeof(hdr) && unsigned_varint_decode(hdr, used, &need, &consumed) != UNSIGNED_VARINT_OK)
    {
        /* Varint too long or malformed */
        return LIBP2P_ERR_INTERNAL;
    }

    if (need > max_len)
    {
        /* Early return: header consumed, leave payload for caller to drain if desired. */
        return LIBP2P_ERR_MSG_TOO_LARGE;
    }

    /* Read payload with EAGAIN tolerance */
    size_t got = 0;
    start = now_mono_ms();
    while (got < need)
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        (void)libp2p_stream_set_deadline(s, remain);

        ssize_t n = libp2p_stream_read(s, buf + got, (size_t)need - got);
        if (n > 0)
        {
            got += (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
            continue;
        return (ssize_t)n; /* EOF/fatal */
    }
    (void)libp2p_stream_set_deadline(s, 0);
    return (ssize_t)got;
}

ssize_t libp2p_lp_recv_io_timeout(libp2p_io_t *io, uint8_t *buf, size_t max_len, uint64_t stall_timeout_ms)
{
    if (!io || !buf)
        return LIBP2P_ERR_NULL_PTR;

    const uint64_t slow_ms = (stall_timeout_ms > 0) ? stall_timeout_ms : 2000;
    uint8_t hdr[10];
    size_t used = 0;
    uint64_t need = 0;
    size_t consumed = 0;
    uint64_t start = now_mono_ms();

    while (used < sizeof(hdr))
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (used > 0 && remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        if (remain)
            libp2p_io_set_deadline(io, remain);
        ssize_t n = libp2p_io_read(io, &hdr[used], 1);
        if (n == 1)
        {
            used++;
            start = now_mono_ms();
            if (unsigned_varint_decode(hdr, used, &need, &consumed) == UNSIGNED_VARINT_OK)
                break;
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            if (used == 0)
                return LIBP2P_ERR_AGAIN;
            continue;
        }
        return (ssize_t)n;
    }
    if (used == sizeof(hdr) && unsigned_varint_decode(hdr, used, &need, &consumed) != UNSIGNED_VARINT_OK)
        return LIBP2P_ERR_INTERNAL;
    if (need > max_len)
    {
        /* Early return: header consumed, leave payload for caller to drain if desired. */
        return LIBP2P_ERR_MSG_TOO_LARGE;
    }
    size_t got = 0;
    start = now_mono_ms();
    while (got < need)
    {
        uint64_t elapsed = now_mono_ms() - start;
        uint64_t remain = (elapsed < slow_ms) ? (slow_ms - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_ERR_TIMEOUT;
        libp2p_io_set_deadline(io, remain);
        ssize_t n = libp2p_io_read(io, buf + got, (size_t)need - got);
        if (n > 0)
        {
            got += (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            continue;
        }
        return (ssize_t)n;
    }
    return (ssize_t)got;
}

ssize_t libp2p_lp_recv_io(libp2p_io_t *io, uint8_t *buf, size_t max_len)
{
    /* Preserve original behavior with default stall timeout. */
    return libp2p_lp_recv_io_timeout(io, buf, max_len, 0);
}
