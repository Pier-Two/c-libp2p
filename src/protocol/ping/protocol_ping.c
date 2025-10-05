#include "protocol/ping/protocol_ping.h"
#include "../../host/host_internal.h"
#include "libp2p/stream_internal.h"
#include "libp2p/log.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#else
#include <stdlib.h>
#endif

#ifndef NOW_MONO_MS_DECLARED
#include <time.h>
static inline uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}
#define NOW_MONO_MS_DECLARED 1
#endif

static int get_random_bytes(void *buf, size_t len)
{
#if defined(__linux__)
    ssize_t r = getrandom(buf, len, 0);
    if (r == (ssize_t)len)
        return 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t total = 0;
    while (total < len)
    {
        ssize_t n = read(fd, (char *)buf + total, len - total);
        if (n <= 0)
        {
            close(fd);
            return -1;
        }
        total += n;
    }
    close(fd);
    return 0;
#elif defined(_WIN32)
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
#else
    arc4random_buf(buf, len);
    return 0;
#endif
}

static inline libp2p_ping_err_t map_conn_err(ssize_t v)
{
    switch ((libp2p_conn_err_t)v)
    {
        case LIBP2P_CONN_ERR_TIMEOUT:
            return LIBP2P_PING_ERR_TIMEOUT;
        case LIBP2P_CONN_ERR_AGAIN:
            return LIBP2P_PING_ERR_IO;
        case LIBP2P_CONN_ERR_EOF:
        case LIBP2P_CONN_ERR_CLOSED:
        case LIBP2P_CONN_ERR_INTERNAL:
        default:
            return LIBP2P_PING_ERR_IO;
    }
}

static libp2p_ping_err_t conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    while (len)
    {
        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            /* Caller sets deadline; rely on transport to block */
            continue;
        }
        return map_conn_err(n);
    }
    return LIBP2P_PING_OK;
}

static libp2p_ping_err_t conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
{
    while (len)
    {
        ssize_t n = libp2p_conn_read(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            /* Caller sets deadline; rely on transport to block */
            continue;
        }
        return map_conn_err(n);
    }
    return LIBP2P_PING_OK;
}

libp2p_ping_err_t libp2p_ping_roundtrip(libp2p_conn_t *conn, uint64_t timeout_ms, uint64_t *rtt_ms)
{
    if (!conn)
    {
        return LIBP2P_PING_ERR_NULL_PTR;
    }

    uint8_t payload[32];
    if (get_random_bytes(payload, sizeof(payload)) != 0)
    {
        return LIBP2P_PING_ERR_IO;
    }

    if (timeout_ms)
    {
        libp2p_conn_set_deadline(conn, timeout_ms);
    }

    uint64_t start = now_mono_ms();
    libp2p_ping_err_t rc = conn_write_all(conn, payload, sizeof(payload));
    if (rc != LIBP2P_PING_OK)
    {
        libp2p_conn_set_deadline(conn, 0);
        return rc;
    }

    uint8_t echo[32];
    rc = conn_read_exact(conn, echo, sizeof(echo));
    libp2p_conn_set_deadline(conn, 0);
    if (rc != LIBP2P_PING_OK)
    {
        return rc;
    }

    if (memcmp(payload, echo, sizeof(payload)) != 0)
    {
        return LIBP2P_PING_ERR_UNEXPECTED;
    }

    if (rtt_ms)
    {
        *rtt_ms = now_mono_ms() - start;
    }
    return LIBP2P_PING_OK;
}

libp2p_ping_err_t libp2p_ping_serve(libp2p_conn_t *conn)
{
    if (!conn)
    {
        return LIBP2P_PING_ERR_NULL_PTR;
    }
    uint8_t buf[32];
    for (;;)
    {
        libp2p_ping_err_t rc = conn_read_exact(conn, buf, sizeof(buf));
        if (rc != LIBP2P_PING_OK)
        {
            /* EOF means remote closed write end - stop gracefully */
            if (rc == LIBP2P_PING_ERR_IO)
            {
                return rc;
            }
            return LIBP2P_PING_OK;
        }
        rc = conn_write_all(conn, buf, sizeof(buf));
        if (rc != LIBP2P_PING_OK)
        {
            return rc;
        }
    }
}

/* ----------------- Stream-based helpers ----------------- */

static inline libp2p_ping_err_t map_stream_err(ssize_t v)
{
    switch ((int)v)
    {
        case LIBP2P_ERR_TIMEOUT:
            return LIBP2P_PING_ERR_TIMEOUT;
        case LIBP2P_ERR_AGAIN:
            return LIBP2P_PING_ERR_IO;
        default:
            if (v <= 0)
                return LIBP2P_PING_ERR_IO;
            return LIBP2P_PING_OK;
    }
}

/* Event-driven variant: avoid sleeping on EAGAIN by arming per-iteration
 * deadlines. If overall_deadline_ms is non-zero, it is treated as an
 * absolute CLOCK_MONOTONIC timestamp; otherwise a modest per-iteration
 * wait (1s) is used. */
static libp2p_ping_err_t stream_write_all(libp2p_stream_t *s, const uint8_t *buf, size_t len, uint64_t overall_deadline_ms)
{
    while (len)
    {
        /* Compute a per-iteration wait window */
        uint64_t wait_ms = 1000; /* default 1s slice */
        if (overall_deadline_ms)
        {
            uint64_t now = now_mono_ms();
            if (now >= overall_deadline_ms)
            {
                LP_LOGD("PING", "read timeout stream=%p", (void *)s);
                return LIBP2P_PING_ERR_TIMEOUT;
            }
            uint64_t remain = overall_deadline_ms - now;
            if (remain < wait_ms)
                wait_ms = remain;
        }
        (void)libp2p_stream_set_deadline(s, wait_ms);

        ssize_t n = libp2p_stream_write(s, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            /* Try again; deadline blocks until writable. */
            continue;
        }
        fprintf(stderr, "[PING] stream_write_all error n=%zd\n", n);
        (void)libp2p_stream_set_deadline(s, 0);
        return map_stream_err(n);
    }
    (void)libp2p_stream_set_deadline(s, 0);
    return LIBP2P_PING_OK;
}

static libp2p_ping_err_t stream_read_exact(libp2p_stream_t *s, uint8_t *buf, size_t len, uint64_t overall_deadline_ms)
{
    while (len)
    {
        /* Compute a per-iteration wait window */
        uint64_t wait_ms = 1000; /* default 1s slice */
        if (overall_deadline_ms)
        {
            uint64_t now = now_mono_ms();
            if (now >= overall_deadline_ms)
                return LIBP2P_PING_ERR_TIMEOUT;
            uint64_t remain = overall_deadline_ms - now;
            if (remain < wait_ms)
                wait_ms = remain;
        }
        (void)libp2p_stream_set_deadline(s, wait_ms);

        LP_LOGD("PING", "read attempt stream=%p len=%zu wait_ms=%" PRIu64, (void *)s, len, wait_ms);
        ssize_t n = libp2p_stream_read(s, buf, len);
        LP_LOGD("PING", "read returned stream=%p n=%zd", (void *)s, n);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_ERR_AGAIN)
        {
            LP_LOGD("PING", "read would-block stream=%p", (void *)s);
            /* Try again; deadline blocks until readable. */
            continue;
        }
        if (n == 0 || n == LIBP2P_ERR_EOF || n == LIBP2P_ERR_CLOSED || n == LIBP2P_ERR_RESET || n == LIBP2P_ERR_NULL_PTR)
        {
            LP_LOGD("PING", "stream closed stream=%p rc=%zd", (void *)s, n);
            (void)libp2p_stream_set_deadline(s, 0);
            return LIBP2P_PING_OK;
        }
        fprintf(stderr, "[PING] stream_read_exact error n=%zd\n", n);
        (void)libp2p_stream_set_deadline(s, 0);
        return map_stream_err(n);
    }
    (void)libp2p_stream_set_deadline(s, 0);
    return LIBP2P_PING_OK;
}

libp2p_ping_err_t libp2p_ping_roundtrip_stream(libp2p_stream_t *s, uint64_t timeout_ms, uint64_t *rtt_ms)
{
    if (!s)
        return LIBP2P_PING_ERR_NULL_PTR;
    uint8_t payload[32];
    if (get_random_bytes(payload, sizeof(payload)) != 0)
        return LIBP2P_PING_ERR_IO;
    uint64_t start = now_mono_ms();
    uint64_t deadline = timeout_ms ? (start + timeout_ms) : 0;
    LP_LOGD("PING", "roundtrip begin stream=%p timeout_ms=%" PRIu64, (void *)s, timeout_ms);
    libp2p_ping_err_t rc = stream_write_all(s, payload, sizeof(payload), deadline);
    if (rc != LIBP2P_PING_OK)
    {
        LP_LOGD("PING", "write failed rc=%d", rc);
        return rc;
    }
    LP_LOGD("PING", "write complete stream=%p", (void *)s);
    uint8_t echo[32];
    rc = stream_read_exact(s, echo, sizeof(echo), deadline);
    if (rc != LIBP2P_PING_OK)
    {
        LP_LOGD("PING", "read failed rc=%d", rc);
        return rc;
    }
    LP_LOGD("PING", "read complete stream=%p", (void *)s);
    if (memcmp(payload, echo, sizeof(payload)) != 0)
        return LIBP2P_PING_ERR_UNEXPECTED;
    if (rtt_ms)
        *rtt_ms = now_mono_ms() - start;
    LP_LOGD("PING", "roundtrip ok stream=%p rtt_ms=%" PRIu64, (void *)s, rtt_ms ? *rtt_ms : 0);
    return LIBP2P_PING_OK;
}

libp2p_ping_err_t libp2p_ping_serve_stream(libp2p_stream_t *s)
{
    if (!s)
        return LIBP2P_PING_ERR_NULL_PTR;
    uint8_t buf[32];
    for (;;)
    {
        /* No external timeout: use modest per-iteration waits in helpers */
        libp2p_ping_err_t rc = stream_read_exact(s, buf, sizeof(buf), 0);
        if (rc != LIBP2P_PING_OK)
        {
            if (rc == LIBP2P_PING_ERR_IO)
                return rc;
            return LIBP2P_PING_OK;
        }
        rc = stream_write_all(s, buf, sizeof(buf), 0);
        if (rc != LIBP2P_PING_OK)
            return rc;
    }
}

typedef struct ping_srv_ctx
{
    libp2p_stream_t *s;
    struct libp2p_host *host;
} ping_srv_ctx_t;

static void *ping_srv_thread(void *arg)
{
    ping_srv_ctx_t *ctx = (ping_srv_ctx_t *)arg;
    if (!ctx)
        return NULL;
    libp2p_stream_t *s = ctx->s;
    struct libp2p_host *host = ctx->host;
    free(ctx);
    (void)libp2p_ping_serve_stream(s);
    if (s)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
    }
    if (host)
    {
        libp2p__worker_dec(host);
    }
    return NULL;
}

static void ping_on_open(libp2p_stream_t *s, void *ud)
{
    (void)ud;
    ping_srv_ctx_t *ctx = (ping_srv_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        if (s)
        {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }
    ctx->s = s;
    struct libp2p_host *host = libp2p__stream_host(s);
    ctx->host = host;
    /* Ensure inbound QUIC streams start delivering payload bytes immediately. */
    libp2p_stream_set_read_interest(s, true);
    /* account for detached worker lifetimes so host_free waits safely */
    if (host)
        libp2p__worker_inc(host);
    pthread_t th;
    if (pthread_create(&th, NULL, ping_srv_thread, ctx) == 0)
    {
        pthread_detach(th);
        return;
    }
    if (host)
        libp2p__worker_dec(host);
    free(ctx);
    if (s)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
    }

}
int libp2p_ping_service_start(struct libp2p_host *host, libp2p_protocol_server_t **out_server)
{
    if (!host || !out_server)
        return -1;
    libp2p_protocol_def_t def = {
        .protocol_id = LIBP2P_PING_PROTO_ID,
        .read_mode = LIBP2P_READ_PULL,
        .on_open = ping_on_open,
        .on_data = NULL,
        .on_eof = NULL,
        .on_close = NULL,
        .on_error = NULL,
        .user_data = NULL,
    };
    return libp2p_host_listen_protocol(host, &def, out_server);
}

int libp2p_ping_service_stop(struct libp2p_host *host, libp2p_protocol_server_t *server)
{
    if (!host || !server)
        return -1;
    return libp2p_host_unlisten(host, server);
}
