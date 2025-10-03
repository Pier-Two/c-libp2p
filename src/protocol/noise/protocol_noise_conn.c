#include "protocol/noise/protocol_noise_conn.h"
#include <noise/protocol/constants.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "libp2p/log.h"

#define NOISE_MAX_READ_ERROR_LOGS 4

#define NOISE_LOG_READ_ERROR(ctx, fmt, ...)                                                                      \
    do                                                                                                           \
    {                                                                                                            \
        if ((ctx) && (ctx)->read_error_logs < NOISE_MAX_READ_ERROR_LOGS)                                        \
        {                                                                                                        \
            LP_LOGE("NOISE", fmt, ##__VA_ARGS__);                                                               \
            (ctx)->read_error_logs++;                                                                            \
            if ((ctx)->read_error_logs == NOISE_MAX_READ_ERROR_LOGS)                                             \
                LP_LOGW("NOISE", "suppressing further noise read errors for this connection");                \
        }                                                                                                        \
    } while (0)

#include "protocol/noise/protocol_noise_extensions.h"
#include <time.h>

/* Local monotonic ms helper to avoid cross-module linkage. */
static inline uint64_t local_now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static libp2p_conn_err_t read_exact_bounded_conn(libp2p_conn_t *rc, uint8_t *dst, size_t need, uint64_t fallback_ms)
{
    if (!rc || !dst)
        return LIBP2P_CONN_ERR_NULL_PTR;
    const uint64_t FALLBACK_MS = (fallback_ms > 0) ? fallback_ms : 2000;
    uint64_t start = local_now_mono_ms();
    size_t off = 0;
    while (off < need)
    {
        uint64_t elapsed = local_now_mono_ms() - start;
        uint64_t remain = (elapsed < FALLBACK_MS) ? (FALLBACK_MS - elapsed) : 0;
        if (remain == 0)
            return LIBP2P_CONN_ERR_TIMEOUT;
        libp2p_conn_set_deadline(rc, remain);
        ssize_t r = libp2p_conn_read(rc, dst + off, need - off);
        if (r > 0)
        {
            off += (size_t)r;
            start = local_now_mono_ms();
            continue;
        }
        if (r == LIBP2P_CONN_ERR_AGAIN)
            continue;
        libp2p_conn_set_deadline(rc, 0);
        return (libp2p_conn_err_t)r;
    }
    libp2p_conn_set_deadline(rc, 0);
    return LIBP2P_CONN_OK;
}
typedef struct noise_conn_ctx
{
    libp2p_conn_t *raw;
    NoiseCipherState *send;
    NoiseCipherState *recv;
    uint8_t *buf;
    size_t buf_len;
    size_t buf_pos;
    /* Debug-only: expected usage phase, e.g. "post_noise", "yamux_active" */
    char phase[24];
    /* In-progress inbound frame state */
    uint8_t hdr_tmp[2];
    size_t hdr_got;
    uint8_t *cipher_pending;
    uint16_t cipher_len;
    size_t cipher_got;
    uint8_t *early_data;
    size_t early_data_len;
    uint8_t *extensions;
    size_t extensions_len;
    noise_extensions_t *parsed_ext;
    size_t max_plaintext;
    uint64_t send_count;
    uint64_t recv_count;
    unsigned read_error_logs;
    /* Serialize writes so 2-byte header + ciphertext are not interleaved
     * across threads on the underlying stream. */
    pthread_mutex_t write_mtx;
    /* Serialize reads so header/cipher accumulation state is not corrupted
     * by concurrent readers. */
    pthread_mutex_t read_mtx;
} noise_conn_ctx_t;

static ssize_t noise_conn_read(libp2p_conn_t *c, void *buf, size_t len)
{
    noise_conn_ctx_t *ctx = c->ctx;
    pthread_mutex_lock(&ctx->read_mtx);
    if (ctx->recv_count == UINT64_MAX)
    {
        libp2p_conn_close(ctx->raw);
        pthread_mutex_unlock(&ctx->read_mtx);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    if (ctx->buf_len > ctx->buf_pos)
    {
        size_t avail = ctx->buf_len - ctx->buf_pos;
        size_t n = len < avail ? len : avail;
        memcpy(buf, ctx->buf + ctx->buf_pos, n);
        ctx->buf_pos += n;
        if (ctx->buf_pos == ctx->buf_len)
        {
            free(ctx->buf);
            ctx->buf = NULL;
            ctx->buf_len = ctx->buf_pos = 0;
        }
        pthread_mutex_unlock(&ctx->read_mtx);
        return (ssize_t)n;
    }

    /* Accumulate Noise frame header (2 bytes) */
    while (ctx->hdr_got < 2)
    {
        ssize_t r = libp2p_conn_read(ctx->raw, ctx->hdr_tmp + ctx->hdr_got, 2 - ctx->hdr_got);
        if (r > 0)
        {
            ctx->hdr_got += (size_t)r;
            continue;
        }
        if (r == LIBP2P_CONN_ERR_AGAIN || r == LIBP2P_CONN_ERR_TIMEOUT)
        {
            pthread_mutex_unlock(&ctx->read_mtx);
            return LIBP2P_CONN_ERR_AGAIN;
        }
        NOISE_LOG_READ_ERROR(ctx, "header read error r=%zd", r);
        pthread_mutex_unlock(&ctx->read_mtx);
        return r; /* EOF/CLOSED/INTERNAL */
    }
    uint16_t mlen = ((uint16_t)ctx->hdr_tmp[0] << 8) | ctx->hdr_tmp[1];
    if (!ctx->cipher_pending)
    {
        ctx->cipher_pending = (uint8_t *)malloc(mlen);
        if (!ctx->cipher_pending)
            return LIBP2P_CONN_ERR_INTERNAL;
        ctx->cipher_len = mlen;
        ctx->cipher_got = 0;
    }
    while (ctx->cipher_got < ctx->cipher_len)
    {
        ssize_t r = libp2p_conn_read(ctx->raw, ctx->cipher_pending + ctx->cipher_got, ctx->cipher_len - ctx->cipher_got);
        if (r > 0)
        {
            ctx->cipher_got += (size_t)r;
            continue;
        }
        if (r == LIBP2P_CONN_ERR_AGAIN || r == LIBP2P_CONN_ERR_TIMEOUT)
        {
            /* Non-fatal stall; keep partial state for next call */
            pthread_mutex_unlock(&ctx->read_mtx);
            return LIBP2P_CONN_ERR_AGAIN;
        }
        /* Fatal: EOF/CLOSED/INTERNAL */
        NOISE_LOG_READ_ERROR(ctx, "cipher read error r=%zd (mlen=%u got=%zu)", r, (unsigned)ctx->cipher_len, ctx->cipher_got);
        free(ctx->cipher_pending);
        ctx->cipher_pending = NULL;
        ctx->cipher_len = 0;
        ctx->cipher_got = 0;
        ctx->hdr_got = 0;
        pthread_mutex_unlock(&ctx->read_mtx);
        return r;
    }
    NoiseBuffer nb;
    noise_buffer_set_input(nb, ctx->cipher_pending, ctx->cipher_len);
    int err = noise_cipherstate_decrypt(ctx->recv, &nb);
    if (err == NOISE_ERROR_INVALID_NONCE)
    {
        NOISE_LOG_READ_ERROR(ctx, "decrypt INVALID_NONCE (recv_count=%llu)", (unsigned long long)ctx->recv_count);
        free(ctx->cipher_pending);
        ctx->cipher_pending = NULL;
        ctx->cipher_len = 0;
        ctx->cipher_got = 0;
        ctx->hdr_got = 0;
        libp2p_conn_close(ctx->raw);
        pthread_mutex_unlock(&ctx->read_mtx);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    if (err != NOISE_ERROR_NONE)
    {
        NOISE_LOG_READ_ERROR(ctx, "decrypt failed err=%d", err);
        free(ctx->cipher_pending);
        ctx->cipher_pending = NULL;
        ctx->cipher_len = 0;
        ctx->cipher_got = 0;
        ctx->hdr_got = 0;
        pthread_mutex_unlock(&ctx->read_mtx);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    ctx->recv_count++;
    size_t max_plain = ctx->max_plaintext ? ctx->max_plaintext : NOISE_MAX_PAYLOAD_LEN;
    if (nb.size > max_plain)
    {
        NOISE_LOG_READ_ERROR(ctx, "plaintext too large nb.size=%zu max_plain=%zu", (size_t)nb.size, max_plain);
        free(ctx->cipher_pending);
        ctx->cipher_pending = NULL;
        ctx->cipher_len = 0;
        ctx->cipher_got = 0;
        ctx->hdr_got = 0;
        pthread_mutex_unlock(&ctx->read_mtx);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    ctx->buf = malloc(nb.size);
    if (!ctx->buf)
    {
        NOISE_LOG_READ_ERROR(ctx, "malloc failed for plaintext size=%zu", (size_t)nb.size);
        free(ctx->cipher_pending);
        ctx->cipher_pending = NULL;
        ctx->cipher_len = 0;
        ctx->cipher_got = 0;
        ctx->hdr_got = 0;
        pthread_mutex_unlock(&ctx->read_mtx);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    memcpy(ctx->buf, nb.data, nb.size);
    LP_LOGT("NOISE", "read mlen=%u plain=%zu", (unsigned)ctx->cipher_len, (size_t)nb.size);
    free(ctx->cipher_pending);
    ctx->cipher_pending = NULL;
    ctx->cipher_len = 0;
    ctx->cipher_got = 0;
    ctx->hdr_got = 0;
    ctx->buf_len = nb.size;
    ctx->buf_pos = 0;
    size_t n = len < nb.size ? len : nb.size;
    memcpy(buf, ctx->buf, n);
    ctx->buf_pos = n;
    if (ctx->buf_pos == ctx->buf_len)
    {
        free(ctx->buf);
        ctx->buf = NULL;
        ctx->buf_len = ctx->buf_pos = 0;
    }
    pthread_mutex_unlock(&ctx->read_mtx);
    return (ssize_t)n;
}

static ssize_t noise_conn_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    noise_conn_ctx_t *ctx = c->ctx;
    pthread_mutex_lock(&ctx->write_mtx);
    if (ctx->send_count == UINT64_MAX)
    {
        libp2p_conn_close(ctx->raw);
        pthread_mutex_unlock(&ctx->write_mtx);
        return LIBP2P_CONN_ERR_CLOSED;
    }

    /* No pending buffered frames: we always fully flush an encrypted frame
     * before returning to preserve libp2p_conn_write semantics. */
    size_t mac_len = noise_cipherstate_get_mac_length(ctx->send);
    size_t max_allowed = NOISE_MAX_PAYLOAD_LEN - mac_len;
    size_t limit = ctx->max_plaintext && ctx->max_plaintext < max_allowed ? ctx->max_plaintext : max_allowed;
    if (len > limit)
    {
        pthread_mutex_unlock(&ctx->write_mtx);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    uint16_t mlen = (uint16_t)(len + mac_len);
    uint8_t *frame = NULL;
    uint8_t *payload = NULL;
    uint8_t *header = NULL;
    ssize_t ret = (ssize_t)len;

    /* Allocate slightly more than the frame size so we can align the
     * payload to a 32-bit boundary while still prefixing the two-byte
     * length header immediately before it. The noise reference
     * implementation casts the payload pointer to uint32_t* and
     * assumes natural alignment, so make sure we honour that contract
     * even when the header reserves two bytes. */
    size_t alloc_len = (size_t)mlen + 6;
    frame = (uint8_t *)malloc(alloc_len);
    if (!frame)
    {
        ret = LIBP2P_CONN_ERR_INTERNAL;
        goto out_unlock;
    }

    uintptr_t payload_addr = (uintptr_t)(frame + 2);
    const uintptr_t align_mask = (uintptr_t)3;
    payload_addr = (payload_addr + align_mask) & ~align_mask; /* align to 4 bytes */
    payload = (uint8_t *)payload_addr;
    header = payload - 2;

    if ((uintptr_t)(payload + mlen) > (uintptr_t)(frame + alloc_len))
    {
        free(frame);
        ret = LIBP2P_CONN_ERR_INTERNAL;
        goto out_unlock;
    }

    memcpy(payload, buf, len);
    NoiseBuffer nb;
    noise_buffer_set_inout(nb, payload, len, mlen);
    int err = noise_cipherstate_encrypt(ctx->send, &nb);
    if (err == NOISE_ERROR_INVALID_NONCE)
    {
        free(frame);
        libp2p_conn_close(ctx->raw);
        ret = LIBP2P_CONN_ERR_CLOSED;
        goto out_unlock;
    }
    if (err != NOISE_ERROR_NONE)
    {
        free(frame);
        ret = LIBP2P_CONN_ERR_INTERNAL;
        goto out_unlock;
    }
    header[0] = (uint8_t)(nb.size >> 8);
    header[1] = (uint8_t)nb.size;
    size_t total = nb.size + 2;
    size_t off = 0;
    LP_LOGT("NOISE", "write plain=%zu cipher_total=%zu", (size_t)len, total);
    /* Rely on caller-set deadlines on the underlying raw connection to block
     * efficiently between retries. Serialize the whole write under the mutex
     * to prevent interleaving with other writers. */
    while (off < total)
    {
        ssize_t rc = libp2p_conn_write(ctx->raw, header + off, total - off);
        if (rc > 0)
        {
            off += (size_t)rc;
            continue;
        }
        if (rc == LIBP2P_CONN_ERR_AGAIN)
        {
            /* Try again; deadline (if any) will block without spinning. */
            continue;
        }
        /* Fatal: free and propagate */
        free(frame);
        ret = rc;
        goto out_unlock;
    }
    free(frame);
    ctx->send_count++;
out_unlock:
    pthread_mutex_unlock(&ctx->write_mtx);
    return ret;
}

static libp2p_conn_err_t noise_conn_set_deadline(libp2p_conn_t *c, uint64_t ms)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_set_deadline(ctx->raw, ms);
}

static const multiaddr_t *noise_conn_local(libp2p_conn_t *c)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_local_addr(ctx->raw);
}

static const multiaddr_t *noise_conn_remote(libp2p_conn_t *c)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_remote_addr(ctx->raw);
}

const uint8_t *noise_conn_get_early_data(const libp2p_conn_t *c, size_t *len)
{
    if (!c)
        return NULL;
    noise_conn_ctx_t *ctx = c->ctx;
    if (len)
        *len = ctx->early_data_len;
    return ctx->early_data;
}

const uint8_t *noise_conn_get_extensions(const libp2p_conn_t *c, size_t *len)
{
    if (!c)
        return NULL;
    noise_conn_ctx_t *ctx = c->ctx;
    if (len)
        *len = ctx->extensions_len;
    return ctx->extensions;
}

const noise_extensions_t *noise_conn_get_parsed_extensions(const libp2p_conn_t *c)
{
    if (!c)
        return NULL;
    noise_conn_ctx_t *ctx = c->ctx;
    return ctx->parsed_ext;
}

static libp2p_conn_err_t noise_conn_close(libp2p_conn_t *c)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_close(ctx->raw);
}

static int noise_conn_get_fd(libp2p_conn_t *c)
{
    if (!c || !c->ctx)
        return -1;
    noise_conn_ctx_t *ctx = c->ctx;
    // Delegate to the underlying raw connection's get_fd
    if (ctx->raw && ctx->raw->vt && ctx->raw->vt->get_fd)
        return ctx->raw->vt->get_fd(ctx->raw);
    return -1;
}

static void noise_conn_free(libp2p_conn_t *c)
{
    if (!c)
        return;
    noise_conn_ctx_t *ctx = c->ctx;
    if (ctx)
    {
        noise_cipherstate_free(ctx->send);
        noise_cipherstate_free(ctx->recv);
        libp2p_conn_free(ctx->raw);
        free(ctx->buf);
        free(ctx->cipher_pending);
        free(ctx->early_data);
        free(ctx->extensions);
        noise_extensions_free(ctx->parsed_ext);
        pthread_mutex_destroy(&ctx->write_mtx);
        pthread_mutex_destroy(&ctx->read_mtx);
        free(ctx);
    }
    free(c);
}

static const libp2p_conn_vtbl_t NOISE_CONN_VTBL = {
    .read = noise_conn_read,
    .write = noise_conn_write,
    .set_deadline = noise_conn_set_deadline,
    .local_addr = noise_conn_local,
    .remote_addr = noise_conn_remote,
    .close = noise_conn_close,
    .free = noise_conn_free,
    .get_fd = noise_conn_get_fd,
};

libp2p_conn_t *make_noise_conn(libp2p_conn_t *raw, NoiseCipherState *send, NoiseCipherState *recv, size_t max_plaintext, uint8_t *early_data,
                               size_t early_data_len, uint8_t *extensions, size_t extensions_len, noise_extensions_t *parsed_ext)
{
    if (!raw || !send || !recv)
    {
        LP_LOGE("NOISE", "make_noise_conn: NULL input (raw=%p, send=%p, recv=%p)", raw, send, recv);
        return NULL;
    }
    noise_conn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        LP_LOGE("NOISE", "make_noise_conn: calloc for ctx failed");
        return NULL;
    }
    uint8_t *early_copy = NULL;
    if (early_data && early_data_len > 0)
    {
        early_copy = (uint8_t *)malloc(early_data_len);
        if (!early_copy)
        {
            LP_LOGE("NOISE", "make_noise_conn: malloc early_data copy failed");
            free(ctx);
            return NULL;
        }
        memcpy(early_copy, early_data, early_data_len);
    }

    uint8_t *ext_copy = NULL;
    if (extensions && extensions_len > 0)
    {
        ext_copy = (uint8_t *)malloc(extensions_len);
        if (!ext_copy)
        {
            LP_LOGE("NOISE", "make_noise_conn: malloc extensions copy failed");
            free(early_copy);
            free(ctx);
            return NULL;
        }
        memcpy(ext_copy, extensions, extensions_len);
    }

    ctx->raw = raw;
    ctx->send = send;
    ctx->recv = recv;
    ctx->max_plaintext = max_plaintext;
    ctx->send_count = 0;
    ctx->recv_count = 0;
    ctx->phase[0] = '\0';
    ctx->hdr_got = 0;
    ctx->cipher_pending = NULL;
    ctx->cipher_len = 0;
    ctx->cipher_got = 0;
    ctx->early_data = early_copy;
    ctx->early_data_len = early_data_len;
    ctx->extensions = ext_copy;
    ctx->extensions_len = extensions_len;
    ctx->parsed_ext = parsed_ext;
    pthread_mutex_init(&ctx->write_mtx, NULL);
    pthread_mutex_init(&ctx->read_mtx, NULL);
    libp2p_conn_t *c = calloc(1, sizeof(*c));
    if (!c)
    {
        LP_LOGE("NOISE", "make_noise_conn: calloc for c failed");
        free(early_copy);
        free(ext_copy);
        free(ctx);
        return NULL;
    }
    c->vt = &NOISE_CONN_VTBL;
    c->ctx = ctx;
    return c;
}

void noise_conn_debug_set_phase(libp2p_conn_t *c, const char *phase)
{
    if (!c || !c->ctx || !phase)
        return;
    noise_conn_ctx_t *ctx = (noise_conn_ctx_t *)c->ctx;
    /* Best-effort copy */
    size_t n = strlen(phase);
    if (n >= sizeof(ctx->phase))
        n = sizeof(ctx->phase) - 1;
    memcpy(ctx->phase, phase, n);
    ctx->phase[n] = '\0';
}

const char *noise_conn_debug_get_phase(const libp2p_conn_t *c)
{
    if (!c || !c->ctx)
        return NULL;
    const noise_conn_ctx_t *ctx = (const noise_conn_ctx_t *)c->ctx;
    return ctx->phase[0] ? ctx->phase : NULL;
}

size_t noise_conn_debug_get_max_plaintext(const libp2p_conn_t *c)
{
    if (!c || !c->ctx)
        return 0;
    const noise_conn_ctx_t *ctx = (const noise_conn_ctx_t *)c->ctx;
    return ctx->max_plaintext;
}

void noise_conn_debug_set_send_count(libp2p_conn_t *c, uint64_t count)
{
    if (!c || !c->ctx)
        return;
    noise_conn_ctx_t *ctx = (noise_conn_ctx_t *)c->ctx;
    pthread_mutex_lock(&ctx->write_mtx);
    ctx->send_count = count;
    pthread_mutex_unlock(&ctx->write_mtx);
}

void noise_conn_debug_set_recv_count(libp2p_conn_t *c, uint64_t count)
{
    if (!c || !c->ctx)
        return;
    noise_conn_ctx_t *ctx = (noise_conn_ctx_t *)c->ctx;
    pthread_mutex_lock(&ctx->read_mtx);
    ctx->recv_count = count;
    pthread_mutex_unlock(&ctx->read_mtx);
}
