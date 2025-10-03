#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include "protocol_mplex_write_queue.h"
#include "libp2p/log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Forward declaration
static int conn_write_partial(libp2p_conn_t *conn, const uint8_t *buf, size_t len, size_t *written);
static void dump_bytes(const char *tag, const uint8_t *buf, size_t len, size_t max)
{
    if (!buf || len == 0)
        return;

    size_t n = len < max ? len : max;
    char line[256];
    size_t pos = 0;
    if (tag)
        pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%s:", tag);

    for (size_t i = 0; i < n && pos < sizeof(line); i++)
    {
        pos += (size_t)snprintf(line + pos, sizeof(line) - pos, " %02x", buf[i]);
    }

    if (n < len && pos < sizeof(line))
        (void)snprintf(line + pos, sizeof(line) - pos, " ...(%zu)", len);

    LP_LOGT("MPLEX_SEND", "%s", line);
}

int libp2p_mplex_send_frame_nonblocking(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_frame_t *frame)
{
    if (!ctx || !frame)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (frame->data_len > LIBP2P_MPLEX_MAX_MESSAGE)
        return LIBP2P_MPLEX_ERR_PROTOCOL;

    // Serialize send path to prevent frame interleaving and race on pending buffer
    pthread_mutex_lock(&ctx->mutex);

    // If there is a pending write buffer from a previous partial send, flush it first
    if (ctx->pending_write_buf && ctx->pending_write_off < ctx->pending_write_len)
    {
        size_t remain = ctx->pending_write_len - ctx->pending_write_off;
        size_t pushed = 0;
        int prc = conn_write_partial(ctx->conn, ctx->pending_write_buf + ctx->pending_write_off, remain, &pushed);
        LP_LOGT("MPLEX_SEND", "flush pending ctx=%p pushed=%zu remain_before=%zu rc=%d", (void *)ctx, pushed, remain, prc);
        ctx->pending_write_off += pushed;
        if (prc == LIBP2P_MPLEX_ERR_AGAIN)
        {
            atomic_store(&ctx->want_write, true);
            pthread_mutex_unlock(&ctx->mutex);
            return LIBP2P_MPLEX_ERR_AGAIN;
        }
        if (prc != LIBP2P_MPLEX_OK)
        {
            pthread_mutex_unlock(&ctx->mutex);
            return prc;
        }
        // If fully flushed, free buffer
        if (ctx->pending_write_off >= ctx->pending_write_len)
        {
            LP_LOGT("MPLEX_SEND", "pending drained ctx=%p", (void *)ctx);
            free(ctx->pending_write_buf);
            ctx->pending_write_buf = NULL;
            ctx->pending_write_len = 0;
            ctx->pending_write_off = 0;
        }
    }

    // Encode the entire frame into a single contiguous buffer to guarantee atomic framing when possible
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    int enc_rc = libp2p_mplex_encode_frame(frame, &encoded, &encoded_len);
    if (enc_rc != LIBP2P_MPLEX_OK)
    {
        pthread_mutex_unlock(&ctx->mutex);
        return enc_rc;
    }
    // Debug: dump first bytes of encoded frame
    if (encoded && encoded_len)
        dump_bytes("[MPLEX_SEND] encoded", encoded, encoded_len, 32);

    // Try to send encoded buffer
    size_t written = 0;
    int rc = conn_write_partial(ctx->conn, encoded, encoded_len, &written);
    LP_LOGT("MPLEX_SEND", "write attempt ctx=%p flag=%u id=%llu total=%zu wrote=%zu rc=%d", (void *)ctx, (unsigned)frame->flag,
            (unsigned long long)frame->id, encoded_len, written, rc);
    if (rc != LIBP2P_MPLEX_OK && rc != LIBP2P_MPLEX_ERR_AGAIN)
    {
        LP_LOGW("MPLEX_SEND", "write error rc=%d (written=%zu of %zu)", rc, written, encoded_len);
    }

    // If we couldn't write the full buffer due to EAGAIN, stash the remainder and signal want_write
    if (rc == LIBP2P_MPLEX_ERR_AGAIN)
    {
        atomic_store(&ctx->want_write, true);
        libp2p_mplex_wake(ctx);
        size_t remain = encoded_len - written;
        ctx->pending_write_buf = malloc(remain);
        if (!ctx->pending_write_buf)
        {
            free(encoded);
            pthread_mutex_unlock(&ctx->mutex);
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }
        memcpy(ctx->pending_write_buf, encoded + written, remain);
        ctx->pending_write_len = remain;
        ctx->pending_write_off = 0;
        LP_LOGT("MPLEX_SEND", "stashed pending ctx=%p remain=%zu", (void *)ctx, remain);
        free(encoded);
        pthread_mutex_unlock(&ctx->mutex);
        return LIBP2P_MPLEX_ERR_AGAIN;
    }

    // If we got any other error, return it immediately
    if (rc != LIBP2P_MPLEX_OK)
    {
        free(encoded);
        pthread_mutex_unlock(&ctx->mutex);
        return rc;
    }

    // Success path
    free(encoded);
    pthread_mutex_unlock(&ctx->mutex);

    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_flush_writes(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    // Process all pending writes
    while (1)
    {
        // First flush any pending contiguous buffer
        if (ctx->pending_write_buf && ctx->pending_write_off < ctx->pending_write_len)
        {
            pthread_mutex_lock(&ctx->mutex);
            size_t remain = ctx->pending_write_len - ctx->pending_write_off;
            size_t pushed = 0;
            int prc = conn_write_partial(ctx->conn, ctx->pending_write_buf + ctx->pending_write_off, remain, &pushed);
            LP_LOGT("MPLEX_SEND", "flush pending (loop) ctx=%p pushed=%zu remain_before=%zu rc=%d", (void *)ctx, pushed, remain, prc);
            ctx->pending_write_off += pushed;
            if (prc == LIBP2P_MPLEX_ERR_AGAIN)
            {
                pthread_mutex_unlock(&ctx->mutex);
                libp2p_mplex_wake(ctx);
                return LIBP2P_MPLEX_ERR_AGAIN;
            }
            if (prc != LIBP2P_MPLEX_OK)
            {
                pthread_mutex_unlock(&ctx->mutex);
                return prc;
            }
            if (ctx->pending_write_off >= ctx->pending_write_len)
            {
                LP_LOGT("MPLEX_SEND", "pending drained (loop) ctx=%p", (void *)ctx);
                free(ctx->pending_write_buf);
                ctx->pending_write_buf = NULL;
                ctx->pending_write_len = 0;
                ctx->pending_write_off = 0;
            }
            pthread_mutex_unlock(&ctx->mutex);
        }

        libp2p_mplex_frame_t *frame = libp2p_mplex_write_queue_pop(&ctx->write_queue);
        if (!frame)
            break;

        int rc = libp2p_mplex_send_frame_nonblocking(ctx, frame);
        libp2p_mplex_frame_free(frame);
        free(frame);

        // If we get EAGAIN, put the frame back and stop for now
        if (rc == LIBP2P_MPLEX_ERR_AGAIN)
        {
            // In a real implementation, we'd need to handle partial sends
            // For now, we'll just return and let the event loop call us again
            libp2p_mplex_wake(ctx);
            return LIBP2P_MPLEX_ERR_AGAIN;
        }

        if (rc != LIBP2P_MPLEX_OK)
        {
            return rc;
        }
    }

    // No more pending writes
    atomic_store(&ctx->want_write, false);
    libp2p_mplex_wake(ctx);

    // Trigger write ready events for all streams that might be waiting
    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->streams.length; i++)
    {
        libp2p_mplex_stream_t *stream = ctx->streams.streams[i];
        if (stream && stream->write_ready_callback)
        {
            // Unlock mutex before calling callback to avoid deadlocks
            pthread_mutex_unlock(&ctx->mutex);
            libp2p_mplex_trigger_write_ready_event(stream);
            pthread_mutex_lock(&ctx->mutex);
        }
    }
    pthread_mutex_unlock(&ctx->mutex);

    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_encode_frame(const libp2p_mplex_frame_t *frame, uint8_t **out_encoded_data, size_t *out_encoded_len)
{
    if (!frame || !out_encoded_data || !out_encoded_len)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    // Do not enforce maximum message length here to allow tests to craft
    // intentionally malformed frames (e.g. oversized length) for inbound
    // protocol validation. Sending paths perform their own length checks.

    // Encode header: (stream_id << 3) | flag
    uint64_t header = (frame->id << 3) | (frame->flag & 0x07);
    uint8_t header_buf[10];
    size_t header_len;

    unsigned_varint_err_t err = unsigned_varint_encode(header, header_buf, sizeof(header_buf), &header_len);
    if (err != UNSIGNED_VARINT_OK)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Encode payload length
    uint8_t len_buf[10];
    size_t len_len;

    err = unsigned_varint_encode(frame->data_len, len_buf, sizeof(len_buf), &len_len);
    if (err != UNSIGNED_VARINT_OK)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Allocate frame buffer. If the caller did not provide a payload pointer,
    // only encode the header and length varint to allow crafting frames for
    // protocol tests without allocating/copying large payloads.
    size_t payload_bytes = (frame->data && frame->data_len > 0) ? frame->data_len : 0;
    *out_encoded_len = header_len + len_len + payload_bytes;
    *out_encoded_data = malloc(*out_encoded_len);
    if (!*out_encoded_data)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Copy components
    memcpy(*out_encoded_data, header_buf, header_len);
    memcpy(*out_encoded_data + header_len, len_buf, len_len);
    if (payload_bytes > 0)
        memcpy(*out_encoded_data + header_len + len_len, frame->data, payload_bytes);

    return LIBP2P_MPLEX_OK;
}

// Helper function to write data with proper EAGAIN handling
static int conn_write_partial(libp2p_conn_t *conn, const uint8_t *buf, size_t len, size_t *written)
{
    if (!conn || !buf || !written)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    *written = 0;

    while (*written < len)
    {
        ssize_t n = libp2p_conn_write(conn, buf + *written, len - *written);
        if (n > 0)
        {
            *written += (size_t)n;
            // If we wrote everything, return success; otherwise we'll attempt
            // another immediate write below. If that would block, we report
            // EAGAIN to let the caller stash the remainder for later.
            if (*written >= len)
                return LIBP2P_MPLEX_OK;
            continue;
        }

        // Underlying connection closed/EOF → propagate as EOF
        if (n == LIBP2P_CONN_ERR_EOF || n == LIBP2P_CONN_ERR_CLOSED)
        {
            return LIBP2P_MPLEX_ERR_EOF;
        }

        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            // Non-blocking: do not spin; report partial progress and return
            // EAGAIN so the caller can queue the remainder and wait for
            // writable notification.
            return LIBP2P_MPLEX_ERR_AGAIN;
        }

        // Any other error: map to internal error and break
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    return LIBP2P_MPLEX_OK;
}
