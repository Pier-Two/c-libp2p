#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int libp2p_mplex_stream_open(libp2p_mplex_ctx_t *ctx, const uint8_t *name, size_t name_len, libp2p_mplex_stream_t **out_stream)
{
    if (!ctx || !out_stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (!ctx->negotiated)
        return LIBP2P_MPLEX_ERR_HANDSHAKE;

    pthread_mutex_lock(&ctx->mutex);

    // Check stream ID limit
    if (ctx->next_stream_id >= LIBP2P_MPLEX_MAX_STREAM_ID)
    {
        pthread_mutex_unlock(&ctx->mutex);
        return LIBP2P_MPLEX_ERR_PROTOCOL;
    }

    // Allocate new stream ID
    uint64_t stream_id = ctx->next_stream_id++;

    // Create stream object
    libp2p_mplex_stream_t *stream = libp2p_mplex_stream_new(stream_id, name, name_len, true, ctx);
    if (!stream)
    {
        ctx->next_stream_id--; // Rollback
        pthread_mutex_unlock(&ctx->mutex);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    // Add to active streams
    if (libp2p_mplex_stream_array_add(&ctx->streams, stream) != LIBP2P_MPLEX_OK)
    {
        libp2p_mplex_stream_free(stream);
        ctx->next_stream_id--; // Rollback
        pthread_mutex_unlock(&ctx->mutex);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    pthread_mutex_unlock(&ctx->mutex);

    // Prepare NEW_STREAM frame
    libp2p_mplex_frame_t frame = {.id = stream_id, .flag = LIBP2P_MPLEX_FRAME_NEW_STREAM, .data = (uint8_t *)name, .data_len = name_len};

    // If there is pending data or we already want write, enqueue to preserve order
    if (ctx->pending_write_buf != NULL || atomic_load(&ctx->want_write))
    {
        int qrc = libp2p_mplex_write_queue_push(&ctx->write_queue, &frame);
        if (qrc != LIBP2P_MPLEX_OK)
        {
            // Roll back: remove from streams array and free
            pthread_mutex_lock(&ctx->mutex);
            size_t index;
            if (libp2p_mplex_find_stream(ctx, stream_id, true, &index) != NULL)
            {
                libp2p_mplex_stream_array_remove(&ctx->streams, index);
                libp2p_mplex_stream_free(stream);
            }
            pthread_mutex_unlock(&ctx->mutex);
            return qrc;
        }
        atomic_store(&ctx->want_write, true);
        (void)libp2p_mplex_flush_writes(ctx);
        *out_stream = stream;
        return LIBP2P_MPLEX_OK;
    }

    // Fast path: attempt immediate send
    int rc = libp2p_mplex_send_frame_nonblocking(ctx, &frame);
    if (rc == LIBP2P_MPLEX_OK)
    {
        *out_stream = stream;
        return LIBP2P_MPLEX_OK;
    }
    if (rc == LIBP2P_MPLEX_ERR_AGAIN)
    {
        // Remainder was stashed by the send routine; mark want_write and succeed
        atomic_store(&ctx->want_write, true);
        *out_stream = stream;
        return LIBP2P_MPLEX_OK;
    }

    // Hard failure: roll back stream allocation
    pthread_mutex_lock(&ctx->mutex);
    size_t index;
    if (libp2p_mplex_find_stream(ctx, stream_id, true, &index) != NULL)
    {
        libp2p_mplex_stream_array_remove(&ctx->streams, index);
        libp2p_mplex_stream_free(stream);
    }
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

int libp2p_mplex_accept_stream(libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t **out_stream)
{
    if (!ctx || !out_stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (!ctx->negotiated)
        return LIBP2P_MPLEX_ERR_HANDSHAKE;

    // Try to pop a stream from the incoming queue
    libp2p_mplex_stream_t *stream = libp2p_mplex_stream_queue_pop(&ctx->incoming);
    if (!stream)
        return LIBP2P_MPLEX_ERR_AGAIN;

    *out_stream = stream;
    return LIBP2P_MPLEX_OK;
}

libp2p_mplex_ssize_t libp2p_mplex_stream_read(libp2p_mplex_stream_t *stream, void *buf, size_t max_len)
{
    if (!stream || !buf)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (max_len == 0)
        return 0;

    pthread_mutex_lock(&stream->lock);

    libp2p_mplex_ctx_t *ctx = stream->ctx;
    if (!ctx)
    {
        pthread_mutex_unlock(&stream->lock);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    // Check stream state
    if (stream->state & LIBP2P_MPLEX_STREAM_STATE_RESET)
    {
        pthread_mutex_unlock(&stream->lock);
        return LIBP2P_MPLEX_ERR_RESET;
    }

    // Check if we have data available. If empty and no dedicated background
    // loop is running (dialer case), opportunistically pump once here to make
    // progress during synchronous negotiations invoked from the runtime thread
    // (listener case). This avoids races with a concurrent loop thread while
    // still letting single-threaded runtimes progress handshakes.
    if (stream->queued == 0)
    {
        if (!ctx->loop_thread_started)
        {
            pthread_mutex_unlock(&stream->lock);
            (void)libp2p_mplex_on_readable(ctx);
            pthread_mutex_lock(&stream->lock);
            ctx = stream->ctx;
            if (!ctx)
            {
                pthread_mutex_unlock(&stream->lock);
                return LIBP2P_MPLEX_ERR_INTERNAL;
            }
        }
        if (stream->queued == 0)
        {
            if (stream->state & LIBP2P_MPLEX_STREAM_REMOTE_CLOSED)
            {
                pthread_mutex_unlock(&stream->lock);
                return 0; // EOF
            }
            pthread_mutex_unlock(&stream->lock);
            return LIBP2P_MPLEX_ERR_AGAIN;
        }
    }

    // Copy data from slice buffer
    size_t to_copy = mplex_stream_dequeue(stream, buf, max_len);

    pthread_mutex_unlock(&stream->lock);

    return (libp2p_mplex_ssize_t)to_copy;
}

int libp2p_mplex_stream_close(libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    pthread_mutex_lock(&stream->lock);

    // Check if already closed or reset
    if (stream->state & LIBP2P_MPLEX_STREAM_STATE_RESET)
    {
        pthread_mutex_unlock(&stream->lock);
        return LIBP2P_MPLEX_ERR_RESET;
    }

    if (stream->state & LIBP2P_MPLEX_STREAM_LOCAL_CLOSED)
    {
        pthread_mutex_unlock(&stream->lock);
        return LIBP2P_MPLEX_OK; // Already closed
    }

    // Mark as locally closed
    stream->state |= LIBP2P_MPLEX_STREAM_LOCAL_CLOSED;

    pthread_mutex_unlock(&stream->lock);

    // Send close frame
    libp2p_mplex_frame_t frame = {.id = stream->id,
                                  .flag = stream->initiator ? LIBP2P_MPLEX_FRAME_CLOSE_INITIATOR : LIBP2P_MPLEX_FRAME_CLOSE_RECEIVER,
                                  .data = NULL,
                                  .data_len = 0};

    int rc = libp2p_mplex_send_frame_nonblocking(stream->ctx, &frame);

    // Return OK even if sending the frame failed, as the stream is locally closed
    (void)rc;
    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_stream_reset(libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    pthread_mutex_lock(&stream->lock);

    // Check if already reset
    if (stream->state & LIBP2P_MPLEX_STREAM_STATE_RESET)
    {
        pthread_mutex_unlock(&stream->lock);
        return LIBP2P_MPLEX_OK; // Already reset
    }

    // Mark as reset
    stream->state |= LIBP2P_MPLEX_STREAM_STATE_RESET;
    stream->state |= LIBP2P_MPLEX_STREAM_LOCAL_CLOSED;
    stream->state |= LIBP2P_MPLEX_STREAM_REMOTE_CLOSED;

    // Clear read buffer slices
    mplex_stream_free_slices(stream);

    pthread_mutex_unlock(&stream->lock);

    // Send reset frame
    libp2p_mplex_frame_t frame = {.id = stream->id,
                                  .flag = stream->initiator ? LIBP2P_MPLEX_FRAME_RESET_INITIATOR : LIBP2P_MPLEX_FRAME_RESET_RECEIVER,
                                  .data = NULL,
                                  .data_len = 0};

    int rc = libp2p_mplex_send_frame_nonblocking(stream->ctx, &frame);

    // If we failed to send the reset frame, that's still OK as the stream is marked as reset

    return rc;
}

void libp2p_mplex_stream_set_user_data(libp2p_mplex_stream_t *stream, void *user_data)
{
    if (!stream)
        return;

    pthread_mutex_lock(&stream->lock);
    stream->user_data = user_data;
    pthread_mutex_unlock(&stream->lock);
}

void *libp2p_mplex_stream_get_user_data(const libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return NULL;

    return stream->user_data; // Reading a pointer is atomic
}

void libp2p_mplex_stream_set_max_buffer_size(libp2p_mplex_stream_t *stream, size_t max_buffer_size)
{
    if (!stream)
        return;

    pthread_mutex_lock(&stream->lock);
    stream->max_buffer_size = max_buffer_size;
    pthread_mutex_unlock(&stream->lock);
}

size_t libp2p_mplex_stream_get_max_buffer_size(const libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return 0;

    return stream->max_buffer_size; // Reading a size_t is atomic on most platforms
}

uint64_t libp2p_mplex_stream_get_id(const libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return 0;

    return stream->id;
}

libp2p_mplex_ssize_t libp2p_mplex_stream_write_async(libp2p_mplex_stream_t *stream, const void *data, size_t len)
{
    if (!stream || !data)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (len == 0)
        return 0;

    if (len > LIBP2P_MPLEX_MAX_MESSAGE)
        return LIBP2P_MPLEX_ERR_PROTOCOL;

    pthread_mutex_lock(&stream->ctx->mutex);

    // Check stream state
    if (stream->state & LIBP2P_MPLEX_STREAM_STATE_RESET)
    {
        pthread_mutex_unlock(&stream->ctx->mutex);
        return LIBP2P_MPLEX_ERR_RESET;
    }

    if (stream->state & LIBP2P_MPLEX_STREAM_LOCAL_CLOSED)
    {
        pthread_mutex_unlock(&stream->ctx->mutex);
        return LIBP2P_MPLEX_ERR_PROTOCOL;
    }

    pthread_mutex_unlock(&stream->ctx->mutex);

    // Prepare frame metadata
    libp2p_mplex_frame_t frame = {.id = stream->id,
                                  .flag = stream->initiator ? LIBP2P_MPLEX_FRAME_MSG_INITIATOR : LIBP2P_MPLEX_FRAME_MSG_RECEIVER,
                                  .data = (uint8_t *)data,
                                  .data_len = len};

    libp2p_mplex_ctx_t *ctx = stream->ctx;

    // If there is a pending write buffer or the connection already wants write,
    // enqueue the frame to preserve ordering and avoid interleaving.
    if (ctx->pending_write_buf != NULL || atomic_load(&ctx->want_write))
    {
        int qrc = libp2p_mplex_write_queue_push(&ctx->write_queue, &frame);
        if (qrc != LIBP2P_MPLEX_OK)
            return qrc;

        // Signal interest in write events and attempt an immediate flush
        atomic_store(&ctx->want_write, true);
        (void)libp2p_mplex_flush_writes(ctx);

        // Asynchronous API: report bytes accepted for transmission
        return (libp2p_mplex_ssize_t)len;
    }

    // Fast path: attempt to send immediately when no pending data
    int rc = libp2p_mplex_send_frame_nonblocking(ctx, &frame);
    if (rc == LIBP2P_MPLEX_OK)
        return (libp2p_mplex_ssize_t)len;

    if (rc == LIBP2P_MPLEX_ERR_AGAIN)
    {
        // The encoded remainder was stashed into the pending buffer by the
        // send routine. Register interest in write events and return as accepted.
        atomic_store(&ctx->want_write, true);
        return (libp2p_mplex_ssize_t)len;
    }

    return rc;
}
