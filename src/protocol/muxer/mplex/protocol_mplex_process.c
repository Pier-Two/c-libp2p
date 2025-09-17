#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Helper function to handle protocol violations
static int handle_protocol_violation(libp2p_mplex_ctx_t *ctx)
{
    if (ctx && ctx->conn)
    {
        libp2p_conn_close(ctx->conn);
    }

    if (ctx)
    {
        atomic_store(&ctx->stop, true);
    }

    // Trigger connection error event
    if (ctx)
    {
        libp2p_mplex_trigger_error_event(ctx, LIBP2P_MPLEX_ERR_PROTOCOL);
    }

    return LIBP2P_MPLEX_ERR_PROTOCOL;
}

#define MPLEX_VIOL(ctx, msg, id)                                                                                                         \
    do                                                                                                                                   \
    {                                                                                                                                    \
        fprintf(stderr, "[MPLEX] PROTOCOL VIOLATION: %s (stream=%llu) ctx=%p\n", (msg), (unsigned long long)(id), (void *)(ctx));         \
        return handle_protocol_violation((ctx));                                                                                        \
    } while (0)

// Frame dispatch implementation
int libp2p_mplex_dispatch_frame(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_frame_t *frame)
{
    if (!ctx || !frame)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (frame->id >= LIBP2P_MPLEX_MAX_STREAM_ID)
        return handle_protocol_violation(ctx);

    // Close and Reset frames MUST NOT have a payload
    if (frame->flag == LIBP2P_MPLEX_FRAME_CLOSE_INITIATOR || frame->flag == LIBP2P_MPLEX_FRAME_CLOSE_RECEIVER ||
        frame->flag == LIBP2P_MPLEX_FRAME_RESET_INITIATOR || frame->flag == LIBP2P_MPLEX_FRAME_RESET_RECEIVER)
    {
        if (frame->data_len > 0)
        {
            return handle_protocol_violation(ctx);
        }
    }

    pthread_mutex_lock(&ctx->mutex);

    size_t stream_index;
    libp2p_mplex_stream_t *stream = NULL;

    switch (frame->flag)
    {
        case LIBP2P_MPLEX_FRAME_NEW_STREAM:
            fprintf(stderr, "[MPLEX] NEW_STREAM id=%llu len=%zu ctx=%p\n", (unsigned long long)frame->id, frame->data_len, (void *)ctx);
            // Remote side opened a new stream
            // Check if stream already exists (protocol violation)
            stream = libp2p_mplex_find_stream(ctx, frame->id, false, &stream_index);
            if (stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                MPLEX_VIOL(ctx, "NEW_STREAM for existing id", frame->id);
            }

            // Create new stream object
            stream = libp2p_mplex_stream_new(frame->id, frame->data, frame->data_len, false, ctx);
            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                return LIBP2P_MPLEX_ERR_INTERNAL;
            }

            // Add to active streams
            if (libp2p_mplex_stream_array_add(&ctx->streams, stream) != LIBP2P_MPLEX_OK)
            {
                libp2p_mplex_stream_free(stream);
                pthread_mutex_unlock(&ctx->mutex);
                return LIBP2P_MPLEX_ERR_INTERNAL;
            }

            // Queue for acceptance
            if (libp2p_mplex_stream_queue_push(&ctx->incoming, stream) != LIBP2P_MPLEX_OK)
            {
                libp2p_mplex_stream_array_remove(&ctx->streams, ctx->streams.length - 1);
                libp2p_mplex_stream_free(stream);
                pthread_mutex_unlock(&ctx->mutex);
                return LIBP2P_MPLEX_ERR_INTERNAL;
            }

            pthread_mutex_unlock(&ctx->mutex);

            // Trigger stream opened event
            fprintf(stderr, "[MPLEX] trigger OPENED id=%llu ctx=%p\n", (unsigned long long)stream->id, (void *)ctx);
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_OPENED);

            break;

        case LIBP2P_MPLEX_FRAME_MSG_INITIATOR:
            // Message from initiator side
            fprintf(stderr, "[MPLEX] MSG_INITIATOR id=%llu len=%zu ctx=%p\n", (unsigned long long)frame->id, frame->data_len, (void *)ctx);
            stream = libp2p_mplex_find_stream(ctx, frame->id, false, &stream_index);
            if (!stream)
            {
                stream = libp2p_mplex_find_stream(ctx, frame->id, true, &stream_index);
            }

            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                MPLEX_VIOL(ctx, "MSG_INITIATOR for unknown stream", frame->id);
            }

            if (stream->state & LIBP2P_MPLEX_STREAM_REMOTE_CLOSED)
            {
                pthread_mutex_unlock(&ctx->mutex);
                MPLEX_VIOL(ctx, "MSG_INITIATOR on remotely closed stream", frame->id);
            }

            // Check backpressure before appending data
            if (frame->data_len > 0 && stream->queued + frame->data_len > stream->max_buffer_size)
            {
                // Buffer overflow - reset the stream
                pthread_mutex_unlock(&ctx->mutex);
                libp2p_mplex_stream_reset(stream);
                return LIBP2P_MPLEX_ERR_PROTOCOL;
            }

            // Append data to stream buffer
            if (frame->data_len > 0)
            {
                int rc = mplex_stream_enqueue(stream, frame->data, frame->data_len);
                if (rc != LIBP2P_MPLEX_OK)
                {
                    pthread_mutex_unlock(&ctx->mutex);
                    return rc;
                }
            }

            pthread_mutex_unlock(&ctx->mutex);

            // Trigger data available event
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_DATA_AVAILABLE);

            break;

        case LIBP2P_MPLEX_FRAME_MSG_RECEIVER:
            // Message from receiver side
            fprintf(stderr, "[MPLEX] MSG_RECEIVER id=%llu len=%zu ctx=%p\n", (unsigned long long)frame->id, frame->data_len, (void *)ctx);
            stream = libp2p_mplex_find_stream(ctx, frame->id, true, &stream_index);
            if (!stream)
            {
                stream = libp2p_mplex_find_stream(ctx, frame->id, false, &stream_index);
            }

            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                MPLEX_VIOL(ctx, "MSG_RECEIVER for unknown stream", frame->id);
            }

            if (stream->state & LIBP2P_MPLEX_STREAM_REMOTE_CLOSED)
            {
                pthread_mutex_unlock(&ctx->mutex);
                MPLEX_VIOL(ctx, "MSG_RECEIVER on remotely closed stream", frame->id);
            }

            // Check backpressure before appending data
            if (frame->data_len > 0 && stream->queued + frame->data_len > stream->max_buffer_size)
            {
                // Buffer overflow - reset the stream
                pthread_mutex_unlock(&ctx->mutex);
                libp2p_mplex_stream_reset(stream);
                return LIBP2P_MPLEX_ERR_PROTOCOL;
            }

            // Append data to stream buffer
            if (frame->data_len > 0)
            {
                int rc = mplex_stream_enqueue(stream, frame->data, frame->data_len);
                if (rc != LIBP2P_MPLEX_OK)
                {
                    pthread_mutex_unlock(&ctx->mutex);
                    return rc;
                }
            }

            pthread_mutex_unlock(&ctx->mutex);

            // Trigger data available event
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_DATA_AVAILABLE);

            break;

        case 7: /* Unknown/invalid flag observed in tests */
            pthread_mutex_unlock(&ctx->mutex);
            MPLEX_VIOL(ctx, "Unknown flag", frame->flag);

            break;

        case LIBP2P_MPLEX_FRAME_CLOSE_INITIATOR:
            // Remote side closed initiator side
            stream = libp2p_mplex_find_stream(ctx, frame->id, false, &stream_index);
            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                return handle_protocol_violation(ctx);
            }

            stream->state |= LIBP2P_MPLEX_STREAM_REMOTE_CLOSED;
            pthread_mutex_unlock(&ctx->mutex);

            // Trigger stream closed event
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_CLOSED);

            break;

        case LIBP2P_MPLEX_FRAME_CLOSE_RECEIVER:
            // Remote side closed receiver side
            stream = libp2p_mplex_find_stream(ctx, frame->id, true, &stream_index);
            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                return handle_protocol_violation(ctx);
            }

            stream->state |= LIBP2P_MPLEX_STREAM_REMOTE_CLOSED;
            pthread_mutex_unlock(&ctx->mutex);

            // Trigger stream closed event
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_CLOSED);

            break;

        case LIBP2P_MPLEX_FRAME_RESET_INITIATOR:
            // Remote side reset initiator side
            stream = libp2p_mplex_find_stream(ctx, frame->id, false, &stream_index);
            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                return handle_protocol_violation(ctx);
            }

            stream->state |= LIBP2P_MPLEX_STREAM_STATE_RESET;
            // Clear any queued data as part of reset semantics
            mplex_stream_free_slices(stream);
            pthread_mutex_unlock(&ctx->mutex);

            // Trigger stream reset event
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_RESET);

            break;

        case LIBP2P_MPLEX_FRAME_RESET_RECEIVER:
            // Remote side reset receiver side
            stream = libp2p_mplex_find_stream(ctx, frame->id, true, &stream_index);
            if (!stream)
            {
                pthread_mutex_unlock(&ctx->mutex);
                return handle_protocol_violation(ctx);
            }

            stream->state |= LIBP2P_MPLEX_STREAM_STATE_RESET;
            // Clear any queued data as part of reset semantics
            mplex_stream_free_slices(stream);
            pthread_mutex_unlock(&ctx->mutex);

            // Trigger stream reset event
            libp2p_mplex_trigger_stream_event(ctx, stream, LIBP2P_MPLEX_STREAM_RESET);

            break;

        default:
            pthread_mutex_unlock(&ctx->mutex);
            return handle_protocol_violation(ctx);
    }

    return LIBP2P_MPLEX_OK;
}
