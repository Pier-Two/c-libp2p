#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include "libp2p/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int libp2p_mplex_set_event_callbacks(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_event_callbacks_t *callbacks)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    pthread_mutex_lock(&ctx->mutex);

    if (callbacks)
    {
        ctx->event_callbacks = *callbacks;
        LP_LOGT("MPLEX", "set callbacks ctx=%p on_stream_event=%p user_data=%p", (void *)ctx,
                (void *)ctx->event_callbacks.on_stream_event, ctx->event_callbacks.user_data);
    }
    else
    {
        memset(&ctx->event_callbacks, 0, sizeof(ctx->event_callbacks));
    }

    pthread_mutex_unlock(&ctx->mutex);

    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_stream_set_event_callback(libp2p_mplex_stream_t *stream, libp2p_mplex_stream_callback_t callback, void *user_data)
{
    if (!stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    pthread_mutex_lock(&stream->ctx->mutex);

    stream->event_callback = callback;
    stream->event_callback_user_data = user_data;

    pthread_mutex_unlock(&stream->ctx->mutex);

    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_stream_set_write_ready_callback(libp2p_mplex_stream_t *stream, libp2p_mplex_stream_write_ready_callback_t callback, void *user_data)
{
    if (!stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    pthread_mutex_lock(&stream->ctx->mutex);

    stream->write_ready_callback = callback;
    stream->write_ready_callback_user_data = user_data;

    pthread_mutex_unlock(&stream->ctx->mutex);

    return LIBP2P_MPLEX_OK;
}

// Helper function to trigger stream events
void libp2p_mplex_trigger_stream_event(libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t *stream, libp2p_mplex_event_t event)
{
    if (!ctx || !stream)
        return;

    // First check for stream-specific callback
    if (stream->event_callback)
    {
        LP_LOGT("MPLEX", "stream cb streamctx=%p event=%d", (void *)stream->ctx, (int)event);
        stream->event_callback(stream, event, stream->event_callback_user_data);
        return;
    }

    // Then check for context-wide callback without holding the mutex while invoking
    libp2p_mplex_stream_callback_t cb = NULL;
    void *cb_ud = NULL;
    pthread_mutex_lock(&ctx->mutex);
    cb = ctx->event_callbacks.on_stream_event;
    cb_ud = ctx->event_callbacks.user_data;
    pthread_mutex_unlock(&ctx->mutex);
    if (cb)
    {
        LP_LOGT("MPLEX", "ctx cb ctx=%p streamctx=%p event=%d userdata=%p", (void *)ctx, (void *)stream->ctx, (int)event, cb_ud);
        cb(stream, event, cb_ud);
    }
}

// Helper function to trigger error events
void libp2p_mplex_trigger_error_event(libp2p_mplex_ctx_t *ctx, int error)
{
    if (!ctx)
        return;

    libp2p_mplex_error_callback_t cb = NULL;
    void *cb_ud = NULL;
    pthread_mutex_lock(&ctx->mutex);
    cb = ctx->event_callbacks.on_error;
    cb_ud = ctx->event_callbacks.user_data;
    pthread_mutex_unlock(&ctx->mutex);
    if (cb)
    {
        cb(ctx, error, cb_ud);
    }
}

// Helper function to trigger write ready events
void libp2p_mplex_trigger_write_ready_event(libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return;

    if (stream->write_ready_callback)
    {
        stream->write_ready_callback(stream, stream->write_ready_callback_user_data);
    }
}
