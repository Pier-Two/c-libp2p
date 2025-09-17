#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol_mplex_conn.h"
#include "protocol_mplex_internal.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Event-driven API implementations

int libp2p_mplex_new(libp2p_conn_t *conn, libp2p_mplex_ctx_t **out_ctx)
{
    if (!conn || !out_ctx)
    {
        fprintf(stderr, "[MPLEX] new ERR_NULL_PTR conn=%p out_ctx=%p\n", (void *)conn, (void *)out_ctx);
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    }

    // Get file descriptor using the connection's vtable if available.
    // For tests that don't use the event loop, allow missing/invalid fd.
    int fd = -1;
    if (conn->vt && conn->vt->get_fd)
    {
        fd = conn->vt->get_fd(conn);
    }

    libp2p_mplex_ctx_t *ctx = calloc(1, sizeof(libp2p_mplex_ctx_t));
    if (!ctx)
    {
        fprintf(stderr, "[MPLEX] new ERR_INTERNAL allocating ctx\n");
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    // Use the provided connection directly
    ctx->conn = conn;
    ctx->fd = fd; // May be -1 when not needed (no event loop usage)
    ctx->next_stream_id = 1;
    atomic_init(&ctx->want_write, false);
    atomic_init(&ctx->stop, false);
    ctx->negotiated = false;
    ctx->pending_write_buf = NULL;
    ctx->pending_write_len = 0;
    ctx->pending_write_off = 0;

    // Initialize incremental read buffer
    ctx->rx_buf = NULL;
    ctx->rx_len = 0;
    ctx->rx_off = 0;
    ctx->rx_cap = 0;

    // Initialize stream management
    int rc = libp2p_mplex_stream_array_init(&ctx->streams);
    if (rc != LIBP2P_MPLEX_OK)
    {
        // ctx->conn is externally provided, do not free it here.
        free(ctx);
        fprintf(stderr, "[MPLEX] new stream_array_init rc=%d\n", rc);
        return rc;
    }

    rc = libp2p_mplex_stream_queue_init(&ctx->incoming);
    if (rc != LIBP2P_MPLEX_OK)
    {
        libp2p_mplex_stream_array_destroy(&ctx->streams);
        // ctx->conn is externally provided, do not free it here.
        free(ctx);
        fprintf(stderr, "[MPLEX] new stream_queue_init rc=%d\n", rc);
        return rc;
    }

    rc = libp2p_mplex_write_queue_init(&ctx->write_queue);
    if (rc != LIBP2P_MPLEX_OK)
    {
        libp2p_mplex_stream_queue_destroy(&ctx->incoming);
        libp2p_mplex_stream_array_destroy(&ctx->streams);
        // ctx->conn is externally provided, do not free it here.
        free(ctx);
        fprintf(stderr, "[MPLEX] new write_queue_init rc=%d\n", rc);
        return rc;
    }

    pthread_mutex_init(&ctx->mutex, NULL);

    // Initialize event callback fields
    memset(&ctx->event_callbacks, 0, sizeof(ctx->event_callbacks));
    ctx->loop_thread_started = 0;

    // Initialize wake pipe for event-loop wakeups (best-effort)
    ctx->wake_read_fd = -1;
    ctx->wake_write_fd = -1;
    int fds[2];
    if (pipe(fds) == 0)
    {
        // Set non-blocking and close-on-exec on both ends
        for (int i = 0; i < 2; i++)
        {
            int flags = fcntl(fds[i], F_GETFL, 0);
            if (flags != -1)
                (void)fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
            int clo = fcntl(fds[i], F_GETFD, 0);
            if (clo != -1)
                (void)fcntl(fds[i], F_SETFD, clo | FD_CLOEXEC);
        }
        ctx->wake_read_fd = fds[0];
        ctx->wake_write_fd = fds[1];
    }

    *out_ctx = ctx;
    fprintf(stderr, "[MPLEX] new OK ctx=%p fd=%d\n", (void *)ctx, ctx->fd);
    return LIBP2P_MPLEX_OK;
}

void libp2p_mplex_free(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return;

    // Signal stop to any running processing loops
    atomic_store(&ctx->stop, true);

    // Memory barrier to ensure the stop signal is visible to all threads
    atomic_thread_fence(memory_order_seq_cst);

    // Do not close or free the underlying connection here.
    // Ownership remains with the caller/upgrader. Just detach.
    ctx->conn = NULL;

    // Clean up all streams with proper synchronization
    pthread_mutex_lock(&ctx->mutex);

    // Strategy: Clear the incoming queue without freeing streams (they're also in the array)
    libp2p_mplex_stream_queue_destroy(&ctx->incoming);

    // Free all streams from the array only - this ensures each stream is freed exactly once
    for (size_t i = 0; i < ctx->streams.length; i++)
    {
        libp2p_mplex_stream_t *stream = ctx->streams.streams[i];
        if (stream)
        {
            libp2p_mplex_stream_free(stream);
            ctx->streams.streams[i] = NULL;
        }
    }
    libp2p_mplex_stream_array_destroy(&ctx->streams);

    // Clean up write queue
    libp2p_mplex_write_queue_destroy(&ctx->write_queue);

    // Pending write buffer cleanup
    if (ctx->pending_write_buf)
    {
        free(ctx->pending_write_buf);
        ctx->pending_write_buf = NULL;
        ctx->pending_write_len = 0;
        ctx->pending_write_off = 0;
    }

    // Read buffer cleanup
    if (ctx->rx_buf)
    {
        free(ctx->rx_buf);
        ctx->rx_buf = NULL;
        ctx->rx_len = 0;
        ctx->rx_off = 0;
        ctx->rx_cap = 0;
    }

    pthread_mutex_unlock(&ctx->mutex);

    // Destroy mutex with additional synchronization
    pthread_mutex_destroy(&ctx->mutex);

    // Final memory barrier before freeing the context
    atomic_thread_fence(memory_order_seq_cst);

    // If a background loop thread is running, stop it and join to avoid races
    if (ctx->loop_thread_started)
    {
        (void)libp2p_mplex_stop_event_loop(ctx);
        pthread_join(ctx->loop_thread, NULL);
        ctx->loop_thread_started = 0;
    }

    // Close wake pipe if created
    if (ctx->wake_read_fd >= 0)
        close(ctx->wake_read_fd);
    if (ctx->wake_write_fd >= 0)
        close(ctx->wake_write_fd);
    free(ctx);
}

int libp2p_mplex_get_fd(const libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return -1;

    // Prefer querying the live connection for its current FD so callers don't
    // accidentally poll a stale descriptor after close() or replacement.
    if (ctx->conn && ctx->conn->vt && ctx->conn->vt->get_fd)
    {
        int live_fd = ctx->conn->vt->get_fd(ctx->conn);
        return live_fd;
    }

    return ctx->fd;
}

int libp2p_mplex_on_readable(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx || !ctx->conn)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    // Drain all complete frames currently available, including those already
    // buffered in ctx->rx_buf. This prevents starvation when multiple frames
    // are coalesced into a single socket read.
    fprintf(stderr, "[MPLEX] readable ctx=%p fd=%d\n", (void *)ctx, libp2p_mplex_get_fd(ctx));
    for (;;)
    {
        libp2p_mplex_frame_t frame;
        int rc = libp2p_mplex_read_frame(ctx, &frame);
        if (rc == LIBP2P_MPLEX_ERR_AGAIN)
        {
            // No complete frame available right now; done for this callback
            return LIBP2P_MPLEX_OK;
        }
        if (rc != LIBP2P_MPLEX_OK)
        {
            fprintf(stderr, "[MPLEX] readable rc=%d ctx=%p\n", rc, (void *)ctx);
            return rc;
        }

        fprintf(stderr, "[MPLEX] recv frame ctx=%p flag=%u id=%llu len=%zu\n", (void *)ctx, (unsigned)frame.flag, (unsigned long long)frame.id,
                frame.data_len);
        int drc = libp2p_mplex_dispatch_frame(ctx, &frame);
        libp2p_mplex_frame_free(&frame);
        if (drc != LIBP2P_MPLEX_OK)
        {
            fprintf(stderr, "[MPLEX] dispatch rc=%d ctx=%p\n", drc, (void *)ctx);
            return drc;
        }
        // Loop to attempt parsing any additional frames already buffered
    }
}

int libp2p_mplex_on_writable(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    atomic_store(&ctx->want_write, false);

    // Flush any pending writes from write queue
    int rc = libp2p_mplex_flush_writes(ctx);

    // If there are still pending writes, set want_write flag
    if (rc == LIBP2P_MPLEX_ERR_AGAIN)
    {
        atomic_store(&ctx->want_write, true);
        libp2p_mplex_wake(ctx);
        return LIBP2P_MPLEX_OK; // Not an error, just means we need to wait for more writable events
    }

    return rc;
}

void libp2p_mplex_wake(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return;
    int w = ctx->wake_write_fd;
    if (w < 0)
        return;
    const uint8_t byte = 1;
    (void)write(w, &byte, 1); // best-effort, ignore EAGAIN
}

int libp2p_mplex_negotiate_outbound(libp2p_mplex_ctx_t *ctx, uint64_t timeout_ms)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (ctx->negotiated)
        return LIBP2P_MPLEX_OK;

    // Prepare proposal array
    const char *proposals[] = {LIBP2P_MPLEX_PROTO_ID, NULL};

    // Perform multiselect negotiation as dialer
    libp2p_multiselect_err_t result = libp2p_multiselect_dial(ctx->conn, proposals, timeout_ms,
                                                              NULL // We don't need to know which was selected since we only offered one
    );

    switch (result)
    {
        case LIBP2P_MULTISELECT_OK:
            ctx->negotiated = true;
            return LIBP2P_MPLEX_OK;
        case LIBP2P_MULTISELECT_ERR_TIMEOUT:
            return LIBP2P_MPLEX_ERR_TIMEOUT;
        case LIBP2P_MULTISELECT_ERR_UNAVAIL:
            return LIBP2P_MPLEX_ERR_HANDSHAKE;
        case LIBP2P_MULTISELECT_ERR_PROTO_MAL:
        case LIBP2P_MULTISELECT_ERR_IO:
            return LIBP2P_MPLEX_ERR_PROTOCOL;
        case LIBP2P_MULTISELECT_ERR_NULL_PTR:
            return LIBP2P_MPLEX_ERR_NULL_PTR;
        case LIBP2P_MULTISELECT_ERR_INTERNAL:
        default:
            return LIBP2P_MPLEX_ERR_INTERNAL;
    }
}

int libp2p_mplex_negotiate_inbound(libp2p_mplex_ctx_t *ctx, uint64_t timeout_ms)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (ctx->negotiated)
        return LIBP2P_MPLEX_OK;

    // Prepare supported protocols array
    const char *supported[] = {LIBP2P_MPLEX_PROTO_ID, NULL};

    // Configure multiselect
    libp2p_multiselect_config_t config = libp2p_multiselect_config_default();
    config.handshake_timeout_ms = timeout_ms;
    config.enable_ls = false; // Don't support listing for now

    // Perform multiselect negotiation as listener
    libp2p_multiselect_err_t result = libp2p_multiselect_listen(ctx->conn, supported, &config,
                                                                NULL // We don't need to know which was selected since we only support one
    );

    switch (result)
    {
        case LIBP2P_MULTISELECT_OK:
            ctx->negotiated = true;
            return LIBP2P_MPLEX_OK;
        case LIBP2P_MULTISELECT_ERR_TIMEOUT:
            return LIBP2P_MPLEX_ERR_TIMEOUT;
        case LIBP2P_MULTISELECT_ERR_UNAVAIL:
            return LIBP2P_MPLEX_ERR_HANDSHAKE;
        case LIBP2P_MULTISELECT_ERR_PROTO_MAL:
        case LIBP2P_MULTISELECT_ERR_IO:
            return LIBP2P_MPLEX_ERR_PROTOCOL;
        case LIBP2P_MULTISELECT_ERR_NULL_PTR:
            return LIBP2P_MPLEX_ERR_NULL_PTR;
        case LIBP2P_MULTISELECT_ERR_INTERNAL:
        default:
            return LIBP2P_MPLEX_ERR_INTERNAL;
    }
}

// -----------------------------------------------------------------------------
// Muxer factory (direct v2 integration)
// -----------------------------------------------------------------------------

// Minimal libp2p_muxer_t vtable that negotiates an mplex v2 context and stores
// it in the muxer->ctx. Stream operations are handled by higher layers.
static int mplex_vtbl_negotiate(libp2p_muxer_t *mx, libp2p_conn_t *c, uint64_t timeout_ms, bool inbound)
{
    if (!mx || !c)
        return LIBP2P_MUXER_ERR_NULL_PTR;

    libp2p_mplex_ctx_t *ctx = NULL;
    int rc = libp2p_mplex_new(c, &ctx);
    if (rc != LIBP2P_MPLEX_OK || !ctx)
        return LIBP2P_MUXER_ERR_INTERNAL;

    if (inbound)
        rc = libp2p_mplex_negotiate_inbound(ctx, timeout_ms);
    else
        rc = libp2p_mplex_negotiate_outbound(ctx, timeout_ms);

    if (rc != LIBP2P_MPLEX_OK)
    {
        libp2p_mplex_free(ctx);
        return LIBP2P_MUXER_ERR_HANDSHAKE;
    }

    mx->ctx = ctx;
    return LIBP2P_MUXER_OK;
}

static void mplex_vtbl_free(libp2p_muxer_t *mx)
{
    if (!mx)
        return;
    if (mx->ctx)
        libp2p_mplex_free((libp2p_mplex_ctx_t *)mx->ctx);
    free(mx);
}

libp2p_muxer_t *libp2p_mplex_muxer_new(void)
{
    static const libp2p_muxer_vtbl_t VTBL = {
        .negotiate = mplex_vtbl_negotiate,
        .open_stream = NULL,  // not used by current upgrader
        .stream_read = NULL,  // handled at higher level
        .stream_write = NULL, // handled at higher level
        .stream_close = NULL, // handled at higher level
        .free = mplex_vtbl_free,
    };

    libp2p_muxer_t *m = (libp2p_muxer_t *)calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    m->vt = &VTBL;
    m->ctx = NULL;
    return m;
}
