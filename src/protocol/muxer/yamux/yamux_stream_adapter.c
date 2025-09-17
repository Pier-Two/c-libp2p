#include "libp2p/stream_internal.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

typedef struct
{
    libp2p_yamux_ctx_t *ctx;
    uint32_t id;
} ystream_ctx_t;

static ssize_t yst_read(void *io_ctx, void *buf, size_t len)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    if (!x || !x->ctx || !buf)
        return LIBP2P_ERR_NULL_PTR;
    size_t out = 0;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(x->ctx, x->id, (uint8_t *)buf, len, &out);
    switch (rc)
    {
        case LIBP2P_YAMUX_OK:
            return (ssize_t)out;
        case LIBP2P_YAMUX_ERR_AGAIN:
            return LIBP2P_ERR_AGAIN;
        case LIBP2P_YAMUX_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_YAMUX_ERR_EOF:
            return 0;
        case LIBP2P_YAMUX_ERR_RESET:
            return 0;
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

static ssize_t yst_write(void *io_ctx, const void *buf, size_t len)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    if (!x || !x->ctx || !buf)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_send(x->ctx, x->id, (const uint8_t *)buf, len, 0);
    if (rc == LIBP2P_YAMUX_OK)
        return (ssize_t)len;
    if (rc == LIBP2P_YAMUX_ERR_AGAIN)
        return LIBP2P_ERR_AGAIN;
    if (rc == LIBP2P_YAMUX_ERR_TIMEOUT)
        return LIBP2P_ERR_TIMEOUT;
    return LIBP2P_ERR_INTERNAL;
}

static int yst_close(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    return (x && x->ctx) ? (libp2p_yamux_stream_close(x->ctx, x->id) == LIBP2P_YAMUX_OK ? 0 : LIBP2P_ERR_INTERNAL) : 0;
}
static int yst_reset(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    return (x && x->ctx) ? (libp2p_yamux_stream_reset(x->ctx, x->id) == LIBP2P_YAMUX_OK ? 0 : LIBP2P_ERR_INTERNAL) : 0;
}
static int yst_deadline(void *io_ctx, uint64_t ms)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    return (x && x->ctx && x->ctx->conn) ? libp2p_conn_set_deadline(x->ctx->conn, ms) : LIBP2P_ERR_NULL_PTR;
}
static const multiaddr_t *yst_local(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    return (x && x->ctx && x->ctx->conn) ? libp2p_conn_local_addr(x->ctx->conn) : NULL;
}
static const multiaddr_t *yst_remote(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    return (x && x->ctx && x->ctx->conn) ? libp2p_conn_remote_addr(x->ctx->conn) : NULL;
}

static int yst_is_writable(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    if (!x || !x->ctx)
        return -1;
    int writable = 0;
    pthread_mutex_lock(&x->ctx->mtx);
    for (size_t i = 0; i < x->ctx->num_streams; i++)
    {
        libp2p_yamux_stream_t *st = x->ctx->streams[i];
        if (st && st->id == x->id)
        {
            if (!st->local_closed && !st->reset && st->send_window > 0)
                writable = 1;
            break;
        }
    }
    pthread_mutex_unlock(&x->ctx->mtx);
    return writable;
}

static int yst_has_readable(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    if (!x || !x->ctx)
        return -1;
    int readable = 0;
    pthread_mutex_lock(&x->ctx->mtx);
    for (size_t i = 0; i < x->ctx->num_streams; i++)
    {
        libp2p_yamux_stream_t *st = x->ctx->streams[i];
        if (st && st->id == x->id)
        {
            size_t unread = (st->buf_len > st->buf_pos) ? (st->buf_len - st->buf_pos) : 0;
            if (unread > 0)
                readable = 1;
            break;
        }
    }
    pthread_mutex_unlock(&x->ctx->mtx);
    return readable;
}

static void yst_free_ctx(void *io_ctx)
{
    ystream_ctx_t *x = (ystream_ctx_t *)io_ctx;
    if (!x)
        return;
    if (x->ctx)
        libp2p_yamux_ctx_free(x->ctx); /* drop our reference */
    free(x);
}

libp2p_stream_t *libp2p_stream_from_yamux(struct libp2p_host *host, libp2p_yamux_ctx_t *ctx, uint32_t id, const char *protocol_id, int initiator,
                                          peer_id_t *remote_peer)
{
    if (!ctx)
        return NULL;
    /* Hold a reference to the session while this stream exists. */
    atomic_fetch_add_explicit(&ctx->refcnt, 1, memory_order_acq_rel);
    ystream_ctx_t *yc = (ystream_ctx_t *)calloc(1, sizeof(*yc));
    if (!yc)
    {
        libp2p_yamux_ctx_free(ctx);
        return NULL;
    }
    yc->ctx = ctx;
    yc->id = id;
    libp2p_stream_backend_ops_t ops = {
        .read = yst_read,
        .write = yst_write,
        .close = yst_close,
        .reset = yst_reset,
        .set_deadline = yst_deadline,
        .local_addr = yst_local,
        .remote_addr = yst_remote,
        .is_writable = yst_is_writable,
        .has_readable = yst_has_readable,
        .free_ctx = yst_free_ctx,
    };
    libp2p_stream_t *s = libp2p_stream_from_ops(host, yc, &ops, protocol_id, initiator, remote_peer);
    if (!s)
    {
        yst_free_ctx(yc);
    }
    return s;
}
