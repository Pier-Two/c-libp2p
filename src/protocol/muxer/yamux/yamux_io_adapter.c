#include "libp2p/io.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

typedef struct
{
    libp2p_yamux_ctx_t *ctx;
    uint32_t id;
} yamux_io_ctx_t;

static ssize_t yio_read(libp2p_io_t *self, void *buf, size_t len)
{
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)self->ctx;
    if (!x || !x->ctx || !buf)
        return LIBP2P_ERR_NULL_PTR;
    size_t out = 0;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(x->ctx, x->id, (uint8_t *)buf, len, &out);
    if (rc == LIBP2P_YAMUX_ERR_AGAIN)
    {
        /* Opportunistically pump frames while no central loop is active to
         * avoid handshake stalls. This mirrors inbound runtime behavior but
         * only runs when a read is already pending, preserving event-driven
         * semantics (no periodic polling). */
        if (!atomic_load_explicit(&x->ctx->loop_active, memory_order_acquire))
        {
            for (;;)
            {
                libp2p_yamux_err_t pr = libp2p_yamux_process_one(x->ctx);
                if (pr == LIBP2P_YAMUX_ERR_AGAIN)
                    break; /* no more frames buffered */
                if (pr != LIBP2P_YAMUX_OK)
                    break; /* propagate on next recv */
            }
            /* Retry once after pumping */
            rc = libp2p_yamux_stream_recv(x->ctx, x->id, (uint8_t *)buf, len, &out);
        }
    }
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

static ssize_t yio_write(libp2p_io_t *self, const void *buf, size_t len)
{
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)self->ctx;
    if (!x || !x->ctx || !buf)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_send(x->ctx, x->id, (const uint8_t *)buf, len, 0);
    if (rc == LIBP2P_YAMUX_OK)
        return (ssize_t)len;
    if (rc == LIBP2P_YAMUX_ERR_AGAIN)
    {
        /* Opportunistically pump frames to advance flow control if no loop is active. */
        if (!atomic_load_explicit(&x->ctx->loop_active, memory_order_acquire))
        {
            for (int i = 0; i < 4; i++)
            {
                libp2p_yamux_err_t pr = libp2p_yamux_process_one(x->ctx);
                if (pr == LIBP2P_YAMUX_ERR_AGAIN)
                    break;
                if (pr != LIBP2P_YAMUX_OK)
                    break;
            }
            rc = libp2p_yamux_stream_send(x->ctx, x->id, (const uint8_t *)buf, len, 0);
            if (rc == LIBP2P_YAMUX_OK)
                return (ssize_t)len;
        }
        return LIBP2P_ERR_AGAIN;
    }
    if (rc == LIBP2P_YAMUX_ERR_TIMEOUT)
        return LIBP2P_ERR_TIMEOUT;
    return LIBP2P_ERR_INTERNAL;
}

static int yio_deadline(libp2p_io_t *self, uint64_t ms)
{
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)self->ctx;
    if (!x || !x->ctx || !x->ctx->conn)
        return LIBP2P_ERR_NULL_PTR;
    return libp2p_conn_set_deadline(x->ctx->conn, ms);
}

static const multiaddr_t *yio_local(libp2p_io_t *self)
{
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)self->ctx;
    if (!x || !x->ctx || !x->ctx->conn)
        return NULL;
    return libp2p_conn_local_addr(x->ctx->conn);
}

static const multiaddr_t *yio_remote(libp2p_io_t *self)
{
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)self->ctx;
    if (!x || !x->ctx || !x->ctx->conn)
        return NULL;
    return libp2p_conn_remote_addr(x->ctx->conn);
}

static int yio_close(libp2p_io_t *self)
{
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)self->ctx;
    if (!x || !x->ctx)
        return 0;
    return libp2p_yamux_stream_close(x->ctx, x->id) == LIBP2P_YAMUX_OK ? 0 : LIBP2P_ERR_INTERNAL;
}

static void yio_free(libp2p_io_t *self)
{
    if (!self)
        return;
    if (self->ctx)
        free(self->ctx);
    free(self);
}

static const libp2p_io_vtbl_t YAMUX_IO_VT = {
    .read = yio_read,
    .write = yio_write,
    .set_deadline = yio_deadline,
    .local_addr = yio_local,
    .remote_addr = yio_remote,
    .close = yio_close,
    .free = yio_free,
};

libp2p_io_t *libp2p_io_from_yamux(libp2p_yamux_ctx_t *ctx, uint32_t id)
{
    libp2p_io_t *io = (libp2p_io_t *)calloc(1, sizeof(*io));
    yamux_io_ctx_t *x = (yamux_io_ctx_t *)calloc(1, sizeof(*x));
    if (!io || !x)
    {
        free(io);
        free(x);
        return NULL;
    }
    x->ctx = ctx;
    x->id = id;
    io->vt = &YAMUX_IO_VT;
    io->ctx = x;
    return io;
}
