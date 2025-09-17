#include "libp2p/io.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include <stdlib.h>

typedef struct
{
    libp2p_mplex_stream_t *s;
} io_mplex_ctx_t;

/* Map mplex stream return codes to unified libp2p IO/error codes expected by
 * libp2p_io_* users (e.g., multistream-select). */
static inline ssize_t map_mplex_read_rc(libp2p_mplex_ssize_t rc)
{
    if (rc > 0)
        return (ssize_t)rc;
    switch (rc)
    {
        case 0:
            /* mplex read returns 0 to indicate EOF when the remote closed the
             * stream and no buffered data remains. libp2p_io expects negative
             * LIBP2P_ERR_EOF instead of 0 to distinguish from a short read. */
            return LIBP2P_ERR_EOF;
        case LIBP2P_MPLEX_ERR_AGAIN:
            return LIBP2P_ERR_AGAIN;
        case LIBP2P_MPLEX_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_MPLEX_ERR_RESET:
            return LIBP2P_ERR_RESET;
        case LIBP2P_MPLEX_ERR_NULL_PTR:
            return LIBP2P_ERR_NULL_PTR;
        case LIBP2P_MPLEX_ERR_EOF:
            return LIBP2P_ERR_EOF;
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

static inline ssize_t map_mplex_write_rc(libp2p_mplex_ssize_t rc)
{
    if (rc >= 0)
        return (ssize_t)rc;
    switch (rc)
    {
        case LIBP2P_MPLEX_ERR_AGAIN:
            return LIBP2P_ERR_AGAIN;
        case LIBP2P_MPLEX_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_MPLEX_ERR_RESET:
            return LIBP2P_ERR_RESET;
        case LIBP2P_MPLEX_ERR_NULL_PTR:
            return LIBP2P_ERR_NULL_PTR;
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

static ssize_t io_mplex_read(libp2p_io_t *self, void *buf, size_t len)
{
    io_mplex_ctx_t *x = (io_mplex_ctx_t *)self->ctx;
    if (!x || !x->s)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_mplex_ssize_t rc = libp2p_mplex_stream_read(x->s, buf, len);
    return map_mplex_read_rc(rc);
}

static ssize_t io_mplex_write(libp2p_io_t *self, const void *buf, size_t len)
{
    io_mplex_ctx_t *x = (io_mplex_ctx_t *)self->ctx;
    if (!x || !x->s)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_mplex_ssize_t rc = libp2p_mplex_stream_write_async(x->s, buf, len);
    return map_mplex_write_rc(rc);
}

static int io_mplex_deadline(libp2p_io_t *self, uint64_t ms)
{
    (void)self;
    (void)ms;
    /* Per-stream deadlines are enforced at the IO helper layer using
     * monotonic clocks. Avoid mutating the underlying connection's deadline
     * which multiplexes multiple streams. */
    return 0;
}

static const multiaddr_t *io_mplex_local(libp2p_io_t *self)
{
    io_mplex_ctx_t *x = (io_mplex_ctx_t *)self->ctx;
    if (!x || !x->s || !x->s->ctx || !x->s->ctx->conn)
        return NULL;
    return libp2p_conn_local_addr(x->s->ctx->conn);
}

static const multiaddr_t *io_mplex_remote(libp2p_io_t *self)
{
    io_mplex_ctx_t *x = (io_mplex_ctx_t *)self->ctx;
    if (!x || !x->s || !x->s->ctx || !x->s->ctx->conn)
        return NULL;
    return libp2p_conn_remote_addr(x->s->ctx->conn);
}

static int io_mplex_close(libp2p_io_t *self)
{
    io_mplex_ctx_t *x = (io_mplex_ctx_t *)self->ctx;
    if (!x || !x->s)
        return 0;
    return libp2p_mplex_stream_close(x->s);
}

static void io_mplex_free(libp2p_io_t *self)
{
    if (!self)
        return;
    if (self->ctx)
        free(self->ctx);
    free(self);
}

static const libp2p_io_vtbl_t IO_MPLEX_VT = {
    .read = io_mplex_read,
    .write = io_mplex_write,
    .set_deadline = io_mplex_deadline,
    .local_addr = io_mplex_local,
    .remote_addr = io_mplex_remote,
    .close = io_mplex_close,
    .free = io_mplex_free,
};

libp2p_io_t *libp2p_io_from_mplex(libp2p_mplex_stream_t *s)
{
    if (!s)
        return NULL;
    libp2p_io_t *io = (libp2p_io_t *)calloc(1, sizeof(*io));
    io_mplex_ctx_t *x = (io_mplex_ctx_t *)calloc(1, sizeof(*x));
    if (!io || !x)
    {
        free(io);
        free(x);
        return NULL;
    }
    x->s = s;
    io->vt = &IO_MPLEX_VT;
    io->ctx = x;
    return io;
}
