#include "libp2p/io.h"
#include "libp2p/stream.h"
#include "transport/connection.h"
#include <stdlib.h>

typedef struct
{
    libp2p_conn_t *c;
} io_conn_ctx_t;

static ssize_t io_conn_read(libp2p_io_t *self, void *buf, size_t len)
{
    io_conn_ctx_t *x = (io_conn_ctx_t *)self->ctx;
    return x && x->c ? libp2p_conn_read(x->c, buf, len) : LIBP2P_ERR_NULL_PTR;
}
static ssize_t io_conn_write(libp2p_io_t *self, const void *buf, size_t len)
{
    io_conn_ctx_t *x = (io_conn_ctx_t *)self->ctx;
    return x && x->c ? libp2p_conn_write(x->c, buf, len) : LIBP2P_ERR_NULL_PTR;
}
static int io_conn_deadline(libp2p_io_t *self, uint64_t ms)
{
    io_conn_ctx_t *x = (io_conn_ctx_t *)self->ctx;
    return x && x->c ? libp2p_conn_set_deadline(x->c, ms) : LIBP2P_ERR_NULL_PTR;
}
static const multiaddr_t *io_conn_local(libp2p_io_t *self)
{
    io_conn_ctx_t *x = (io_conn_ctx_t *)self->ctx;
    return x && x->c ? libp2p_conn_local_addr(x->c) : NULL;
}
static const multiaddr_t *io_conn_remote(libp2p_io_t *self)
{
    io_conn_ctx_t *x = (io_conn_ctx_t *)self->ctx;
    return x && x->c ? libp2p_conn_remote_addr(x->c) : NULL;
}
static int io_conn_close(libp2p_io_t *self)
{
    io_conn_ctx_t *x = (io_conn_ctx_t *)self->ctx;
    return x && x->c ? libp2p_conn_close(x->c) : 0;
}
static void io_conn_free(libp2p_io_t *self)
{
    if (!self)
        return;
    if (self->ctx)
        free(self->ctx);
    free(self);
}

static const libp2p_io_vtbl_t IO_CONN_VT = {
    .read = io_conn_read,
    .write = io_conn_write,
    .set_deadline = io_conn_deadline,
    .local_addr = io_conn_local,
    .remote_addr = io_conn_remote,
    .close = io_conn_close,
    .free = io_conn_free,
};

libp2p_io_t *libp2p_io_from_conn(libp2p_conn_t *c)
{
    if (!c)
        return NULL;
    libp2p_io_t *io = (libp2p_io_t *)calloc(1, sizeof(*io));
    io_conn_ctx_t *x = (io_conn_ctx_t *)calloc(1, sizeof(*x));
    if (!io || !x)
    {
        free(io);
        free(x);
        return NULL;
    }
    x->c = c;
    io->vt = &IO_CONN_VT;
    io->ctx = x;
    return io;
}

typedef struct
{
    libp2p_stream_t *s;
} io_stream_ctx_t;

static ssize_t io_stream_read(libp2p_io_t *self, void *buf, size_t len)
{
    io_stream_ctx_t *x = (io_stream_ctx_t *)self->ctx;
    return x && x->s ? libp2p_stream_read(x->s, buf, len) : LIBP2P_ERR_NULL_PTR;
}
static ssize_t io_stream_write(libp2p_io_t *self, const void *buf, size_t len)
{
    io_stream_ctx_t *x = (io_stream_ctx_t *)self->ctx;
    return x && x->s ? libp2p_stream_write(x->s, buf, len) : LIBP2P_ERR_NULL_PTR;
}
static int io_stream_deadline(libp2p_io_t *self, uint64_t ms)
{
    io_stream_ctx_t *x = (io_stream_ctx_t *)self->ctx;
    return x && x->s ? libp2p_stream_set_deadline(x->s, ms) : LIBP2P_ERR_NULL_PTR;
}
static const multiaddr_t *io_stream_local(libp2p_io_t *self)
{
    (void)self; /* no direct API; leave NULL */
    return NULL;
}
static const multiaddr_t *io_stream_remote(libp2p_io_t *self)
{
    (void)self; /* no direct API; leave NULL */
    return NULL;
}
static int io_stream_close(libp2p_io_t *self)
{
    io_stream_ctx_t *x = (io_stream_ctx_t *)self->ctx;
    return x && x->s ? libp2p_stream_close(x->s) : 0;
}
static void io_stream_free(libp2p_io_t *self)
{
    if (!self)
        return;
    if (self->ctx)
        free(self->ctx);
    free(self);
}

static const libp2p_io_vtbl_t IO_STREAM_VT = {
    .read = io_stream_read,
    .write = io_stream_write,
    .set_deadline = io_stream_deadline,
    .local_addr = io_stream_local,
    .remote_addr = io_stream_remote,
    .close = io_stream_close,
    .free = io_stream_free,
};

libp2p_io_t *libp2p_io_from_stream(libp2p_stream_t *s)
{
    if (!s)
        return NULL;
    libp2p_io_t *io = (libp2p_io_t *)calloc(1, sizeof(*io));
    io_stream_ctx_t *x = (io_stream_ctx_t *)calloc(1, sizeof(*x));
    if (!io || !x)
    {
        free(io);
        free(x);
        return NULL;
    }
    x->s = s;
    io->vt = &IO_STREAM_VT;
    io->ctx = x;
    return io;
}
