#include "libp2p/stream_internal.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

typedef struct
{
    libp2p_mplex_ctx_t *ctx;
    libp2p_mplex_stream_t *st;
} mstream_ctx_t;

/* Map mplex stream return codes to unified libp2p stream error codes
 * expected by libp2p_stream_* users (e.g., ping). */
static inline ssize_t map_mplex_read_to_stream_err(libp2p_mplex_ssize_t rc)
{
    if (rc > 0)
        return (ssize_t)rc;
    switch (rc)
    {
        case 0:
            // Treat 0 (EOF) as unified EOF
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

static inline ssize_t map_mplex_write_to_stream_err(libp2p_mplex_ssize_t rc)
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

static ssize_t mst_read(void *io_ctx, void *buf, size_t len)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->st)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_mplex_ssize_t rc = libp2p_mplex_stream_read(x->st, buf, len);
    return map_mplex_read_to_stream_err(rc);
}

static ssize_t mst_write(void *io_ctx, const void *buf, size_t len)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->st)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_mplex_ssize_t rc = libp2p_mplex_stream_write_async(x->st, buf, len);
    return map_mplex_write_to_stream_err(rc);
}

static int mst_close(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->st)
        return LIBP2P_ERR_NULL_PTR;
    int rc = libp2p_mplex_stream_close(x->st);
    return (rc == LIBP2P_MPLEX_OK) ? 0 : LIBP2P_ERR_INTERNAL;
}

static int mst_reset(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->st)
        return LIBP2P_ERR_NULL_PTR;
    int rc = libp2p_mplex_stream_reset(x->st);
    return (rc == LIBP2P_MPLEX_OK) ? 0 : LIBP2P_ERR_INTERNAL;
}

static int mst_deadline(void *io_ctx, uint64_t ms)
{
    (void)io_ctx;
    (void)ms;
    return 0; /* Deadlines handled by IO helpers; avoid per-conn deadline. */
}

static const multiaddr_t *mst_local(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->ctx || !x->ctx->conn)
        return NULL;
    return libp2p_conn_local_addr(x->ctx->conn);
}

static const multiaddr_t *mst_remote(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->ctx || !x->ctx->conn)
        return NULL;
    return libp2p_conn_remote_addr(x->ctx->conn);
}

static int mst_is_writable(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->st)
        return -1;
    /* mplex has no per-stream window; treat as writable if not locally closed/reset */
    int writable = 1;
    pthread_mutex_lock(&x->st->lock);
    if ((x->st->state & LIBP2P_MPLEX_STREAM_LOCAL_CLOSED) || (x->st->state & LIBP2P_MPLEX_STREAM_STATE_RESET))
        writable = 0;
    pthread_mutex_unlock(&x->st->lock);
    return writable;
}

static int mst_has_readable(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x || !x->st)
        return -1;
    int readable = 0;
    pthread_mutex_lock(&x->st->lock);
    if (x->st->queued > 0)
        readable = 1;
    pthread_mutex_unlock(&x->st->lock);
    return readable;
}

static void mst_free_ctx(void *io_ctx)
{
    mstream_ctx_t *x = (mstream_ctx_t *)io_ctx;
    if (!x)
        return;
    /* We do not own ctx or stream; just free the small wrapper */
    free(x);
}

libp2p_stream_t *libp2p_stream_from_mplex(struct libp2p_host *host, libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t *stream, const char *protocol_id,
                                          int initiator, peer_id_t *remote_peer)
{
    if (!ctx || !stream)
        return NULL;
    mstream_ctx_t *mc = (mstream_ctx_t *)calloc(1, sizeof(*mc));
    if (!mc)
        return NULL;
    mc->ctx = ctx;
    mc->st = stream;
    libp2p_stream_backend_ops_t ops = {
        .read = mst_read,
        .write = mst_write,
        .close = mst_close,
        .reset = mst_reset,
        .set_deadline = mst_deadline,
        .local_addr = mst_local,
        .remote_addr = mst_remote,
        .is_writable = mst_is_writable,
        .has_readable = mst_has_readable,
        .free_ctx = mst_free_ctx,
    };
    libp2p_stream_t *s = libp2p_stream_from_ops(host, mc, &ops, protocol_id, initiator, remote_peer);
    if (!s)
    {
        mst_free_ctx(mc);
    }
    return s;
}
