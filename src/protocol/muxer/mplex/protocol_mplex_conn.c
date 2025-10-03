#include "protocol_mplex_conn.h"
#include "libp2p/log.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static ssize_t mplex_read(libp2p_conn_t *self, void *buf, size_t len)
{
    mplex_conn_ctx_t *ctx = (mplex_conn_ctx_t *)self->ctx;

    if (atomic_load(&ctx->closed))
        return LIBP2P_CONN_ERR_CLOSED;

    /* Enforce non-blocking semantics regardless of current FD flags */
    ssize_t n = recv(ctx->fd, buf, len,
#ifdef MSG_DONTWAIT
                     MSG_DONTWAIT
#else
                     0
#endif
    );

    if (n > 0)
    {
        atomic_fetch_add(&ctx->read_bytes, n);
        return n;
    }

    if (n == 0)
        return LIBP2P_CONN_ERR_EOF;

    switch (errno)
    {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            return LIBP2P_CONN_ERR_AGAIN;
        default:
            return LIBP2P_CONN_ERR_INTERNAL;
    }
}

static ssize_t mplex_write(libp2p_conn_t *self, const void *buf, size_t len)
{
    mplex_conn_ctx_t *ctx = (mplex_conn_ctx_t *)self->ctx;

    if (atomic_load(&ctx->closed))
        return LIBP2P_CONN_ERR_CLOSED;

    int send_flags = 0;
#ifdef MSG_DONTWAIT
    send_flags |= MSG_DONTWAIT;
#endif
#ifdef MSG_NOSIGNAL
    /* Prevent SIGPIPE on platforms without SO_NOSIGPIPE */
    send_flags |= MSG_NOSIGNAL;
#endif
    ssize_t n = send(ctx->fd, buf, len, send_flags);

    if (n > 0)
    {
        atomic_fetch_add(&ctx->write_bytes, n);
        return n;
    }

    if (n == 0)
        return LIBP2P_CONN_ERR_EOF;

    switch (errno)
    {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            return LIBP2P_CONN_ERR_AGAIN;
        case EPIPE:
            // Handle SIGPIPE gracefully
            atomic_store(&ctx->closed, true);
            return LIBP2P_CONN_ERR_CLOSED;
        default:
            return LIBP2P_CONN_ERR_INTERNAL;
    }
}

static libp2p_conn_err_t mplex_close(libp2p_conn_t *self)
{
    mplex_conn_ctx_t *ctx = (mplex_conn_ctx_t *)self->ctx;
    atomic_store(&ctx->closed, true);
    // Proactively shutdown to avoid blocking close due to lingering buffers
    if (ctx->fd >= 0)
    {
        shutdown(ctx->fd, SHUT_RDWR);
        // Set non-blocking again before close for safety
        int flags = fcntl(ctx->fd, F_GETFL, 0);
        if (flags != -1)
        {
            (void)fcntl(ctx->fd, F_SETFL, flags | O_NONBLOCK);
        }
        close(ctx->fd);
        ctx->fd = -1;
    }
    return LIBP2P_CONN_OK;
}

static int mplex_get_fd(libp2p_conn_t *self)
{
    if (!self || !self->ctx)
        return -1;
    mplex_conn_ctx_t *ctx = (mplex_conn_ctx_t *)self->ctx;
    return ctx->fd;
}

static void mplex_conn_free_impl(libp2p_conn_t *self)
{
    if (!self)
        return;

    mplex_conn_ctx_t *ctx = (mplex_conn_ctx_t *)self->ctx;
    if (ctx)
    {
        if (!atomic_load(&ctx->closed) && ctx->fd >= 0)
        {
            // Same safe shutdown path as close()
            shutdown(ctx->fd, SHUT_RDWR);
            int flags = fcntl(ctx->fd, F_GETFL, 0);
            if (flags != -1)
            {
                (void)fcntl(ctx->fd, F_SETFL, flags | O_NONBLOCK);
            }
            close(ctx->fd);
        }
        free(ctx);
    }
    free(self);
}

static const libp2p_conn_vtbl_t mplex_conn_vtbl = {
    .read = mplex_read,
    .write = mplex_write,
    .close = mplex_close,
    .free = mplex_conn_free_impl,
    .get_fd = mplex_get_fd,
    .set_deadline = NULL, // TODO: implement if needed
    .local_addr = NULL,   // TODO: implement if needed
    .remote_addr = NULL   // TODO: implement if needed
};

// Helper function to set a socket to non-blocking mode
static int set_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        LP_LOGW("MPLEX", "set_nb F_GETFL fd=%d errno=%d", fd, errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        LP_LOGW("MPLEX", "set_nb F_SETFL fd=%d errno=%d", fd, errno);
        return -1;
    }

    LP_LOGT("MPLEX", "set_nb OK fd=%d", fd);
    return 0;
}

libp2p_conn_t *mplex_conn_new(int fd)
{
    // Validate file descriptor early
    if (fd < 0)
    {
        return NULL;
    }

    // Avoid SIGPIPE per-socket, not process-wide
#ifdef SO_NOSIGPIPE
    {
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif

    // Try to set non-blocking. If it fails, proceed anyway since the
    // read/write paths use non-blocking semantics (MSG_DONTWAIT) where possible.
    // This makes tests resilient when FDs are pipes or unusual descriptors.
    if (set_socket_nonblocking(fd) == -1)
    {
        LP_LOGW("MPLEX", "mplex_conn_new WARN set_nb fd=%d (continuing without O_NONBLOCK)", fd);
    }

    mplex_conn_ctx_t *ctx = calloc(1, sizeof(mplex_conn_ctx_t));
    if (!ctx)
    {
        LP_LOGE("MPLEX", "mplex_conn_new ERR calloc ctx fd=%d", fd);
        return NULL;
    }

    ctx->fd = fd;
    atomic_init(&ctx->closed, false);
    atomic_init(&ctx->read_bytes, 0);
    atomic_init(&ctx->write_bytes, 0);

    libp2p_conn_t *conn = malloc(sizeof(libp2p_conn_t));
    if (!conn)
    {
        free(ctx);
        LP_LOGE("MPLEX", "mplex_conn_new ERR malloc conn fd=%d", fd);
        return NULL;
    }

    conn->vt = &mplex_conn_vtbl;
    conn->ctx = ctx;

    LP_LOGT("MPLEX", "mplex_conn_new OK fd=%d", fd);
    return conn;
}

void mplex_conn_free(libp2p_conn_t *conn)
{
    if (!conn)
        return;
    /* Always delegate to the vtable free to avoid leaking ctx/FD */
    if (conn->vt && conn->vt->free)
    {
        conn->vt->free(conn);
    }
    else
    {
        free(conn);
    }
}
