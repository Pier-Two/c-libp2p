#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "protocol/tcp/protocol_tcp_poller.h"
#include "protocol/tcp/protocol_tcp_queue.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include "libp2p/log.h"

/* Listener helpers implemented in protocol_tcp.c */
libp2p_listener_err_t tcp_listener_accept(libp2p_listener_t *l, libp2p_conn_t **out);
libp2p_listener_err_t tcp_listener_local(libp2p_listener_t *l, multiaddr_t **out);
libp2p_listener_err_t tcp_listener_close(libp2p_listener_t *l);
void tcp_listener_free(libp2p_listener_t *l);

/** Create and configure a listening socket. */
static int prepare_socket(const struct sockaddr_storage *ss, socklen_t ss_len, tcp_transport_ctx_t *transport_ctx)
{
#ifdef SOCK_CLOEXEC
    int fd = socket(ss->ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(ss->ss_family, SOCK_STREAM, 0);
#endif
    if (fd < 0)
        return -1;
#ifndef SOCK_CLOEXEC
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
    {
        close(fd);
        return -1;
    }
#endif
    if (set_nonblocking(fd) == -1)
    {
        perror("[TCP] prepare_socket: set_nonblocking failed");
        close(fd);
        return -1;
    }
    if (transport_ctx->cfg.reuse_port)
    {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) < 0
#ifdef SO_REUSEPORT
            || setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) < 0
#endif
        )
        {
            perror("[TCP] prepare_socket: setsockopt(SO_REUSE*) failed");
            close(fd);
            return -1;
        }
    }
    if (bind(fd, (const struct sockaddr *)ss, ss_len) != 0)
    {
        perror("[TCP] prepare_socket: bind failed");
        close(fd);
        return -1;
    }
    size_t requested_size = (transport_ctx->cfg.listen_backlog > 0) ? transport_ctx->cfg.listen_backlog : (size_t)SOMAXCONN;
    size_t clamped_size = (requested_size > (size_t)SOMAXCONN) ? (size_t)SOMAXCONN : requested_size;
    int backlog = (clamped_size > (size_t)INT_MAX) ? INT_MAX : (int)clamped_size;
    if (listen(fd, backlog) != 0)
    {
        perror("[TCP] prepare_socket: listen failed");
        close(fd);
        return -1;
    }
#ifdef TCP_FASTOPEN
    {
        int tfo_queue_len = backlog;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &tfo_queue_len, sizeof tfo_queue_len);
    }
#endif
    return fd;
}

/** Allocate and register the listener context structures. */
static libp2p_transport_err_t build_listener(int fd, tcp_transport_ctx_t *transport_ctx, const multiaddr_t *addr, libp2p_listener_t **out)
{
    tcp_listener_ctx_t *listener_ctx = calloc(1, sizeof *listener_ctx);
    if (!listener_ctx)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    atomic_init(&listener_ctx->closed, false);
    atomic_init(&listener_ctx->refcount, 1);
    atomic_init(&listener_ctx->state.waiters, 0);
    atomic_init(&listener_ctx->fd, fd);
    atomic_init(&listener_ctx->gc.free_epoch, 0);
    listener_ctx->transport_ctx = transport_ctx;
    cq_init(&listener_ctx->q);
    listener_ctx->state.cond_clock = CLOCK_REALTIME;
#if defined(_POSIX_MONOTONIC_CLOCK) && !defined(__APPLE__)
    {
        pthread_condattr_t attr;
        if (pthread_condattr_init(&attr) == 0)
        {
            if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0)
                listener_ctx->state.cond_clock = CLOCK_MONOTONIC;
            pthread_cond_destroy(&listener_ctx->q.cond);
            pthread_cond_init(&listener_ctx->q.cond, &attr);
            pthread_condattr_destroy(&attr);
        }
    }
#endif
    atomic_init(&listener_ctx->state.disabled, false);
    listener_ctx->state.enable_at_ms = 0;
    listener_ctx->state.backoff_ms = 100;
    listener_ctx->state.poll_ms = (transport_ctx->cfg.accept_poll_ms != 0) ? transport_ctx->cfg.accept_poll_ms : 1000;
    listener_ctx->state.close_timeout_ms = transport_ctx->cfg.close_timeout_ms;

    struct sockaddr_storage actual = {0};
    socklen_t actual_len = sizeof actual;
    if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) == 0)
        listener_ctx->local = sockaddr_to_multiaddr(&actual, actual_len);
    else
        listener_ctx->local = multiaddr_copy(addr, NULL);

    {
        int __se = 0;
        char *__ls = listener_ctx->local ? multiaddr_to_str(listener_ctx->local, &__se) : NULL;
        LP_LOGD("TCP", "build_listener: initial local=%s (err=%d)", __ls ? __ls : "(null)", __se);
        free(__ls);
    }

    /* If caller requested an ephemeral port (/tcp/0), ensure the stored
       local multiaddr reflects the kernel-assigned port by re-reading
       via getsockname. This avoids returning a useless "/tcp/0" to callers
       of libp2p_listener_local_addr(). */
    if (listener_ctx->local)
    {
        int serr = 0;
        char *s = multiaddr_to_str(listener_ctx->local, &serr);
        if (s)
        {
            /* naive check: "/tcp/0" substring indicates ephemeral request */
            if (strstr(s, "/tcp/0") != NULL)
            {
                multiaddr_free(listener_ctx->local);
                if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) == 0)
                {
                    listener_ctx->local = sockaddr_to_multiaddr(&actual, actual_len);
                }
                else
                {
                    listener_ctx->local = multiaddr_copy(addr, NULL);
                }

                int __se2 = 0;
                char *__ls2 = listener_ctx->local ? multiaddr_to_str(listener_ctx->local, &__se2) : NULL;
                LP_LOGD("TCP", "build_listener: corrected local=%s (err=%d)", __ls2 ? __ls2 : "(null)", __se2);
                free(__ls2);
            }
            free(s);
        }
    }
    if (!listener_ctx->local)
    {
        pthread_cond_destroy(&listener_ctx->q.cond);
        pthread_mutex_destroy(&listener_ctx->q.mtx);
        free(listener_ctx);
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    if (poller_add(transport_ctx, listener_ctx) != 0)
    {
        multiaddr_free(listener_ctx->local);
        pthread_cond_destroy(&listener_ctx->q.cond);
        pthread_mutex_destroy(&listener_ctx->q.mtx);
        free(listener_ctx);
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p_listener_t *l = calloc(1, sizeof *l);
    if (!l)
    {
        poller_del(transport_ctx, listener_ctx);
        multiaddr_free(listener_ctx->local);
        pthread_cond_destroy(&listener_ctx->q.cond);
        pthread_mutex_destroy(&listener_ctx->q.mtx);
        free(listener_ctx);
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    static const libp2p_listener_vtbl_t TCP_LISTENER_VTBL = {
        .accept = tcp_listener_accept,
        .local_addr = tcp_listener_local,
        .close = tcp_listener_close,
        .free = tcp_listener_free,
    };
    l->vt = &TCP_LISTENER_VTBL;
    l->ctx = listener_ctx;
    atomic_init(&l->refcount, 1);
    if (pthread_mutex_init(&l->mutex, NULL) != 0)
    {
        poller_del(transport_ctx, listener_ctx);
        multiaddr_free(listener_ctx->local);
        pthread_cond_destroy(&listener_ctx->q.cond);
        pthread_mutex_destroy(&listener_ctx->q.mtx);
        free(listener_ctx);
        close(fd);
        free(l);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    pthread_mutex_lock(&transport_ctx->listeners.lock);
    if (atomic_load_explicit(&transport_ctx->closed, memory_order_acquire))
    {
        pthread_mutex_unlock(&transport_ctx->listeners.lock);
        poller_del(transport_ctx, listener_ctx);
        multiaddr_free(listener_ctx->local);
        pthread_cond_destroy(&listener_ctx->q.cond);
        pthread_mutex_destroy(&listener_ctx->q.mtx);
        free(listener_ctx);
        close(fd);
        free(l);
        return LIBP2P_TRANSPORT_ERR_CLOSED;
    }
    size_t new_count = transport_ctx->listeners.count + 1;
    libp2p_listener_t **new_list = realloc(transport_ctx->listeners.list, sizeof *transport_ctx->listeners.list * new_count);
    if (!new_list)
    {
        pthread_mutex_unlock(&transport_ctx->listeners.lock);
        poller_del(transport_ctx, listener_ctx);
        multiaddr_free(listener_ctx->local);
        pthread_cond_destroy(&listener_ctx->q.cond);
        pthread_mutex_destroy(&listener_ctx->q.mtx);
        free(listener_ctx);
        close(fd);
        free(l);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    transport_ctx->listeners.list = new_list;
    transport_ctx->listeners.list[transport_ctx->listeners.count++] = l;
    pthread_mutex_unlock(&transport_ctx->listeners.lock);

    *out = l;
    return LIBP2P_TRANSPORT_OK;
}

libp2p_transport_err_t tcp_listen(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out)
{
    if (out)
        *out = NULL;
    if (!self || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;

    tcp_transport_ctx_t *transport_ctx = self->ctx;
    if (!transport_ctx)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    if (atomic_load_explicit(&transport_ctx->closed, memory_order_acquire))
        return LIBP2P_TRANSPORT_ERR_CLOSED;

    uint64_t p0;
    if (multiaddr_get_protocol_code(addr, 0, &p0) == 0 && (p0 == MULTICODEC_DNS4 || p0 == MULTICODEC_DNS6))
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;

    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (multiaddr_to_sockaddr(addr, &ss, &ss_len) != 0)
    {
        LP_LOGW("TCP", "tcp_listen: multiaddr_to_sockaddr failed for addr; unsupported");
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    }

    int fd = prepare_socket(&ss, ss_len, transport_ctx);
    if (fd < 0)
    {
        LP_LOGW("TCP", "tcp_listen: prepare_socket failed (errno=%d: %s)", errno, strerror(errno));
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }

    return build_listener(fd, transport_ctx, addr, out);
}
