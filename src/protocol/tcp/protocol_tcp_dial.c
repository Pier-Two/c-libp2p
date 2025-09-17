#include <arpa/inet.h>
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
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol/tcp/protocol_tcp_poller.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/transport.h"

/**
 * Helper creating a non-blocking, close-on-exec TCP socket.
 */
static int prepare_socket(int family)
{
#ifdef SOCK_CLOEXEC
    int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(family, SOCK_STREAM, 0);
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
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * Apply transport specific socket options.
 */
static libp2p_transport_err_t configure_socket_options(int fd, tcp_transport_ctx_t *transport_ctx)
{
    if (transport_ctx->cfg.nodelay)
    {
        int on = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) < 0)
            return map_sockopt_errno(errno);
    }
    if (transport_ctx->cfg.reuse_port)
    {
        int on = 1;
        int rc1 = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#ifdef SO_REUSEPORT
        int rc2 = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        if (rc1 < 0 || rc2 < 0)
            return map_sockopt_errno(errno);
#else
        if (rc1 < 0)
            return map_sockopt_errno(errno);
#endif
    }
    if (transport_ctx->cfg.keepalive)
    {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) < 0)
            return map_sockopt_errno(errno);
    }
#ifdef TCP_FASTOPEN
    {
        int tfo_enable = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &tfo_enable, sizeof tfo_enable);
    }
#endif
    return LIBP2P_TRANSPORT_OK;
}

/**
 * Wait for a non-blocking connect to finish or timeout.
 */
static libp2p_transport_err_t wait_for_connect(int fd, tcp_transport_ctx_t *transport_ctx, libp2p_conn_t **out)
{
    struct pollfd pfd = {.fd = fd, .events = POLLOUT | POLLIN};

    int64_t cfg_to = transport_ctx->cfg.connect_timeout_ms;
    if (cfg_to > INT_MAX)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INVALID_ARG;
    }
    const uint64_t safety_cap_ms = 10ULL * 60ULL * 1000ULL; /* 10 minutes */
    uint64_t timeout_ms_duration;
    if (cfg_to < 0)
        timeout_ms_duration = safety_cap_ms;
    else if (cfg_to == 0)
        timeout_ms_duration = 30000; /* 30s default */
    else
        timeout_ms_duration = (uint64_t)cfg_to;

    uint64_t now_ms = now_mono_ms();
    uint64_t deadline_ms = (timeout_ms_duration > UINT64_MAX - now_ms) ? UINT64_MAX : now_ms + timeout_ms_duration;

    while (1)
    {
        if (atomic_load_explicit(&transport_ctx->closed, memory_order_acquire))
        {
            close(fd);
            return LIBP2P_TRANSPORT_ERR_CLOSED;
        }
        uint64_t current_ms = now_mono_ms();
        int wait_ms;
        if (current_ms >= deadline_ms)
            wait_ms = 0;
        else
        {
            uint64_t delta = deadline_ms - current_ms;
            wait_ms = (delta > INT_MAX) ? INT_MAX : (int)delta;
        }
#ifdef _WIN32
        fd_set rfds, wfds, efds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET((SOCKET)fd, &wfds);
        FD_SET((SOCKET)fd, &rfds);
        FD_SET((SOCKET)fd, &efds);
        struct timeval tv, *ptv = NULL;
        if (wait_ms >= 0)
        {
            tv.tv_sec = wait_ms / 1000;
            tv.tv_usec = (wait_ms % 1000) * 1000;
            ptv = &tv;
        }
        int ret = select(0, &rfds, &wfds, &efds, ptv);
        if (ret == SOCKET_ERROR)
            errno = WSAGetLastError();
        pfd.revents = 0;
        if (ret > 0)
        {
            if (FD_ISSET((SOCKET)fd, &rfds))
                pfd.revents |= POLLIN;
            if (FD_ISSET((SOCKET)fd, &wfds))
                pfd.revents |= POLLOUT;
            if (FD_ISSET((SOCKET)fd, &efds))
                pfd.revents |= POLLERR;
        }
#else
        int ret = poll(&pfd, 1, wait_ms);
#endif
        if (ret == 0)
        {
            /* Timed out waiting for connect to complete */
            close(fd);
            return LIBP2P_TRANSPORT_ERR_TIMEOUT;
        }
#ifdef POLLNVAL
        const short fatal_mask = POLLNVAL;
#else
        const short fatal_mask = 0;
#endif
        if (pfd.revents & (POLLOUT | POLLIN | POLLERR | POLLHUP | fatal_mask))
        {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
            {
                close(fd);
                return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
            }
            if (err != 0)
            {
                close(fd);
                return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
            }
            *out = make_tcp_conn(fd);
            if (!*out)
            {
                close(fd);
                return LIBP2P_TRANSPORT_ERR_INTERNAL;
            }
            return LIBP2P_TRANSPORT_OK;
        }
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }
}

libp2p_transport_err_t tcp_dial(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out)
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

    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (multiaddr_to_sockaddr(addr, &ss, &ss_len) != 0)
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;

    uint16_t port_n;
    if (ss.ss_family == AF_INET)
    {
        if (ss_len < sizeof(struct sockaddr_in))
            return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
        port_n = ((struct sockaddr_in *)&ss)->sin_port;
    }
    else if (ss.ss_family == AF_INET6)
    {
        if (ss_len < sizeof(struct sockaddr_in6))
            return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
        port_n = ((struct sockaddr_in6 *)&ss)->sin6_port;
    }
    else
    {
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    }
    if (ntohs(port_n) == 0)
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;

    int fd = prepare_socket(ss.ss_family);
    if (fd < 0)
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;

    libp2p_transport_err_t rc = configure_socket_options(fd, transport_ctx);
    if (rc != LIBP2P_TRANSPORT_OK)
    {
        close(fd);
        return rc;
    }

    int c = connect(fd, (struct sockaddr *)&ss, ss_len);
#ifdef _WIN32
    int errsv = (c == 0) ? 0 : WSAGetLastError();
    if (errsv == WSAEWOULDBLOCK)
        errsv = EWOULDBLOCK;
    else if (errsv == WSAEINPROGRESS)
        errsv = EINPROGRESS;
    else if (errsv == WSAEALREADY)
        errsv = EALREADY;
#else
    int errsv = errno;
#endif
    if (c != 0 && errsv != EINPROGRESS && errsv != EINTR && errsv != EALREADY && errsv != EWOULDBLOCK && errsv != EAGAIN)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }
    if (c == 0)
    {
        *out = make_tcp_conn(fd);
        if (!*out)
        {
            close(fd);
            return LIBP2P_TRANSPORT_ERR_INTERNAL;
        }
        return LIBP2P_TRANSPORT_OK;
    }

    return wait_for_connect(fd, transport_ctx, out);
}
