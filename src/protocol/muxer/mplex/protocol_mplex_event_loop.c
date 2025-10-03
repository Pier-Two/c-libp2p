#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include "libp2p/log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/epoll.h>
#define HAS_EPOLL 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(FORCE_KQUEUE)
#if defined(FORCE_KQUEUE)
#include <kqueue/sys/event.h>
#else
#include <sys/event.h>
#endif
#define HAS_KQUEUE 1
#else
#include <poll.h>
#define HAS_POLL 1
#endif

int libp2p_mplex_run_event_loop(libp2p_mplex_ctx_t *ctx, int timeout_ms)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    // Get file descriptor
    int fd = libp2p_mplex_get_fd(ctx);
    if (fd < 0)
        return LIBP2P_MPLEX_ERR_AGAIN; // No event source; nothing to process

    LP_LOGT("MPLEX", "event_loop enter ctx=%p fd=%d timeout=%d", (void *)ctx, fd, timeout_ms);
    const bool single_shot = (timeout_ms >= 0);
#ifdef HAS_EPOLL
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Add file descriptor to epoll
    struct epoll_event ev_data;
    ev_data.events = EPOLLIN | EPOLLET; // Register WRITE dynamically based on want_write
    ev_data.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev_data) < 0)
    {
        close(epoll_fd);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    // Add wake pipe (read end) if available
    const int wake_fd = ctx->wake_read_fd;
    if (wake_fd >= 0)
    {
        struct epoll_event ev_wake;
        ev_wake.events = EPOLLIN | EPOLLET;
        ev_wake.data.fd = wake_fd;
        (void)epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &ev_wake);
    }

    // Event loop
    for (;;)
    {
        struct epoll_event events[10];
        // If timeout_ms < 0, block indefinitely; wake-ups come via wake pipe
        int actual_timeout = (timeout_ms < 0) ? -1 : timeout_ms;

        int num_events = epoll_wait(epoll_fd, events, 10, actual_timeout);

        if (num_events < 0)
        {
            if (errno == EINTR)
                continue;
            close(epoll_fd);
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }

        // Keep WRITE interest in sync with want_write flag
        bool want_write = atomic_load(&ctx->want_write);
        uint32_t desired = EPOLLIN | EPOLLET | (want_write ? EPOLLOUT : 0);
        if (ev_data.events != desired)
        {
            ev_data.events = desired;
            ev_data.data.fd = fd;
            (void)epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev_data);
        }

        for (int i = 0; i < num_events; i++)
        {
            int ev_fd = events[i].data.fd;
            if (wake_fd >= 0 && ev_fd == wake_fd && (events[i].events & EPOLLIN))
            {
                // Drain wake pipe
                uint8_t buf[128];
                while (read(wake_fd, buf, sizeof(buf)) > 0)
                {
                }
                continue;
            }
            if (ev_fd == fd && (events[i].events & EPOLLIN))
            {
                int rc = libp2p_mplex_on_readable(ctx);
                if (rc != LIBP2P_MPLEX_OK && rc != 0 && rc != LIBP2P_MPLEX_ERR_AGAIN)
                {
                    close(epoll_fd);
                    return rc;
                }
            }
            if (ev_fd == fd && (events[i].events & EPOLLOUT))
            {
                int rc = libp2p_mplex_on_writable(ctx);
                if (rc != LIBP2P_MPLEX_OK)
                {
                    close(epoll_fd);
                    return rc;
                }
            }
        }

        if (single_shot || atomic_load(&ctx->stop))
            break;
    }

    close(epoll_fd);
    LP_LOGT("MPLEX", "event_loop exit ctx=%p", (void *)ctx);
    return LIBP2P_MPLEX_OK;

#elif defined(HAS_KQUEUE)
    // Create kqueue instance
    int kq = kqueue();
    if (kq < 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Add READ filter; add WRITE only when there are pending writes
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0)
    {
        close(kq);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }
    bool write_registered = false;

    // Register wake pipe (read end) if available
    const int wake_fd = ctx->wake_read_fd;
    if (wake_fd >= 0)
    {
        EV_SET(&ev, wake_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
        (void)kevent(kq, &ev, 1, NULL, 0, NULL);
    }

    // Event loop
    for (;;)
    {
        struct timespec ts;
        struct timespec *timeout_ptr = NULL;

        if (timeout_ms >= 0)
        {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1000000;
            timeout_ptr = &ts;
        }

        // Keep WRITE interest in sync with want_write flag
        bool want_write = atomic_load(&ctx->want_write);
        if (want_write && !write_registered)
        {
            EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
            (void)kevent(kq, &ev, 1, NULL, 0, NULL);
            write_registered = true;
        }
        else if (!want_write && write_registered)
        {
            EV_SET(&ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
            (void)kevent(kq, &ev, 1, NULL, 0, NULL);
            write_registered = false;
        }

        struct kevent events[4];
        int num_events = kevent(kq, NULL, 0, events, 4, timeout_ptr);

        if (num_events < 0)
        {
            if (errno == EINTR)
                continue;
            close(kq);
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }

        for (int i = 0; i < num_events; i++)
        {
            if (events[i].flags & EV_EOF)
            {
                close(kq);
                LP_LOGW("MPLEX", "event_loop exit ctx=%p (EV_EOF)", (void *)ctx);
                return LIBP2P_MPLEX_ERR_EOF;
            }
            if (wake_fd >= 0 && events[i].filter == EVFILT_READ && (int)events[i].ident == wake_fd)
            {
                // Drain wake pipe
                uint8_t buf[128];
                while (read(wake_fd, buf, sizeof(buf)) > 0)
                {
                }
                continue;
            }
            if (events[i].filter == EVFILT_READ && (int)events[i].ident == fd)
            {
                int rc = libp2p_mplex_on_readable(ctx);
                if (rc != LIBP2P_MPLEX_OK && rc != 0 && rc != LIBP2P_MPLEX_ERR_AGAIN)
                {
                    close(kq);
                    return rc;
                }
            }
            else if (events[i].filter == EVFILT_WRITE && (int)events[i].ident == fd)
            {
                int rc = libp2p_mplex_on_writable(ctx);
                if (rc == LIBP2P_MPLEX_ERR_AGAIN)
                {
                    // Still not fully flushed; keep WRITE interest
                    continue;
                }
                if (rc != LIBP2P_MPLEX_OK)
                {
                    close(kq);
                    return rc;
                }
            }
        }

        if (single_shot || atomic_load(&ctx->stop))
            break;
    }

    close(kq);
    LP_LOGT("MPLEX", "event_loop exit ctx=%p", (void *)ctx);
    return LIBP2P_MPLEX_OK;

#else // HAS_POLL
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;

    // Event loop
    for (;;)
    {
        // Build pollfd set with connection fd and optional wake pipe
        struct pollfd pfds[2];
        nfds_t nfds = 0;
        int idx_fd = -1, idx_wake = -1;

        pfds[nfds].fd = fd;
        pfds[nfds].events = POLLIN | (atomic_load(&ctx->want_write) ? POLLOUT : 0);
        idx_fd = (int)nfds;
        nfds++;

        int wake_fd = ctx->wake_read_fd;
        if (wake_fd >= 0)
        {
            pfds[nfds].fd = wake_fd;
            pfds[nfds].events = POLLIN;
            idx_wake = (int)nfds;
            nfds++;
        }

        int ret = poll(pfds, nfds, (timeout_ms < 0) ? -1 : timeout_ms);

        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }

        if (ret > 0)
        {
            if (idx_wake >= 0 && (pfds[idx_wake].revents & POLLIN))
            {
                uint8_t buf[128];
                while (read(pfds[idx_wake].fd, buf, sizeof(buf)) > 0)
                {
                }
            }
            if (idx_fd >= 0 && (pfds[idx_fd].revents & POLLIN))
            {
                int rc = libp2p_mplex_on_readable(ctx);
                if (rc != LIBP2P_MPLEX_OK && rc != 0 && rc != LIBP2P_MPLEX_ERR_AGAIN)
                {
                    return rc;
                }
            }
            if (idx_fd >= 0 && (pfds[idx_fd].revents & POLLOUT))
            {
                int rc = libp2p_mplex_on_writable(ctx);
                if (rc != LIBP2P_MPLEX_OK)
                {
                    return rc;
                }
            }
        }

        if (single_shot || atomic_load(&ctx->stop))
            break;
    }

    LP_LOGT("MPLEX", "event_loop exit ctx=%p", (void *)ctx);
    return LIBP2P_MPLEX_OK;
#endif
}

int libp2p_mplex_stop_event_loop(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    atomic_store(&ctx->stop, true);
    libp2p_mplex_wake(ctx);
    return LIBP2P_MPLEX_OK;
}

/* Start a detached background thread that continuously processes events
 * for the given mplex context. Returns 0 on success. The thread runs until
 * libp2p_mplex_stop_event_loop() is called and joins in mplex_free(). */
static void *mplex_loop_thread(void *arg)
{
    libp2p_mplex_ctx_t *ctx = (libp2p_mplex_ctx_t *)arg;
    if (!ctx)
        return NULL;
    (void)libp2p_mplex_run_event_loop(ctx, -1);
    return NULL;
}

int libp2p_mplex_start_event_loop_thread(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    if (ctx->loop_thread_started)
        return LIBP2P_MPLEX_OK;
    pthread_t th;
    if (pthread_create(&th, NULL, mplex_loop_thread, ctx) != 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;
    ctx->loop_thread = th;
    ctx->loop_thread_started = 1;
    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_process_events(libp2p_mplex_ctx_t *ctx, int timeout_ms)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    // Get file descriptor
    int fd = libp2p_mplex_get_fd(ctx);
    if (fd < 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Check if we should stop before processing events
    if (atomic_load(&ctx->stop))
        return LIBP2P_MPLEX_OK;

#ifdef HAS_EPOLL
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Add file descriptor to epoll
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET | (atomic_load(&ctx->want_write) ? EPOLLOUT : 0);
    event.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
    {
        close(epoll_fd);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    // Register wake pipe (read end) if available
    const int wake_fd = ctx->wake_read_fd;
    if (wake_fd >= 0)
    {
        struct epoll_event ev_wake;
        ev_wake.events = EPOLLIN | EPOLLET;
        ev_wake.data.fd = wake_fd;
        (void)epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &ev_wake);
    }

    // Process events once
    struct epoll_event events[10];
    int actual_timeout = timeout_ms;

    int num_events = epoll_wait(epoll_fd, events, 10, actual_timeout);

    // Close epoll fd immediately after waiting to avoid race conditions
    int epoll_errno = errno;
    // We will close epoll_fd after processing the ready events below

    if (num_events < 0)
    {
        close(epoll_fd);
        if (epoll_errno == EINTR)
            return LIBP2P_MPLEX_OK;
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    for (int i = 0; i < num_events; i++)
    {
        // Check if we should stop before processing each event
        if (atomic_load(&ctx->stop))
        {
            close(epoll_fd);
            return LIBP2P_MPLEX_OK;
        }

        int ev_fd = events[i].data.fd;
        if (wake_fd >= 0 && ev_fd == wake_fd && (events[i].events & EPOLLIN))
        {
            // Drain wake pipe
            uint8_t buf[128];
            while (read(wake_fd, buf, sizeof(buf)) > 0)
            {
            }
            continue;
        }
        if (ev_fd == fd && (events[i].events & EPOLLIN))
        {
            int rc = libp2p_mplex_on_readable(ctx);
            if (rc != LIBP2P_MPLEX_OK && rc != 0 && rc != LIBP2P_MPLEX_ERR_AGAIN)
            {
                close(epoll_fd);
                return rc;
            }
        }
        if (ev_fd == fd && (events[i].events & EPOLLOUT))
        {
            int rc = libp2p_mplex_on_writable(ctx);
            if (rc != LIBP2P_MPLEX_OK)
            {
                close(epoll_fd);
                return rc;
            }
        }
    }

    close(epoll_fd);

    return LIBP2P_MPLEX_OK;

#elif defined(HAS_KQUEUE)
    // Create kqueue instance
    int kq = kqueue();
    if (kq < 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Add file descriptor to kqueue
    struct kevent events[3];
    int nreg = 0;
    EV_SET(&events[nreg++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (atomic_load(&ctx->want_write))
    {
        EV_SET(&events[nreg++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
    }
    // Register wake pipe (read end) if available
    const int wake_fd = ctx->wake_read_fd;
    if (wake_fd >= 0)
    {
        EV_SET(&events[nreg++], wake_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    }
    if (kevent(kq, events, nreg, NULL, 0, NULL) < 0)
    {
        close(kq);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    // Process events once
    struct timespec ts;
    struct timespec *timeout_ptr = NULL;

    if (timeout_ms >= 0)
    {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        timeout_ptr = &ts;
    }

    struct kevent event;
    // For kqueue, timeout_ms=0 should return immediately, which is the correct behavior
    int num_events = kevent(kq, NULL, 0, &event, 1, timeout_ptr);

    // Close kqueue fd immediately after waiting to avoid race conditions
    int kqueue_errno = errno;

    if (num_events < 0)
    {
        close(kq);
        if (kqueue_errno == EINTR)
            return LIBP2P_MPLEX_OK;
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    if (num_events > 0)
    {
        if (event.flags & EV_EOF)
        {
            close(kq);
            // Peer closed the connection; map to EOF
            return LIBP2P_MPLEX_ERR_EOF;
        }
        // Check if we should stop before processing the event
        if (atomic_load(&ctx->stop))
        {
            close(kq);
            return LIBP2P_MPLEX_OK;
        }

        if (wake_fd >= 0 && event.filter == EVFILT_READ && (int)event.ident == wake_fd)
        {
            // Drain wake pipe
            uint8_t buf[128];
            while (read(wake_fd, buf, sizeof(buf)) > 0)
            {
            }
            close(kq);
            return LIBP2P_MPLEX_OK;
        }
        if (event.filter == EVFILT_READ && (int)event.ident == fd)
        {
            int rc = libp2p_mplex_on_readable(ctx);
            if (rc != LIBP2P_MPLEX_OK && rc != 0 && rc != LIBP2P_MPLEX_ERR_AGAIN)
            {
                close(kq);
                return rc;
            }
        }
        else if (event.filter == EVFILT_WRITE && (int)event.ident == fd)
        {
            int rc = libp2p_mplex_on_writable(ctx);
            if (rc != LIBP2P_MPLEX_OK)
            {
                close(kq);
                return rc;
            }
        }
    }

    close(kq);

    return LIBP2P_MPLEX_OK;

#else // HAS_POLL
    // Build pollfd set with connection fd and optional wake pipe
    struct pollfd pfds[2];
    nfds_t nfds = 0;
    int idx_fd = -1, idx_wake = -1;

    pfds[nfds].fd = fd;
    pfds[nfds].events = POLLIN | (atomic_load(&ctx->want_write) ? POLLOUT : 0);
    idx_fd = (int)nfds;
    nfds++;

    int wake_fd = ctx->wake_read_fd;
    if (wake_fd >= 0)
    {
        pfds[nfds].fd = wake_fd;
        pfds[nfds].events = POLLIN;
        idx_wake = (int)nfds;
        nfds++;
    }

    // Process events once
    // For poll, timeout_ms=0 should return immediately, which is the correct behavior
    int ret = poll(pfds, nfds, timeout_ms);

    if (ret < 0)
    {
        if (errno == EINTR)
            return LIBP2P_MPLEX_OK;
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    if (ret > 0)
    {
        // Check if we should stop before processing events
        if (atomic_load(&ctx->stop))
            return LIBP2P_MPLEX_OK;

        if (idx_wake >= 0 && (pfds[idx_wake].revents & POLLIN))
        {
            uint8_t buf[128];
            while (read(pfds[idx_wake].fd, buf, sizeof(buf)) > 0)
            {
            }
        }
        if (idx_fd >= 0 && (pfds[idx_fd].revents & POLLIN))
        {
            int rc = libp2p_mplex_on_readable(ctx);
            if (rc != LIBP2P_MPLEX_OK && rc != 0 && rc != LIBP2P_MPLEX_ERR_AGAIN)
            {
                return rc;
            }
        }
        if (idx_fd >= 0 && (pfds[idx_fd].revents & POLLOUT))
        {
            int rc = libp2p_mplex_on_writable(ctx);
            if (rc != LIBP2P_MPLEX_OK)
            {
                return rc;
            }
        }
    }

    return LIBP2P_MPLEX_OK;
#endif
}
