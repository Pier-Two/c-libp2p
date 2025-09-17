#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol/tcp/protocol_tcp_poller.h"
#include "protocol/tcp/protocol_tcp_queue.h"
#include "protocol/tcp/protocol_tcp_util.h"

/* transient resource‑exhaustion errors we back‑off on */
#define TRANSIENT_ERR(e) ((e) == EMFILE || (e) == ENFILE || (e) == ENOBUFS)

/* Maximum number of unconsumed accepted connections per listener */
#define ACCEPT_QUEUE_MAX 1024
#define MAX_ACCEPT_PER_LOOP 32

#if defined(USE_KQUEUE)
#include <sys/event.h> /* struct kevent, EV_SET, kevent()       */
#elif defined(USE_EPOLL)
#include <sys/epoll.h> /* struct epoll_event, epoll_*()         */
#endif

int poller_add(struct tcp_transport_ctx *transport_ctx, tcp_listener_ctx_t *listener_ctx)
{
#if USE_EPOLL
    struct epoll_event ev;
    ev.events = EPOLLIN
#ifdef EPOLLEXCLUSIVE
                | EPOLLEXCLUSIVE
#endif
        ;
    ev.data.ptr = listener_ctx;
    return epoll_ctl(transport_ctx->epfd, EPOLL_CTL_ADD, listener_ctx->fd, &ev);
#elif USE_KQUEUE
    struct kevent kev;
    EV_SET(&kev, listener_ctx->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, listener_ctx);
    return kevent(transport_ctx->kqfd, &kev, 1, NULL, 0, NULL);
#else /* generic / Windows fallback: no external poll-set needed */
    (void)transport_ctx;
    (void)listener_ctx;
    return 0; /* success – accept loop will use blocking accept() */
#endif
}

void poller_del(struct tcp_transport_ctx *transport_ctx, tcp_listener_ctx_t *listener_ctx)
{
#if USE_EPOLL
    epoll_ctl(transport_ctx->epfd, EPOLL_CTL_DEL, listener_ctx->fd, NULL);
#elif USE_KQUEUE
    struct kevent kev;
    EV_SET(&kev, listener_ctx->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(transport_ctx->kqfd, &kev, 1, NULL, 0, NULL);
#else /* generic / Windows fallback */
    (void)transport_ctx;
    (void)listener_ctx;
    /* nothing to do – socket isn't in a global poll-set */
#endif
}

static void destroy_listener_ctx(tcp_listener_ctx_t *ctx)
{
    /* finally safe to close the fd */
    close(ctx->fd);

    libp2p_conn_t *c;
    while ((c = cq_pop(&ctx->q)))
    {
        libp2p_conn_free(c);
    }
    pthread_cond_destroy(&ctx->q.cond);
    pthread_mutex_destroy(&ctx->q.mtx);
    multiaddr_free(ctx->local);
    free(ctx);
}

static inline void release_listener_ref(tcp_listener_ctx_t *listener_ctx)
{
    /* ensure decrement and signal are under the same mutex to prevent lost wakeups */
    pthread_mutex_lock(&listener_ctx->q.mtx);
    unsigned old = atomic_fetch_sub_explicit(&listener_ctx->refcount, 1, memory_order_release);
    assert(old >= 1);
    if (old == 2)
    {
        pthread_cond_signal(&listener_ctx->q.cond);
    }
    pthread_mutex_unlock(&listener_ctx->q.mtx);
}

void *poll_loop(void *arg)
{
    tcp_transport_ctx_t *transport_ctx = arg;

#if USE_EPOLL
    struct epoll_event evs[64];
#elif defined(USE_KQUEUE)
    struct kevent evs[64];
#else
    /* Windows fallback: we rely on WSAPoll() to watch listener sockets. */
    WSAPOLLFD pfd_arr[64];
#endif

    while (!atomic_load_explicit(&transport_ctx->closed, memory_order_acquire))
    {
        /* wait up to 200 ms for new readiness events */
#if defined(USE_EPOLL)
        int n = epoll_wait(transport_ctx->epfd, evs, (int)(sizeof evs / sizeof *evs), 200);
#elif defined(USE_KQUEUE)
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
        int n = kevent(transport_ctx->kqfd, NULL, 0, evs, (int)(sizeof evs / sizeof *evs), &ts);
#else
        /* Build pollfd array from current listeners */
        pthread_mutex_lock(&transport_ctx->listeners.lock);
        size_t n_list = (transport_ctx->listeners.count < (sizeof pfd_arr / sizeof *pfd_arr)) ? transport_ctx->listeners.count
                                                                                              : (sizeof pfd_arr / sizeof *pfd_arr);
        size_t pidx = 0;
        tcp_listener_ctx_t *lmap[64];
        for (size_t i = 0; i < transport_ctx->listeners.count && pidx < n_list; ++i)
        {
            libp2p_listener_t *pub = transport_ctx->listeners.list[i];
            if (!pub)
                continue;
            tcp_listener_ctx_t *lc = (tcp_listener_ctx_t *)pub->ctx;
            if (!lc)
                continue;
            if (atomic_load_explicit(&lc->state.disabled, memory_order_acquire) || atomic_load_explicit(&lc->closed, memory_order_acquire))
                continue;
            pfd_arr[pidx].fd = lc->fd;
            pfd_arr[pidx].events = POLLRDNORM;
            pfd_arr[pidx].revents = 0;
            lmap[pidx] = lc;
            ++pidx;
        }
        pthread_mutex_unlock(&transport_ctx->listeners.lock);
        int n;
        if (pidx == 0)
        {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
            nanosleep(&ts, NULL);
            n = 0;
        }
        else
        {
            n = WSAPoll(pfd_arr, (ULONG)pidx, 200);
            if (n == SOCKET_ERROR)
            {
                n = 0;
            }
        }
#endif

        /* improved error handling */
        if (n < 0)
        {
            if (errno == EINTR)
            {
                /* interrupted by signal: treat as timeout/no events */
                n = 0;
            }
            else
            {
#if defined(USE_EPOLL)
                perror("poll_loop: epoll_wait failed");
#elif defined(USE_KQUEUE)
                perror("poll_loop: kevent failed");
#endif
                /* still treat as no events to avoid busy-looping */
                n = 0;
            }
        }

#if defined(USE_EPOLL) || defined(USE_KQUEUE)
        /* handle the batch of ready listeners */
        for (int i = 0; i < n; ++i)
        {
#if defined(USE_EPOLL)
            /* Check for self-wakeup event */
            if (evs[i].data.ptr == transport_ctx)
            {
                char buf[64];
                {
                    ssize_t r;
                    do
                    {
                        r = read(transport_ctx->wakeup.pipe[0], buf, sizeof(buf));
                    } while (r > 0);
                    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        perror("poll_loop: draining wakeup pipe failed");
                    }
                }
                continue;
            }
            if (evs[i].data.ptr == NULL)
            {
                continue;
            }

            tcp_listener_ctx_t *listener_ctx = (tcp_listener_ctx_t *)evs[i].data.ptr;
#elif defined(USE_KQUEUE)
            /* check for self-wakeup event */
            if (evs[i].udata == transport_ctx)
            {
                char buf[64];
                {
                    ssize_t r;
                    do
                    {
                        r = read(transport_ctx->wakeup.pipe[0], buf, sizeof(buf));
                    } while (r > 0);
                    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        perror("poll_loop: draining wakeup pipe failed");
                    }
                }
                continue;
            }

            if (evs[i].udata == NULL)
            {
                continue;
            }
            tcp_listener_ctx_t *listener_ctx = (tcp_listener_ctx_t *)evs[i].udata;
#endif

            /* grab a temporary reference *before* inspecting any fields */
            atomic_fetch_add_explicit(&listener_ctx->refcount, 1, memory_order_acq_rel);

            if (atomic_load_explicit(&listener_ctx->closed, memory_order_acquire) ||
                atomic_load_explicit(&listener_ctx->gc.pending_free, memory_order_acquire))
            {
                goto done_listener;
            }

            /* inside poll_loop(), in the accept batch */
            int accept_count = 0;
            while (accept_count < MAX_ACCEPT_PER_LOOP)
            {
                /* backpressure: stop accepting when the queue is full */
                size_t qlen_now = atomic_load_explicit(&listener_ctx->q.len, memory_order_relaxed);
                if (qlen_now >= ACCEPT_QUEUE_MAX)
                {
                    /* Metrics: record backpressure condition */
                    if (transport_ctx->metrics)
                    {
                        libp2p_metrics_inc_counter(transport_ctx->metrics, "libp2p_accept_backpressure", "{\"transport\":\"tcp\",\"reason\":\"queue_full\"}", 1.0);
                        libp2p_metrics_observe_histogram(transport_ctx->metrics, "libp2p_accept_queue_depth", "{\"transport\":\"tcp\"}", (double)qlen_now);
                    }
                    break; /* defer further accepts until consumer drains the queue */
                }
                int fd;
#if defined(__linux__) && defined(SOCK_CLOEXEC)
                fd = accept4(listener_ctx->fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
                fd = accept(listener_ctx->fd, NULL, NULL);
                if (fd >= 0)
                {
                    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1 || set_nonblocking(fd) == -1)
                    {
                        close(fd);

                        /* fall through: stop processing this listener for now */
                        goto done_listener;
                    }
                }
#endif
                if (fd < 0)
                {
                    int err = errno;
                    if (err == EAGAIN || err == EWOULDBLOCK)
                    {
                        break; /* backlog drained */
                    }

                    /* temporary back‑off on resource exhaustion */
                    if (TRANSIENT_ERR(err) && !atomic_load_explicit(&listener_ctx->state.disabled, memory_order_acquire))
                    {
                        atomic_store_explicit(&listener_ctx->state.disabled, true, memory_order_release);
                        pthread_cond_broadcast(&listener_ctx->q.cond);
                        listener_ctx->state.enable_at_ms = now_mono_ms() + listener_ctx->state.backoff_ms;
                        if (listener_ctx->state.backoff_ms < 10 * 1000)
                        {
                            listener_ctx->state.backoff_ms <<= 1; /* exponential back‑off */
                        }

                        /* Metrics: record transient backpressure + backoff */
                        if (transport_ctx->metrics)
                        {
                            libp2p_metrics_inc_counter(transport_ctx->metrics, "libp2p_accept_backpressure", "{\"transport\":\"tcp\",\"reason\":\"resource_exhaustion\"}", 1.0);
                            libp2p_metrics_observe_histogram(transport_ctx->metrics, "libp2p_listener_backoff_ms", "{\"transport\":\"tcp\"}", (double)listener_ctx->state.backoff_ms);
                        }

                        poller_del(transport_ctx, listener_ctx); /* remove from poll set */
                    }

                    /* fall through: stop processing this listener for now */
                    goto done_listener;
                }

                accept_count++;

                /* TCP_NODELAY */
                if (listener_ctx->transport_ctx->cfg.nodelay)
                {
                    int on = 1;
                    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
                    {
                        close(fd);
                        continue;
                    }
                }

                /* SO_KEEPALIVE */
                if (listener_ctx->transport_ctx->cfg.keepalive)
                {
                    int on = 1;
                    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
                    {
                        close(fd);
                        continue;
                    }
                }

                /* build our libp2p_conn_t wrapper */
                libp2p_conn_t *c = make_tcp_conn(fd);
                if (c == NULL)
                {
                    /* allocation failed — ensure we close the socket and
                    immediately retry accepting the next one */
                    close(fd);
                    continue;
                }

                /* only enqueue if the listener is still open */
                if (!atomic_load_explicit(&listener_ctx->closed, memory_order_acquire))
                {
                    cq_push(&listener_ctx->q, c);
                    /* Metrics: observe queue depth after enqueue */
                    if (transport_ctx->metrics)
                    {
                        size_t qlen_after = atomic_load_explicit(&listener_ctx->q.len, memory_order_relaxed);
                        libp2p_metrics_observe_histogram(transport_ctx->metrics, "libp2p_accept_queue_depth", "{\"transport\":\"tcp\"}", (double)qlen_after);
                    }
                }
                else
                {
                    libp2p_conn_free(c);
                }
            }

            /* end accept loop */
        done_listener:
            release_listener_ref(listener_ctx);
            continue;
        }

#endif /* defined(USE_EPOLL) || defined(USE_KQUEUE) */

        /* try to re-enable listeners after back-off */
        uint64_t now = now_mono_ms();
        pthread_mutex_lock(&transport_ctx->listeners.lock);
        for (size_t j = 0; j < transport_ctx->listeners.count; ++j)
        {
            libp2p_listener_t *pub = transport_ctx->listeners.list[j];
            if (!pub)
            {
                continue;
            }
            tcp_listener_ctx_t *l = (tcp_listener_ctx_t *)pub->ctx;
            if (atomic_load_explicit(&l->state.disabled, memory_order_acquire) && now >= l->state.enable_at_ms)
            {
                if (poller_add(transport_ctx, l) == 0)
                {
                    atomic_store_explicit(&l->state.disabled, false, memory_order_release);
                }
                else
                {
                    l->state.enable_at_ms = now + l->state.backoff_ms;
                    if (l->state.backoff_ms < 10 * 1000)
                        l->state.backoff_ms <<= 1;
                }
            }
        }
        pthread_mutex_unlock(&transport_ctx->listeners.lock);

        /* advance epoch and reap deferred-free listeners */
        uint64_t my_epoch = atomic_fetch_add(&transport_ctx->gc.poll_epoch, 1) + 1;

        pthread_mutex_lock(&transport_ctx->gc.lock);
        tcp_listener_ctx_t **pp = &transport_ctx->gc.head;
        while (*pp)
        {
            tcp_listener_ctx_t *victim = *pp;

            if (atomic_load_explicit(&victim->refcount, memory_order_acquire) == 0 && victim->gc.free_epoch <= my_epoch)
            {
                /* unlink from graveyard list */
                *pp = victim->gc.next_free;
                pthread_mutex_unlock(&transport_ctx->gc.lock);

                destroy_listener_ctx(victim);

                /* re-lock and continue scanning from head */
                pthread_mutex_lock(&transport_ctx->gc.lock);
                continue;
            }
            pp = &(*pp)->gc.next_free;
        }
        pthread_mutex_unlock(&transport_ctx->gc.lock);

#ifndef USE_EPOLL
#ifndef USE_KQUEUE
        /* Windows WSAPoll-based processing */
        if (n > 0)
        {
            for (int i = 0; i < (int)pidx; ++i)
            {
                if (!(pfd_arr[i].revents & POLLRDNORM))
                    continue;
                tcp_listener_ctx_t *listener_ctx = lmap[i];
                if (!listener_ctx)
                    continue;
                atomic_fetch_add_explicit(&listener_ctx->refcount, 1, memory_order_acq_rel);
                if (atomic_load_explicit(&listener_ctx->closed, memory_order_acquire) ||
                    atomic_load_explicit(&listener_ctx->gc.pending_free, memory_order_acquire))
                {
                    release_listener_ref(listener_ctx);
                    continue;
                }
                int accept_count = 0;
                while (accept_count < MAX_ACCEPT_PER_LOOP)
                {
                    /* backpressure: stop accepting when the queue is full */
                    size_t qlen_now = atomic_load_explicit(&listener_ctx->q.len, memory_order_relaxed);
                    if (qlen_now >= ACCEPT_QUEUE_MAX)
                    {
                        if (transport_ctx->metrics)
                        {
                            libp2p_metrics_inc_counter(transport_ctx->metrics, "libp2p_accept_backpressure", "{\"transport\":\"tcp\",\"reason\":\"queue_full\"}", 1.0);
                            libp2p_metrics_observe_histogram(transport_ctx->metrics, "libp2p_accept_queue_depth", "{\"transport\":\"tcp\"}", (double)qlen_now);
                        }
                        break;
                    }

                    SOCKET s = accept(listener_ctx->fd, NULL, NULL);
                    if (s == INVALID_SOCKET)
                    {
                        int werr = WSAGetLastError();
                        if (werr == WSAEWOULDBLOCK)
                            break;
                        if ((werr == WSAEMFILE || werr == WSAENOBUFS) && !atomic_load_explicit(&listener_ctx->state.disabled, memory_order_acquire))
                        {
                            atomic_store_explicit(&listener_ctx->state.disabled, true, memory_order_release);
                            pthread_cond_broadcast(&listener_ctx->q.cond);
                            listener_ctx->state.enable_at_ms = now_mono_ms() + listener_ctx->state.backoff_ms;
                            if (listener_ctx->state.backoff_ms < 10000)
                                listener_ctx->state.backoff_ms <<= 1;
                            poller_del(transport_ctx, listener_ctx);
                            if (transport_ctx->metrics)
                            {
                                libp2p_metrics_inc_counter(transport_ctx->metrics, "libp2p_accept_backpressure", "{\"transport\":\"tcp\",\"reason\":\"resource_exhaustion\"}", 1.0);
                                libp2p_metrics_observe_histogram(transport_ctx->metrics, "libp2p_listener_backoff_ms", "{\"transport\":\"tcp\"}", (double)listener_ctx->state.backoff_ms);
                            }
                        }
                        break;
                    }
                    int fd = (int)s;
                    accept_count++;
                    if (set_nonblocking(fd) == -1)
                    {
                        closesocket(s);
                        continue;
                    }
                    if (listener_ctx->transport_ctx->cfg.nodelay)
                    {
                        int on = 1;
                        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof on);
                    }
                    if (listener_ctx->transport_ctx->cfg.keepalive)
                    {
                        int on = 1;
                        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof on);
                    }
                    libp2p_conn_t *c = make_tcp_conn(fd);
                    if (c)
                    {
                        if (!atomic_load_explicit(&listener_ctx->closed, memory_order_acquire))
                        {
                            cq_push(&listener_ctx->q, c);
                            if (transport_ctx->metrics)
                            {
                                size_t qlen_after = atomic_load_explicit(&listener_ctx->q.len, memory_order_relaxed);
                                libp2p_metrics_observe_histogram(transport_ctx->metrics, "libp2p_accept_queue_depth", "{\"transport\":\"tcp\"}", (double)qlen_after);
                            }
                        }
                        else
                            libp2p_conn_free(c);
                    }
                    else
                        closesocket(s);
                }
                release_listener_ref(listener_ctx);
            }
        }
#endif
#endif
    }

    return NULL;
}
