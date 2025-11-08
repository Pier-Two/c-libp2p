#include "libp2p/runtime.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#define RT_USE_EPOLL 1
#include <sys/epoll.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#define RT_USE_KQUEUE 1
#include <sys/event.h>
#include <sys/time.h>
#else
#define RT_USE_POLL 1
#include <poll.h>
#endif

typedef struct rt_fd_watcher
{
    int fd;
    int want_read;
    int want_write;
    libp2p_rt_fd_cb cb;
    void *ud;
    struct rt_fd_watcher *next;
} rt_fd_watcher_t;

typedef struct rt_timer
{
    int id;
    uint64_t next_ms;
    uint64_t interval_ms; /* 0 for one-shot */
    libp2p_rt_timer_cb cb;
    void *ud;
    struct rt_timer *next;
} rt_timer_t;

struct libp2p_runtime
{
    atomic_bool stop;
    rt_fd_watcher_t *fds; /* singly-linked */
    rt_timer_t *timers;   /* singly-linked */
    pthread_mutex_t lock;
#if RT_USE_EPOLL
    int epfd;
#elif RT_USE_KQUEUE
    int kq;
#else
    /* poll fallback: nothing global */
#endif
};

static uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

libp2p_runtime_t *libp2p_runtime_new(void)
{
    libp2p_runtime_t *rt = calloc(1, sizeof(*rt));
    if (!rt)
        return NULL;
    atomic_init(&rt->stop, false);
    if (pthread_mutex_init(&rt->lock, NULL) != 0)
    {
        free(rt);
        return NULL;
    }
#if RT_USE_EPOLL
    rt->epfd = epoll_create1(0);
    if (rt->epfd < 0)
    {
        pthread_mutex_destroy(&rt->lock);
        free(rt);
        return NULL;
    }
#elif RT_USE_KQUEUE
    rt->kq = kqueue();
    if (rt->kq < 0)
    {
        pthread_mutex_destroy(&rt->lock);
        free(rt);
        return NULL;
    }
#endif
    return rt;
}

void libp2p_runtime_free(libp2p_runtime_t *rt)
{
    if (!rt)
        return;
#if RT_USE_EPOLL
    if (rt->epfd >= 0)
        close(rt->epfd);
#elif RT_USE_KQUEUE
    if (rt->kq >= 0)
        close(rt->kq);
#endif
    pthread_mutex_lock(&rt->lock);
    rt_fd_watcher_t *f = rt->fds;
    rt->fds = NULL;
    rt_timer_t *t = rt->timers;
    rt->timers = NULL;
    pthread_mutex_unlock(&rt->lock);
    while (f)
    {
        rt_fd_watcher_t *n = f->next;
        free(f);
        f = n;
    }
    while (t)
    {
        rt_timer_t *n = t->next;
        free(t);
        t = n;
    }
    pthread_mutex_destroy(&rt->lock);
    free(rt);
}

void libp2p_runtime_stop(libp2p_runtime_t *rt)
{
    if (!rt)
        return;
    atomic_store(&rt->stop, true);
#if RT_USE_EPOLL
    /* Wake epoll_wait by writing to a self-pipe would be ideal; for simplicity
       rely on short timeouts driven by timers below. */
#elif RT_USE_KQUEUE
    /* Same; rely on short timeout */
#endif
}

static rt_fd_watcher_t *find_fd_unlocked(libp2p_runtime_t *rt, int fd)
{
    for (rt_fd_watcher_t *it = rt->fds; it; it = it->next)
        if (it->fd == fd)
            return it;
    return NULL;
}

int libp2p_runtime_add_fd(libp2p_runtime_t *rt, int fd, int want_read, int want_write, libp2p_rt_fd_cb cb, void *user_data)
{
    if (!rt || fd < 0 || !cb)
        return -1;
    rt_fd_watcher_t *w = calloc(1, sizeof(*w));
    if (!w)
        return -1;
    w->fd = fd;
    w->want_read = want_read ? 1 : 0;
    w->want_write = want_write ? 1 : 0;
    w->cb = cb;
    w->ud = user_data;

    pthread_mutex_lock(&rt->lock);
    if (find_fd_unlocked(rt, fd))
    {
        pthread_mutex_unlock(&rt->lock);
        free(w);
        return 0;
    }
    w->next = rt->fds;
    rt->fds = w;
    pthread_mutex_unlock(&rt->lock);

#if RT_USE_EPOLL
    struct epoll_event ev = {0};
    ev.events = (w->want_read ? EPOLLIN : 0) | (w->want_write ? EPOLLOUT : 0) | EPOLLET;
    ev.data.fd = fd;
    if (epoll_ctl(rt->epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
        goto add_fd_fail;
#elif RT_USE_KQUEUE
    struct kevent kev[2];
    int n = 0;
    if (w->want_read)
    {
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)fd);
    }
    if (w->want_write)
    {
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)fd);
    }
    if (n > 0 && kevent(rt->kq, kev, n, NULL, 0, NULL) < 0)
        goto add_fd_fail;
#else
    (void)want_read;
    (void)want_write; /* poll config happens in run() */
#endif
    return 0;

add_fd_fail:
    pthread_mutex_lock(&rt->lock);
    rt_fd_watcher_t **pp = &rt->fds;
    while (*pp)
    {
        if (*pp == w)
        {
            *pp = w->next;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&rt->lock);
    free(w);
    return -1;
}

int libp2p_runtime_mod_fd(libp2p_runtime_t *rt, int fd, int want_read, int want_write)
{
    if (!rt)
        return -1;
    pthread_mutex_lock(&rt->lock);
    rt_fd_watcher_t *w = find_fd_unlocked(rt, fd);
    if (!w)
    {
        pthread_mutex_unlock(&rt->lock);
        return -1;
    }
    w->want_read = want_read ? 1 : 0;
    w->want_write = want_write ? 1 : 0;
    pthread_mutex_unlock(&rt->lock);
#if RT_USE_EPOLL
    struct epoll_event ev = {0};
    ev.events = (w->want_read ? EPOLLIN : 0) | (w->want_write ? EPOLLOUT : 0) | EPOLLET;
    ev.data.fd = fd;
    return epoll_ctl(rt->epfd, EPOLL_CTL_MOD, fd, &ev);
#elif RT_USE_KQUEUE
    struct kevent kev[2];
    int n = 0;
    /* Simplistic: delete both then add as needed */
    EV_SET(&kev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    kevent(rt->kq, kev, n, NULL, 0, NULL);
    n = 0;
    if (w->want_read)
    {
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)fd);
    }
    if (w->want_write)
    {
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)fd);
    }
    if (n > 0 && kevent(rt->kq, kev, n, NULL, 0, NULL) < 0)
        return -1;
    return 0;
#else
    return 0;
#endif
}

int libp2p_runtime_del_fd(libp2p_runtime_t *rt, int fd)
{
    if (!rt)
        return -1;
    int removed = 0;
    pthread_mutex_lock(&rt->lock);
    rt_fd_watcher_t **pp = &rt->fds;
    while (*pp)
    {
        if ((*pp)->fd == fd)
        {
            rt_fd_watcher_t *victim = *pp;
            *pp = victim->next;
            free(victim);
            removed = 1;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&rt->lock);
    if (!removed)
        return 0;
#if RT_USE_EPOLL
    epoll_ctl(rt->epfd, EPOLL_CTL_DEL, fd, NULL);
#elif RT_USE_KQUEUE
    struct kevent kev[2];
    EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    kevent(rt->kq, kev, 2, NULL, 0, NULL);
#endif
    return 0;
}

int libp2p_runtime_add_timer(libp2p_runtime_t *rt, uint64_t delay_ms, int repeat, libp2p_rt_timer_cb cb, void *user_data)
{
    if (!rt || !cb)
        return -1;
    static atomic_int next_id = 1;
    rt_timer_t *t = calloc(1, sizeof(*t));
    if (!t)
        return -1;
    t->id = atomic_fetch_add(&next_id, 1);
    t->interval_ms = repeat ? delay_ms : 0;
    t->next_ms = now_mono_ms() + delay_ms;
    t->cb = cb;
    t->ud = user_data;
    pthread_mutex_lock(&rt->lock);
    t->next = rt->timers;
    rt->timers = t;
    pthread_mutex_unlock(&rt->lock);
    return t->id;
}

int libp2p_runtime_cancel_timer(libp2p_runtime_t *rt, int timer_id)
{
    if (!rt || timer_id <= 0)
        return -1;
    pthread_mutex_lock(&rt->lock);
    rt_timer_t **pp = &rt->timers;
    while (*pp)
    {
        if ((*pp)->id == timer_id)
        {
            rt_timer_t *victim = *pp;
            *pp = victim->next;
            free(victim);
            pthread_mutex_unlock(&rt->lock);
            return 0;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&rt->lock);
    return 0;
}

static int64_t next_timeout_ms(libp2p_runtime_t *rt)
{
    uint64_t now = now_mono_ms();
    int64_t best = -1; /* -1 means infinite */
    pthread_mutex_lock(&rt->lock);
    for (rt_timer_t *t = rt->timers; t; t = t->next)
    {
        int64_t d = (int64_t)(t->next_ms - now);
        if (d < 0)
            d = 0;
        if (best < 0 || d < best)
            best = d;
    }
    pthread_mutex_unlock(&rt->lock);
    /* Also avoid blocking forever so stop() can take effect quickly */
    if (best < 0 || best > 50)
        best = 50; /* 50ms max */
    return best;
}

static void fire_due_timers(libp2p_runtime_t *rt)
{
    if (!rt)
        return;
    for (;;)
    {
        libp2p_rt_timer_cb cb = NULL;
        void *ud = NULL;
        rt_timer_t *one_shot = NULL;
        int repeating = 0;
        uint64_t now = now_mono_ms();

        pthread_mutex_lock(&rt->lock);
        rt_timer_t **pp = &rt->timers;
        while (*pp && (*pp)->next_ms > now)
            pp = &(*pp)->next;
        if (*pp)
        {
            rt_timer_t *t = *pp;
            cb = t->cb;
            ud = t->ud;
            repeating = t->interval_ms ? 1 : 0;
            if (repeating)
            {
                t->next_ms = now + t->interval_ms;
            }
            else
            {
                *pp = t->next;
                one_shot = t;
            }
        }
        pthread_mutex_unlock(&rt->lock);

        if (!cb)
            break;

        cb(ud);
        if (!repeating && one_shot)
            free(one_shot);
    }
}

int libp2p_runtime_run(libp2p_runtime_t *rt)
{
    if (!rt)
        return -1;
    /* Do not forcibly clear the stop flag here. A concurrent caller may
       have already requested a stop (e.g., during teardown). Clearing it
       would race and potentially lose the stop, causing hangs. The runtime
       is intended for one-shot run; it starts with stop=false from new(). */
    while (!atomic_load(&rt->stop))
    {
        int64_t timeout = next_timeout_ms(rt);

#if RT_USE_EPOLL
        struct epoll_event ev[16];
        int n = epoll_wait(rt->epfd, ev, 16, (int)timeout);
        if (n < 0 && errno == EINTR)
            n = 0;
        for (int i = 0; i < n; ++i)
        {
            int fd = ev[i].data.fd;
            short events = 0;
            if (ev[i].events & EPOLLIN)
                events |= 0x1;
            if (ev[i].events & EPOLLOUT)
                events |= 0x2;
            libp2p_rt_fd_cb cb = NULL;
            void *cb_ud = NULL;
            pthread_mutex_lock(&rt->lock);
            rt_fd_watcher_t *w = find_fd_unlocked(rt, fd);
            if (w && w->cb)
            {
                cb = w->cb;
                cb_ud = w->ud;
            }
            pthread_mutex_unlock(&rt->lock);
            if (cb)
                cb(fd, events, cb_ud);
        }
#elif RT_USE_KQUEUE
        struct kevent kev[16];
        struct timespec ts, *tsp = NULL;
        if (timeout >= 0)
        {
            ts.tv_sec = timeout / 1000;
            ts.tv_nsec = (timeout % 1000) * 1000000L;
            tsp = &ts;
        }
        int n = kevent(rt->kq, NULL, 0, kev, 16, tsp);
        if (n < 0 && errno == EINTR)
            n = 0;
        for (int i = 0; i < n; ++i)
        {
            int fd = (int)(intptr_t)kev[i].udata;
            short events = 0;
            if (kev[i].filter == EVFILT_READ)
                events |= 0x1;
            if (kev[i].filter == EVFILT_WRITE)
                events |= 0x2;
            libp2p_rt_fd_cb cb = NULL;
            void *cb_ud = NULL;
            pthread_mutex_lock(&rt->lock);
            rt_fd_watcher_t *w = find_fd_unlocked(rt, fd);
            if (w && w->cb)
            {
                cb = w->cb;
                cb_ud = w->ud;
            }
            pthread_mutex_unlock(&rt->lock);
            if (cb)
                cb(fd, events, cb_ud);
        }
#else
        /* poll fallback */
        /* Count watchers */
        int cnt = 0;
        pthread_mutex_lock(&rt->lock);
        for (rt_fd_watcher_t *it = rt->fds; it; it = it->next)
            cnt++;
        struct pollfd *pfds = cnt ? (struct pollfd *)calloc((size_t)cnt, sizeof(*pfds)) : NULL;
        libp2p_rt_fd_cb *cb_map = cnt ? (libp2p_rt_fd_cb *)calloc((size_t)cnt, sizeof(*cb_map)) : NULL;
        void **ud_map = cnt ? (void **)calloc((size_t)cnt, sizeof(*ud_map)) : NULL;
        int idx = 0;
        for (rt_fd_watcher_t *it = rt->fds; it; it = it->next)
        {
            pfds[idx].fd = it->fd;
            pfds[idx].events = (it->want_read ? POLLIN : 0) | (it->want_write ? POLLOUT : 0);
            cb_map[idx] = it->cb;
            ud_map[idx] = it->ud;
            idx++;
        }
        pthread_mutex_unlock(&rt->lock);
        int n = (cnt > 0) ? poll(pfds, (nfds_t)cnt, (int)timeout) : 0;
        if (n > 0)
        {
            for (int i = 0; i < cnt; ++i)
            {
                if (pfds[i].revents)
                {
                    short events = 0;
                    if (pfds[i].revents & POLLIN)
                        events |= 0x1;
                    if (pfds[i].revents & POLLOUT)
                        events |= 0x2;
                    libp2p_rt_fd_cb cb = cb_map ? cb_map[i] : NULL;
                    void *cb_ud = ud_map ? ud_map[i] : NULL;
                    if (cb)
                        cb(pfds[i].fd, events, cb_ud);
                }
            }
        }
        free(cb_map);
        free(ud_map);
        free(pfds);
#endif

        fire_due_timers(rt);
    }
    return 0;
}
