#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <signal.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "protocol/tcp/protocol_tcp_poller.h"
#include <unistd.h>
#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol/tcp/protocol_tcp_queue.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include "libp2p/log.h"

/* Forward declarations for helpers implemented in separate modules */
libp2p_transport_err_t tcp_dial(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out);
libp2p_transport_err_t tcp_listen(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out);

#ifdef USE_KQUEUE
#include <sys/event.h>
#endif

/* Common 1 ms back‑off interval – use everywhere instead of duplicating literals */
static const struct timespec BACKOFF_1MS = {.tv_sec = 0, .tv_nsec = 1000000L};

/* ── Helper: write() that never raises SIGPIPE ─────────────────────────── */
static inline ssize_t write_ignore_sigpipe(int fd, const void *buf, size_t len)
{
#ifdef MSG_NOSIGNAL /* Linux & most BSDs: send() with MSG_NOSIGNAL suppresses SIGPIPE */
    return send(fd, buf, len, MSG_NOSIGNAL);
#else /* Portable fallback: temporarily ignore SIGPIPE around write()  */
    struct sigaction sa_ign = {0}, sa_old;
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    if (sigaction(SIGPIPE, &sa_ign, &sa_old) != 0)
    {
        /* Could not install handler – fall back to plain write() (may raise SIGPIPE) */
        return write(fd, buf, len);
    }
    ssize_t r = write(fd, buf, len);
    (void)sigaction(SIGPIPE, &sa_old, NULL); /* restore original disposition */
    return r;
#endif
}

/**
 * @brief Actually destroy a TCP listener, cleaning up resources and removing it from poller.
 *
 * This function marks the listener as closed, removes it from the poller, closes its file descriptor,
 * removes it from the transport context's listener list, wakes up any waiting threads, and decrements
 * the reference count. It is intended for internal use when a listener is being fully destroyed.
 *
 * @param l Pointer to the libp2p_listener_t to destroy.
 */
static void tcp_listener_destroy_actual(libp2p_listener_t *l)
{
    /* null check */
    if (!l)
    {
        return;
    }

    /* per-transport destroyer counter: increment at entry */
    tcp_transport_ctx_t *transport_ctx = ((tcp_listener_ctx_t *)l->ctx)->transport_ctx;
    if (transport_ctx)
    {
        atomic_fetch_add_explicit(&transport_ctx->gc.active_destroyers, 1, memory_order_acquire);
    }

    /* extract contexts */
    tcp_listener_ctx_t *ctx = l->ctx;
    /* transport_ctx is already set above */

    /* mark listener closed and remove from poller */
    if (ctx)
    {
        atomic_store_explicit(&ctx->closed, true, memory_order_release);
        if (transport_ctx)
        {
            poller_del(transport_ctx, ctx);
        }

        /* remove from transport context's listeners */
        if (transport_ctx)
        {
            pthread_mutex_lock(&transport_ctx->listeners.lock);
            for (size_t i = 0; i < transport_ctx->listeners.count; ++i)
            {
                if (transport_ctx->listeners.list[i] == l)
                {
                    transport_ctx->listeners.list[i] = NULL;
                    break;
                }
            }
            pthread_mutex_unlock(&transport_ctx->listeners.lock);
        }

        /* wake up any waiting threads */
        pthread_mutex_lock(&ctx->q.mtx);
        pthread_cond_broadcast(&ctx->q.cond);
        pthread_mutex_unlock(&ctx->q.mtx);

        /* refcount decrement with underflow guard (ABA‑safe, no wrap‑around) */
        size_t cur = atomic_load_explicit(&ctx->refcount, memory_order_acquire);
        for (;;)
        {
            if (cur == 0)
            {
                LP_LOGE("TCP", "tcp_listener_destroy_actual: ctx->refcount underflow ctx=%p", (void *)ctx);
                abort(); /* unrecoverable memory accounting error */
            }
            if (atomic_compare_exchange_weak_explicit(&ctx->refcount, &cur, cur - 1, memory_order_acq_rel, memory_order_acquire))
            {
                break; /* success */
            }
            /* cur has been updated with latest value — retry */
        }

        bool last = (cur == 1);

        if (last)
        {
            /* last reference: safe to close socket and tear down synchronously */
            int fd = atomic_exchange_explicit(&ctx->fd, -1, memory_order_acq_rel);
            if (fd >= 0)
            {
                shutdown(fd, SHUT_RDWR);
                int fl = fcntl(fd, F_GETFL, 0);
                if (fl != -1)
                {
                    (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                }
                close(fd);
            }

            /* last reference: safe to destroy listener context now */
            libp2p_conn_t *c;

            /* drain accept‑queue */
            while ((c = cq_pop(&ctx->q)))
            {
                libp2p_conn_free(c);
            }

            /* wait until all threads exit pthread_cond_wait() */
            while (atomic_load_explicit(&ctx->state.waiters, memory_order_acquire) != 0)
            {
                nanosleep(&BACKOFF_1MS, NULL); /* blocks, avoids priority inversion */
            }

            /* destroy cond‑var and its mutex while holding it */
            pthread_mutex_lock(&ctx->q.mtx);
            int rc_cd = pthread_cond_destroy(&ctx->q.cond);
            if (rc_cd != 0)
            {
                LP_LOGE("TCP", "pthread_cond_destroy(ctx->q.cond) failed: %s", strerror(rc_cd));
                abort();
            }

            pthread_mutex_unlock(&ctx->q.mtx);

            int rc_md = pthread_mutex_destroy(&ctx->q.mtx);
            if (rc_md != 0)
            {
                LP_LOGE("TCP", "pthread_mutex_destroy(ctx->q.mtx) failed: %s", strerror(rc_md));
                abort();
            }

            /* release remaining resources */
            multiaddr_free(ctx->local);
            free(ctx);
        }
        else
        {
            /* defer free: add to graveyard for poll loop cleanup */
            atomic_store_explicit(&ctx->gc.pending_free, true, memory_order_release);
            if (transport_ctx)
            {
                size_t cur_epoch = atomic_load_explicit(&transport_ctx->gc.poll_epoch, memory_order_acquire);
                size_t next_epoch = (cur_epoch == SIZE_MAX) ? cur_epoch : cur_epoch + 1;
                atomic_store_explicit(&ctx->gc.free_epoch, next_epoch, memory_order_release);

                pthread_mutex_lock(&transport_ctx->gc.lock);
                ctx->gc.next_free = transport_ctx->gc.head;
                transport_ctx->gc.head = ctx;
                pthread_mutex_unlock(&transport_ctx->gc.lock);

                int wpipe = atomic_load_explicit(&transport_ctx->wakeup.pipe[1], memory_order_acquire);
                if (wpipe >= 0)
                {
                    uint8_t wake_byte = 1;
                    ssize_t wr;
                    do
                    {
                        wr = write(wpipe, &wake_byte, 1);
                    } while (wr < 0 && errno == EINTR);
                    (void)wr;
                }
            }
        }
    }

    /* destroy public listener mutex (no remaining refs) */
    safe_mutex_lock(&l->mutex);   /* take ownership */
    safe_mutex_unlock(&l->mutex); /* leave it unlocked as required */
    int rc_lm = pthread_mutex_destroy(&l->mutex);
    if (rc_lm != 0)
    {
        LP_LOGE("TCP", "pthread_mutex_destroy(l->mutex) failed: %s", strerror(rc_lm));
        abort();
    }
    free(l); /* no thread can access l – refcount already hit zero */

    /* opportunistic listener‑array compaction */
    if (transport_ctx)
    {
        libp2p_listener_t **snap_list;
        size_t snap_len;

        /* snapshot + live‑count under lock */
        safe_mutex_lock(&transport_ctx->listeners.lock);
        snap_list = transport_ctx->listeners.list;
        snap_len = transport_ctx->listeners.count;

        size_t live = 0;
        for (size_t i = 0; i < snap_len; ++i)
        {
            if (snap_list[i] != NULL)
            {
                ++live;
            }
        }

        /* If a previous shrink failed (OOM or CAS‑loss), force a retry. */
        bool pending = atomic_load_explicit(&transport_ctx->gc.compact_pending, memory_order_acquire);

        /* Flags for actions to perform once we drop the lock */
        bool detach_and_free = false;
        bool do_shrink = false;

        if (snap_list)
        {
            if (live == 0)
            {
                /* array is completely empty – detach now, free later */
                transport_ctx->listeners.list = NULL;
                transport_ctx->listeners.count = 0;
                detach_and_free = true; /* we own snap_list */
            }
            else if ((live < snap_len && live <= (snap_len * 3) / 4) || /* normal 25 % rule */
                     (pending && live < snap_len))                      /* forced retry    */
            {
                /* worth shrinking; build new array outside the lock */
                do_shrink = true;
            }
        }
        safe_mutex_unlock(&transport_ctx->listeners.lock);

        /* free empty array outside lock */
        if (detach_and_free)
        {
            free(snap_list);
            atomic_store_explicit(&transport_ctx->gc.compact_pending, false, memory_order_release);

            /* nothing left to do */
            snap_list = NULL;
            snap_len = 0;
        }

        /* perform compaction if marked */
        if (do_shrink && snap_list)
        {
            libp2p_listener_t **new_list = malloc(live * sizeof *new_list);
            if (!new_list)
            {
                LP_LOGW("TCP", "tcp_listener_destroy_actual: unable to compact listener list (wanted %zu -> %zu) due to OOM – will retry later", snap_len, live);
                atomic_store_explicit(&transport_ctx->gc.compact_pending, true, memory_order_release);
            }
            else
            {
                /* quick re‑validation before we spend time copying */
                safe_mutex_lock(&transport_ctx->listeners.lock);
                bool still_same = (transport_ctx->listeners.list == snap_list) && (transport_ctx->listeners.count == snap_len);
                safe_mutex_unlock(&transport_ctx->listeners.lock);

                if (!still_same)
                {
                    /* the array changed while we were unlocked – abort early */
                    atomic_store_explicit(&transport_ctx->gc.compact_pending, true, memory_order_release);
                    free(new_list);
                    new_list = NULL;
                }

                if (new_list)
                {
                    /* copy live entries */
                    size_t j = 0;
                    for (size_t i = 0; i < snap_len; ++i)
                    {
                        if (snap_list[i] != NULL)
                        {
                            new_list[j++] = snap_list[i];
                        }
                    }

                    /* attempt atomic‑ish swap */
                    safe_mutex_lock(&transport_ctx->listeners.lock);
                    if (transport_ctx->listeners.list == snap_list)
                    {
                        libp2p_listener_t **old = transport_ctx->listeners.list;
                        transport_ctx->listeners.list = new_list;
                        transport_ctx->listeners.count = live;
                        safe_mutex_unlock(&transport_ctx->listeners.lock);

                        free(old);        /* we successfully took ownership */
                        snap_list = NULL; /* avoid dangling pointer — defensive */
                        atomic_store_explicit(&transport_ctx->gc.compact_pending, false, memory_order_release);
                    }
                    else
                    {
                        safe_mutex_unlock(&transport_ctx->listeners.lock);
                        atomic_store_explicit(&transport_ctx->gc.compact_pending, true, memory_order_release);
                        free(new_list); /* lost the race – discard copy  */
                    }
                }
            }
        }
    }

    /* per-transport destroyer counter: decrement at exit */
    if (transport_ctx)
    {
        atomic_fetch_sub_explicit(&transport_ctx->gc.active_destroyers, 1, memory_order_release);
    }
}

/**
 * @brief Release reference counts for a listener and its context.
 *
 * This function decrements the reference count for the listener and its context,
 * and if the reference count drops to 0, it triggers the actual destruction of the listener.
 *
 * @param l Pointer to the libp2p_listener_t to release references for.
 * @param ctx Pointer to the tcp_listener_ctx_t associated with the listener.
 */
static inline void tcp_listener_release_refs(libp2p_listener_t *l, tcp_listener_ctx_t *ctx)
{
    /* drop the listener wrapper's reference */
    unsigned prev = atomic_fetch_sub_explicit(&l->refcount, 1, memory_order_release);

    /* underflow guard: prev represents the value *before* subtraction */
    if (prev == 0)
    {
        LP_LOGE("TCP", "tcp_listener_release_refs: listener refcount underflow l=%p", (void *)l);
        abort(); /* double‑free / resurrection */
    }

    /* if this was not the last wrapper ref, also drop the ctx ref and return */
    if (prev != 1)
    {
        /* decrement ctx->refcount safely without temporary wrap‑around */
        size_t cur = atomic_load_explicit(&ctx->refcount, memory_order_acquire);
        for (;;)
        {
            if (cur == 0)
            {
                LP_LOGE("TCP", "tcp_listener_release_refs: ctx->refcount underflow l=%p ctx=%p", (void *)l, (void *)ctx);
                abort(); /* memory accounting corrupted */
            }
            if (atomic_compare_exchange_weak_explicit(&ctx->refcount, &cur, cur - 1, memory_order_acq_rel, memory_order_acquire))
            {
                break; /* success */
            }
            /* retry with freshly loaded value */
        }
        return; /* other wrapper references still hold the context */
    }

    /* last wrapper reference */
    atomic_thread_fence(memory_order_acquire);

    /* destroy wrapper (also drops the final ctx reference) */
    tcp_listener_destroy_actual(l);
}

/**
 * @brief Main accept function for a TCP listener.
 *
 * This function attempts to accept a new connection from the listener's queue.
 * It checks for null pointers, closed listener, and overflow conditions.
 * If successful, it returns a new libp2p_conn_t pointer.
 *
 * @param l Pointer to the libp2p_listener_t to accept a connection from.
 * @param out Pointer to a libp2p_conn_t pointer to store the accepted connection.
 * @return libp2p_listener_err_t The result of the operation.
 */
libp2p_listener_err_t tcp_listener_accept(libp2p_listener_t *l, libp2p_conn_t **out)
{
    /* null check */
    if (!l || !out)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    *out = NULL;

    /* null check */
    if (!l->ctx)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    tcp_listener_ctx_t *ctx = atomic_load_explicit(&l->ctx, memory_order_acquire);

    /* closed check */
    if (atomic_load_explicit(&ctx->closed, memory_order_acquire))
    {
        return LIBP2P_LISTENER_ERR_CLOSED;
    }

    /* increment listener refcount with ABA‑safe overflow guard */
    _Atomic uint64_t attempts = 0;
    for (;;)
    {
        unsigned l_cur = atomic_load_explicit(&l->refcount, memory_order_relaxed);
        if (l_cur >= UINT_MAX - 1)
        {
            return LIBP2P_LISTENER_ERR_OVERFLOW; /* prevent wrap‑around */
        }
        if (atomic_compare_exchange_strong_explicit(&l->refcount, &l_cur, l_cur + 1, memory_order_acq_rel, memory_order_relaxed))
        {
            break; /* success */
        }
        cas_backoff(&attempts);
        /* retry on contention */
    }

    /* increment context refcount with overflow guard */
    _Atomic uint64_t attempts_ctx = 0;
    for (;;)
    {
        size_t ctx_cur = atomic_load_explicit(&ctx->refcount, memory_order_relaxed);
        if (ctx_cur >= SIZE_MAX - 1)
        {
            /* rollback listener increment */
            unsigned l_prev = atomic_fetch_sub_explicit(&l->refcount, 1, memory_order_acq_rel);
            if (l_prev == 0)
            {
                LP_LOGE("TCP", "tcp_listener_accept rollback: l->refcount underflow l=%p", (void *)l);
                abort(); /* invariant violated */
            }
            if (l_prev == 1)
            {
                tcp_listener_destroy_actual(l);
            }
            return LIBP2P_LISTENER_ERR_OVERFLOW;
        }
        if (atomic_compare_exchange_strong_explicit(&ctx->refcount, &ctx_cur, ctx_cur + 1, memory_order_acq_rel, memory_order_relaxed))
        {
            break; /* success */
        }
        cas_backoff(&attempts_ctx);
        /* retry on contention */
    }

    /* enter critical section */
    if (pthread_mutex_lock(&ctx->q.mtx) != 0)
    {
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_MUTEX;
    }

    /* derive wait period, clamp to 24 h to avoid long overflow */
    const uint64_t WAIT_MS_RAW = ctx->state.poll_ms;
    const uint64_t WAIT_MS_MIN = 1;                               /* avoid busy‑spin */
    const uint64_t WAIT_MS_CAP = 24ULL * 60ULL * 60ULL * 1000ULL; /* 24 hours        */

    uint64_t wait_ms = WAIT_MS_RAW ? WAIT_MS_RAW : WAIT_MS_MIN;

    if (wait_ms > WAIT_MS_CAP)
    {
        wait_ms = WAIT_MS_CAP; /* cap excessively large values */
    }

    const time_t WAIT_SEC = (time_t)(wait_ms / 1000);             /* ≤ 86 400        */
    const long WAIT_NSEC = (long)((wait_ms % 1000) * 1000000ULL); /* < 1 000 000 000 */

    while (!ctx->q.head && !atomic_load_explicit(&ctx->closed, memory_order_acquire) &&
           !atomic_load_explicit(&ctx->state.disabled, memory_order_acquire))
    {
        struct timespec ts;
        const clockid_t WAIT_CLOCK = ctx->state.cond_clock;

        /* get current time */
        if (clock_gettime(WAIT_CLOCK, &ts) != 0)
        {
            safe_mutex_unlock(&ctx->q.mtx);
            tcp_listener_release_refs(l, ctx);
            return LIBP2P_LISTENER_ERR_INTERNAL;
        }

        /* add wait time safely, clamping on 32‑bit time_t */
        timespec_add_safe(&ts, (int64_t)WAIT_SEC, WAIT_NSEC);

        /* wait for condition variable – maintain waiter counter */
        atomic_fetch_add_explicit(&ctx->state.waiters, 1, memory_order_relaxed);
        int rc = pthread_cond_timedwait(&ctx->q.cond, &ctx->q.mtx, &ts);
        atomic_fetch_sub_explicit(&ctx->state.waiters, 1, memory_order_release);

        /* Retry on timeout or signal interruption */
        if (rc == ETIMEDOUT || rc == EINTR)
        {
            continue;
        }

        /* check for unexpected errors */
        if (rc != 0)
        {
            safe_mutex_unlock(&ctx->q.mtx);
            tcp_listener_release_refs(l, ctx);
            return LIBP2P_LISTENER_ERR_INTERNAL;
        }
    }

    /* if closed, report CLOSED regardless of disabled state */
    if (atomic_load_explicit(&ctx->closed, memory_order_acquire) && !ctx->q.head)
    {
        safe_mutex_unlock(&ctx->q.mtx);
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_CLOSED;
    }

    /* disabled (back-off) */
    if (atomic_load_explicit(&ctx->state.disabled, memory_order_acquire) && !ctx->q.head)
    {
        safe_mutex_unlock(&ctx->q.mtx);
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_BACKOFF;
    }

    /* dequeue one connection */
    conn_node_t *n = ctx->q.head;
    ctx->q.head = n->next;
    if (!ctx->q.head)
    {
        ctx->q.tail = NULL;
    }
    /* maintain queue length accounting */
    atomic_fetch_sub_explicit(&ctx->q.len, 1, memory_order_relaxed);

    /* validate queue integrity: connection pointer must be non‑NULL */
    if (n->c == NULL)
    {
        free(n);
        safe_mutex_unlock(&ctx->q.mtx);
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_INTERNAL;
    }

    *out = n->c;

    /* capture accept latency before freeing the node */
    uint64_t acc_at = n->accepted_at_ms;
    /* free node while still holding the queue mutex */
    free(n);

    /* unlock mutex */
    safe_mutex_unlock(&ctx->q.mtx);

    /* Metrics: record accept latency and queue depth after pop */
    tcp_transport_ctx_t *tctx = ctx->transport_ctx;
    if (tctx && tctx->metrics)
    {
        uint64_t now = now_mono_ms();
        if (acc_at > 0 && now >= acc_at)
        {
            libp2p_metrics_observe_histogram(tctx->metrics, "libp2p_accept_latency_ms", "{\"transport\":\"tcp\"}", (double)(now - acc_at));
        }
        size_t qlen_after = atomic_load_explicit(&ctx->q.len, memory_order_relaxed);
        libp2p_metrics_observe_histogram(tctx->metrics, "libp2p_accept_queue_depth", "{\"transport\":\"tcp\"}", (double)qlen_after);
    }

    /* release references */
    tcp_listener_release_refs(l, ctx);
    return LIBP2P_LISTENER_OK;
}

/**
 * @brief Retrieve the local multiaddress of a TCP listener.
 *
 * This function obtains the local address associated with the given listener.
 * It validates the arguments, ensures the listener is still valid (not destroyed),
 * and returns a reference to the local multiaddress if available.
 *
 * @param l   Pointer to the libp2p_listener_t structure.
 * @param out Output pointer to receive the local multiaddr_t* (set to NULL on error).
 * @return LIBP2P_LISTENER_OK on success, or an appropriate LIBP2P_LISTENER_ERR_* code on failure.
 */
libp2p_listener_err_t tcp_listener_local(libp2p_listener_t *l, multiaddr_t **out)
{
    /* validate arguments  */
    if (!out)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }
    *out = NULL;

    if (!l)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    /* take a wrapper reference (ABA‑safe, overflow‑safe) */
    _Atomic uint64_t attempts = 0;
    for (;;)
    {
        unsigned cur = atomic_load_explicit(&l->refcount, memory_order_relaxed);

        /* already destroyed → cannot resurrect */
        if (cur == 0)
        {
            return LIBP2P_LISTENER_ERR_CLOSED;
        }

        /* prevent wrap‑around to UINT_MAX */
        if (cur >= UINT_MAX - 1)
        {
            return LIBP2P_LISTENER_ERR_OVERFLOW;
        }

        if (atomic_compare_exchange_strong_explicit(&l->refcount, &cur, cur + 1, memory_order_acquire, memory_order_relaxed))
        {
            break; /* success */
        }

        cas_backoff(&attempts);
        /* retry on contention */
    }

    /* access context (l->ctx is assigned once at construction and never changes) */
    tcp_listener_ctx_t *ctx = atomic_load_explicit(&l->ctx, memory_order_acquire);
    if (!ctx)
    {
        /* treat as closed or not yet initialised; drop our temporary ref */
        (void)atomic_fetch_sub_explicit(&l->refcount, 1, memory_order_release);
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }
    libp2p_listener_err_t rc = LIBP2P_LISTENER_OK;
    multiaddr_t *addr = NULL;

    /* safely copy the listener's local address.
     * guard against a NULL pointer (possible on OOM during construction). */
    if (ctx->local != NULL)
    {
        addr = multiaddr_copy(ctx->local, NULL);
    }

    if (!addr)
    {
        /* Fallback to getsockname() */
        struct sockaddr_storage ss;
        socklen_t ss_len = sizeof ss;
        int lfd = atomic_load_explicit(&ctx->fd, memory_order_acquire);
        LP_LOGD("TCP", "tcp_listener_local: ctx->local=%p fd=%d", (void *)ctx->local, lfd);
        if (lfd >= 0 && getsockname(lfd, (struct sockaddr *)&ss, &ss_len) == 0)
        {
            addr = sockaddr_to_multiaddr(&ss, ss_len);
            if (addr)
            {
                int se = 0;
                char *s = multiaddr_to_str(addr, &se);
                LP_LOGD("TCP", "tcp_listener_local: fallback addr=%s (err=%d)", s ? s : "(null)", se);
                free(s);
            }
            else
            {
                LP_LOGW("TCP", "tcp_listener_local: sockaddr_to_multiaddr returned NULL");
            }
        }
        else
        {
            LP_LOGW("TCP", "tcp_listener_local: getsockname failed");
        }
    }

    if (!addr)
    {
        rc = LIBP2P_LISTENER_ERR_INTERNAL;
    }
    else
    {
        int se = 0;
        char *s = multiaddr_to_str(addr, &se);
        LP_LOGD("TCP", "tcp_listener_local: copied addr=%s (err=%d)", s ? s : "(null)", se);
        free(s);
        *out = addr;
    }

    /* release temporary wrapper reference (do not destroy here; caller owns lifetime) */
    (void)atomic_fetch_sub_explicit(&l->refcount, 1, memory_order_release);

    return rc;
}

/**
 * @brief Close a TCP listener and detach it from the poller.
 *
 * This function marks the listener as closed, detaches it from the poller,
 * wakes up any threads blocked in accept(), and decrements the reference count.
 * If the reference count drops to zero, the listener is destroyed.
 *
 * @param l Pointer to the libp2p_listener_t to close.
 * @return LIBP2P_LISTENER_OK on success,
 *         LIBP2P_LISTENER_ERR_CLOSED if already closed,
 *         LIBP2P_LISTENER_ERR_NULL_PTR if l or l->ctx is NULL,
 *         LIBP2P_LISTENER_ERR_OVERFLOW on refcount overflow.
 */
libp2p_listener_err_t tcp_listener_close(libp2p_listener_t *l)
{
    if (!l)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }
    LP_LOGD("TCP", "listener_close: begin l=%p", (void *)l);

    tcp_listener_ctx_t *ctx = atomic_load_explicit(&l->ctx, memory_order_acquire);
    if (!ctx)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    /* extra diagnostics to locate crash site */
    LP_LOGD("TCP", "listener_close: ctx=%p fd=%d transport_ctx=%p q.mtx=%p q.cond=%p", (void *)ctx,
            atomic_load_explicit(&ctx->fd, memory_order_relaxed), (void *)ctx->transport_ctx, (void *)&ctx->q.mtx, (void *)&ctx->q.cond);

    bool timed_out = false;

    /* already closed? (returns previous value) */
    if (atomic_exchange_explicit(&ctx->closed, true, memory_order_acq_rel))
        return LIBP2P_LISTENER_ERR_CLOSED;

    /* detach from poller; fd stays open until refcount == 1 */
    if (ctx->transport_ctx)
    {
        /* poller_del() returns void in the current API; simply invoke it. */
        LP_LOGD("TCP", "listener_close: calling poller_del(ctx=%p)", (void *)ctx);
        poller_del(ctx->transport_ctx, ctx);
        LP_LOGD("TCP", "listener_close: returned from poller_del(ctx=%p)", (void *)ctx);
    }

    /* wake up any thread blocked in accept() */
    LP_LOGD("TCP", "listener_close: locking q.mtx=%p", (void *)&ctx->q.mtx);
    if (safe_mutex_lock(&ctx->q.mtx) != 0) /* aborts on error, but keep RAII rollback for static analysis */
        return LIBP2P_LISTENER_ERR_MUTEX;

    /* Mark disabled so accept() breaks out of its wait-loop even if not closed observed yet. */
    atomic_store_explicit(&ctx->state.disabled, true, memory_order_release);
    /* Avoid broadcasting on a potentially-destroyed condition variable during teardown.
       Accept loop uses short timed waits (poll_ms), so it will observe disabled soon. */
    LP_LOGD("TCP", "listener_close: unlocking q.mtx=%p", (void *)&ctx->q.mtx);
    safe_mutex_unlock(&ctx->q.mtx);
    /* Skip best-effort broadcasts to avoid races with condition destruction. */

    /* Always return non-blocking here. We signaled accept() waiters and
     * detached from the poller; destruction will be handled by the wrapper
     * free path after the accept thread joins. This avoids shutdown races. */
    LP_LOGD("TCP", "listener_close: end rc=%d (always non-blocking)", LIBP2P_LISTENER_OK);
    return LIBP2P_LISTENER_OK;

    /* wait until the poll thread has dropped its extra ref, with timeout */
    if (safe_mutex_lock(&ctx->q.mtx) != 0)
    {
        /* should be unreachable; perform reference rollback for completeness */
        unsigned l_old = listener_refcount_fetch_sub(l);
        if (l_old == 1)
        {
            tcp_listener_destroy_actual(l);
        }
        return LIBP2P_LISTENER_ERR_MUTEX;
    }

    /* progressive back‑off when pthread_cond_* gets interrupted by signals */
    _Atomic uint64_t eintr_attempts = 0;

    while (atomic_load_explicit(&ctx->refcount, memory_order_acquire) > 1)
    {
        uint32_t to_ms = ctx->state.close_timeout_ms;

        /* immediate forced‑close */
        if (to_ms == 0)
        {
            timed_out = true;
            break; /* skip wait, go force‑close path */
        }

        struct timespec ts;
        /* use the same clock as the condition variable */
        clockid_t wait_clock = ctx->state.cond_clock;
        int rc_clock = clock_gettime(wait_clock, &ts);
        if (rc_clock != 0)
        {
            /* Failed to obtain current time – treat as timeout/error to avoid UB */
            timed_out = true;
            break;
        }

        /* UINT32_MAX means "wait forever" → use plain pthread_cond_wait */
        int ret;
        if (to_ms == UINT32_MAX)
        {
            atomic_fetch_add_explicit(&ctx->state.waiters, 1, memory_order_relaxed);
            ret = pthread_cond_wait(&ctx->q.cond, &ctx->q.mtx);
            atomic_fetch_sub_explicit(&ctx->state.waiters, 1, memory_order_release);
        }
        else
        {
            /* add relative timeout safely (handles 32‑bit time_t overflow) */
            timespec_add_safe(&ts, (int64_t)(to_ms / 1000), (long)((to_ms % 1000) * 1000000L));
            atomic_fetch_add_explicit(&ctx->state.waiters, 1, memory_order_relaxed);
            ret = pthread_cond_timedwait(&ctx->q.cond, &ctx->q.mtx, &ts);
            atomic_fetch_sub_explicit(&ctx->state.waiters, 1, memory_order_release);
        }

        /* handle result from pthread_cond_* */
        if (ret == 0)
        {
            /* successful wake‑up – reset EINTR back‑off */
            atomic_store_explicit(&eintr_attempts, 0, memory_order_relaxed);
            /* woken up (broadcast / signal) – loop to re‑check refcount */
            continue;
        }
        if (ret == EINTR)
        {
            /* progressive back‑off on spurious signal interruptions */
            cas_backoff(&eintr_attempts);
            continue;
        }
        if (ret == ETIMEDOUT)
        {
            timed_out = true;
            break;
        }

        /* any other error (e.g. ECANCELED, EINVAL) is unexpected and fatal */
        LP_LOGE("TCP", "tcp_listener_close: pthread_cond_* returned %s – treating as forced timeout", strerror(ret));
        timed_out = true;
        break;
        /* otherwise: signalled but refcount still >1 → loop again */
    }
    safe_mutex_unlock(&ctx->q.mtx);

    if (timed_out && atomic_load_explicit(&ctx->refcount, memory_order_acquire) > 1)
    {
        /* forced close to prevent fd leak if poll thread reference remains */
        int oldfd = atomic_exchange_explicit(&ctx->fd, -1, memory_order_acq_rel);
        if (oldfd >= 0)
        {
            close(oldfd);
        }

        /* mark listener for deferred free in graveyard */
        atomic_store_explicit(&ctx->gc.pending_free, true, memory_order_release);

        if (ctx->transport_ctx)
        {
            /* transport context still valid – schedule for deferred free and notify poll loop */
            size_t cur_epoch = atomic_load_explicit(&ctx->transport_ctx->gc.poll_epoch, memory_order_acquire);
            /* saturate at SIZE_MAX so the epoch never wraps back to 0 */
            size_t next_epoch = (cur_epoch == SIZE_MAX) ? cur_epoch : cur_epoch + 1;
            atomic_store_explicit(&ctx->gc.free_epoch, next_epoch, memory_order_release);

            /* wake transport poll loop to process pending free */
            int wpipe_t = atomic_load_explicit(&ctx->transport_ctx->wakeup.pipe[1], memory_order_acquire);
            if (wpipe_t >= 0)
            {
                /* ensure write-end is non-blocking (constructor sets O_NONBLOCK, but double-check) */
                int __wflags = fcntl(wpipe_t, F_GETFL, 0);
                if (__wflags != -1 && !(__wflags & O_NONBLOCK))
                {
                    (void)fcntl(wpipe_t, F_SETFL, __wflags | O_NONBLOCK);
                }

                uint8_t wake = 1;
                /* best‑effort non‑blocking write to wake poll loop; ignore EAGAIN/EPIPE */
                ssize_t _w;
                do
                {
                    _w = write(wpipe_t, &wake, 1);
                } while (_w < 0 && errno == EINTR);
                /* ignore EAGAIN/EPIPE; poll loop will handle close next cycle */
            }
        }
        else
        {
            /* no transport context – skip poll-loop wake‑up, but still mark for free */
            atomic_store_explicit(&ctx->gc.free_epoch, 0, memory_order_release);
        }

        return LIBP2P_LISTENER_ERR_TIMEOUT;
    }

    return LIBP2P_LISTENER_OK;
}

void tcp_listener_free(libp2p_listener_t *l)
{
    if (!l)
    {
        return;
    }

    /*
     * libp2p_listener_unref() already decremented the wrapper's refcount
     * to zero before invoking this function.  Performing another decrement
     * here would underflow the counter and leak the listener.  Simply
     * destroy the listener now.
     */
    tcp_listener_destroy_actual(l);
}

/**
 * @brief Create and register a new TCP listener for the given multiaddress.
 *
 * This function creates a new TCP listening socket bound to the specified multiaddress,
 * wraps it in a libp2p_listener_t, and registers it with the transport context. The
 * listener is then available for accepting incoming connections. On error, the function
 * ensures that no partially-initialized listener is returned and all resources are cleaned up.
 *
 * @param self  Pointer to the transport instance (must not be NULL).
 * @param addr  The multiaddress to listen on (must not be NULL, must not be DNS).
 * @param out   Output pointer for the created listener (must not be NULL; set to NULL on error).
 * @return      LIBP2P_TRANSPORT_OK on success, or an appropriate error code on failure.
 */

/**
 * @brief Gracefully shuts down the TCP transport, signaling the poll loop and closing resources.
 *
 * This function signals the transport's poll loop to shut down, wakes it up if necessary,
 * and performs cleanup of the transport context. It is safe to call multiple times and
 * handles concurrent shutdown attempts. Any I/O errors encountered during the wakeup
 * process are surfaced via the return value.
 *
 * @param self Pointer to the libp2p_transport_t representing the TCP transport.
 * @return LIBP2P_TRANSPORT_OK on success, or an appropriate error code on failure.
 */
static libp2p_transport_err_t tcp_close(libp2p_transport_t *self)
{
    /* gracefully handle NULL transport or missing context */
    if (!self)
    {
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    }

    /* gracefully handle NULL transport or missing context */
    struct tcp_transport_ctx *ctx = self->ctx;
    if (ctx == NULL)
    {
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    }

    /* signal shutdown: the poll loop and subsequent operations will observe this */
    atomic_store_explicit(&ctx->closed, true, memory_order_release);

    /* track wake‑up write outcome so we can surface I/O failures */
    libp2p_transport_err_t rc = LIBP2P_TRANSPORT_OK;

    /* atomically fetch and invalidate the write end of the wakeup pipe */
    int wpipe = atomic_exchange_explicit(&ctx->wakeup.pipe[1], -1, /* invalidate */
                                         memory_order_acq_rel);
    if (wpipe >= 0)
    {
        /* block SIGPIPE for the duration of the write‑retry loop */
        sigset_t old_sigset;
        int sigblk_rc = sigpipe_block(&old_sigset); /* 0 = success */
        bool sigpipe_blocked = (sigblk_rc == 0);
        uint8_t byte = 1;
        struct pollfd pfd = {.fd = wpipe, .events = POLLOUT};
        int einval_retries = 0;
        int eintr_retries = 0;
        int eagain_retries = 0;
        const int MAX_EINVAL_RETRIES = 100;
        const int MAX_EINTR_RETRIES = 100;
        const int MAX_EAGAIN_RETRIES = 100;
        const int POLL_WAIT_MS = 1000; /* 1‑second cap on poll() */

        /* guard against endless EINTR/EAGAIN storms */
        int total_retries = 0;
        const int MAX_TOTAL_RETRIES = 1000; /* upper bound – adjust as needed */
        while (1)
        {
            if (++total_retries > MAX_TOTAL_RETRIES)
            {
                rc = LIBP2P_TRANSPORT_ERR_TIMEOUT;
                break;
            }
            ssize_t w = sigpipe_blocked ? write(wpipe, &byte, 1) : write_ignore_sigpipe(wpipe, &byte, 1);

            /* success – wrote the single wake‑up byte */
            if (w == 1)
            {
                eintr_retries = 0;  /* reset EINTR counter on success */
                eagain_retries = 0; /* reset EAGAIN back‑off counter */
                einval_retries = 0; /* reset EINVAL back‑off counter */
                break;
            }

            /* handle EINTR error */
            if (w < 0 && errno == EINTR)
            {
                /* signal interruption: treat as if poll timed out – reset other counters */
                eagain_retries = 0;
                einval_retries = 0;
                if (++eintr_retries > MAX_EINTR_RETRIES)
                {
                    nanosleep(&BACKOFF_1MS, NULL);
                    eintr_retries = 0;
                }
                continue; /* retry the write after handling EINTR */
            }
            if (w < 0 && errno == EAGAIN)
            {
                /* progressive back‑off when POLLOUT races with full pipe buffer */
                if (++eagain_retries > MAX_EAGAIN_RETRIES)
                {
                    nanosleep(&BACKOFF_1MS, NULL);
                    eagain_retries = 0;
                }

                /* wait until pipe is writable so the wake‑up byte is not lost */
                pfd.revents = 0; /* clear stale revents before polling */
                int pres = poll(&pfd, 1, POLL_WAIT_MS);
                if (pres < 0)
                {
                    /* handle EINTR error */
                    if (errno == EINTR)
                    {
                        /* signal interruption: treat as if poll timed out – reset other counters */
                        eagain_retries = 0;
                        einval_retries = 0;
                        if (++eintr_retries > MAX_EINTR_RETRIES)
                        {
                            nanosleep(&BACKOFF_1MS, NULL);
                            eintr_retries = 0;
                        }
                        continue;
                    }

                    /* handle EINVAL and EBADF errors */
                    if (errno == EINVAL)
                    {
                        if (++einval_retries > MAX_EINVAL_RETRIES)
                        {
                            rc = LIBP2P_TRANSPORT_ERR_INTERNAL;
                            break;
                        }
                        nanosleep(&BACKOFF_1MS, NULL);
                        continue;
                    }
                    else if (errno == EBADF)
                    {
                        /* write‑end already closed – benign */
                        rc = LIBP2P_TRANSPORT_OK;
                        break;
                    }

                    /* unexpected poll error; give up */
                    rc = LIBP2P_TRANSPORT_ERR_INTERNAL;
                    break;
                }

                /* pres == 0 means poll timed out – retry */
                if (pres == 0)
                {
                    continue;
                }

                /* inspect revents: fail fast on error conditions, even when POLLOUT is also set */
#ifdef POLLNVAL
                if (pfd.revents & POLLNVAL)
                {
                    rc = LIBP2P_TRANSPORT_ERR_INTERNAL;
                    break;
                }
#endif
                if (pfd.revents & (POLLERR | POLLHUP))
                {
                    rc = LIBP2P_TRANSPORT_ERR_INTERNAL;
                    break;
                }

                /* if the descriptor is *not* reported writable, treat as unexpected */
                if (!(pfd.revents & POLLOUT))
                {
                    rc = LIBP2P_TRANSPORT_ERR_INTERNAL;
                    break;
                }

                /* descriptor is writable and no error flags are set – retry the write */
                continue;
            }

            /* reader end already closed – not a failure during shutdown */
            if (w < 0 && errno == EPIPE)
            {
                rc = LIBP2P_TRANSPORT_OK;
                break;
            }

            /* descriptor already closed or invalid – also benign during shutdown */
            if (w < 0 && errno == EBADF)
            {
                rc = LIBP2P_TRANSPORT_OK;
                break;
            }

            /* on other errors, give up */
            rc = LIBP2P_TRANSPORT_ERR_INTERNAL;
            break;
        }

        /* restore original signal mask */
        if (sigpipe_blocked)
        {
            sigpipe_restore(&old_sigset);
        }
    }

    /* take ownership of the descriptor above; close it to avoid leaks */
    if (wpipe >= 0)
    {
        close(wpipe);
    }
    LP_LOGD("TCP", "listener_close: end rc=%d", rc);
    return rc;
}

/**
 * @brief Frees all resources associated with a TCP transport.
 *
 * This function gracefully shuts down the TCP transport, including signaling
 * the poll loop to exit, closing all listeners, draining the graveyard,
 * destroying mutexes and condition variables, and freeing all allocated memory.
 * It is safe to call with a NULL transport or context.
 *
 * @param t Pointer to the libp2p_transport_t to free.
 */
static void tcp_free(libp2p_transport_t *t)
{
    /* gracefully handle NULL transport or missing context */
    if (t == NULL || t->ctx == NULL)
    {
        return;
    }
    struct tcp_transport_ctx *ctx = t->ctx;

    /* signal shutdown and wake the poll loop */
    atomic_store_explicit(&ctx->closed, true, memory_order_release);

    int wpipe = atomic_load_explicit(&ctx->wakeup.pipe[1], memory_order_acquire);
    if (wpipe >= 0)
    {
        /* block SIGPIPE while we poke the poll loop */
        sigset_t old_sigset;
        int sigblk_rc = sigpipe_block(&old_sigset); /* 0 = success */
        bool sigpipe_blocked = (sigblk_rc == 0);

        /* write a single byte to wake up the poll loop */
        const uint8_t byte = 1;
        struct pollfd pfd = {.fd = wpipe, .events = POLLOUT};

        int eintr_retries = 0;
        int eagain_retries = 0;
        int einval_retries = 0;
        int badfd_retries = 0;

        const int MAX_EINTR_RETRIES = 100;
        const int MAX_EAGAIN_RETRIES = 100;
        const int MAX_EINVAL_RETRIES = 100;
        const int MAX_BADFD_RETRIES = 10;

        /* guard against endless EINTR/EAGAIN storms */
        while (1)
        {
            ssize_t w = sigpipe_blocked ? write(wpipe, &byte, 1) : write_ignore_sigpipe(wpipe, &byte, 1);
            if (w > 0) /* success */
            {
                eintr_retries = eagain_retries = einval_retries = badfd_retries = 0;
                break;
            }

            /* treat 0-byte write as EAGAIN for safety. */
            if (w == 0)
            {
                if (++eagain_retries > MAX_EAGAIN_RETRIES)
                {
                    nanosleep(&BACKOFF_1MS, NULL);
                    eagain_retries = 0;
                }
                continue; /* retry the write */
            }

            if (w < 0 && errno == EINTR)
            {
                eagain_retries = einval_retries = badfd_retries = 0;
                if (++eintr_retries > MAX_EINTR_RETRIES)
                {
                    nanosleep(&BACKOFF_1MS, NULL);
                    eintr_retries = 0;
                }
                continue;
            }

            if (w < 0 && errno == EAGAIN)
            {
                if (++eagain_retries > MAX_EAGAIN_RETRIES)
                {
                    nanosleep(&BACKOFF_1MS, NULL);
                    eagain_retries = 0;
                }

                /* wait until writable instead of spinning */
                pfd.revents = 0;
                int pres = poll(&pfd, 1, 100); /* 100 ms cap */

                if (pres < 0)
                {
                    if (errno == EINTR)
                    {
                        eagain_retries = einval_retries = badfd_retries = 0;
                        if (++eintr_retries > MAX_EINTR_RETRIES)
                        {
                            nanosleep(&BACKOFF_1MS, NULL);
                            eintr_retries = 0;
                        }
                        continue;
                    }
                    if (errno == EINVAL)
                    {
                        if (++einval_retries <= MAX_EINVAL_RETRIES)
                        {
                            nanosleep(&BACKOFF_1MS, NULL);
                            continue;
                        }
                    }
                    else if (errno == EBADF)
                    {
                        if (++badfd_retries > MAX_BADFD_RETRIES)
                        {
                            break; /* abort */
                        }

                        int new_wpipe = atomic_load_explicit(&ctx->wakeup.pipe[1], memory_order_acquire);
                        if (new_wpipe < 0 || new_wpipe == wpipe)
                        {
                            break; /* still invalid */
                        }

                        wpipe = new_wpipe;
                        pfd.fd = wpipe;
                        eintr_retries = eagain_retries = einval_retries = 0;
                        continue;
                    }
                    break; /* unexpected poll error */
                }

                if (pres == 0)
                {
                    /* poll timed out – treat like EAGAIN and apply progressive back‑off */
                    if (++eagain_retries > MAX_EAGAIN_RETRIES)
                    {
                        nanosleep(&BACKOFF_1MS, NULL);
                        eagain_retries = 0;
                    }
                    continue; /* retry the write */
                }

                if (!(pfd.revents & POLLOUT)
#ifdef POLLNVAL
                    || (pfd.revents & POLLNVAL)
#endif
                    || (pfd.revents & (POLLERR | POLLHUP)))
                {
                    break; /* unexpected event – abort */
                }

                /* descriptor writable – retry write() */
                continue;
            }

            /* reader end already closed – waking‑byte is unnecessary */
            if (w < 0 && errno == EPIPE)
            {
                /* prevent retrying */
                break;
            }

            if (w < 0 && (errno == EBADF || errno == EINVAL))
            {
                if (++badfd_retries > MAX_BADFD_RETRIES)
                {
                    break; /* too many attempts */
                }

                int new_wpipe = atomic_load_explicit(&ctx->wakeup.pipe[1], memory_order_acquire);
                if (new_wpipe < 0 || new_wpipe == wpipe)
                {
                    break; /* still invalid */
                }

                wpipe = new_wpipe;
                pfd.fd = wpipe;
                eintr_retries = eagain_retries = einval_retries = 0;
                continue; /* retry */
            }

            /* fallback: close read-end so poll loop wakes up and sees shutdown */
            {
                int rfd_fallback = atomic_exchange_explicit(&ctx->wakeup.pipe[0], -1, memory_order_acq_rel);
                if (rfd_fallback >= 0)
                {
                    /* best-effort close; ignore EBADF, retry once on EINTR. */
                    int rc_close;
                    do
                    {
                        rc_close = close(rfd_fallback);
                    } while (rc_close < 0 && errno == EINTR);
                    /* ignore EBADF or other errors – descriptor is gone or already closing. */
                }
            }
            break; /* abort further writes – poll loop will wake via HUP/EBADF */
        }

        /* restore original signal disposition */
        if (sigpipe_blocked)
        {
            sigpipe_restore(&old_sigset);
        }

        /* do not close wpipe here; ownership is transferred elsewhere. Clear local copy. */
        wpipe = -1;
    }

    /* wait for the poll thread to exit before touching listeners */
    libp2p_listener_t **listeners = NULL;
    size_t n_listeners = 0;

#ifdef __linux__
    {
        struct timespec ts;
        int rc;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        {
            /* clock_gettime failed – fall back to a blocking join */
            rc = pthread_join(ctx->thr, NULL);
        }
        else
        {
            ts.tv_sec += 5; /* 5-second timeout */
            rc = pthread_timedjoin_np(ctx->thr, NULL, &ts);
        }

        /* if the thread no longer exists, treat that as an already‑completed join. */
        if (rc == ESRCH)
        {
            rc = 0;
        }
        if (rc != 0)
        {
            /* progressive back-off: 1 s → 2 s → 4 s … up to 30 s total */
            const int MAX_TOTAL_WAIT_SEC = 30;
            int interval = 1;
            int waited = 0;
            bool joined = false;

            while (waited < MAX_TOTAL_WAIT_SEC)
            {
                struct timespec ts_extra;
                if (clock_gettime(CLOCK_MONOTONIC, &ts_extra) != 0)
                {
                    break; /* clock failed – take leak path */
                }
                ts_extra.tv_sec += interval;

                if (pthread_timedjoin_np(ctx->thr, NULL, &ts_extra) == 0)
                {
                    LP_LOGI("TCP", "poll thread joined after %d second%s of extra wait", waited + interval,
                            ((waited + interval) == 1) ? "" : "s");
                    joined = true;
                    break;
                }

                waited += interval;
                if (interval < 8)
                {
                    interval *= 2; /* exponential back-off */
                }
                if (waited + interval > MAX_TOTAL_WAIT_SEC)
                {
                    interval = MAX_TOTAL_WAIT_SEC - waited;
                }
            }

            if (!joined)
            {
                LP_LOGW("TCP", "poll thread still alive; attempting cancellation (%s)", strerror(rc));

                /* Best-effort cancellation of the poll thread */
                pthread_cancel(ctx->thr);
                if (pthread_join(ctx->thr, NULL) != 0)
                {
                    LP_LOGW("TCP", "poll thread did not respond to cancel; leaking context");

                    (void)pthread_detach(ctx->thr);
                    free(t);
                    return;
                }
            }
        }
    }
#else  /* !__linux__ */
    {
        int rc = pthread_join(ctx->thr, NULL);
        if (rc != 0)
        {
            LP_LOGW("TCP", "initial pthread_join failed (%s); waiting up to 30 s for poll thread to exit", strerror(rc));

            const int MAX_TOTAL_WAIT_SEC = 30;
            int interval = 1;
            int waited = 0;
            bool joined = false;

            while (waited < MAX_TOTAL_WAIT_SEC)
            {
                if (pthread_kill(ctx->thr, 0) == ESRCH)
                {
                    if (pthread_join(ctx->thr, NULL) == 0)
                    {
                        LP_LOGI("TCP", "poll thread joined after %d second%s of extra wait", waited, (waited == 1) ? "" : "s");
                    }
                    joined = true;
                    break;
                }

                struct timespec ts_sleep = {.tv_sec = interval, .tv_nsec = 0};
                nanosleep(&ts_sleep, NULL);

                waited += interval;
                if (interval < 8)
                {
                    interval *= 2;
                }
                if (waited + interval > MAX_TOTAL_WAIT_SEC)
                {
                    interval = MAX_TOTAL_WAIT_SEC - waited;
                }
            }

            if (!joined)
            {
                LP_LOGW("TCP", "poll thread still alive after extended wait; detaching and leaking transport context to avoid use-after-free");

                /* detach so the OS reclaims thread resources once it exits */
                (void)pthread_detach(ctx->thr);

                /* leave fds open; detached thread may still use them. Kernel will clean up. */
                /* free transport wrapper; context is leaked to avoid use-after-free */
                free(t);
                return;
            }
        }
    }
#endif /* __linux__ */

    /* detach and close all listeners */
    if (safe_mutex_lock(&ctx->listeners.lock) != 0)
    {
        LP_LOGE("TCP", "tcp_free: safe_mutex_lock(&ctx->listeners.lock) failed – aborting to avoid inconsistent listener state");
        abort();
    }
    listeners = ctx->listeners.list;
    n_listeners = ctx->listeners.count;
    ctx->listeners.list = NULL;
    ctx->listeners.count = 0;
    if (safe_mutex_unlock(&ctx->listeners.lock) != 0)
    {
        LP_LOGE("TCP", "tcp_free: safe_mutex_unlock(&ctx->listeners.lock) failed – state may be inconsistent");
        abort();
    }

    /* close all listeners (safe now – no poll thread races) */
    if (listeners && n_listeners > 0)
    {
        for (size_t i = 0; i < n_listeners; ++i)
        {
            libp2p_listener_t *l = listeners[i];
            if (l && l->vt && l->vt->close)
            {
                l->vt->close(l);
            }
        }
    }

    /* final listener destruction (refcount already dropped by close) */
    if (listeners && n_listeners > 0)
    {
        for (size_t i = 0; i < n_listeners; ++i)
        {
            libp2p_listener_t *l = listeners[i];
            if (!l)
            {
                continue;
            }

            /* only destroy listener if refcount is exactly 1; skip if 0 or >1. */
            unsigned cur = atomic_load_explicit(&l->refcount, memory_order_acquire);

            /* already destroyed */
            if (cur == 0)
            {
                continue; /* nothing left to do */
            }

            /* still in use elsewhere – do *not* touch it */
            if (cur > 1)
            {
                continue;
            }

            /* cur == 1 → try to seize the last ref */
            if (atomic_compare_exchange_strong_explicit(&l->refcount, &cur, 0, memory_order_acq_rel, memory_order_acquire))
            {
                /* successfully took the last reference – now destroy */
                atomic_thread_fence(memory_order_acquire);
                tcp_listener_destroy_actual(l);
            }
        }
    }

    /* wait for concurrent tcp_listener_destroy_actual() calls; timeout to avoid spin, leak on timeout. */
    const int MAX_TOTAL_WAIT_MS = 30000; /* 30 s overall cap */
    struct timespec start_ts;
    bool have_start_ts = (clock_gettime(CLOCK_MONOTONIC, &start_ts) == 0);

    /* if we failed to obtain the start timestamp, leak immediately instead of waiting forever. */
    bool leaked_list_snapshot = !have_start_ts;
    _Atomic uint64_t spin_attempts = 0;

    while (!leaked_list_snapshot && atomic_load_explicit(&ctx->gc.active_destroyers, memory_order_acquire) != 0)
    {
        cas_backoff(&spin_attempts); /* progressive yield / sleep (≤1 ms) */

        struct timespec now_ts;
        if (have_start_ts && clock_gettime(CLOCK_MONOTONIC, &now_ts) == 0)
        {
            long long elapsed_ms = (now_ts.tv_sec - start_ts.tv_sec) * 1000LL + (now_ts.tv_nsec - start_ts.tv_nsec) / 1000000LL;
            if (elapsed_ms >= MAX_TOTAL_WAIT_MS)
            {
                leaked_list_snapshot = true;
                break;
            }
        }
    }

    if (leaked_list_snapshot && atomic_load_explicit(&ctx->gc.active_destroyers, memory_order_acquire) != 0)
    {
        LP_LOGW("TCP", "tcp_free waited %d ms but %zu listener destroyer(s) are still active; leaking detached listener snapshot to avoid use-after-free",
               MAX_TOTAL_WAIT_MS, (size_t)atomic_load_explicit(&ctx->gc.active_destroyers, memory_order_relaxed));
        /* intentional leak: do not free(listeners) */
    }
    else
    {
        free(listeners);
    }

    /* drain graveyard and release remaining OS resources */
    if (safe_mutex_lock(&ctx->gc.lock) != 0)
    {
        LP_LOGE("TCP", "tcp_free: safe_mutex_lock(&gc.lock) failed – aborting to avoid inconsistent graveyard state");
        abort();
    }
    tcp_listener_ctx_t *g2 = ctx->gc.head;
    while (g2)
    {
        tcp_listener_ctx_t *next = g2->gc.next_free;

        int tmpfd = atomic_exchange_explicit(&g2->fd, -1, memory_order_acq_rel);
        if (tmpfd >= 0)
        {
            shutdown(tmpfd, SHUT_RDWR);
            int fl = fcntl(tmpfd, F_GETFL, 0);
            if (fl != -1)
                (void)fcntl(tmpfd, F_SETFL, fl | O_NONBLOCK);
            close(tmpfd);
        }

        safe_mutex_lock(&g2->q.mtx);
        libp2p_conn_t *c;
        while ((c = cq_pop(&g2->q)))
        {
            libp2p_conn_free(c);
        }
        safe_mutex_unlock(&g2->q.mtx);

        int rc_cd = pthread_cond_destroy(&g2->q.cond);
        if (rc_cd != 0)
        {
            LP_LOGE("TCP", "pthread_cond_destroy(&g2->q.cond) failed: %s", strerror(rc_cd));
            abort();
        }

        int rc_md = pthread_mutex_destroy(&g2->q.mtx);
        if (rc_md != 0)
        {
            LP_LOGE("TCP", "pthread_mutex_destroy(&g2->q.mtx) failed: %s", strerror(rc_md));
            abort();
        }

        multiaddr_free(g2->local);
        free(g2);

        g2 = next;
    }
    ctx->gc.head = NULL;
    if (safe_mutex_unlock(&ctx->gc.lock) != 0)
    {
        LP_LOGE("TCP", "tcp_free: safe_mutex_unlock(&gc.lock) failed – state may be inconsistent");
        abort();
    }

    /* tear down transport-level OS resources */
#if USE_EPOLL
    if (ctx->epfd >= 0)
    {
        close(ctx->epfd);
        ctx->epfd = -1; /* mark closed */
    }
#elif USE_KQUEUE
    if (ctx->kqfd >= 0)
    {
        close(ctx->kqfd);
        ctx->kqfd = -1; /* mark closed */
    }
#endif

    int rfd = atomic_exchange_explicit(&ctx->wakeup.pipe[0], -1, memory_order_acq_rel);
    if (rfd >= 0)
    {
        close(rfd);
    }
    int wfd = atomic_exchange_explicit(&ctx->wakeup.pipe[1], -1, memory_order_acq_rel);
    if (wfd >= 0)
    {
        close(wfd);
    }

    /* destroy mutexes and free ctx / wrapper */
    int rc_lck = pthread_mutex_destroy(&ctx->listeners.lock);
    if (rc_lck != 0)
    {
        LP_LOGE("TCP", "pthread_mutex_destroy(&ctx->listeners.lock) failed: %s", strerror(rc_lck));
        abort();
    }

    int rc_glck = pthread_mutex_destroy(&ctx->gc.lock);
    if (rc_glck != 0)
    {
        LP_LOGE("TCP", "pthread_mutex_destroy(&ctx->gc.lock) failed: %s", strerror(rc_glck));
        abort();
    }

    free(ctx);
    free(t);

#ifdef _WIN32
    /* Balance the WSAStartup() performed in libp2p_tcp_transport_new().       */
    WSACleanup();
#endif
}

/**
 * @brief Create and initialize a new TCP transport instance.
 *
 * Allocates and sets up a new libp2p_transport_t object for TCP transport,
 * including its context and configuration. Initializes necessary mutexes and
 * internal structures. Returns NULL on failure.
 *
 * @param cfg Optional pointer to a libp2p_tcp_config_t configuration struct.
 *            If NULL, the default configuration is used.
 * @return Pointer to a newly allocated libp2p_transport_t, or NULL on error.
 */
libp2p_transport_t *libp2p_tcp_transport_new(const libp2p_tcp_config_t *cfg)
{
#ifdef _WIN32
    /* Ensure WinSock is initialised before any socket calls on Windows.       */
    /* It is safe (and cheap) to invoke WSAStartup multiple times as long as   */
    /* each successful call is paired with a WSACleanup().                     */
    WSADATA wsa_data;
    const WORD wsa_ver_req = MAKEWORD(2, 2);
    if (WSAStartup(wsa_ver_req, &wsa_data) != 0)
    {
        /* WSAStartup failed – cannot use sockets. */
        return NULL;
    }
#endif

    /* function‑local transport v‑table (shared, static storage duration) */
    static const libp2p_transport_vtbl_t TCP_TRANSPORT_VTBL = {
        .can_handle = tcp_can_handle,
        .dial = tcp_dial,
        .listen = tcp_listen,
        .close = tcp_close,
        .free = tcp_free,
    };

    /* allocate memory for transport and context */
    libp2p_transport_t *t = calloc(1, sizeof *t);
    struct tcp_transport_ctx *ctx = calloc(1, sizeof *ctx);
    if (!t || !ctx)
    {
        free(t);
        free(ctx);
        return NULL;
    }

    /* copy config */
    ctx->cfg = cfg ? *cfg : libp2p_tcp_config_default();

    /* initialize main transport lock */
    int rc = pthread_mutex_init(&ctx->listeners.lock, NULL);
    if (rc != 0)
    {
        free(ctx);
        free(t);
        return NULL;
    }

    /* initialize graveyard mechanism */
    ctx->gc.head = NULL;
    rc = pthread_mutex_init(&ctx->gc.lock, NULL);
    if (rc != 0)
    {
        /* undo earlier mutex */
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }

    /* initialize poll-epoch counter */
    atomic_init(&ctx->gc.poll_epoch, 0);
    atomic_init(&ctx->gc.active_destroyers, 0);

#if USE_EPOLL
    /* create epoll instance with CLOEXEC to prevent FD leaks across fork/exec */
    ctx->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epfd < 0)
    {
        {
            int rc = pthread_mutex_destroy(&ctx->gc.lock);
            if (rc != 0)
            {
                LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }
#elif USE_KQUEUE
    ctx->kqfd = kqueue();
    if (ctx->kqfd < 0)
    {
        {
            int rc = pthread_mutex_destroy(&ctx->gc.lock);
            if (rc != 0)
            {
                LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }
#endif

    /* setup self-wakeup pipe for poll loop (portable fallback for systems without pipe2) */
    if (pipe((int *)ctx->wakeup.pipe) != 0) /* cast silences _Atomic → int warning */
    {
        perror("pipe");
#if USE_EPOLL
        close(ctx->epfd);
#elif USE_KQUEUE
        close(ctx->kqfd);
#endif
        {
            int rc = pthread_mutex_destroy(&ctx->gc.lock);
            if (rc != 0)
            {
                LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }

    /* set close-on-exec and non-blocking flags on both ends */
    for (int j = 0; j < 2; ++j)
    {
        int flags;
        /* FD_CLOEXEC */
        flags = fcntl(ctx->wakeup.pipe[j], F_GETFD, 0);
        if (flags == -1 || fcntl(ctx->wakeup.pipe[j], F_SETFD, flags | FD_CLOEXEC) == -1)
        {
#if USE_EPOLL
            close(ctx->epfd);
#elif USE_KQUEUE
            close(ctx->kqfd);
#endif
            close(ctx->wakeup.pipe[0]);
            close(ctx->wakeup.pipe[1]);
            {
                int rc = pthread_mutex_destroy(&ctx->gc.lock);
                if (rc != 0)
                {
                    LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
                }
            }
            {
                int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
                if (rc2 != 0)
                {
                    LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
                }
            }
            free(ctx);
            free(t);
            return NULL;
        }

        /* O_NONBLOCK */
        flags = fcntl(ctx->wakeup.pipe[j], F_GETFL, 0);
        if (flags == -1 || fcntl(ctx->wakeup.pipe[j], F_SETFL, flags | O_NONBLOCK) == -1)
        {
#if USE_EPOLL
            close(ctx->epfd);
#elif USE_KQUEUE
            close(ctx->kqfd);
#endif
            close(ctx->wakeup.pipe[0]);
            close(ctx->wakeup.pipe[1]);
            {
                int rc = pthread_mutex_destroy(&ctx->gc.lock);
                if (rc != 0)
                {
                    LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
                }
            }
            {
                int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
                if (rc2 != 0)
                {
                    LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
                }
            }
            free(ctx);
            free(t);
            return NULL;
        }
    }

    /* use ctx pointer as unique wakeup marker */
    ctx->wakeup.marker = ctx;
#if USE_EPOLL
    struct epoll_event ev_wakeup = {.events = EPOLLIN, .data.ptr = ctx->wakeup.marker};
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->wakeup.pipe[0], &ev_wakeup) != 0)
    {
        close(ctx->wakeup.pipe[0]);
        close(ctx->wakeup.pipe[1]);
        close(ctx->epfd);
        {
            int rc = pthread_mutex_destroy(&ctx->gc.lock);
            if (rc != 0)
            {
                LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }
#elif USE_KQUEUE
    struct kevent kev_wakeup;
    EV_SET(&kev_wakeup, ctx->wakeup.pipe[0], EVFILT_READ, EV_ADD, 0, 0, ctx->wakeup.marker);
    if (kevent(ctx->kqfd, &kev_wakeup, 1, NULL, 0, NULL) < 0)
    {
        close(ctx->wakeup.pipe[0]);
        close(ctx->wakeup.pipe[1]);
        close(ctx->kqfd);
        {
            int rc = pthread_mutex_destroy(&ctx->gc.lock);
            if (rc != 0)
            {
                LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }
#endif

    if (pthread_create(&ctx->thr, NULL, poll_loop, ctx) != 0)
    {
#if USE_EPOLL
        close(ctx->epfd);
#elif USE_KQUEUE
        close(ctx->kqfd);
#endif
        close(ctx->wakeup.pipe[0]);
        close(ctx->wakeup.pipe[1]);
        {
            int rc = pthread_mutex_destroy(&ctx->gc.lock);
            if (rc != 0)
            {
                LP_LOGW("TCP", "failed to destroy graveyard mutex: %s", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->listeners.lock);
            if (rc2 != 0)
            {
                LP_LOGW("TCP", "failed to destroy transport mutex: %s", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }

    t->vt = &TCP_TRANSPORT_VTBL;
    t->ctx = ctx;
    return t;
}
