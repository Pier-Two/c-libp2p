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

#include <unistd.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol/tcp/protocol_tcp_poller.h"
#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif
#include "protocol/tcp/protocol_tcp_queue.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

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
    tcp_transport_ctx_t *tctx = ((tcp_listener_ctx_t *)l->ctx)->tctx;
    if (tctx)
    {
        atomic_fetch_add_explicit(&tctx->active_listener_destroyers, 1, memory_order_acquire);
    }

    /* extract contexts */
    tcp_listener_ctx_t *ctx = l->ctx;
    /* tctx is already set above */

    /* mark listener closed and remove from poller */
    if (ctx)
    {
        atomic_store_explicit(&ctx->closed, true, memory_order_release);
        if (tctx)
        {
            poller_del(tctx, ctx);
        }

        /* atomically close file descriptor */
        int fd = atomic_exchange_explicit(&ctx->fd, -1, memory_order_acq_rel);
        if (fd >= 0)
        {
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }

        /* remove from transport context's listeners */
        if (tctx)
        {
            pthread_mutex_lock(&tctx->lck);
            for (size_t i = 0; i < tctx->n_listeners; ++i)
            {
                if (tctx->listeners[i] == l)
                {
                    tctx->listeners[i] = NULL;
                    break;
                }
            }
            pthread_mutex_unlock(&tctx->lck);
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
                fprintf(stderr, "[fatal] tcp_listener_destroy_actual(ctx=%p): ctx->refcount underflow\n", (void *)ctx);
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
            /* last reference: safe to destroy listener context now */
            libp2p_conn_t *c;

            /* drain accept‑queue */
            while ((c = cq_pop(&ctx->q)))
            {
                libp2p_conn_free(c);
            }

            /* wait until all threads exit pthread_cond_wait() */
            while (atomic_load_explicit(&ctx->waiters, memory_order_acquire) != 0)
            {
                nanosleep(&BACKOFF_1MS, NULL); /* blocks, avoids priority inversion */
            }

            /* destroy cond‑var and its mutex while holding it */
            pthread_mutex_lock(&ctx->q.mtx);
            int rc_cd = pthread_cond_destroy(&ctx->q.cond);
            if (rc_cd != 0)
            {
                fprintf(stderr, "[fatal] pthread_cond_destroy(ctx->q.cond) failed: %s\n", strerror(rc_cd));
                abort();
            }

            pthread_mutex_unlock(&ctx->q.mtx);

            int rc_md = pthread_mutex_destroy(&ctx->q.mtx);
            if (rc_md != 0)
            {
                fprintf(stderr, "[fatal] pthread_mutex_destroy(ctx->q.mtx) failed: %s\n", strerror(rc_md));
                abort();
            }

            /* release remaining resources */
            multiaddr_free(ctx->local);
            free(ctx);
        }
        else
        {
            /* defer free: add to graveyard for poll loop cleanup */
            atomic_store_explicit(&ctx->pending_free, true, memory_order_release);
            if (tctx)
            {
                size_t cur_epoch = atomic_load_explicit(&tctx->poll_epoch, memory_order_acquire);
                size_t next_epoch = (cur_epoch == SIZE_MAX) ? cur_epoch : cur_epoch + 1;
                atomic_store_explicit(&ctx->free_epoch, next_epoch, memory_order_release);

                pthread_mutex_lock(&tctx->graveyard_lck);
                ctx->next_free = tctx->graveyard_head;
                tctx->graveyard_head = ctx;
                pthread_mutex_unlock(&tctx->graveyard_lck);
            }
        }
    }

    /* destroy public listener mutex (no remaining refs) */
    safe_mutex_lock(&l->mutex);   /* take ownership */
    safe_mutex_unlock(&l->mutex); /* leave it unlocked as required */
    int rc_lm = pthread_mutex_destroy(&l->mutex);
    if (rc_lm != 0)
    {
        fprintf(stderr, "[fatal] pthread_mutex_destroy(l->mutex) failed: %s\n", strerror(rc_lm));
        abort();
    }
    free(l); /* no thread can access l – refcount already hit zero */

    /* opportunistic listener‑array compaction */
    if (tctx)
    {
        libp2p_listener_t **snap_list;
        size_t snap_len;

        /* snapshot + live‑count under lock */
        safe_mutex_lock(&tctx->lck);
        snap_list = tctx->listeners;
        snap_len = tctx->n_listeners;

        size_t live = 0;
        for (size_t i = 0; i < snap_len; ++i)
        {
            if (snap_list[i] != NULL)
            {
                ++live;
            }
        }

        /* If a previous shrink failed (OOM or CAS‑loss), force a retry. */
        bool pending = atomic_load_explicit(&tctx->compact_pending, memory_order_acquire);

        /* Flags for actions to perform once we drop the lock */
        bool detach_and_free = false;
        bool do_shrink = false;

        if (snap_list)
        {
            if (live == 0)
            {
                /* array is completely empty – detach now, free later */
                tctx->listeners = NULL;
                tctx->n_listeners = 0;
                detach_and_free = true; /* we own snap_list */
            }
            else if ((live < snap_len && live <= (snap_len * 3) / 4) || /* normal 25 % rule */
                     (pending && live < snap_len))                      /* forced retry    */
            {
                /* worth shrinking; build new array outside the lock */
                do_shrink = true;
            }
        }
        safe_mutex_unlock(&tctx->lck);

        /* free empty array outside lock */
        if (detach_and_free)
        {
            free(snap_list);
            atomic_store_explicit(&tctx->compact_pending, false, memory_order_release);

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
                fprintf(stderr,
                        "[warn] tcp_listener_destroy_actual: unable to compact listener list "
                        "(wanted %zu -> %zu entries) due to OOM – will retry later\n",
                        snap_len, live);
                atomic_store_explicit(&tctx->compact_pending, true, memory_order_release);
            }
            else
            {
                /* quick re‑validation before we spend time copying */
                safe_mutex_lock(&tctx->lck);
                bool still_same = (tctx->listeners == snap_list) && (tctx->n_listeners == snap_len);
                safe_mutex_unlock(&tctx->lck);

                if (!still_same)
                {
                    /* the array changed while we were unlocked – abort early */
                    atomic_store_explicit(&tctx->compact_pending, true, memory_order_release);
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
                    safe_mutex_lock(&tctx->lck);
                    if (tctx->listeners == snap_list)
                    {
                        libp2p_listener_t **old = tctx->listeners;
                        tctx->listeners = new_list;
                        tctx->n_listeners = live;
                        safe_mutex_unlock(&tctx->lck);

                        free(old);        /* we successfully took ownership */
                        snap_list = NULL; /* avoid dangling pointer — defensive */
                        atomic_store_explicit(&tctx->compact_pending, false, memory_order_release);
                    }
                    else
                    {
                        safe_mutex_unlock(&tctx->lck);
                        atomic_store_explicit(&tctx->compact_pending, true, memory_order_release);
                        free(new_list); /* lost the race – discard copy  */
                    }
                }
            }
        }
    }

    /* per-transport destroyer counter: decrement at exit */
    if (tctx)
    {
        atomic_fetch_sub_explicit(&tctx->active_listener_destroyers, 1, memory_order_release);
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
        fprintf(stderr, "[fatal] tcp_listener_release_refs(%p): listener refcount underflow\n", (void *)l);
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
                fprintf(stderr, "[fatal] tcp_listener_release_refs(%p,%p): ctx->refcount underflow\n", (void *)l, (void *)ctx);
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
static libp2p_listener_err_t tcp_listener_accept(libp2p_listener_t *l, libp2p_conn_t **out)
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
                fprintf(stderr, "[fatal] tcp_listener_accept rollback(%p): l->refcount underflow\n", (void *)l);
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
    const uint64_t WAIT_MS_RAW = ctx->poll_ms;
    const uint64_t WAIT_MS_MIN = 1;                               /* avoid busy‑spin */
    const uint64_t WAIT_MS_CAP = 24ULL * 60ULL * 60ULL * 1000ULL; /* 24 hours        */

    uint64_t wait_ms = WAIT_MS_RAW ? WAIT_MS_RAW : WAIT_MS_MIN;

    if (wait_ms > WAIT_MS_CAP)
    {
        wait_ms = WAIT_MS_CAP; /* cap excessively large values */
    }

    const time_t WAIT_SEC = (time_t)(wait_ms / 1000);             /* ≤ 86 400        */
    const long WAIT_NSEC = (long)((wait_ms % 1000) * 1000000ULL); /* < 1 000 000 000 */

    while (!ctx->q.head && !atomic_load_explicit(&ctx->closed, memory_order_acquire) && !atomic_load_explicit(&ctx->disabled, memory_order_acquire))
    {
        struct timespec ts;
        const clockid_t WAIT_CLOCK = ctx->cond_clock;

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
        atomic_fetch_add_explicit(&ctx->waiters, 1, memory_order_relaxed);
        int rc = pthread_cond_timedwait(&ctx->q.cond, &ctx->q.mtx, &ts);
        atomic_fetch_sub_explicit(&ctx->waiters, 1, memory_order_release);

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

    /* disabled (back-off) */
    if (atomic_load_explicit(&ctx->disabled, memory_order_acquire) && !ctx->q.head)
    {
        safe_mutex_unlock(&ctx->q.mtx);
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_BACKOFF;
    }

    /* closed */
    if (!ctx->q.head)
    {
        safe_mutex_unlock(&ctx->q.mtx);
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_CLOSED;
    }

    /* dequeue one connection */
    conn_node_t *n = ctx->q.head;
    ctx->q.head = n->next;
    if (!ctx->q.head)
    {
        ctx->q.tail = NULL;
    }

    /* validate queue integrity: connection pointer must be non‑NULL */
    if (n->c == NULL)
    {
        free(n);
        safe_mutex_unlock(&ctx->q.mtx);
        tcp_listener_release_refs(l, ctx);
        return LIBP2P_LISTENER_ERR_INTERNAL;
    }

    *out = n->c;

    /* free node while still holding the queue mutex */
    free(n);

    /* unlock mutex */
    safe_mutex_unlock(&ctx->q.mtx);

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
static libp2p_listener_err_t tcp_listener_local(libp2p_listener_t *l, multiaddr_t **out)
{
    /* validate arguments  */
    if (!out)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }
    *out = NULL;

    if (!l || !l->ctx)
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
        rc = LIBP2P_LISTENER_ERR_INTERNAL;
    }
    else
    {
        *out = addr;
    }

    /* release wrapper reference & maybe destroy */
    unsigned l_old = listener_refcount_fetch_sub(l);
    if (l_old == 1)
    {
        atomic_thread_fence(memory_order_acquire); /* pair with other acquires */
        tcp_listener_destroy_actual(l);
    }

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
static libp2p_listener_err_t tcp_listener_close(libp2p_listener_t *l)
{
    if (!l)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    /* increment wrapper refcount with overflow guard (same pattern as accept()) */
    {
        for (;;)
        {
            unsigned cur = atomic_load_explicit(&l->refcount, memory_order_relaxed);
            if (cur >= UINT_MAX - 1)
            {
                /* prevent wrap‑around that could resurrect destroyed listeners */
                return LIBP2P_LISTENER_ERR_OVERFLOW;
            }
            if (atomic_compare_exchange_strong_explicit(&l->refcount, &cur, cur + 1, memory_order_acq_rel, memory_order_relaxed))
            {
                break; /* success */
            }
            cas_backoff(NULL); /* progressive back‑off on contention (no counter needed) */
        }
    }

    tcp_listener_ctx_t *ctx = atomic_load_explicit(&l->ctx, memory_order_acquire);
    if (!ctx)
    {
        /* undo the ref we just added and bail out */
        unsigned l_old = listener_refcount_fetch_sub(l);
        if (l_old == 1)
        {
            tcp_listener_destroy_actual(l);
        }
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    bool timed_out = false;

    /* already closed? (returns previous value) */
    if (atomic_exchange_explicit(&ctx->closed, true, memory_order_acq_rel))
    {
        /* decrement wrapper refcount and maybe destroy */
        unsigned l_old = listener_refcount_fetch_sub(l);
        if (l_old == 1)
        {
            tcp_listener_destroy_actual(l);
            return LIBP2P_LISTENER_ERR_CLOSED;
        }
        return LIBP2P_LISTENER_ERR_CLOSED;
    }

    /* detach from poller; fd stays open until refcount == 1 */
    if (ctx->tctx)
    {
        /* poller_del() returns void in the current API; simply invoke it. */
        poller_del(ctx->tctx, ctx);
    }

    /* wake up any thread blocked in accept() */
    if (safe_mutex_lock(&ctx->q.mtx) != 0) /* aborts on error, but keep RAII rollback for static analysis */
    {
        /* undo the reference we took at the top of tcp_listener_close() */
        unsigned l_old = listener_refcount_fetch_sub(l);
        if (l_old == 1)
        {
            tcp_listener_destroy_actual(l);
        }
        return LIBP2P_LISTENER_ERR_MUTEX;
    }

    /* wake up any thread blocked in accept() */
    int rc_bc = pthread_cond_broadcast(&ctx->q.cond);
    if (rc_bc != 0)
    {
        /* log and ensure the mutex is released so crash handlers do not dead‑lock */
        fprintf(stderr, "[fatal] tcp_listener_close: pthread_cond_broadcast failed: %s\n", strerror(rc_bc));

        /* best‑effort unlock: use plain pthread API to avoid recursive abort */
        safe_mutex_unlock(&ctx->q.mtx);
        abort();
    }
    safe_mutex_unlock(&ctx->q.mtx);

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
        uint32_t to_ms = ctx->close_timeout_ms;

        /* immediate forced‑close */
        if (to_ms == 0)
        {
            timed_out = true;
            break; /* skip wait, go force‑close path */
        }

        struct timespec ts;
        /* use the same clock as the condition variable */
        clockid_t wait_clock = ctx->cond_clock;
        int rc_clock = clock_gettime(wait_clock, &ts);
        if (rc_clock != 0)
        {
            /* Failed to obtain current time – treat as timeout/error to avoid UB */
            timed_out = true;
            break;
        }

        /* UINT32_MAX means “wait forever” → use plain pthread_cond_wait */
        int ret;
        if (to_ms == UINT32_MAX)
        {
            atomic_fetch_add_explicit(&ctx->waiters, 1, memory_order_relaxed);
            ret = pthread_cond_wait(&ctx->q.cond, &ctx->q.mtx);
            atomic_fetch_sub_explicit(&ctx->waiters, 1, memory_order_release);
        }
        else
        {
            /* add relative timeout safely (handles 32‑bit time_t overflow) */
            timespec_add_safe(&ts, (int64_t)(to_ms / 1000), (long)((to_ms % 1000) * 1000000L));
            atomic_fetch_add_explicit(&ctx->waiters, 1, memory_order_relaxed);
            ret = pthread_cond_timedwait(&ctx->q.cond, &ctx->q.mtx, &ts);
            atomic_fetch_sub_explicit(&ctx->waiters, 1, memory_order_release);
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
        fprintf(stderr, "[fatal] tcp_listener_close: pthread_cond_* returned %s – treating as forced timeout\n", strerror(ret));
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
        atomic_store_explicit(&ctx->pending_free, true, memory_order_release);

        if (ctx->tctx)
        {
            /* transport context still valid – schedule for deferred free and notify poll loop */
            size_t cur_epoch = atomic_load_explicit(&ctx->tctx->poll_epoch, memory_order_acquire);
            /* saturate at SIZE_MAX so the epoch never wraps back to 0 */
            size_t next_epoch = (cur_epoch == SIZE_MAX) ? cur_epoch : cur_epoch + 1;
            atomic_store_explicit(&ctx->free_epoch, next_epoch, memory_order_release);

            /* wake transport poll loop to process pending free */
            int wpipe_t = atomic_load_explicit(&ctx->tctx->wakeup_pipe[1], memory_order_acquire);
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
            atomic_store_explicit(&ctx->free_epoch, 0, memory_order_release);
        }

        /* decrement wrapper refcount and maybe destroy */
        unsigned l_old = listener_refcount_fetch_sub(l);
        if (l_old == 1)
        {
            tcp_listener_destroy_actual(l);
            return LIBP2P_LISTENER_ERR_TIMEOUT;
        }
        return LIBP2P_LISTENER_ERR_TIMEOUT;
    }

    /* decrement wrapper refcount and maybe destroy */
    unsigned l_old = listener_refcount_fetch_sub(l);
    if (l_old == 1)
    {
        tcp_listener_destroy_actual(l);
        return LIBP2P_LISTENER_OK;
    }
    return LIBP2P_LISTENER_OK;
}

void tcp_listener_free(libp2p_listener_t *l)
{
    if (!l)
    {
        return;
    }

    /* decrement wrapper refcount and invoke actual destroy when it drops to zero */
    unsigned old = listener_refcount_fetch_sub(l);
    if (old == 1)
    {
        /* acquire fence for refcount zero, as elsewhere. */
        atomic_thread_fence(memory_order_acquire);
        tcp_listener_destroy_actual(l);
    }
}

/**
 * Attempts to establish a TCP connection to the given multiaddress.
 *
 * @param self  Pointer to the transport instance.
 * @param addr  The multiaddress to dial (must be a valid TCP address).
 * @param out   Output pointer for the resulting connection (set on success).
 * @return      LIBP2P_TRANSPORT_OK on success, or an appropriate error code on failure.
 */
static libp2p_transport_err_t tcp_dial(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out)
{
    /* Always reset output pointer so caller never sees an indeterminate value,
     * even if we exit via the early NULL‑argument guard below. */
    if (out)
    {
        *out = NULL;
    }

    if (!self || !addr || !out)
    {
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    }
    struct tcp_transport_ctx *tctx = self->ctx;
    if (!tctx)
    {
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    }
    if (atomic_load_explicit(&tctx->closed, memory_order_acquire))
    {
        return LIBP2P_TRANSPORT_ERR_CLOSED;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (multiaddr_to_sockaddr(addr, &ss, &ss_len) != 0)
    {
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    }

    uint16_t port_n;
    if (ss.ss_family == AF_INET)
    {
        if (ss_len < sizeof(struct sockaddr_in))
        {
            return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
        }
        port_n = ((struct sockaddr_in *)&ss)->sin_port;
    }
    else if (ss.ss_family == AF_INET6)
    {
        if (ss_len < sizeof(struct sockaddr_in6))
        {
            return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
        }
        port_n = ((struct sockaddr_in6 *)&ss)->sin6_port;
    }
    else
    {
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    }
    if (ntohs(port_n) == 0)
    {
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    }

#ifdef SOCK_CLOEXEC
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
#endif
    if (fd < 0)
    {
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }

#ifdef SOCK_CLOEXEC
    /* FD_CLOEXEC already set by the SOCK_CLOEXEC flag; only set nonblocking */
    if (set_nonblocking(fd) == -1)
    {
        /* close socket and return on error; do not reuse closed fd */
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }
#else
    /* set close-on-exec and nonblocking flags robustly */
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }
    if (set_nonblocking(fd) == -1)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }
#endif

    /* socket options (TCP_NODELAY, SO_REUSEADDR/PORT, SO_KEEPALIVE, TCP_FASTOPEN) */
    if (tctx->cfg.nodelay)
    {
        int on = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) < 0)
        {
            int errsv = errno;
            close(fd);
            return map_sockopt_errno(errsv);
        }
    }
    if (tctx->cfg.reuse_port)
    {
        int on = 1;
        int rc1 = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#ifdef SO_REUSEPORT
        int rc2 = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        if (rc1 < 0 || rc2 < 0)
        {
            int errsv = errno;
            close(fd);
            return map_sockopt_errno(errsv);
        }
#else
        if (rc1 < 0)
        {
            int errsv = errno;
            close(fd);
            return map_sockopt_errno(errsv);
        }
#endif
    }
    if (tctx->cfg.keepalive)
    {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) < 0)
        {
            int errsv = errno;
            close(fd);
            return map_sockopt_errno(errsv);
        }
    }
#ifdef TCP_FASTOPEN
    {
        int tfo_enable = 1;
        /* ignoring return value is fine for TFO as it's opportunistic */
        (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &tfo_enable, sizeof tfo_enable);
    }
#endif
    /* end of socket options */

    int rc = connect(fd, (struct sockaddr *)&ss, ss_len);
    int errsv = errno;

    /* treat in-progress/interrupted connect as EINPROGRESS to use poll completion. */
    if (rc != 0 && errsv != EINPROGRESS && errsv != EINTR && errsv != EALREADY && errsv != EWOULDBLOCK && /* often equal to EAGAIN */
        errsv != EAGAIN)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
    }

    /* case 1: immediate connect */
    if (rc == 0)
    {
        *out = make_tcp_conn(fd);
        if (!*out)
        {
            close(fd); /* close on allocation failure */
            return LIBP2P_TRANSPORT_ERR_INTERNAL;
        }
        return LIBP2P_TRANSPORT_OK;
    }

    /* listen for POLLOUT and POLLIN in case of early data */
    struct pollfd pfd = {.fd = fd, .events = POLLOUT | POLLIN};

    /* timeout setup with safety cap (10 minutes) */
    int64_t cfg_to = tctx->cfg.connect_timeout;
    if (cfg_to > INT_MAX)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INVALID_ARG;
    }
    const uint64_t safety_cap_ms = 10ULL * 60ULL * 1000ULL; /* 10 minutes in ms */
    uint64_t timeout_ms_duration;
    if (cfg_to < 0)
    {
        timeout_ms_duration = safety_cap_ms;
    }
    else if (cfg_to == 0)
    {
        timeout_ms_duration = 30000; /* default 30 seconds */
    }
    else
    {
        timeout_ms_duration = (uint64_t)cfg_to;
    }
    uint64_t now_ms = now_mono_ms();
    uint64_t deadline_ms;
    if (timeout_ms_duration > UINT64_MAX - now_ms)
    {
        deadline_ms = UINT64_MAX;
    }
    else
    {
        deadline_ms = now_ms + timeout_ms_duration;
    }

    while (1)
    {
        /* Abort promptly if the transport is closed while we are waiting. */
        if (atomic_load_explicit(&tctx->closed, memory_order_acquire))
        {
            close(fd);
            return LIBP2P_TRANSPORT_ERR_CLOSED;
        }
        /* compute wait_ms for poll with safety cap */
        uint64_t current_ms = now_mono_ms();
        int wait_ms;
        if (current_ms >= deadline_ms)
        {
            wait_ms = 0; /* timeout expired */
        }
        else
        {
            uint64_t delta = deadline_ms - current_ms;

            /* clamp to INT_MAX to avoid overflow when casting */
            wait_ms = (delta > INT_MAX) ? INT_MAX : (int)delta;
        }

        /* removed pre-poll timeout check: always call poll, even if wait_ms == 0 */
        int ret = poll(&pfd, 1, wait_ms);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                /* clear pfd.revents after EINTR */
                pfd.revents = 0;
                continue;
            }
            close(fd);
            return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
        }

        /* timeout occurred */
        if (ret == 0)
        {
            close(fd);
            return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
        }

        /* evaluate poll result (POLLERR / POLLHUP quirks included) */
#ifdef POLLNVAL
        const short fatal_mask = POLLNVAL; /* invalid‑fd, always fatal     */
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
            if (err != 0) /* connect() really failed */
            {
                close(fd);
                return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
            }

            /* connected successfully (even if POLLHUP was set) */
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
static libp2p_transport_err_t tcp_listen(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out)
{
    /* ensure the caller never observes an indeterminate value on error paths */
    if (out)
    {
        *out = NULL;
    }
    if (!self || !addr || !out)
    {
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    }

    /* function‑local listener v‑table (shared, static storage duration) */
    static const libp2p_listener_vtbl_t TCP_LISTENER_VTBL = {
        .accept = tcp_listener_accept,
        .local_addr = tcp_listener_local,
        .close = tcp_listener_close,
        .free = tcp_listener_free,
    };

    /* reject DNS on listen (dial-only) */
    {
        uint64_t p0;
        if (multiaddr_get_protocol_code(addr, 0, &p0) == 0 && (p0 == MULTICODEC_DNS4 || p0 == MULTICODEC_DNS6))
        {
            return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
        }
    }

    struct tcp_transport_ctx *tctx = self->ctx;
    if (!tctx)
    {
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;
    }
    /* abort early if the transport is already closed to avoid wasted work */
    if (atomic_load_explicit(&tctx->closed, memory_order_acquire))
    {
        return LIBP2P_TRANSPORT_ERR_CLOSED;
    }

    /* convert multiaddr to sockaddr */
    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (multiaddr_to_sockaddr(addr, &ss, &ss_len) != 0)
    {
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;
    }

    /* create listener socket */
#ifdef SOCK_CLOEXEC
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
#endif
    if (fd < 0)
    {
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }

#ifndef SOCK_CLOEXEC
    /* set FD_CLOEXEC when the flag was not supplied to socket() */
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }
#endif
    if (set_nonblocking(fd) == -1)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }

    /* SO_REUSEADDR / SO_REUSEPORT */
    if (tctx->cfg.reuse_port)
    {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) < 0
#ifdef SO_REUSEPORT
            || setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) < 0
#endif
        )
        {
            int errsv = errno;
            close(fd);
            return map_sockopt_errno(errsv);
        }
    }

    /* bind & listen */
    if (bind(fd, (struct sockaddr *)&ss, ss_len) != 0)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }

    /* safely convert user-supplied size_t backlog to int without overflow */
    size_t requested_size = (tctx->cfg.backlog > 0) ? tctx->cfg.backlog : (size_t)SOMAXCONN;

    /* clamp to SOMAXCONN */
    size_t clamped_size = (requested_size > (size_t)SOMAXCONN) ? (size_t)SOMAXCONN : requested_size;

    /* clamp to INT_MAX and cast to int */
    int backlog = (clamped_size > (size_t)INT_MAX) ? INT_MAX : (int)clamped_size;
    if (listen(fd, backlog) != 0)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_LISTEN_FAIL;
    }

    /* server-side TCP Fast Open */
#ifdef TCP_FASTOPEN
    {
        int tfo_queue_len = backlog;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &tfo_queue_len, sizeof tfo_queue_len);
    }
#endif

    /* allocate internal listener context */
    tcp_listener_ctx_t *lctx = calloc(1, sizeof *lctx);
    if (!lctx)
    {
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    /* initialize listener state */
    atomic_init(&lctx->closed, false);
    atomic_init(&lctx->refcount, 1);

    /* no threads are waiting yet */
    atomic_init(&lctx->waiters, 0);
    atomic_init(&lctx->fd, fd);
    atomic_init(&lctx->free_epoch, 0);

    lctx->tctx = tctx;
    cq_init(&lctx->q);

    /* default until proven otherwise */
    lctx->cond_clock = CLOCK_REALTIME;
#if defined(_POSIX_MONOTONIC_CLOCK) && !defined(__APPLE__)
    {
        pthread_condattr_t attr;
        if (pthread_condattr_init(&attr) == 0)
        {
            int rc_clock = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
            if (rc_clock == 0)
            {
                /* wait against the monotonic clock */
                lctx->cond_clock = CLOCK_MONOTONIC;
            }
            /* re‑create the condvar using whatever clock attr now contains */
            pthread_cond_destroy(&lctx->q.cond);
            int rc_cnd = pthread_cond_init(&lctx->q.cond, &attr);
            pthread_condattr_destroy(&attr);
            if (rc_cnd != 0)
            {
                /* initialization failed – abort construction and clean up */
                pthread_mutex_destroy(&lctx->q.mtx);
                free(lctx);
                close(fd);
                return LIBP2P_TRANSPORT_ERR_INTERNAL;
            }
        }
    }
#endif

    /* temporary back‑off (initialised here, used in poll_loop) */
    atomic_init(&lctx->disabled, false); /* listener is active */
    lctx->enable_at_ms = 0;              /* no back‑off deadline yet */
    lctx->backoff_ms = 100;              /* first back‑off = 100 ms */

    /* per-listener accept() poll period (ms) */
    lctx->poll_ms = (tctx->cfg.accept_poll_ms != 0) ? tctx->cfg.accept_poll_ms : 1000; /* library default (1 s) */

    /* per-listener close timeout (ms) */
    lctx->close_timeout_ms = tctx->cfg.close_timeout_ms;

    /* determine actual listen address */
    struct sockaddr_storage actual = {0};
    socklen_t actual_len = sizeof actual;
    if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) == 0)
    {
        lctx->local = sockaddr_to_multiaddr(&actual, actual_len);
    }
    else
    {
        lctx->local = multiaddr_copy(addr, NULL);
    }
    if (lctx->local == NULL)
    {
        /* OOM on multiaddr allocation: cleanup and bail */
        pthread_cond_destroy(&lctx->q.cond);
        pthread_mutex_destroy(&lctx->q.mtx);
        free(lctx);
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    /* register with poll loop */
    if (poller_add(tctx, lctx) != 0)
    {
        multiaddr_free(lctx->local);
        pthread_cond_destroy(&lctx->q.cond);
        pthread_mutex_destroy(&lctx->q.mtx);
        free(lctx);
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    /* allocate the public listener wrapper */
    libp2p_listener_t *l = calloc(1, sizeof *l);
    if (!l)
    {
        /* clean up on failure */
        poller_del(tctx, lctx);
        multiaddr_free(lctx->local);
        pthread_cond_destroy(&lctx->q.cond);
        pthread_mutex_destroy(&lctx->q.mtx);
        free(lctx);
        close(fd);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    l->vt = &TCP_LISTENER_VTBL;
    l->ctx = lctx;

    /* initialize wrapper reference count */
    atomic_init(&l->refcount, 1);

    /* initialize public mutex to guard vtbl calls, checking for errors */
    int rc_mutex = pthread_mutex_init(&l->mutex, NULL);
    if (rc_mutex != 0)
    {
        /* cleanup on mutex init failure */
        poller_del(tctx, lctx);
        multiaddr_free(lctx->local);
        pthread_cond_destroy(&lctx->q.cond);
        pthread_mutex_destroy(&lctx->q.mtx);
        free(lctx);
        close(fd);
        free(l);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    /* store the wrapper in the transport context (with realloc check) */
    pthread_mutex_lock(&tctx->lck);
    if (atomic_load_explicit(&tctx->closed, memory_order_acquire))
    {
        pthread_mutex_unlock(&tctx->lck);
        poller_del(tctx, lctx);
        multiaddr_free(lctx->local);
        pthread_cond_destroy(&lctx->q.cond);
        pthread_mutex_destroy(&lctx->q.mtx);
        free(lctx);
        close(fd);
        free(l);
        return LIBP2P_TRANSPORT_ERR_CLOSED;
    }

    /* store the listener in the transport context */
    size_t new_count = tctx->n_listeners + 1;
    libp2p_listener_t **new_list = realloc(tctx->listeners, sizeof *tctx->listeners * new_count);
    if (!new_list)
    {
        /* roll back on OOM */
        pthread_mutex_unlock(&tctx->lck);
        poller_del(tctx, lctx);
        multiaddr_free(lctx->local);
        pthread_cond_destroy(&lctx->q.cond);
        pthread_mutex_destroy(&lctx->q.mtx);
        free(lctx);
        close(fd);
        free(l);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    tctx->listeners = new_list;
    tctx->listeners[tctx->n_listeners++] = l;
    pthread_mutex_unlock(&tctx->lck);

    *out = l;
    return LIBP2P_TRANSPORT_OK;
}

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
    int wpipe = atomic_exchange_explicit(&ctx->wakeup_pipe[1], -1, /* invalidate */
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

    int wpipe = atomic_load_explicit(&ctx->wakeup_pipe[1], memory_order_acquire);
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

                        int new_wpipe = atomic_load_explicit(&ctx->wakeup_pipe[1], memory_order_acquire);
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

                int new_wpipe = atomic_load_explicit(&ctx->wakeup_pipe[1], memory_order_acquire);
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
                int rfd_fallback = atomic_exchange_explicit(&ctx->wakeup_pipe[0], -1, memory_order_acq_rel);
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
                    fprintf(stderr, "libp2p-c: poll thread joined after %d second%s of extra wait\n", waited + interval,
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
                fprintf(stderr,
                        "libp2p-c: poll thread still alive; "
                        "detaching and leaking transport context to avoid use-after-free "
                        "(%s)\n",
                        strerror(rc));

                /* detach so the OS reclaims thread resources once it exits */
                (void)pthread_detach(ctx->thr);

                /* leave fds open; poll thread may still use them. Kernel will reclaim. */
                /* free transport wrapper; intentionally leak ctx for poll thread safety. */
                free(t);
                return;
            }
        }
    }
#else  /* !__linux__ */
    {
        int rc = pthread_join(ctx->thr, NULL);
        if (rc != 0)
        {
            fprintf(stderr,
                    "libp2p-c: initial pthread_join failed (%s); "
                    "waiting up to 30 s for poll thread to exit\n",
                    strerror(rc));

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
                        fprintf(stderr, "libp2p-c: poll thread joined after %d second%s of extra wait\n", waited, (waited == 1) ? "" : "s");
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
                fprintf(stderr, "libp2p-c: poll thread still alive after extended wait; "
                                "detaching and leaking transport context to avoid use-after-free\n");

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
    if (safe_mutex_lock(&ctx->lck) != 0)
    {
        fprintf(stderr, "[fatal] tcp_free: safe_mutex_lock(&ctx->lck) failed – "
                        "aborting to avoid inconsistent listener state\n");
        abort();
    }
    listeners = ctx->listeners;
    n_listeners = ctx->n_listeners;
    ctx->listeners = NULL;
    ctx->n_listeners = 0;
    if (safe_mutex_unlock(&ctx->lck) != 0)
    {
        fprintf(stderr, "[fatal] tcp_free: safe_mutex_unlock(&ctx->lck) failed – "
                        "state may be inconsistent\n");
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
    const int MAX_TOTAL_WAIT_MS = 30000; /* 30 s overall cap */
    struct timespec start_ts;
    bool have_start_ts = (clock_gettime(CLOCK_MONOTONIC, &start_ts) == 0);

    /* if we failed to obtain the start timestamp, leak immediately instead of waiting forever. */
    bool leaked_list_snapshot = !have_start_ts;
    _Atomic uint64_t spin_attempts = 0;

    while (!leaked_list_snapshot && atomic_load_explicit(&ctx->active_listener_destroyers, memory_order_acquire) != 0)
    {
        cas_backoff(&spin_attempts); /* progressive yield / sleep (≤1 ms) */

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

    if (leaked_list_snapshot && atomic_load_explicit(&ctx->active_listener_destroyers, memory_order_acquire) != 0)
    {
        fprintf(stderr,
                "libp2p-c: tcp_free waited %d ms but %zu listener destroyer(s) are still active; "
                "leaking detached listener snapshot to avoid use‑after‑free\n",
                MAX_TOTAL_WAIT_MS, (size_t)atomic_load_explicit(&ctx->active_listener_destroyers, memory_order_relaxed));
        /* intentional leak: do not free(listeners) */
    }
    else
    {
        free(listeners);
    }

    /* drain graveyard and release remaining OS resources */
    if (safe_mutex_lock(&ctx->graveyard_lck) != 0)
    {
        fprintf(stderr, "[fatal] tcp_free: safe_mutex_lock(&graveyard_lck) failed – "
                        "aborting to avoid inconsistent graveyard state\n");
        abort();
    }
    tcp_listener_ctx_t *g2 = ctx->graveyard_head;
    while (g2)
    {
        tcp_listener_ctx_t *next = g2->next_free;

        int tmpfd = atomic_exchange_explicit(&g2->fd, -1, memory_order_acq_rel);
        if (tmpfd >= 0)
        {
            shutdown(tmpfd, SHUT_RDWR);
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
            fprintf(stderr, "[fatal] pthread_cond_destroy(&g2->q.cond) failed: %s\n", strerror(rc_cd));
            abort();
        }

        int rc_md = pthread_mutex_destroy(&g2->q.mtx);
        if (rc_md != 0)
        {
            fprintf(stderr, "[fatal] pthread_mutex_destroy(&g2->q.mtx) failed: %s\n", strerror(rc_md));
            abort();
        }

        multiaddr_free(g2->local);
        free(g2);

        g2 = next;
    }
    ctx->graveyard_head = NULL;
    if (safe_mutex_unlock(&ctx->graveyard_lck) != 0)
    {
        fprintf(stderr, "[fatal] tcp_free: safe_mutex_unlock(&graveyard_lck) failed – "
                        "state may be inconsistent\n");
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

    int rfd = atomic_exchange_explicit(&ctx->wakeup_pipe[0], -1, memory_order_acq_rel);
    if (rfd >= 0)
    {
        close(rfd);
    }
    int wfd = atomic_exchange_explicit(&ctx->wakeup_pipe[1], -1, memory_order_acq_rel);
    if (wfd >= 0)
    {
        close(wfd);
    }

    /* destroy mutexes and free ctx / wrapper */
    int rc_lck = pthread_mutex_destroy(&ctx->lck);
    if (rc_lck != 0)
    {
        fprintf(stderr, "[fatal] pthread_mutex_destroy(&ctx->lck) failed: %s\n", strerror(rc_lck));
        abort();
    }

    int rc_glck = pthread_mutex_destroy(&ctx->graveyard_lck);
    if (rc_glck != 0)
    {
        fprintf(stderr, "[fatal] pthread_mutex_destroy(&ctx->graveyard_lck) failed: %s\n", strerror(rc_glck));
        abort();
    }

    free(ctx);
    free(t);
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
    int rc = pthread_mutex_init(&ctx->lck, NULL);
    if (rc != 0)
    {
        free(ctx);
        free(t);
        return NULL;
    }

    /* initialize graveyard mechanism */
    ctx->graveyard_head = NULL;
    rc = pthread_mutex_init(&ctx->graveyard_lck, NULL);
    if (rc != 0)
    {
        /* undo earlier mutex */
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }

    /* initialize poll-epoch counter */
    atomic_init(&ctx->poll_epoch, 0);
    atomic_init(&ctx->active_listener_destroyers, 0);

#if USE_EPOLL
    /* create epoll instance with CLOEXEC to prevent FD leaks across fork/exec */
    ctx->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epfd < 0)
    {
        {
            int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
            if (rc != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
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
            int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
            if (rc != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }
#endif

    /* setup self-wakeup pipe for poll loop (portable fallback for systems without pipe2) */
    if (pipe((int *)ctx->wakeup_pipe) != 0) /* cast silences _Atomic → int warning */
    {
        perror("pipe");
#if USE_EPOLL
        close(ctx->epfd);
#elif USE_KQUEUE
        close(ctx->kqfd);
#endif
        {
            int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
            if (rc != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
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
        flags = fcntl(ctx->wakeup_pipe[j], F_GETFD, 0);
        if (flags == -1 || fcntl(ctx->wakeup_pipe[j], F_SETFD, flags | FD_CLOEXEC) == -1)
        {
#if USE_EPOLL
            close(ctx->epfd);
#elif USE_KQUEUE
            close(ctx->kqfd);
#endif
            close(ctx->wakeup_pipe[0]);
            close(ctx->wakeup_pipe[1]);
            {
                int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
                if (rc != 0)
                {
                    fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
                }
            }
            {
                int rc2 = pthread_mutex_destroy(&ctx->lck);
                if (rc2 != 0)
                {
                    fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
                }
            }
            free(ctx);
            free(t);
            return NULL;
        }

        /* O_NONBLOCK */
        flags = fcntl(ctx->wakeup_pipe[j], F_GETFL, 0);
        if (flags == -1 || fcntl(ctx->wakeup_pipe[j], F_SETFL, flags | O_NONBLOCK) == -1)
        {
#if USE_EPOLL
            close(ctx->epfd);
#elif USE_KQUEUE
            close(ctx->kqfd);
#endif
            close(ctx->wakeup_pipe[0]);
            close(ctx->wakeup_pipe[1]);
            {
                int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
                if (rc != 0)
                {
                    fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
                }
            }
            {
                int rc2 = pthread_mutex_destroy(&ctx->lck);
                if (rc2 != 0)
                {
                    fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
                }
            }
            free(ctx);
            free(t);
            return NULL;
        }
    }

    /* use ctx pointer as unique wakeup marker */
    ctx->wakeup_marker = ctx;
#if USE_EPOLL
    struct epoll_event ev_wakeup = {.events = EPOLLIN, .data.ptr = ctx->wakeup_marker};
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->wakeup_pipe[0], &ev_wakeup) != 0)
    {
        close(ctx->wakeup_pipe[0]);
        close(ctx->wakeup_pipe[1]);
        close(ctx->epfd);
        {
            int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
            if (rc != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
            }
        }
        free(ctx);
        free(t);
        return NULL;
    }
#elif USE_KQUEUE
    struct kevent kev_wakeup;
    EV_SET(&kev_wakeup, ctx->wakeup_pipe[0], EVFILT_READ, EV_ADD, 0, 0, ctx->wakeup_marker);
    if (kevent(ctx->kqfd, &kev_wakeup, 1, NULL, 0, NULL) < 0)
    {
        close(ctx->wakeup_pipe[0]);
        close(ctx->wakeup_pipe[1]);
        close(ctx->kqfd);
        {
            int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
            if (rc != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
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
        close(ctx->wakeup_pipe[0]);
        close(ctx->wakeup_pipe[1]);
        {
            int rc = pthread_mutex_destroy(&ctx->graveyard_lck);
            if (rc != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy graveyard mutex: %s\n", strerror(rc));
            }
        }
        {
            int rc2 = pthread_mutex_destroy(&ctx->lck);
            if (rc2 != 0)
            {
                fprintf(stderr, "libp2p-c: warning: failed to destroy transport mutex: %s\n", strerror(rc2));
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