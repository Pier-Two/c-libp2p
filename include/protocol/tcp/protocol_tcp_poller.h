#ifndef PROTOCOL_TCP_POLLER_H
#define PROTOCOL_TCP_POLLER_H
/**
 * @file protocol_tcp_poller.h
 * @brief epoll/kqueue accept-loop helpers and transport context types.
 */

#include <pthread.h>   /* pthread_t / mutex           */
#include <stdatomic.h> /* atomic_*                    */
#include <stddef.h>    /* size_t                      */
#include <stdint.h>    /* uintptr_t                   */
#include <time.h>      /* clockid_t                   */

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"       /* libp2p_tcp_config_t   */
#include "protocol/tcp/protocol_tcp_queue.h" /* conn_queue_t          */
#include "transport/listener.h"              /* libp2p_listener_t     */
#include "libp2p/metrics.h"                  /* libp2p_metrics_t      */

/* Forward‐declare the listener typedef so we can use it below */
typedef struct tcp_listener tcp_listener_ctx_t;

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(_WIN32)
/* Windows: neither kqueue nor epoll is available – rely on WSAPoll() instead */
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define USE_KQUEUE 1
#else
#define USE_EPOLL 1
#endif
#endif

/** @brief Transport-wide context. */
struct tcp_transport_ctx
{
    libp2p_tcp_config_t cfg;
    atomic_bool closed;

#if defined(USE_EPOLL)
    int epfd;
#elif defined(USE_KQUEUE)
    int kqfd;
#endif

    pthread_t thr;

    struct
    {
        pthread_mutex_t lock;
        libp2p_listener_t **list;
        size_t count;
    } listeners;

    struct
    {
        pthread_mutex_t lock;
        tcp_listener_ctx_t *head;
        _Atomic uint64_t poll_epoch;
        _Atomic bool compact_pending;     /* pending listener‑array compaction */
        _Atomic size_t active_destroyers; /* per-transport destroyer counter */
    } gc;

    struct
    {
        void *marker;        /* unique marker for wakeup events */
        _Atomic int pipe[2]; /* [0]: read end, [1]: write end */
    } wakeup;

    /* Optional metrics sink (provided by host, may be NULL) */
    libp2p_metrics_t *metrics;
};

typedef struct tcp_transport_ctx tcp_transport_ctx_t;

/** @brief Per-listener context. */
struct tcp_listener
{
    _Atomic int fd; /* atomic ⇒ close/read race‑free */
    multiaddr_t *local;
    atomic_bool closed;
    _Atomic size_t refcount;
    conn_queue_t q;
    struct tcp_transport_ctx *transport_ctx;

    struct
    {
        _Atomic bool pending_free;
        struct tcp_listener *next_free;
        _Atomic size_t free_epoch;
    } gc;

    struct
    {
        _Atomic bool disabled;     /* true  ⇒ not in poll-set   */
        uint64_t enable_at_ms;     /* wall-clock when to re-add */
        uint32_t backoff_ms;       /* next delay (100 → 200 …)  */
        uint32_t poll_ms;          /* accept() poll period in ms */
        uint32_t close_timeout_ms; /* listener close timeout in ms */
        clockid_t cond_clock;      /* Clock used with pthread_cond_timedwait in accept() */
        _Atomic size_t waiters;    /* number of threads currently blocked */
    } state;
};

/**
 * @brief Register a listener with the poller.
 *
 * @param transport_ctx Transport context to use.
 * @param listener_ctx  Listener to add to the poll set.
 * @return 0 on success, -1 on error.
 */
int poller_add(tcp_transport_ctx_t *transport_ctx, tcp_listener_ctx_t *listener_ctx);

/**
 * @brief Remove a listener from the poller.
 *
 * @param transport_ctx Transport context used to manage the listener.
 * @param listener_ctx  Listener to remove.
 */
void poller_del(tcp_transport_ctx_t *transport_ctx, tcp_listener_ctx_t *listener_ctx);

/**
 * @brief Thread entry point for the poll loop.
 *
 * @param arg Pointer to the transport context.
 * @return NULL on exit.
 */
void *poll_loop(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_TCP_POLLER_H */
