#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

#include "protocol/tcp/protocol_tcp_queue.h"
#include "protocol/tcp/protocol_tcp_util.h" /* now_mono_ms */

/**
 * @brief Initialize a connection queue.
 *
 * Initializes the mutex and condition variable for the queue,
 * and sets the head and tail pointers to NULL.
 *
 * @param q Pointer to the connection queue to initialize.
 */
void cq_init(conn_queue_t *q)
{
    if (pthread_mutex_init(&q->mtx, NULL) != 0)
    {
        abort();
    }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0)
    {
        pthread_mutex_destroy(&q->mtx);
        abort();
    }
#if defined(_POSIX_MONOTONIC_CLOCK) && !defined(__APPLE__)
    {
        int rc_clock = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        /* On some platforms (e.g. Windows pthreads-w32) this call returns
           EINVAL / ENOTSUP because CLOCK_MONOTONIC is not supported.  That
           is perfectly fine – fall back to the default CLOCK_REALTIME */
        if (rc_clock != 0 && rc_clock != EINVAL && rc_clock != ENOTSUP)
        {
            /* Any other error (e.g. EPERM) really is unexpected. */
            pthread_condattr_destroy(&attr);
            pthread_mutex_destroy(&q->mtx);
            abort();
        }
    }
#endif
    if (pthread_cond_init(&q->cond, &attr) != 0)
    {
        pthread_condattr_destroy(&attr);
        pthread_mutex_destroy(&q->mtx);
        abort();
    }
    pthread_condattr_destroy(&attr);
    q->head = q->tail = NULL;
    atomic_init(&q->len, 0);
}

/**
 * @brief Push a connection onto the queue.
 *
 * Allocates a new node for the given connection and appends it to the tail of the queue.
 * If allocation fails, the connection is freed.
 * Signals the condition variable to notify any waiting threads.
 *
 * @param q Pointer to the connection queue.
 * @param c Pointer to the connection to enqueue.
 */
void cq_push(conn_queue_t *q, libp2p_conn_t *c)
{
    conn_node_t *n = (conn_node_t *)malloc(sizeof *n);
    if (!n)
    {
        libp2p_conn_free(c);
        return;
    }
    n->c = c;
    n->next = NULL;
    n->accepted_at_ms = now_mono_ms();

    pthread_mutex_lock(&q->mtx);

    if (q->tail)
    {
        q->tail->next = n;
        q->tail = n;
    }
    else
    {
        q->head = q->tail = n;
    }

    atomic_fetch_add_explicit(&q->len, 1, memory_order_relaxed);
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mtx);
}

/**
 * @brief Pop a connection from the queue.
 *
 * Removes and returns the connection at the head of the queue.
 * If the queue is empty, returns NULL.
 *
 * @param q Pointer to the connection queue.
 * @return Pointer to the popped connection, or NULL if the queue is empty.
 */
libp2p_conn_t *cq_pop(conn_queue_t *q)
{
    pthread_mutex_lock(&q->mtx);

    conn_node_t *n = q->head;
    if (!n)
    {
        pthread_mutex_unlock(&q->mtx);
        return NULL;
    }
    q->head = n->next;
    if (!q->head)
        q->tail = NULL;
    atomic_fetch_sub_explicit(&q->len, 1, memory_order_relaxed);
    pthread_mutex_unlock(&q->mtx);

    libp2p_conn_t *c = n->c;
    free(n);
    return c;
}

/**
 * @brief Return the current queue length.
 *
 * Lock‑free, relaxed‑ordering accessor suitable for statistics
 * and back‑pressure checks.
 */
size_t cq_length(conn_queue_t *q) { return atomic_load_explicit(&q->len, memory_order_relaxed); }
