#ifndef PROTOCOL_TCP_QUEUE_H
#define PROTOCOL_TCP_QUEUE_H
/**
 * @file protocol_tcp_queue.h
 * @brief Minimal MPSC queue for accepted connections.
 *
 * The implementation lives in protocol_tcp_queue.c.
 *
 * Thread model:
 *   - any thread may push (typically the poll-loop)
 *   - one thread (the listener's accept()) pops
 */
#include "transport/connection.h"
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief Node and queue types used by the accept queue. */
/**
 * @struct conn_node
 * @brief Node in the connection queue.
 */
typedef struct conn_node
{
    libp2p_conn_t *c;       /**< The queued connection. */
    struct conn_node *next; /**< Next node in the queue. */
    uint64_t accepted_at_ms; /**< Monotonic timestamp when accepted/enqueued. */
} conn_node_t;

/**
 * @struct conn_queue
 * @brief Minimal queue structure for TCP connections.
 */
typedef struct
{
    conn_node_t *head;   /**< Front of the queue.    */
    conn_node_t *tail;   /**< Tail of the queue.     */
    pthread_mutex_t mtx; /**< Mutex protecting state.*/
    pthread_cond_t cond; /**< Waker for pop waits.   */
    atomic_size_t len;   /**< Current length.        */
} conn_queue_t;

/** @brief Queue API. */
/**
 * @brief Initialize a connection queue.
 *
 * Sets up the mutex and condition variable and resets the queue state.
 *
 * @param q Pointer to the queue to initialize.
 */
void cq_init(conn_queue_t *q);

/**
 * @brief Enqueue a connection onto the queue.
 *
 * Can safely be called from multiple threads.
 *
 * @param q Queue to push onto.
 * @param c Connection to enqueue.
 */
void cq_push(conn_queue_t *q, libp2p_conn_t *c);

/**
 * @brief Pop a connection from the queue.
 *
 * Thread-safe; returns NULL if the queue is empty.
 *
 * @param q Queue to pop from.
 * @return The connection or NULL when empty.
 */
libp2p_conn_t *cq_pop(conn_queue_t *q);

/**
 * @brief Get the current queue length.
 *
 * Lock-free accessor that may be called concurrently with pushes and pops.
 *
 * @param q Queue to inspect.
 * @return Number of enqueued connections.
 */
size_t cq_length(conn_queue_t *q);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_TCP_QUEUE_H */
