#ifndef PROTOCOL_YAMUX_QUEUE_H
#define PROTOCOL_YAMUX_QUEUE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

/**
 * @file protocol_yamux_queue.h
 * @brief Thread-safe queue for yamux stream handles.
 */

struct libp2p_yamux_stream;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Node in the stream queue.
 */
typedef struct yamux_stream_node
{
    struct libp2p_yamux_stream *s;  /**< Stored stream. */
    struct yamux_stream_node *next; /**< Next node.     */
} yamux_stream_node_t;

/**
 * @brief FIFO queue of streams.
 */
typedef struct
{
    yamux_stream_node_t *head; /**< Front of the queue.  */
    yamux_stream_node_t *tail; /**< Back of the queue.   */
    pthread_mutex_t mtx;       /**< Mutex protecting q.  */
    pthread_cond_t cond;       /**< Signaled on new item.*/
    atomic_size_t len;         /**< Number of elements.  */
} yamux_stream_queue_t;

/**
 * @brief Initialize the stream queue.
 *
 * @param q      The queue to initialize.
 */
void yq_init(yamux_stream_queue_t *q);

/**
 * @brief Push a new stream onto the queue.
 *
 * @param q      The queue to push onto.
 * @param s      The stream to push.
 */
void yq_push(yamux_stream_queue_t *q, struct libp2p_yamux_stream *s);

/**
 * @brief Pop the next stream from the queue.
 *
 * @param q      The queue to pop from.
 * @return       The next stream in the queue or NULL if the queue is empty.
 */
struct libp2p_yamux_stream *yq_pop(yamux_stream_queue_t *q);

/**
 * @brief Get the length of the queue.
 *
 * @param q      The queue to query.
 * @return       The number of elements in the queue.
 */
size_t yq_length(yamux_stream_queue_t *q);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_YAMUX_QUEUE_H */
