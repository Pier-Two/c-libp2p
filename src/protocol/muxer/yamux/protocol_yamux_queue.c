#include "protocol/muxer/yamux/protocol_yamux_queue.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include <stdlib.h>

void yq_init(yamux_stream_queue_t *q)
{
    pthread_mutex_init(&q->mtx, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#if defined(_POSIX_MONOTONIC_CLOCK) && !defined(__APPLE__)
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&q->cond, &attr);
    pthread_condattr_destroy(&attr);
    q->head = q->tail = NULL;
    atomic_init(&q->len, 0);
}

void yq_push(yamux_stream_queue_t *q, struct libp2p_yamux_stream *s)
{
    yamux_stream_node_t *n = malloc(sizeof(*n));
    if (!n)
        return;
    n->s = s;
    n->next = NULL;
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

struct libp2p_yamux_stream *yq_pop(yamux_stream_queue_t *q)
{
    pthread_mutex_lock(&q->mtx);
    yamux_stream_node_t *n = q->head;
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
    struct libp2p_yamux_stream *s = n->s;
    free(n);
    return s;
}

size_t yq_length(yamux_stream_queue_t *q) { return atomic_load_explicit(&q->len, memory_order_relaxed); }
