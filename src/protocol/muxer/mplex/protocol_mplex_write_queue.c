#include "protocol_mplex_write_queue.h"
#include "protocol_mplex_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int libp2p_mplex_write_queue_init(libp2p_mplex_write_queue_t *queue)
{
    if (!queue)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    memset(queue, 0, sizeof(*queue));
    if (pthread_mutex_init(&queue->mutex, NULL) != 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    return LIBP2P_MPLEX_OK;
}

void libp2p_mplex_write_queue_destroy(libp2p_mplex_write_queue_t *queue)
{
    if (!queue)
        return;

    // Free all pending frames
    libp2p_mplex_write_queue_node_t *node = queue->head;
    int node_count = 0;
    while (node)
    {
        libp2p_mplex_write_queue_node_t *next = node->next;
        libp2p_mplex_frame_free(&node->frame);
        free(node);
        node = next;
    }

    pthread_mutex_destroy(&queue->mutex);
    memset(queue, 0, sizeof(*queue));
}

int libp2p_mplex_write_queue_push(libp2p_mplex_write_queue_t *queue, const libp2p_mplex_frame_t *frame)
{
    if (!queue || !frame)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    libp2p_mplex_write_queue_node_t *node = malloc(sizeof(*node));
    if (!node)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    // Copy the frame
    node->frame.id = frame->id;
    node->frame.flag = frame->flag;
    node->frame.data_len = frame->data_len;

    if (frame->data_len > 0)
    {
        node->frame.data = malloc(frame->data_len);
        if (!node->frame.data)
        {
            free(node);
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }
        memcpy(node->frame.data, frame->data, frame->data_len);
    }
    else
    {
        node->frame.data = NULL;
    }

    node->next = NULL;

    pthread_mutex_lock(&queue->mutex);

    if (queue->tail)
    {
        queue->tail->next = node;
    }
    else
    {
        queue->head = node;
    }
    queue->tail = node;
    queue->length++;

    pthread_mutex_unlock(&queue->mutex);

    return LIBP2P_MPLEX_OK;
}

libp2p_mplex_frame_t *libp2p_mplex_write_queue_pop(libp2p_mplex_write_queue_t *queue)
{
    if (!queue)
        return NULL;

    pthread_mutex_lock(&queue->mutex);

    if (!queue->head)
    {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    libp2p_mplex_write_queue_node_t *node = queue->head;
    queue->head = node->next;

    if (!queue->head)
    {
        queue->tail = NULL;
    }

    queue->length--;

    pthread_mutex_unlock(&queue->mutex);

    libp2p_mplex_frame_t *frame = malloc(sizeof(*frame));
    if (!frame)
    {
        // Put the node back in the queue
        pthread_mutex_lock(&queue->mutex);
        node->next = queue->head;
        queue->head = node;
        if (!queue->tail)
        {
            queue->tail = node;
        }
        queue->length++;
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    *frame = node->frame;
    free(node);

    return frame;
}
