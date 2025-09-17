#include <pthread.h>
#include <stdlib.h>

#include "host_internal.h"

typedef struct cb_task_node
{
    libp2p_cbexec_fn fn;
    void *ud;
    struct cb_task_node *next;
} cb_task_node_t;

static void *cbexec_thread(void *arg)
{
    libp2p_host_t *host = (libp2p_host_t *)arg;
    if (!host)
        return NULL;
    for (;;)
    {
        pthread_mutex_lock(&host->mtx);
        while (!host->cb_stop && host->cb_head == NULL)
        {
            pthread_cond_wait(&host->cb_cv, &host->mtx);
        }
        if (host->cb_stop && host->cb_head == NULL)
        {
            pthread_mutex_unlock(&host->mtx);
            break;
        }
        cb_task_node_t *node = (cb_task_node_t *)host->cb_head;
        if (node)
        {
            host->cb_head = node->next;
            if (!host->cb_head)
                host->cb_tail = NULL;
        }
        pthread_mutex_unlock(&host->mtx);

        if (!node)
            continue;
        if (node->fn)
            node->fn(node->ud);
        free(node);
    }
    return NULL;
}

int libp2p__cbexec_start(libp2p_host_t *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&host->mtx);
    host->cb_stop = 0;
    host->cb_head = host->cb_tail = NULL;
    pthread_mutex_unlock(&host->mtx);
    if (pthread_cond_init(&host->cb_cv, NULL) != 0)
        return LIBP2P_ERR_INTERNAL;
    if (pthread_create(&host->cb_thread, NULL, cbexec_thread, host) != 0)
    {
        pthread_cond_destroy(&host->cb_cv);
        return LIBP2P_ERR_INTERNAL;
    }
    host->cb_thread_started = 1;
    return 0;
}

void libp2p__cbexec_stop(libp2p_host_t *host)
{
    if (!host)
        return;
    pthread_mutex_lock(&host->mtx);
    host->cb_stop = 1;
    pthread_cond_broadcast(&host->cb_cv);
    pthread_mutex_unlock(&host->mtx);
    if (host->cb_thread_started)
    {
        pthread_join(host->cb_thread, NULL);
        host->cb_thread_started = 0;
    }
    /* Drain any remaining tasks without executing user callbacks during teardown */
    cb_task_node_t *node = NULL;
    pthread_mutex_lock(&host->mtx);
    node = (cb_task_node_t *)host->cb_head;
    host->cb_head = host->cb_tail = NULL;
    pthread_mutex_unlock(&host->mtx);
    while (node)
    {
        cb_task_node_t *next = node->next;
        free(node);
        node = next;
    }
    pthread_cond_destroy(&host->cb_cv);
}

void libp2p__exec_on_cb_thread(libp2p_host_t *host, libp2p_cbexec_fn fn, void *user_data)
{
    if (!host || !fn)
        return;
    cb_task_node_t *node = (cb_task_node_t *)calloc(1, sizeof(*node));
    if (!node)
        return;
    node->fn = fn;
    node->ud = user_data;
    node->next = NULL;
    pthread_mutex_lock(&host->mtx);
    if (host->cb_tail)
    {
        host->cb_tail->next = node;
        host->cb_tail = node;
    }
    else
    {
        host->cb_head = host->cb_tail = node;
    }
    pthread_cond_broadcast(&host->cb_cv);
    pthread_mutex_unlock(&host->mtx);
}

