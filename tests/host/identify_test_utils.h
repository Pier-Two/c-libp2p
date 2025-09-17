#ifndef IDENTIFY_TEST_UTILS_H
#define IDENTIFY_TEST_UTILS_H

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p/events.h"
#include "libp2p/host.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int done;
    const peer_id_t *expected;
    libp2p_subscription_t *sub;
    const char *log_prefix;
    char **protocols;
    size_t num_protocols;
} protocols_update_waiter_t;

static void protocols_update_waiter_free_list(char **list, size_t count)
{
    if (!list)
        return;
    for (size_t i = 0; i < count; i++)
        free(list[i]);
    free(list);
}

static void protocols_update_waiter_clear_locked(protocols_update_waiter_t *w)
{
    if (!w)
        return;
    protocols_update_waiter_free_list(w->protocols, w->num_protocols);
    w->protocols = NULL;
    w->num_protocols = 0;
}

static void protocols_update_cb(const libp2p_event_t *evt, void *ud)
{
    protocols_update_waiter_t *w = (protocols_update_waiter_t *)ud;
    if (!w || !evt || evt->kind != LIBP2P_EVT_PEER_PROTOCOLS_UPDATED)
        return;
    if (w->expected)
    {
        const peer_id_t *peer = evt->u.peer_protocols_updated.peer;
        if (!peer || peer_id_equals(peer, w->expected) != 1)
            return;
    }

    char **copy = NULL;
    size_t copy_len = 0;
    if (evt->u.peer_protocols_updated.protocols && evt->u.peer_protocols_updated.num_protocols > 0)
    {
        copy = (char **)calloc(evt->u.peer_protocols_updated.num_protocols, sizeof(*copy));
        if (copy)
        {
            for (size_t i = 0; i < evt->u.peer_protocols_updated.num_protocols; i++)
            {
                const char *p = evt->u.peer_protocols_updated.protocols[i];
                if (!p)
                    continue;
                char *dup = strdup(p);
                if (!dup)
                {
                    protocols_update_waiter_free_list(copy, copy_len);
                    copy = NULL;
                    copy_len = 0;
                    break;
                }
                copy[copy_len++] = dup;
            }
            if (copy && copy_len == 0)
            {
                free(copy);
                copy = NULL;
            }
        }
    }

    if (w->log_prefix)
        fprintf(stderr, "%s observed protocols update event\n", w->log_prefix);

    int stored = 0;
    pthread_mutex_lock(&w->mtx);
    if (!w->done)
    {
        protocols_update_waiter_clear_locked(w);
        w->protocols = copy;
        w->num_protocols = copy_len;
        w->done = 1;
        pthread_cond_signal(&w->cv);
        stored = 1;
    }
    pthread_mutex_unlock(&w->mtx);

    if (!stored)
        protocols_update_waiter_free_list(copy, copy_len);
}

static int protocols_update_waiter_start(protocols_update_waiter_t *w,
                                         libp2p_host_t *h,
                                         const peer_id_t *expected,
                                         const char *log_prefix)
{
    if (!w || !h)
        return 0;
    memset(w, 0, sizeof(*w));
    w->expected = expected;
    w->log_prefix = log_prefix;
    if (pthread_mutex_init(&w->mtx, NULL) != 0)
        return 0;
    if (pthread_cond_init(&w->cv, NULL) != 0)
    {
        pthread_mutex_destroy(&w->mtx);
        return 0;
    }
    if (libp2p_event_subscribe(h, protocols_update_cb, w, &w->sub) != 0)
    {
        pthread_cond_destroy(&w->cv);
        pthread_mutex_destroy(&w->mtx);
        w->sub = NULL;
        return 0;
    }
    return 1;
}

static int protocols_update_waiter_wait(protocols_update_waiter_t *w, int timeout_ms)
{
    if (!w || timeout_ms < 0)
        return 0;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L)
    {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&w->mtx);
    int rc = 0;
    while (!w->done && rc == 0)
    {
        rc = pthread_cond_timedwait(&w->cv, &w->mtx, &ts);
        if (rc == ETIMEDOUT)
            break;
    }
    int success = w->done;
    pthread_mutex_unlock(&w->mtx);
    return success;
}

static void protocols_update_waiter_stop(protocols_update_waiter_t *w, libp2p_host_t *h)
{
    if (!w)
        return;
    if (h && w->sub)
        libp2p_event_unsubscribe(h, w->sub);
    pthread_cond_destroy(&w->cv);
    pthread_mutex_destroy(&w->mtx);
    protocols_update_waiter_free_list(w->protocols, w->num_protocols);
    w->protocols = NULL;
    w->num_protocols = 0;
    w->sub = NULL;
    w->expected = NULL;
    w->log_prefix = NULL;
    w->done = 0;
}

#ifdef __cplusplus
}
#endif

#endif /* IDENTIFY_TEST_UTILS_H */
