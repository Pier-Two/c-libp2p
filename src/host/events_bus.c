#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "host_internal.h"
#include "libp2p/metrics.h"

/* subscription struct is defined in host_internal.h */

/* Forward declaration for monotonic clock helper defined below */
static uint64_t monotonic_ms(void);

/* Forward declaration for realtime helper defined near file end */
static void timespec_realtime_after_ms(struct timespec *ts, int timeout_ms);

/* Forward decl for clone used by deep copy */
static peer_id_t *peer_id__clone(const peer_id_t *in);

/* Deep-copy helper for event payloads used by queues */
static void event_deep_copy(libp2p_event_t *dst, const libp2p_event_t *src);
static void event_deep_copy(libp2p_event_t *dst, const libp2p_event_t *src)
{
    if (!dst || !src)
        return;
    *dst = *src; /* start with shallow copy, then duplicate dynamic fields */
    switch (src->kind)
    {
        case LIBP2P_EVT_LISTEN_ADDR_ADDED:
        case LIBP2P_EVT_EXPIRED_LISTEN_ADDR:
            if (src->u.listen_addr_added.addr)
                dst->u.listen_addr_added.addr = strdup(src->u.listen_addr_added.addr);
            break;
        case LIBP2P_EVT_LISTENER_CLOSED:
            if (src->u.listener_closed.addr)
                dst->u.listener_closed.addr = strdup(src->u.listener_closed.addr);
            break;
        case LIBP2P_EVT_LISTENER_ERROR:
            if (src->u.listener_error.addr)
                dst->u.listener_error.addr = strdup(src->u.listener_error.addr);
            if (src->u.listener_error.msg)
                dst->u.listener_error.msg = strdup(src->u.listener_error.msg);
            break;
        case LIBP2P_EVT_DIALING:
            if (src->u.dialing.peer)
                dst->u.dialing.peer = peer_id__clone(src->u.dialing.peer);
            if (src->u.dialing.addr)
                dst->u.dialing.addr = strdup(src->u.dialing.addr);
            break;
        case LIBP2P_EVT_OUTGOING_CONNECTION_ERROR:
        case LIBP2P_EVT_INCOMING_CONNECTION_ERROR:
            if (src->u.outgoing_conn_error.peer)
                dst->u.outgoing_conn_error.peer = peer_id__clone(src->u.outgoing_conn_error.peer);
            if (src->u.outgoing_conn_error.msg)
                dst->u.outgoing_conn_error.msg = strdup(src->u.outgoing_conn_error.msg);
            break;
        case LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE:
        case LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED:
        case LIBP2P_EVT_EXTERNAL_ADDR_EXPIRED:
            if (src->u.new_external_addr_candidate.addr)
                dst->u.new_external_addr_candidate.addr = strdup(src->u.new_external_addr_candidate.addr);
            break;
        case LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER:
            if (src->u.new_external_addr_of_peer.peer)
                dst->u.new_external_addr_of_peer.peer = peer_id__clone(src->u.new_external_addr_of_peer.peer);
            if (src->u.new_external_addr_of_peer.addr)
                dst->u.new_external_addr_of_peer.addr = strdup(src->u.new_external_addr_of_peer.addr);
            break;
        case LIBP2P_EVT_PEER_PROTOCOLS_UPDATED:
            if (src->u.peer_protocols_updated.peer)
                dst->u.peer_protocols_updated.peer = peer_id__clone(src->u.peer_protocols_updated.peer);
            dst->u.peer_protocols_updated.num_protocols = src->u.peer_protocols_updated.num_protocols;
            if (src->u.peer_protocols_updated.protocols && src->u.peer_protocols_updated.num_protocols > 0)
            {
                const char **arr = (const char **)calloc(src->u.peer_protocols_updated.num_protocols, sizeof(*arr));
                if (!arr)
                {
                    dst->u.peer_protocols_updated.protocols = NULL;
                    dst->u.peer_protocols_updated.num_protocols = 0;
                }
                else
                {
                    size_t copied = 0;
                    for (size_t i = 0; i < src->u.peer_protocols_updated.num_protocols; i++)
                    {
                        const char *p = src->u.peer_protocols_updated.protocols[i];
                        if (!p)
                            continue;
                        char *dup = strdup(p);
                        if (!dup)
                        {
                            for (size_t j = 0; j < copied; j++)
                                free((void *)arr[j]);
                            free((void *)arr);
                            arr = NULL;
                            copied = 0;
                            break;
                        }
                        arr[copied++] = dup;
                    }
                    if (!arr)
                    {
                        dst->u.peer_protocols_updated.num_protocols = 0;
                        dst->u.peer_protocols_updated.protocols = NULL;
                    }
                    else
                    {
                        dst->u.peer_protocols_updated.protocols = arr;
                        dst->u.peer_protocols_updated.num_protocols = copied;
                    }
                }
            }
            else
            {
                dst->u.peer_protocols_updated.protocols = NULL;
            }
            break;
        case LIBP2P_EVT_CONN_OPENED:
            if (src->u.conn_opened.peer)
                dst->u.conn_opened.peer = peer_id__clone(src->u.conn_opened.peer);
            if (src->u.conn_opened.addr)
                dst->u.conn_opened.addr = strdup(src->u.conn_opened.addr);
            break;
        case LIBP2P_EVT_CONN_CLOSED:
            if (src->u.conn_closed.peer)
                dst->u.conn_closed.peer = peer_id__clone(src->u.conn_closed.peer);
            break;
        case LIBP2P_EVT_PROTOCOL_NEGOTIATED:
            if (src->u.protocol_negotiated.protocol_id)
                dst->u.protocol_negotiated.protocol_id = strdup(src->u.protocol_negotiated.protocol_id);
            break;
        case LIBP2P_EVT_STREAM_OPENED:
            if (src->u.stream_opened.peer)
                dst->u.stream_opened.peer = peer_id__clone(src->u.stream_opened.peer);
            if (src->u.stream_opened.protocol_id)
                dst->u.stream_opened.protocol_id = strdup(src->u.stream_opened.protocol_id);
            break;
        case LIBP2P_EVT_ERROR:
            if (src->u.error.msg)
                dst->u.error.msg = strdup(src->u.error.msg);
            break;
        default:
            break;
    }
}

/* Forward decl was above; definition follows */

/* Enqueue an event for async subscriber dispatch with backpressure. */
static void enqueue_dispatch_event(struct libp2p_host *host, const libp2p_event_t *evt)
{
    if (!host || !evt)
        return;
    dispatch_node_t *dn = (dispatch_node_t *)calloc(1, sizeof(*dn));
    if (!dn)
        return;
    event_deep_copy(&dn->evt, evt);
    dn->next = NULL;

    pthread_mutex_lock(&host->mtx);
    /* Backpressure: block when queue is full until dispatcher makes space,
     * except during teardown where we must never block shutdown paths. */
    uint64_t wait_start_ms = 0;
    int reported_backpressure = 0;
    while (!host->tearing_down && !host->disp_stop && host->disp_len >= host->disp_max)
    {
        if (!reported_backpressure && host->metrics)
        {
            libp2p_metrics_inc_counter(host->metrics, "libp2p_dispatch_backpressure", "{}", 1.0);
            wait_start_ms = monotonic_ms();
            reported_backpressure = 1;
        }
#ifdef __APPLE__
        struct timespec rel = { .tv_sec = 0, .tv_nsec = 5 * 1000000L };
        (void)pthread_cond_timedwait_relative_np(&host->disp_cv, &host->mtx, &rel);
#else
        struct timespec ts;
        timespec_realtime_after_ms(&ts, 5);
        (void)pthread_cond_timedwait(&host->disp_cv, &host->mtx, &ts);
#endif
    }
    if (host->disp_tail)
    {
        host->disp_tail->next = dn;
        host->disp_tail = dn;
    }
    else
    {
        host->disp_head = host->disp_tail = dn;
    }
    host->disp_len++;
    /* Metrics: observe dispatch queue depth and any backpressure wait time */
    if (host->metrics)
    {
        libp2p_metrics_observe_histogram(host->metrics, "libp2p_dispatch_queue_depth", "{}", (double)host->disp_len);
        if (reported_backpressure)
        {
            uint64_t now_ms = monotonic_ms();
            if (now_ms >= wait_start_ms && wait_start_ms != 0)
            {
                libp2p_metrics_observe_histogram(host->metrics, "libp2p_dispatch_backpressure_wait_ms", "{}", (double)(now_ms - wait_start_ms));
            }
        }
    }
    pthread_cond_broadcast(&host->disp_cv);
    pthread_mutex_unlock(&host->mtx);
}

void libp2p_event_publish(struct libp2p_host *host, const libp2p_event_t *evt)
{
    if (!host || !evt)
        return;
    /* Always enqueue for pull-based consumers first */
    libp2p__enqueue_event(host, evt);
    /* Then enqueue for async subscriber dispatch */
    enqueue_dispatch_event(host, evt);
}

static peer_id_t *peer_id__clone(const peer_id_t *in)
{
    if (!in)
        return NULL;
    peer_id_t *copy = (peer_id_t *)calloc(1, sizeof(*copy));
    if (!copy)
        return NULL;
    if (in->size && in->bytes)
    {
        copy->bytes = (uint8_t *)malloc(in->size);
        if (!copy->bytes)
        {
            free(copy);
            return NULL;
        }
        memcpy(copy->bytes, in->bytes, in->size);
        copy->size = in->size;
    }
    return copy;
}

void libp2p__enqueue_event(struct libp2p_host *host, const libp2p_event_t *evt)
{
    if (!host || !evt)
        return;
    /* Metrics: emit basic counters based on event kind */
    if (host->metrics)
    {
        switch (evt->kind)
        {
            case LIBP2P_EVT_CONN_OPENED:
            {
                const char *dir = evt->u.conn_opened.inbound ? "inbound" : "outbound";
                char labels[128];
                int l = snprintf(labels, sizeof(labels), "{\"direction\":\"%s\"}", dir);
                (void)l;
                libp2p_metrics_inc_counter(host->metrics, "libp2p_conn_opened", labels, 1.0);
                break;
            }
            case LIBP2P_EVT_CONN_CLOSED:
            {
                libp2p_metrics_inc_counter(host->metrics, "libp2p_conn_closed", "{}", 1.0);
                break;
            }
            case LIBP2P_EVT_STREAM_OPENED:
            {
                const char *pid = evt->u.stream_opened.protocol_id ? evt->u.stream_opened.protocol_id : "unknown";
                const char *role = evt->u.stream_opened.initiator ? "initiator" : "responder";
                char labels[256];
                int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\",\"role\":\"%s\"}", pid, role);
                (void)l;
                libp2p_metrics_inc_counter(host->metrics, "libp2p_stream_opened", labels, 1.0);
                break;
            }
            case LIBP2P_EVT_STREAM_CLOSED:
            {
                libp2p_metrics_inc_counter(host->metrics, "libp2p_stream_closed", "{}", 1.0);
                break;
            }
            case LIBP2P_EVT_PROTOCOL_NEGOTIATED:
            {
                const char *pid = evt->u.protocol_negotiated.protocol_id ? evt->u.protocol_negotiated.protocol_id : "unknown";
                char labels[256];
                int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\"}", pid);
                (void)l;
                libp2p_metrics_inc_counter(host->metrics, "libp2p_protocol_negotiated", labels, 1.0);
                break;
            }
            case LIBP2P_EVT_DIALING:
            {
                libp2p_metrics_inc_counter(host->metrics, "libp2p_dial_attempt", "{}", 1.0);
                break;
            }
            case LIBP2P_EVT_OUTGOING_CONNECTION_ERROR:
            {
                libp2p_metrics_inc_counter(host->metrics, "libp2p_conn_error", "{\"direction\":\"outbound\"}", 1.0);
                break;
            }
            case LIBP2P_EVT_INCOMING_CONNECTION_ERROR:
            {
                libp2p_metrics_inc_counter(host->metrics, "libp2p_conn_error", "{\"direction\":\"inbound\"}", 1.0);
                break;
            }
            default:
                break;
        }
    }
    event_node_t *node = (event_node_t *)calloc(1, sizeof(*node));
    if (!node)
        return;
    /* Deep copy of event where needed for strings used by pull API */
    event_deep_copy(&node->evt, evt);
    node->next = NULL;

    pthread_mutex_lock(&host->mtx);
    if (host->evt_tail)
    {
        host->evt_tail->next = node;
        host->evt_tail = node;
    }
    else
    {
        host->evt_head = host->evt_tail = node;
    }
    pthread_cond_broadcast(&host->evt_cv);
    pthread_mutex_unlock(&host->mtx);
}

/* Dispatcher thread: pops dispatch queue FIFO and calls subscribers asynchronously. */
static void *event_dispatch_thread(void *arg)
{
    libp2p_host_t *host = (libp2p_host_t *)arg;
    if (!host)
        return NULL;
    for (;;)
    {
        pthread_mutex_lock(&host->mtx);
        while (!host->disp_stop && host->disp_head == NULL)
        {
            pthread_cond_wait(&host->disp_cv, &host->mtx);
        }
        if (host->disp_stop && host->disp_head == NULL)
        {
            pthread_mutex_unlock(&host->mtx);
            break;
        }
        dispatch_node_t *dn = host->disp_head;
        if (dn)
        {
            host->disp_head = dn->next;
            if (!host->disp_head)
                host->disp_tail = NULL;
            if (host->disp_len > 0)
                host->disp_len--;
        }
        /* signal any blocked publishers (backpressure) */
        pthread_cond_broadcast(&host->disp_cv);
        pthread_mutex_unlock(&host->mtx);

        if (!dn)
            continue;

        /* Snapshot callbacks under lock */
        size_t count = 0;
        pthread_mutex_lock(&host->mtx);
        for (libp2p_subscription_t *it = host->subs; it; it = it->next)
            if (it->cb)
                count++;
        libp2p_event_cb *cbs = count ? (libp2p_event_cb *)calloc(count, sizeof(*cbs)) : NULL;
        void **uds = count ? (void **)calloc(count, sizeof(*uds)) : NULL;
        size_t i = 0;
        if (cbs && uds)
        {
            for (libp2p_subscription_t *it = host->subs; it; it = it->next)
            {
                if (it->cb)
                {
                    cbs[i] = it->cb;
                    uds[i] = it->user_data;
                    i++;
                }
            }
        }
        pthread_mutex_unlock(&host->mtx);

        if (cbs && uds)
        {
            for (size_t j = 0; j < i; j++)
                if (cbs[j])
                    cbs[j](&dn->evt, uds[j]);
        }
        if (cbs)
            free(cbs);
        if (uds)
            free(uds);
        /* Free deep-copied event */
        libp2p_event_free(&dn->evt);
        free(dn);
    }
    return NULL;
}

int libp2p__event_dispatcher_start(struct libp2p_host *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&host->mtx);
    host->disp_stop = 0;
    host->disp_head = host->disp_tail = NULL;
    host->disp_len = 0;
    host->disp_max = 1024; /* default backpressure threshold */
    pthread_mutex_unlock(&host->mtx);
    if (pthread_cond_init(&host->disp_cv, NULL) != 0)
        return LIBP2P_ERR_INTERNAL;
    if (pthread_create(&host->disp_thread, NULL, event_dispatch_thread, host) != 0)
    {
        pthread_cond_destroy(&host->disp_cv);
        return LIBP2P_ERR_INTERNAL;
    }
    host->disp_thread_started = 1;
    return 0;
}

void libp2p__event_dispatcher_stop(struct libp2p_host *host)
{
    if (!host)
        return;
    pthread_mutex_lock(&host->mtx);
    host->disp_stop = 1;
    pthread_cond_broadcast(&host->disp_cv);
    pthread_mutex_unlock(&host->mtx);
    if (host->disp_thread_started)
    {
        pthread_join(host->disp_thread, NULL);
        host->disp_thread_started = 0;
    }
    /* Drain any remaining dispatch nodes */
    dispatch_node_t *dn = NULL;
    pthread_mutex_lock(&host->mtx);
    dn = host->disp_head;
    host->disp_head = host->disp_tail = NULL;
    host->disp_len = 0;
    pthread_mutex_unlock(&host->mtx);
    while (dn)
    {
        dispatch_node_t *next = dn->next;
        libp2p_event_free(&dn->evt);
        free(dn);
        dn = next;
    }
    pthread_cond_destroy(&host->disp_cv);
}

/* Compute an absolute REALTIME deadline `now + ms`. Realtime-based deadlines
 * can be affected by system clock adjustments, so this is only used for
 * short, incremental waits; total timeout is enforced using a monotonic clock
 * in libp2p_host_next_event(). */
static void timespec_realtime_after_ms(struct timespec *ts, int timeout_ms)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += timeout_ms / 1000;
    ts->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L)
    {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

/* Return current monotonic time in milliseconds. */
static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000ull);
}

int libp2p_event_subscribe(struct libp2p_host *host, libp2p_event_cb cb, void *user_data, libp2p_subscription_t **sub)
{
    if (!host || !cb || !sub)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_subscription_t *s = (libp2p_subscription_t *)calloc(1, sizeof(*s));
    if (!s)
        return LIBP2P_ERR_INTERNAL;
    s->cb = cb;
    s->user_data = user_data;
    pthread_mutex_lock(&host->mtx);
    s->next = host->subs;
    host->subs = s;
    pthread_mutex_unlock(&host->mtx);
    *sub = s;
    return 0;
}

void libp2p_event_unsubscribe(struct libp2p_host *host, libp2p_subscription_t *sub)
{
    if (!host || !sub)
        return;
    /*
     * Safety: Do not free the subscription node here because many code paths
     * iterate host->subs without holding the host mutex. Freeing the node
     * concurrently can cause a use-after-free and crash.
     *
     * Instead, mark the subscription as inactive by nulling its callback and
     * user_data. Iteration sites must check for a non-NULL cb before calling.
     * The host will free all subscription nodes in libp2p_host_free().
     */
    pthread_mutex_lock(&host->mtx);
    sub->cb = NULL;
    sub->user_data = NULL;
    pthread_mutex_unlock(&host->mtx);
}

int libp2p_host_next_event(struct libp2p_host *host, int timeout_ms, libp2p_event_t *out_evt)
{
    if (!host || !out_evt)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&host->mtx);
    int rc = 0;
    if (!host->evt_head)
    {
        if (timeout_ms > 0)
        {
            /* Enforce total timeout using a monotonic deadline to avoid
             * sensitivity to system time adjustments. Wait in short slices
             * with realtime absolute deadlines to keep portability. */
            const int slice_ms_max = 50; /* short, responsive waits */
            uint64_t start_ms = monotonic_ms();
            uint64_t deadline_ms = start_ms + (uint64_t)timeout_ms;
            while (!host->evt_head)
            {
                uint64_t now_ms = monotonic_ms();
                if (now_ms >= deadline_ms)
                {
                    rc = 0; /* timeout */
                    goto out_unlock;
                }
                int remaining_ms = (int)(deadline_ms - now_ms);
                int slice_ms = remaining_ms < slice_ms_max ? remaining_ms : slice_ms_max;
#ifdef __APPLE__
                /* On macOS, use relative timedwait to avoid realtime jumps */
                struct timespec rel = {
                    .tv_sec = slice_ms / 1000,
                    .tv_nsec = (long)(slice_ms % 1000) * 1000000L,
                };
                (void)pthread_cond_timedwait_relative_np(&host->evt_cv, &host->mtx, &rel);
#else
                struct timespec ts;
                timespec_realtime_after_ms(&ts, slice_ms);
                (void)pthread_cond_timedwait(&host->evt_cv, &host->mtx, &ts);
#endif
            }
        }
        else
        {
            rc = 0; /* non-blocking or zero timeout */
            goto out_unlock;
        }
    }

    if (host->evt_head)
    {
        event_node_t *node = host->evt_head;
        host->evt_head = node->next;
        if (!host->evt_head)
            host->evt_tail = NULL;
        *out_evt = node->evt; /* shallow copy */
        free(node);
        rc = 1; /* have event */
    }

out_unlock:
    pthread_mutex_unlock(&host->mtx);
    return rc;
}

void libp2p_event_free(libp2p_event_t *evt)
{
    if (!evt)
        return;
    switch (evt->kind)
    {
        case LIBP2P_EVT_LISTEN_ADDR_ADDED:
        case LIBP2P_EVT_EXPIRED_LISTEN_ADDR:
            free((void *)evt->u.listen_addr_added.addr);
            evt->u.listen_addr_added.addr = NULL;
            break;
        case LIBP2P_EVT_LISTENER_CLOSED:
            free((void *)evt->u.listener_closed.addr);
            evt->u.listener_closed.addr = NULL;
            break;
        case LIBP2P_EVT_LISTENER_ERROR:
            free((void *)evt->u.listener_error.addr);
            free((void *)evt->u.listener_error.msg);
            evt->u.listener_error.addr = NULL;
            evt->u.listener_error.msg = NULL;
            break;
        case LIBP2P_EVT_DIALING:
            if (evt->u.dialing.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.dialing.peer);
                free((void *)evt->u.dialing.peer);
                evt->u.dialing.peer = NULL;
            }
            free((void *)evt->u.dialing.addr);
            evt->u.dialing.addr = NULL;
            break;
        case LIBP2P_EVT_OUTGOING_CONNECTION_ERROR:
        case LIBP2P_EVT_INCOMING_CONNECTION_ERROR:
            if (evt->u.outgoing_conn_error.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.outgoing_conn_error.peer);
                free((void *)evt->u.outgoing_conn_error.peer);
                evt->u.outgoing_conn_error.peer = NULL;
            }
            free((void *)evt->u.outgoing_conn_error.msg);
            evt->u.outgoing_conn_error.msg = NULL;
            break;
        case LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE:
        case LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED:
        case LIBP2P_EVT_EXTERNAL_ADDR_EXPIRED:
            free((void *)evt->u.new_external_addr_candidate.addr);
            evt->u.new_external_addr_candidate.addr = NULL;
            break;
        case LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER:
            if (evt->u.new_external_addr_of_peer.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.new_external_addr_of_peer.peer);
                free((void *)evt->u.new_external_addr_of_peer.peer);
                evt->u.new_external_addr_of_peer.peer = NULL;
            }
            free((void *)evt->u.new_external_addr_of_peer.addr);
            evt->u.new_external_addr_of_peer.addr = NULL;
            break;
        case LIBP2P_EVT_PEER_PROTOCOLS_UPDATED:
            if (evt->u.peer_protocols_updated.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.peer_protocols_updated.peer);
                free((void *)evt->u.peer_protocols_updated.peer);
                evt->u.peer_protocols_updated.peer = NULL;
            }
            if (evt->u.peer_protocols_updated.protocols)
            {
                for (size_t i = 0; i < evt->u.peer_protocols_updated.num_protocols; i++)
                    free((void *)evt->u.peer_protocols_updated.protocols[i]);
                free((void *)evt->u.peer_protocols_updated.protocols);
                evt->u.peer_protocols_updated.protocols = NULL;
            }
            evt->u.peer_protocols_updated.num_protocols = 0;
            break;
        case LIBP2P_EVT_CONN_OPENED:
            if (evt->u.conn_opened.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.conn_opened.peer);
                free((void *)evt->u.conn_opened.peer);
                evt->u.conn_opened.peer = NULL;
            }
            free((void *)evt->u.conn_opened.addr);
            evt->u.conn_opened.addr = NULL;
            break;
        case LIBP2P_EVT_CONN_CLOSED:
            if (evt->u.conn_closed.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.conn_closed.peer);
                free((void *)evt->u.conn_closed.peer);
                evt->u.conn_closed.peer = NULL;
            }
            break;
        case LIBP2P_EVT_PROTOCOL_NEGOTIATED:
            free((void *)evt->u.protocol_negotiated.protocol_id);
            evt->u.protocol_negotiated.protocol_id = NULL;
            break;
        case LIBP2P_EVT_STREAM_OPENED:
            if (evt->u.stream_opened.peer)
            {
                peer_id_destroy((peer_id_t *)evt->u.stream_opened.peer);
                free((void *)evt->u.stream_opened.peer);
                evt->u.stream_opened.peer = NULL;
            }
            free((void *)evt->u.stream_opened.protocol_id);
            evt->u.stream_opened.protocol_id = NULL;
            break;
        case LIBP2P_EVT_ERROR:
            free((void *)evt->u.error.msg);
            evt->u.error.msg = NULL;
            break;
        default:
            break;
    }
}
