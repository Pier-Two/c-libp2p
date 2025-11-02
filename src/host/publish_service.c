#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_internal.h"
#include "libp2p/host.h"
#include "libp2p/stream.h"
#include "libp2p/debug_trace.h"
#include "libp2p/events.h"
#include "libp2p/log.h"
#include "libp2p/lpmsg.h"
#include "libp2p/protocol_dial.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"
#include "protocol/identify/protocol_identify.h"

/* Lightweight internal Identify Push publish service
 *
 * Subscribes to host events and triggers async Identify Push deliveries.
 * Rate-limits via host->idpush_inflight/attempts flags, and deduplicates
 * targets per run (by peer id and by remote addr).
 */

typedef struct
{
    libp2p_host_t *host;
    int attempt; /* 1-based attempt counter for retries */
} __libp2p__pub_ctx_t;

static void free_string_list(char **list, size_t len)
{
    if (!list)
        return;
    for (size_t i = 0; i < len; i++)
        free(list[i]);
    free(list);
}

static int peer_supports_identify_push(libp2p_host_t *host, const peer_id_t *peer)
{
    if (!host || !peer)
        return 0;
    const char **protocols = NULL;
    size_t len = 0;
    int rc = libp2p_host_peer_protocols(host, peer, &protocols, &len);
    if (rc != 0 || !protocols || len == 0)
    {
        if (protocols)
            libp2p_host_free_peer_protocols(protocols, len);
        return 0;
    }
    int supported = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (protocols[i] && strcmp(protocols[i], LIBP2P_IDENTIFY_PUSH_PROTO_ID) == 0)
        {
            supported = 1;
            break;
        }
    }
    libp2p_host_free_peer_protocols(protocols, len);
    return supported;
}

static int addr_supports_identify_push(libp2p_host_t *host, const char *addr)
{
    if (!host || !addr)
        return 0;
    const char *needle = strstr(addr, "/p2p/");
    if (!needle || needle[5] == '\0')
        return 0;
    const char *peer_part = needle + 5;
    peer_id_t tmp = {0};
    peer_id_error_t perr = peer_id_create_from_string(peer_part, &tmp);
    if (perr != PEER_ID_SUCCESS)
        return 0;
    int supported = peer_supports_identify_push(host, &tmp);
    peer_id_destroy(&tmp);
    return supported;
}

static void free_peer_list(peer_id_t *peers, size_t len)
{
    if (!peers)
        return;
    for (size_t i = 0; i < len; i++)
        peer_id_destroy(&peers[i]);
    free(peers);
}

static int append_unique_peer(peer_id_t **peers, size_t *len, size_t *cap, const peer_id_t *candidate)
{
    if (!peers || !len || !cap || !candidate || !candidate->bytes || candidate->size == 0)
        return LIBP2P_ERR_NULL_PTR;

    peer_id_t *arr = *peers;
    for (size_t i = 0; i < *len; i++)
    {
        if (peer_id_equals(&arr[i], candidate) == 1)
            return 0;
    }

    if (*len == *cap)
    {
        size_t new_cap = (*cap == 0) ? 8 : (*cap * 2);
        peer_id_t *tmp = (peer_id_t *)realloc(arr, new_cap * sizeof(*tmp));
        if (!tmp)
            return LIBP2P_ERR_INTERNAL;
        for (size_t i = *cap; i < new_cap; i++)
            memset(&tmp[i], 0, sizeof(tmp[i]));
        arr = tmp;
        *peers = tmp;
        *cap = new_cap;
    }

    peer_id_t *slot = &arr[*len];
    slot->bytes = (uint8_t *)malloc(candidate->size);
    if (!slot->bytes)
        return LIBP2P_ERR_INTERNAL;
    memcpy(slot->bytes, candidate->bytes, candidate->size);
    slot->size = candidate->size;
    (*len)++;
    return 0;
}

static int append_unique_string(char ***list, size_t *len, size_t *cap, const char *value)
{
    if (!list || !len || !cap || !value)
        return LIBP2P_ERR_NULL_PTR;

    char **arr = *list;
    for (size_t i = 0; i < *len; i++)
    {
        if (arr[i] && strcmp(arr[i], value) == 0)
            return 0;
    }

    if (*len == *cap)
    {
        size_t new_cap = (*cap == 0) ? 8 : (*cap * 2);
        char **tmp = (char **)realloc(arr, new_cap * sizeof(*tmp));
        if (!tmp)
            return LIBP2P_ERR_INTERNAL;
        for (size_t i = *cap; i < new_cap; i++)
            tmp[i] = NULL;
        arr = tmp;
        *list = tmp;
        *cap = new_cap;
    }

    arr[*len] = strdup(value);
    if (!arr[*len])
        return LIBP2P_ERR_INTERNAL;
    (*len)++;
    return 0;
}

/* Identify Push async open callback context */
typedef struct
{
    uint8_t *payload;
    size_t plen;
} __libp2p__idpush_ctx_t;

static void __libp2p__idpush_on_open(libp2p_stream_t *s, void *user_data, int err)
{
    __libp2p__idpush_ctx_t *ctx = (__libp2p__idpush_ctx_t *)user_data;
    LIBP2P_TRACE("idpush", "on_open stream=%p err=%d plen=%zu", (void *)s, err, ctx ? ctx->plen : 0);
    if (s)
    {
        if (err == 0 && ctx && ctx->payload && ctx->plen > 0)
        {
            (void)libp2p_lp_send(s, ctx->payload, ctx->plen);
            LIBP2P_TRACE("idpush", "payload sent stream=%p bytes=%zu", (void *)s, ctx->plen);
        }
        libp2p_stream_close(s);
        libp2p_stream_free(s);
    }
    if (ctx)
    {
        if (ctx->payload)
            free(ctx->payload);
        free(ctx);
    }
}

typedef enum
{
    PUB_EXIT_ABORTED = 0,
    PUB_EXIT_EMPTY,
    PUB_EXIT_ERROR,
    PUB_EXIT_RETRY,
    PUB_EXIT_DONE,
} publish_exit_t;

/* Async publisher: collect peers from active streams and open identify-push
 * streams asynchronously via libp2p_host_open_stream_async. */
static void *__libp2p__publisher_async(void *arg)
{
    __libp2p__pub_ctx_t *pc = (__libp2p__pub_ctx_t *)arg;
    libp2p_host_t *host = pc ? pc->host : NULL;
    const int attempt = pc ? pc->attempt : 1;
    const bool running_initial = host && atomic_load_explicit(&host->running, memory_order_acquire);

    LP_LOGD("IDENTIFY_PUB", "[async] start (host=%p attempt=%d running=%d)", (void *)host, attempt, running_initial ? 1 : 0);
    LIBP2P_TRACE("idpush", "async start host=%p attempt=%d running=%d", (void *)host, attempt, running_initial ? 1 : 0);
    free(pc);

    publish_exit_t exit_state = PUB_EXIT_ABORTED;
    uint8_t *payload = NULL;
    size_t plen = 0;
    peer_id_t *peers = NULL;
    size_t peers_len = 0, peers_cap = 0;
    char **addr_list = NULL;
    size_t addr_len = 0, addr_cap = 0;
    bool needs_retry = false;
    bool attempted_by_addr = false;

    if (!host || !running_initial)
    {
        LP_LOGD("IDENTIFY_PUB", "[async] abort: host null or not running");
        exit_state = PUB_EXIT_ABORTED;
        goto cleanup;
    }

    int collect_rc = 0;
    pthread_mutex_lock(&host->mtx);
    for (stream_entry_t *se = host->active_streams; se && collect_rc == 0; se = se->next)
    {
        if (!se->s)
            continue;
        if (se->remote_addr)
            collect_rc = append_unique_string(&addr_list, &addr_len, &addr_cap, se->remote_addr);
        if (collect_rc != 0)
            break;
        const peer_id_t *rp = libp2p_stream_remote_peer(se->s);
        if (!rp || !rp->bytes || rp->size == 0)
            continue;
        collect_rc = append_unique_peer(&peers, &peers_len, &peers_cap, rp);
    }
    pthread_mutex_unlock(&host->mtx);

    if (collect_rc != 0)
    {
        LIBP2P_TRACE("idpush", "collector failed rc=%d", collect_rc);
        exit_state = PUB_EXIT_ERROR;
        goto cleanup;
    }

    LP_LOGD("IDENTIFY_PUB", "[async] collected peers=%zu addrs=%zu", peers_len, addr_len);
    LIBP2P_TRACE("idpush", "collector peers=%zu addrs=%zu", peers_len, addr_len);

    if (!atomic_load_explicit(&host->running, memory_order_acquire) || peers_len == 0)
    {
        LIBP2P_TRACE("idpush", "nothing to publish running=%d peers_len=%zu",
                     atomic_load_explicit(&host->running, memory_order_acquire) ? 1 : 0, peers_len);
        exit_state = PUB_EXIT_EMPTY;
        goto cleanup;
    }

    if (libp2p_identify_encode_local(host, NULL, 0, &payload, &plen) != 0 || !payload || plen == 0)
    {
        LP_LOGE("IDENTIFY_PUB", "[async] encode_local failed");
        LIBP2P_TRACE("idpush", "encode_local failed");
        exit_state = PUB_EXIT_ERROR;
        goto cleanup;
    }

    for (size_t i = 0; i < peers_len && atomic_load_explicit(&host->running, memory_order_acquire); i++)
    {
        if (!peer_supports_identify_push(host, &peers[i]))
        {
            LIBP2P_TRACE("idpush", "skip peer without identify-push support");
            continue;
        }
        if (host->peerstore)
        {
            const multiaddr_t **chk = NULL;
            size_t n = 0;
            if (libp2p_peerstore_get_addrs(host->peerstore, &peers[i], &chk, &n) != 0 || n == 0)
                needs_retry = true;
            if (chk)
                libp2p_peerstore_free_addrs(chk, n);
        }

        __libp2p__idpush_ctx_t *ctx = (__libp2p__idpush_ctx_t *)calloc(1, sizeof(*ctx));
        if (!ctx)
            continue;
        ctx->payload = (uint8_t *)malloc(plen);
        if (!ctx->payload)
        {
            free(ctx);
            continue;
        }
        memcpy(ctx->payload, payload, plen);
        ctx->plen = plen;
        LP_LOGD("IDENTIFY_PUB", "[async] open_stream_async by peer id (size=%zu)", peers[i].size);
        LIBP2P_TRACE("idpush", "open_stream_async peer_size=%zu", peers[i].size);
        (void)libp2p_host_open_stream_async(host, &peers[i], LIBP2P_IDENTIFY_PUSH_PROTO_ID, __libp2p__idpush_on_open, ctx);
    }

    if (addr_len > 0)
    {
        libp2p_proto_selector_t sel = {
            .kind = LIBP2P_PROTO_SELECT_EXACT,
            .exact_id = LIBP2P_IDENTIFY_PUSH_PROTO_ID,
            .id_list = NULL,
            .id_list_len = 0,
            .prefix = NULL,
            .base_path = NULL,
            .semver_range = NULL,
        };
        for (size_t j = 0; j < addr_len && atomic_load_explicit(&host->running, memory_order_acquire); j++)
        {
            const char *addr = addr_list[j];
            if (!addr)
                continue;
            if (!addr_supports_identify_push(host, addr))
            {
                LIBP2P_TRACE("idpush", "skip addr without identify-push support");
                continue;
            }
            __libp2p__idpush_ctx_t *ctx = (__libp2p__idpush_ctx_t *)calloc(1, sizeof(*ctx));
            if (!ctx)
                continue;
            ctx->payload = (uint8_t *)malloc(plen);
            if (!ctx->payload)
            {
                free(ctx);
                continue;
            }
            memcpy(ctx->payload, payload, plen);
            ctx->plen = plen;
            attempted_by_addr = true;
            LIBP2P_TRACE("idpush", "dial_selected addr=%s", addr);
            (void)libp2p_host_dial_selected(host, addr, &sel, NULL, __libp2p__idpush_on_open, ctx);
        }
    }

    exit_state = (needs_retry || attempted_by_addr) ? PUB_EXIT_RETRY : PUB_EXIT_DONE;
    if (exit_state == PUB_EXIT_RETRY)
    {
        LIBP2P_TRACE("idpush", "mark pending needs_retry=%d attempted_by_addr=%d attempts=%d",
                     needs_retry ? 1 : 0, attempted_by_addr ? 1 : 0, attempt);
    }
    else
    {
        LIBP2P_TRACE("idpush", "publish complete attempts=%d", attempt);
    }

cleanup:
    free(payload);
    free_peer_list(peers, peers_len);
    free_string_list(addr_list, addr_len);

    if (host)
    {
        pthread_mutex_lock(&host->mtx);
        switch (exit_state)
        {
            case PUB_EXIT_ABORTED:
                host->idpush_inflight = 0;
                break;
            case PUB_EXIT_EMPTY:
            case PUB_EXIT_ERROR:
            case PUB_EXIT_RETRY:
                host->idpush_pending = 1;
                if (attempt > host->idpush_attempts)
                    host->idpush_attempts = attempt;
                host->idpush_inflight = 0;
                break;
            case PUB_EXIT_DONE:
                host->idpush_pending = 0;
                host->idpush_attempts = 0;
                host->idpush_inflight = 0;
                break;
        }
        pthread_mutex_unlock(&host->mtx);
        libp2p__worker_dec(host);
    }

    return NULL;
}

/* Event-driven publish trigger. Handles LOCAL_PROTOCOLS_UPDATED as immediate
 * trigger and uses STREAM/CONN/NEGOTIATED to nudge retries when pending. */
static void push_publish_cb(const libp2p_event_t *evt, void *ud)
{
    libp2p_host_t *host = (libp2p_host_t *)ud;
    if (!evt || !host || !atomic_load_explicit(&host->running, memory_order_acquire))
        return;
    int should_schedule = 0;
    int next_attempt = 0;
    pthread_mutex_lock(&host->mtx);
    /* Event-driven policy: mark pending on LOCAL_PROTOCOLS_UPDATED and
     * schedule if no inflight worker. For connection/stream/protocol events,
     * if pending and not inflight, schedule a retry. */
    switch (evt->kind)
    {
        case LIBP2P_EVT_LOCAL_PROTOCOLS_UPDATED:
            host->idpush_pending = 1;
            host->idpush_attempts = 0;
            if (!host->idpush_inflight)
            {
                host->idpush_inflight = 1;
                next_attempt = host->idpush_attempts + 1;
                should_schedule = 1;
            }
            break;
        case LIBP2P_EVT_STREAM_OPENED:
        case LIBP2P_EVT_CONN_OPENED:
        case LIBP2P_EVT_PROTOCOL_NEGOTIATED:
            if (host->idpush_pending && !host->idpush_inflight && host->idpush_attempts < 3)
            {
                host->idpush_inflight = 1;
                next_attempt = host->idpush_attempts + 1;
                should_schedule = 1;
            }
            break;
        default:
            break;
    }
    pthread_mutex_unlock(&host->mtx);

    if (!should_schedule)
        return;

    LP_LOGD("IDENTIFY_PUB", "[cb] schedule async publisher attempt=%d workers=%d", next_attempt, (int)atomic_load(&host->worker_count));
    __libp2p__pub_ctx_t *pc = (__libp2p__pub_ctx_t *)calloc(1, sizeof(*pc));
    if (!pc)
    {
        pthread_mutex_lock(&host->mtx);
        host->idpush_inflight = 0;
        pthread_mutex_unlock(&host->mtx);
        return;
    }
    pc->host = host;
    pc->attempt = next_attempt;
    pthread_t th;
    libp2p__worker_inc(host);
    if (pthread_create(&th, NULL, __libp2p__publisher_async, pc) == 0)
        pthread_detach(th);
    else
    {
        free(pc);
        libp2p__worker_dec(host);
        pthread_mutex_lock(&host->mtx);
        host->idpush_inflight = 0;
        pthread_mutex_unlock(&host->mtx);
    }
}

void libp2p__schedule_identify_push(libp2p_host_t *host)
{
    if (!host || !atomic_load_explicit(&host->running, memory_order_acquire))
        return;
    int next_attempt = 0;
    pthread_mutex_lock(&host->mtx);
    if (!host->idpush_inflight)
    {
        host->idpush_pending = 1;
        host->idpush_inflight = 1;
        host->idpush_attempts = 0;
        next_attempt = 1;
    }
    pthread_mutex_unlock(&host->mtx);
    if (next_attempt == 0)
        return;
    __libp2p__pub_ctx_t *pc = (__libp2p__pub_ctx_t *)calloc(1, sizeof(*pc));
    if (!pc)
    {
        pthread_mutex_lock(&host->mtx);
        host->idpush_inflight = 0;
        pthread_mutex_unlock(&host->mtx);
        return;
    }
    pc->host = host;
    pc->attempt = next_attempt;
    pthread_t th;
    libp2p__worker_inc(host);
    if (pthread_create(&th, NULL, __libp2p__publisher_async, pc) == 0)
        pthread_detach(th);
    else
    {
        free(pc);
        libp2p__worker_dec(host);
        pthread_mutex_lock(&host->mtx);
        host->idpush_inflight = 0;
        pthread_mutex_unlock(&host->mtx);
    }
}

/* Timer-based retry removed: retries are event-driven only. */

int libp2p_publish_service_start(libp2p_host_t *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    /* Subscribe to local-change events to publish Identify Push */
    (void)libp2p_event_subscribe(host, push_publish_cb, host, &host->identify_push_sub);
    return 0;
}

void libp2p_publish_service_stop(libp2p_host_t *host)
{
    if (!host)
        return;
    if (host->identify_push_sub)
    {
        libp2p_event_unsubscribe(host, host->identify_push_sub);
        host->identify_push_sub = NULL;
    }
    pthread_mutex_lock(&host->mtx);
    host->idpush_pending = 0;
    host->idpush_inflight = 0;
    host->idpush_attempts = 0;
    pthread_mutex_unlock(&host->mtx);
}
