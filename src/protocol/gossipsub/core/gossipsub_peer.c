#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "gossipsub_peer.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libp2p/log.h"
#include "libp2p/runtime.h"
#include "libp2p/muxer.h"
#include "libp2p/stream_internal.h"
#include "libp2p/io.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "../../../host/host_internal.h"

#include <arpa/inet.h>

#define GOSSIPSUB_MODULE "gossipsub"
#include "libp2p/stream.h"
#include "gossipsub_score.h"
#include "gossipsub_rpc.h"
#include "gossipsub_topic.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"

#define GOSSIPSUB_EXPLICIT_DIAL_RETRY_MS 5000ULL

typedef struct gossipsub_explicit_timer_ctx
{
    libp2p_gossipsub_t *gs;
    peer_id_t *peer;
} gossipsub_explicit_timer_ctx_t;

static void gossipsub_peer_explicit_timer_cb(void *user_data);
static libp2p_err_t gossipsub_peer_flush_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry);
static void gossipsub_peer_schedule_flush_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry);
void gossipsub_propagation_try_connect_peer(libp2p_gossipsub_t *gs, const peer_id_t *peer);
static void gossipsub_peer_send_current_subscriptions_locked(libp2p_gossipsub_t *gs,
                                                             gossipsub_peer_entry_t *entry);

static char *gossipsub_peer_extract_remote_ip(libp2p_stream_t *s)
{
    if (!s)
        return NULL;
    const multiaddr_t *addr = libp2p_stream_remote_addr(s);
    if (!addr)
        return NULL;

    size_t protocol_count = multiaddr_nprotocols(addr);
    for (size_t i = 0; i < protocol_count; ++i)
    {
        uint64_t code = 0;
        if (multiaddr_get_protocol_code(addr, i, &code) != MULTIADDR_SUCCESS)
            continue;

        int family = 0;
        uint8_t raw[16];
        size_t raw_len = sizeof(raw);
        if (code == MULTICODEC_IP4)
        {
            family = AF_INET;
            raw_len = 4;
        }
        else if (code == MULTICODEC_IP6)
        {
            family = AF_INET6;
            raw_len = 16;
        }
        else
        {
            continue;
        }

        size_t tmp_len = raw_len;
        if (multiaddr_get_address_bytes(addr, i, raw, &tmp_len) != MULTIADDR_SUCCESS || tmp_len != raw_len)
            continue;

        char buffer[INET6_ADDRSTRLEN];
        const void *src = (const void *)raw;
        if (!inet_ntop(family, src, buffer, sizeof(buffer)))
            continue;
        char *dup = strdup(buffer);
        if (!dup)
            return NULL;
        return dup;
    }
    return NULL;
}

static const char *gossipsub_peer_to_string(const peer_id_t *peer, char *buffer, size_t length)
{
    if (!peer || !buffer || length == 0)
        return "-";
    int rc = peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, buffer, length);
    if (rc > 0)
        return buffer;
    return "-";
}

static gossipsub_sendq_item_t *gossipsub_sendq_item_new(const uint8_t *payload, size_t payload_len)
{
    gossipsub_sendq_item_t *item = (gossipsub_sendq_item_t *)calloc(1, sizeof(*item));
    if (!item)
        return NULL;

    if (payload_len)
    {
        item->payload = (uint8_t *)malloc(payload_len);
        if (!item->payload)
        {
            free(item);
            return NULL;
        }
        memcpy(item->payload, payload, payload_len);
    }

    size_t header_len = 0;
    if (unsigned_varint_encode((uint64_t)payload_len, item->header, sizeof(item->header), &header_len) != UNSIGNED_VARINT_OK)
    {
        free(item->payload);
        free(item);
        return NULL;
    }
    item->payload_len = payload_len;
    item->payload_sent = 0;
    item->header_len = header_len;
    item->header_sent = 0;
    item->next = NULL;
    return item;
}

static void gossipsub_sendq_item_free(gossipsub_sendq_item_t *item)
{
    if (!item)
        return;
    free(item->payload);
    free(item);
}

static void gossipsub_peer_explicit_timer_ctx_free(gossipsub_explicit_timer_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->peer)
        gossipsub_peer_free(ctx->peer);
    free(ctx);
}

static void gossipsub_peer_explicit_timer_cb(void *user_data)
{
    gossipsub_explicit_timer_ctx_t *ctx = (gossipsub_explicit_timer_ctx_t *)user_data;
    if (!ctx)
        return;

    libp2p_gossipsub_t *gs = ctx->gs;
    peer_id_t *peer = ctx->peer;
    if (!gs || !peer)
    {
        gossipsub_peer_explicit_timer_ctx_free(ctx);
        return;
    }

    int should_retry = 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (entry && entry->explicit_peering)
    {
        if (entry->explicit_dial_timer_id > 0)
            entry->explicit_dial_timer_id = 0;
        if (gs->started && (!entry->connected || !entry->stream))
            should_retry = 1;
    }
    pthread_mutex_unlock(&gs->lock);

    if (should_retry)
    {
        gossipsub_propagation_try_connect_peer(gs, peer);

        pthread_mutex_lock(&gs->lock);
        entry = gossipsub_peer_find(gs->peers, peer);
        if (entry && entry->explicit_peering && (!entry->connected || !entry->stream))
            gossipsub_peer_explicit_schedule_dial_locked(gs, entry, GOSSIPSUB_EXPLICIT_DIAL_RETRY_MS);
        pthread_mutex_unlock(&gs->lock);
    }

    gossipsub_peer_explicit_timer_ctx_free(ctx);
}

void gossipsub_peer_explicit_cancel_timer_locked(libp2p_gossipsub_t *gs,
                                                 gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry || entry->explicit_dial_timer_id <= 0 || !gs->runtime)
        return;
    int timer_id = entry->explicit_dial_timer_id;
    entry->explicit_dial_timer_id = 0;
    (void)libp2p_runtime_cancel_timer(gs->runtime, timer_id);
}

void gossipsub_peer_explicit_schedule_dial_locked(libp2p_gossipsub_t *gs,
                                                  gossipsub_peer_entry_t *entry,
                                                  uint64_t delay_ms)
{
    if (!gs || !entry || !gs->runtime)
        return;
    if (!gs->started)
        return;
    if (!entry->explicit_peering)
        return;
    if (entry->explicit_dial_timer_id > 0)
        return;
    gossipsub_explicit_timer_ctx_t *ctx = (gossipsub_explicit_timer_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return;
    ctx->gs = gs;
    ctx->peer = gossipsub_peer_clone(entry->peer);
    if (!ctx->peer)
    {
        free(ctx);
        return;
    }
    uint64_t delay = delay_ms ? delay_ms : 10ULL;
    int timer_id = libp2p_runtime_add_timer(gs->runtime, delay, 0, gossipsub_peer_explicit_timer_cb, ctx);
    if (timer_id <= 0)
    {
        gossipsub_peer_explicit_timer_ctx_free(ctx);
        return;
    }
    entry->explicit_dial_timer_id = timer_id;
}

gossipsub_peer_entry_t *gossipsub_peer_find(gossipsub_peer_entry_t *head, const peer_id_t *peer)
{
    for (; head; head = head->next)
    {
        if (gossipsub_peer_equals(head->peer, peer))
            return head;
    }
    return NULL;
}

gossipsub_peer_entry_t *gossipsub_peer_find_or_add_locked(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer)
        return NULL;

    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (entry)
        return entry;

    peer_id_t *dup = gossipsub_peer_clone(peer);
    if (!dup)
        return NULL;

    entry = (gossipsub_peer_entry_t *)calloc(1, sizeof(*entry));
    if (!entry)
    {
        gossipsub_peer_free(dup);
        return NULL;
    }

    entry->peer = dup;
    entry->explicit_peering = 0;
    entry->connected = 0;
    entry->score = 0.0;
    libp2p_gossipsub_rpc_decoder_init(&entry->decoder);
    LP_LOGT(GOSSIPSUB_MODULE,
            "peer entry initialized entry=%p decoder_max=%zu",
            (void *)entry,
            entry->decoder.max_frame_len);
    entry->next = gs->peers;
    gs->peers = entry;
    return entry;
}

void gossipsub_peer_detach_stream_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry, libp2p_stream_t *s)
{
    (void)gs;
    if (!entry)
        return;

    if (entry->stream && (!s || entry->stream == s))
    {
        char peer_buf[128];
        const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
        LP_LOGD(
            GOSSIPSUB_MODULE,
            "peer_detach_stream peer=%s outbound=%d",
            peer_repr,
            entry->outbound_stream);
        libp2p_stream_on_writable(entry->stream, NULL, NULL);
        libp2p_stream_set_user_data(entry->stream, NULL);
        entry->stream = NULL;
        entry->write_backpressure = 0;
        libp2p_gossipsub_rpc_decoder_reset(&entry->decoder);
        /* Stream used for writing is gone: stop treating the peer as connected for
         * propagation, and drop any queued frames to avoid infinite retry / OOM
         * when a peer goes offline. */
        entry->connected = 0;
        if (entry->sendq_head)
        {
            size_t dropped = 0;
            for (gossipsub_sendq_item_t *it = entry->sendq_head; it; it = it->next)
                dropped++;
            LP_LOGW(GOSSIPSUB_MODULE,
                    "peer_detach_stream dropping %zu queued messages peer=%s",
                    dropped,
                    peer_repr);
            gossipsub_peer_sendq_clear(entry);
        }
        if (entry->explicit_peering)
            gossipsub_peer_explicit_schedule_dial_locked(gs, entry, 0);
    }
}

void gossipsub_peer_attach_stream_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry, libp2p_stream_t *s)
{
    if (!entry)
        return;

    /* IMPORTANT: Do NOT detach the old stream when attaching a new one!
     * 
     * In gossipsub, each peer can have TWO streams:
     * 1. Inbound stream (initiator=0): opened by the remote peer to us
     * 2. Outbound stream (initiator=1): opened by us to the remote peer
     * 
     * Both streams are valid for receiving data. If we detach the old stream,
     * we clear its user_data, causing data arriving on that stream to be dropped
     * because gossipsub_on_stream_data can't find the peer entry.
     * 
     * Instead, we keep the old stream's user_data intact and just update
     * entry->stream to point to the new stream (used for writing).
     * Data can still be received on the old stream because its user_data
     * still points to this entry.
     */
    libp2p_stream_t *old_stream = entry->stream;
    int old_initiator = old_stream ? libp2p_stream_is_initiator(old_stream) : -1;
    int new_initiator = s ? libp2p_stream_is_initiator(s) : -1;

    if (old_stream && old_stream != s)
    {
        char peer_buf[128];
        const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
        LP_LOGI(
            GOSSIPSUB_MODULE,
            "peer_attach_stream peer=%s old_stream=%p (initiator=%d) new_stream=%p (initiator=%d)",
            peer_repr,
            (void *)old_stream,
            old_initiator,
            (void *)s,
            new_initiator);

        /* CRITICAL FIX for rust-libp2p interop:
         *
         * rust-libp2p uses separate streams for reading and writing:
         * - It READS from streams opened TO it (our outbound streams)
         * - It WRITES on streams it opens (our inbound streams)
         *
         * If we have an outbound stream (initiator=1) and receive an inbound stream (initiator=0),
         * we must NOT replace entry->stream (used for writing) with the inbound stream.
         * If we do, our writes go to the inbound stream, but rust-libp2p doesn't read from
         * streams IT opened - it expects to write on them.
         *
         * Only replace if:
         * 1. New stream is outbound (initiator=1) - prefer outbound for writing
         * 2. Old stream is not outbound (initiator!=1) - no outbound to preserve
         * 3. New stream is NULL - clearing the stream
         */
        if (old_initiator == 1 && new_initiator == 0)
        {
            LP_LOGI(
                GOSSIPSUB_MODULE,
                "peer_attach_stream peer=%s KEEPING outbound stream for writing, setting user_data on inbound for receiving",
                peer_repr);
            /* Set user_data on new inbound stream so it can receive data */
            if (s)
                libp2p_stream_set_user_data(s, entry);
            /* Don't replace entry->stream - keep outbound for writing */
            return;
        }
        /* Keep old_stream's user_data pointing to entry so it can still receive data */
    }

    entry->stream = s;
    entry->write_backpressure = 0;
    libp2p_gossipsub_rpc_decoder_reset(&entry->decoder);
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
    const char *proto = s ? libp2p_stream_protocol_id(s) : NULL;
    int is_initiator = s ? libp2p_stream_is_initiator(s) : -1;
    LP_LOGD(
        GOSSIPSUB_MODULE,
        "peer_attach_stream peer=%s stream=%p protocol=%s initiator=%d entry=%p decoder_max=%zu",
        peer_repr,
        (void *)s,
        proto ? proto : "(null)",
        is_initiator,
        (void *)entry,
        entry->decoder.max_frame_len);
    if (entry->explicit_peering)
        gossipsub_peer_explicit_cancel_timer_locked(gs, entry);
    if (s)
    {
        entry->outbound_stream = libp2p_stream_is_initiator(s) ? 1 : 0;
        entry->last_stream_dir_update_ms = gossipsub_now_ms();
        libp2p_stream_set_user_data(s, entry);
        char *ip = gossipsub_peer_extract_remote_ip(s);
        if (ip)
        {
            if (!entry->remote_ip || strcmp(entry->remote_ip, ip) != 0)
            {
                free(entry->remote_ip);
                entry->remote_ip = ip;
            }
            else
                free(ip);
        }
        libp2p_stream_on_writable(s, NULL, NULL);
        
        /* For rust-libp2p interop: if we received an inbound stream (initiator=0),
         * rust-libp2p won't read from it. We need to open our OWN outbound stream
         * on the same connection to send subscriptions.
         * 
         * NOTE: We DON'T do this synchronously here because:
         * 1. The QUIC muxer is single-threaded
         * 2. Blocking multiselect would prevent the QUIC event loop from processing responses
         * 3. This would cause a deadlock/timeout
         * 
         * Instead, we rely on gossipsub_try_open_outbound_stream being called
         * from the CONN_OPENED event handler, which spawns an async thread.
         * 
         * For now, we just use the inbound stream for receiving RPC data.
         * When the async outbound stream is ready, it will be attached separately.
         */
        (void)proto; /* Avoid unused warning - proto is used for context only here */
        
        /* Count subscribed topics for debug */
        size_t topic_count = 0;
        for (gossipsub_topic_state_t *t = gs ? gs->topics : NULL; t; t = t->next)
        {
            if (t->subscribed && t->name)
                topic_count++;
        }
        LP_LOGD(GOSSIPSUB_MODULE,
                "peer_attach_stream peer=%s will_send_subscriptions=%zu",
                peer_repr,
                topic_count);
        
        (void)gossipsub_peer_flush_locked(gs, entry);
        gossipsub_peer_send_current_subscriptions_locked(gs, entry);

        /* Log post-send state */
        size_t queued = 0;
        for (gossipsub_sendq_item_t *it = entry->sendq_head; it; it = it->next)
            queued++;
        LP_LOGD(GOSSIPSUB_MODULE,
                "peer_attach_stream peer=%s after_send_subscriptions sendq_size=%zu stream=%p",
                peer_repr,
                queued,
                (void *)entry->stream);

        /* Schedule a flush if there are pending messages that weren't sent.
         * This handles the case where messages were enqueued while stream was NULL
         * (connected=1 but stream not yet attached due to async open), and the
         * synchronous flush above didn't fully drain the queue (e.g., due to
         * backpressure or edge cases).
         */
        if (entry->sendq_head && !entry->write_backpressure && !entry->flush_scheduled)
        {
            LP_LOGD(GOSSIPSUB_MODULE,
                    "peer_attach_stream peer=%s scheduling_flush_for_pending queued=%zu",
                    peer_repr,
                    queued);
            gossipsub_peer_schedule_flush_locked(gs, entry);
        }
    }
}

void gossipsub_peer_sendq_clear(gossipsub_peer_entry_t *entry)
{
    if (!entry)
        return;

    gossipsub_sendq_item_t *node = entry->sendq_head;
    entry->sendq_head = NULL;
    entry->sendq_tail = NULL;
    while (node)
    {
        gossipsub_sendq_item_t *next = node->next;
        gossipsub_sendq_item_free(node);
        node = next;
    }
}

void gossipsub_peer_topics_clear(gossipsub_peer_entry_t *entry)
{
    if (!entry)
        return;

    gossipsub_peer_topic_t *node = entry->topics;
    entry->topics = NULL;
    entry->topics_count = 0;
    while (node)
    {
        gossipsub_peer_topic_t *next = node->next;
        free(node->name);
        free(node);
        node = next;
    }
}

gossipsub_peer_topic_t *gossipsub_peer_topic_find(gossipsub_peer_topic_t *head, const char *topic)
{
    for (; head; head = head->next)
    {
        if (head->name && topic && strcmp(head->name, topic) == 0)
            return head;
    }
    return NULL;
}

libp2p_err_t gossipsub_peer_topic_subscribe(libp2p_gossipsub_t *gs,
                                            gossipsub_peer_entry_t *entry,
                                            char **topic_ptr)
{
    if (!gs || !entry || !topic_ptr || !*topic_ptr)
        return LIBP2P_ERR_NULL_PTR;

    char *topic_name = *topic_ptr;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        libp2p_gossipsub_topic_config_t cfg = {
            .struct_size = sizeof(cfg),
            .descriptor = {
                .struct_size = sizeof(cfg.descriptor),
                .topic = topic_name
            },
            .score_params = NULL
        };
        libp2p_err_t rc = gossipsub_topic_ensure(gs, &cfg, &topic);
        if (rc != LIBP2P_ERR_OK)
        {
            pthread_mutex_unlock(&gs->lock);
            return rc;
        }
    }

    gossipsub_peer_topic_t *existing = gossipsub_peer_topic_find(entry->topics, topic_name);
    if (!existing)
    {
        gossipsub_peer_topic_t *node = (gossipsub_peer_topic_t *)calloc(1, sizeof(*node));
        if (!node)
        {
            pthread_mutex_unlock(&gs->lock);
            return LIBP2P_ERR_INTERNAL;
        }
        node->name = topic_name;
        node->next = entry->topics;
        entry->topics = node;
        entry->topics_count++;
        *topic_ptr = NULL;
        LP_LOGD(GOSSIPSUB_MODULE, "peer subscribed to topic %s", topic_name);
    }
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

void gossipsub_peer_topic_unsubscribe(libp2p_gossipsub_t *gs,
                                      gossipsub_peer_entry_t *entry,
                                      const char *topic_name)
{
    if (!gs || !entry || !topic_name)
        return;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_topic_t **pp = &entry->topics;
    while (*pp)
    {
        if ((*pp)->name && strcmp((*pp)->name, topic_name) == 0)
        {
            gossipsub_peer_topic_t *victim = *pp;
            *pp = victim->next;
            if (entry->topics_count > 0)
                entry->topics_count--;
            gossipsub_score_on_topic_unsubscribe_locked(gs, entry, topic_name);
            free(victim->name);
            free(victim);
            LP_LOGD(GOSSIPSUB_MODULE, "peer unsubscribed from topic %s", topic_name);
            break;
        }
        pp = &(*pp)->next;
    }

    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (topic)
        gossipsub_topic_remove_peer(gs, topic, entry->peer);
    pthread_mutex_unlock(&gs->lock);
}

libp2p_err_t gossipsub_peer_sendq_pop_locked(gossipsub_peer_entry_t *entry,
                                             uint8_t **out_buf,
                                             size_t *out_len)
{
    if (!entry || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    gossipsub_sendq_item_t *item = entry->sendq_head;
    if (!item)
        return LIBP2P_ERR_UNSUPPORTED;

    entry->sendq_head = item->next;
    if (!entry->sendq_head)
        entry->sendq_tail = NULL;

    uint8_t *buf = NULL;
    if (item->payload_len)
    {
        buf = (uint8_t *)malloc(item->payload_len);
        if (!buf)
        {
            gossipsub_sendq_item_free(item);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(buf, item->payload, item->payload_len);
    }

    *out_buf = buf;
    *out_len = item->payload_len;
    gossipsub_sendq_item_free(item);
    return LIBP2P_ERR_OK;
}

static void gossipsub_stream_writable_cb(libp2p_stream_t *s, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (!gs || !s)
        return;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = (gossipsub_peer_entry_t *)libp2p_stream_get_user_data(s);
    if (entry)
    {
        entry->write_backpressure = 0;
        (void)gossipsub_peer_flush_locked(gs, entry);
    }
    pthread_mutex_unlock(&gs->lock);
}

static libp2p_err_t gossipsub_peer_flush_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;
    
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
    
    if (!entry->stream)
    {
        /* For explicit peers, we'll reconnect automatically, so return AGAIN to retry later.
         * For non-explicit peers, there's no stream and no reconnect - clear the sendq
         * to avoid infinite retry loops and return OK (nothing more to do). */
        if (entry->explicit_peering)
        {
            LP_LOGD(GOSSIPSUB_MODULE,
                    "flush NO_STREAM peer=%s entry=%p (explicit, will retry after reconnect)",
                    peer_repr,
                    (void *)entry);
            return LIBP2P_ERR_AGAIN;
        }

        /* Non-explicit peer with no stream: clear sendq and stop retrying */
        size_t dropped = 0;
        for (gossipsub_sendq_item_t *it = entry->sendq_head; it; it = it->next)
            dropped++;

        if (dropped > 0)
        {
            LP_LOGW(GOSSIPSUB_MODULE,
                    "flush NO_STREAM peer=%s entry=%p dropping %zu queued messages",
                    peer_repr,
                    (void *)entry,
                    dropped);
            gossipsub_peer_sendq_clear(entry);
        }
        return LIBP2P_ERR_OK;
    }

    size_t queued = 0;
    for (gossipsub_sendq_item_t *it = entry->sendq_head; it; it = it->next)
        queued++;
    LP_LOGT(GOSSIPSUB_MODULE,
            "flush START peer=%s stream=%p queued=%zu",
            peer_repr,
            (void *)entry->stream,
            queued);

    size_t frames_written = 0;
    size_t total_bytes_written = 0;
    
    while (entry->stream && entry->sendq_head)
    {
        gossipsub_sendq_item_t *item = entry->sendq_head;
        if (item && item->payload && item->payload_len && item->payload_sent == 0 && item->header_sent == 0)
        {
            libp2p_log_level_t log_level;
            if (libp2p_log_is_enabled(LIBP2P_LOG_TRACE))
                log_level = LIBP2P_LOG_TRACE;
            else if (libp2p_log_is_enabled(LIBP2P_LOG_DEBUG))
                log_level = LIBP2P_LOG_DEBUG;
            else
                log_level = (libp2p_log_level_t)-1;

            if (log_level != (libp2p_log_level_t)-1 && log_level != LIBP2P_LOG_ERROR)
            {
                static const char hex_digits[] = "0123456789abcdef";
                const size_t preview_cap = 64;
                uint8_t combined[preview_cap];
                size_t combined_len = 0;
                size_t header_copy = item->header_len < preview_cap ? item->header_len : preview_cap;
                if (header_copy)
                {
                    memcpy(combined, item->header, header_copy);
                    combined_len += header_copy;
                }
                if (combined_len < preview_cap)
                {
                    size_t remaining = preview_cap - combined_len;
                    size_t payload_copy = item->payload_len < remaining ? item->payload_len : remaining;
                    if (payload_copy)
                    {
                        memcpy(combined + combined_len, item->payload, payload_copy);
                        combined_len += payload_copy;
                    }
                }
                char preview[(preview_cap * 2) + 4];
                size_t preview_idx = 0;
                for (size_t i = 0; i < combined_len; ++i)
                {
                    preview[preview_idx++] = hex_digits[(combined[i] >> 4) & 0xF];
                    preview[preview_idx++] = hex_digits[combined[i] & 0xF];
                }
                preview[preview_idx] = '\0';
                if ((item->header_len + item->payload_len) > preview_cap)
                {
                    preview[preview_idx++] = '.';
                    preview[preview_idx++] = '.';
                    preview[preview_idx++] = '.';
                    preview[preview_idx] = '\0';
                }

                LP_LOGF(log_level,
                        GOSSIPSUB_MODULE,
                        "flush FRAME peer=%s header_len=%zu payload_len=%zu preview=%s",
                        peer_repr,
                        item->header_len,
                        item->payload_len,
                        preview);
            }
        }

        while (item && item->header_sent < item->header_len)
        {
            ssize_t n = libp2p_stream_write(entry->stream, item->header + item->header_sent, item->header_len - item->header_sent);
            LP_LOGD(GOSSIPSUB_MODULE,
                    "flush WRITE_HEADER peer=%s wrote=%zd remaining=%zu",
                    peer_repr,
                    n,
                    item->header_len - item->header_sent);
            if (n > 0)
            {
                item->header_sent += (size_t)n;
                total_bytes_written += (size_t)n;
                continue;
            }
            if (n == 0 || n == LIBP2P_ERR_AGAIN)
            {
                LP_LOGD(GOSSIPSUB_MODULE,
                        "flush BACKPRESSURE peer=%s frames_written=%zu bytes_written=%zu",
                        peer_repr,
                        frames_written,
                        total_bytes_written);
                if (!entry->write_backpressure)
                {
                    entry->write_backpressure = 1;
                    libp2p_stream_on_writable(entry->stream, gossipsub_stream_writable_cb, gs);
                }
                return LIBP2P_ERR_AGAIN;
            }
            LP_LOGW(GOSSIPSUB_MODULE,
                    "flush WRITE_HEADER_FAIL peer=%s rc=%zd header_remaining=%zu",
                    peer_repr,
                    n,
                    item ? (item->header_len - item->header_sent) : 0);
            /* If the stream reports a terminal condition, mark the peer as disconnected.
             *
             * Without this, the peer can remain "connected" (set by CONN_OPENED) even after
             * its pubsub stream dies, causing propagate_frame() to keep enqueueing messages
             * for a dead peer and repeatedly re-triggering flush failures.
             *
             * rc is a libp2p_err_t returned via libp2p_stream_write().
             */
            if (n == LIBP2P_ERR_CLOSED || n == LIBP2P_ERR_RESET || n == LIBP2P_ERR_EOF)
            {
                entry->connected = 0;
            }
            gossipsub_peer_detach_stream_locked(gs, entry, entry->stream);
            /* Clear sendq to prevent infinite retry loops when stream is closed */
            gossipsub_peer_sendq_clear(entry);
            return LIBP2P_ERR_INTERNAL;
        }

        while (item && item->payload_sent < item->payload_len)
        {
            ssize_t n = libp2p_stream_write(entry->stream, item->payload + item->payload_sent, item->payload_len - item->payload_sent);
            LP_LOGD(GOSSIPSUB_MODULE,
                    "flush WRITE_PAYLOAD peer=%s wrote=%zd remaining=%zu",
                    peer_repr,
                    n,
                    item->payload_len - item->payload_sent);
            if (n > 0)
            {
                item->payload_sent += (size_t)n;
                total_bytes_written += (size_t)n;
                continue;
            }
            if (n == 0 || n == LIBP2P_ERR_AGAIN)
            {
                LP_LOGD(GOSSIPSUB_MODULE,
                        "flush BACKPRESSURE peer=%s frames_written=%zu bytes_written=%zu",
                        peer_repr,
                        frames_written,
                        total_bytes_written);
                if (!entry->write_backpressure)
                {
                    entry->write_backpressure = 1;
                    libp2p_stream_on_writable(entry->stream, gossipsub_stream_writable_cb, gs);
                }
                return LIBP2P_ERR_AGAIN;
            }
            LP_LOGW(GOSSIPSUB_MODULE,
                    "flush WRITE_PAYLOAD_FAIL peer=%s rc=%zd",
                    peer_repr,
                    n);
            /* See WRITE_HEADER_FAIL above for rationale */
            if (n == LIBP2P_ERR_CLOSED || n == LIBP2P_ERR_RESET || n == LIBP2P_ERR_EOF)
            {
                entry->connected = 0;
            }
            gossipsub_peer_detach_stream_locked(gs, entry, entry->stream);
            /* Clear sendq to prevent infinite retry loops when stream is closed */
            gossipsub_peer_sendq_clear(entry);
            return LIBP2P_ERR_INTERNAL;
        }

        if (item)
        {
            frames_written++;
            entry->sendq_head = item->next;
            if (!entry->sendq_head)
                entry->sendq_tail = NULL;
            gossipsub_sendq_item_free(item);
        }
    }

    LP_LOGT(GOSSIPSUB_MODULE,
            "flush COMPLETE peer=%s frames_written=%zu bytes_written=%zu stream=%p",
            peer_repr,
            frames_written,
            total_bytes_written,
            (void *)entry->stream);
    
    entry->write_backpressure = 0;
    return LIBP2P_ERR_OK;
}

static void gossipsub_flush_exec(void *user_data)
{
    gossipsub_flush_task_t *task = (gossipsub_flush_task_t *)user_data;
    if (!task)
        return;

    libp2p_gossipsub_t *gs = task->gs;
    peer_id_t *peer = task->peer;
    if (!gs)
    {
        if (peer)
            gossipsub_peer_free(peer);
        free(task);
        return;
    }

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (entry)
    {
        entry->flush_scheduled = 0;
        (void)gossipsub_peer_flush_locked(gs, entry);
    }
    pthread_mutex_unlock(&gs->lock);

    if (peer)
        gossipsub_peer_free(peer);
    free(task);
}

static void gossipsub_peer_schedule_flush_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry || entry->flush_scheduled)
        return;

    gossipsub_flush_task_t *task = (gossipsub_flush_task_t *)calloc(1, sizeof(*task));
    if (!task)
        return;

    peer_id_t *dup = gossipsub_peer_clone(entry->peer);
    if (!dup)
    {
        free(task);
        return;
    }

    entry->flush_scheduled = 1;
    task->gs = gs;
    task->peer = dup;
    libp2p__exec_on_cb_thread(gs->host, gossipsub_flush_exec, task);
}

libp2p_err_t gossipsub_peer_enqueue_frame_locked(libp2p_gossipsub_t *gs,
                                                 gossipsub_peer_entry_t *entry,
                                                 const uint8_t *frame,
                                                 size_t frame_len)
{
    if (!gs || !entry || !frame)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_log_level_t log_level = (libp2p_log_is_enabled(LIBP2P_LOG_TRACE)
                                        ? LIBP2P_LOG_TRACE
                                        : (libp2p_log_is_enabled(LIBP2P_LOG_DEBUG)
                                               ? LIBP2P_LOG_DEBUG
                                               : (libp2p_log_level_t)-1));
    if (frame_len && log_level != (libp2p_log_level_t)-1 && log_level != LIBP2P_LOG_ERROR)
    {
        static const char hex_digits[] = "0123456789abcdef";
        const size_t preview_cap = 64;
        char preview[(preview_cap * 2) + 4];
        size_t preview_len = frame_len < preview_cap ? frame_len : preview_cap;
        for (size_t i = 0; i < preview_len; ++i)
        {
            preview[(i * 2) + 0] = hex_digits[(frame[i] >> 4) & 0xF];
            preview[(i * 2) + 1] = hex_digits[frame[i] & 0xF];
        }
        size_t preview_idx = preview_len * 2;
        preview[preview_idx] = '\0';
        if (frame_len > preview_cap)
        {
            preview[preview_idx++] = '.';
            preview[preview_idx++] = '.';
            preview[preview_idx++] = '.';
            preview[preview_idx] = '\0';
        }

        char peer_buf[128];
        const char *peer_repr = "-";
        if (entry->peer)
        {
            int rc = peer_id_to_string(entry->peer, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
            if (rc > 0)
                peer_repr = peer_buf;
        }

        libp2p_gossipsub_RPC *decoded = NULL;
        libp2p_err_t decode_rc = libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &decoded);
        size_t publish_count = 0;
        size_t data_len = 0;
        const char *topic_name = NULL;
        if (decode_rc == LIBP2P_ERR_OK && decoded)
        {
            publish_count = libp2p_gossipsub_RPC_count_publish(decoded);
            if (publish_count > 0)
            {
                libp2p_gossipsub_Message *first = libp2p_gossipsub_RPC_get_at_publish(decoded, 0);
                if (first)
                {
                    data_len = libp2p_gossipsub_Message_get_size_data(first);
                    topic_name = libp2p_gossipsub_Message_get_topic(first);
                }
            }
        }

        LP_LOGF(log_level,
                GOSSIPSUB_MODULE,
                "enqueue frame peer=%s frame_len=%zu topics=%zu first_topic=%s first_data_len=%zu preview=%s decode_rc=%d",
                peer_repr,
                frame_len,
                publish_count,
                topic_name ? topic_name : "(null)",
                data_len,
                preview,
                decode_rc);

        if (decoded)
            libp2p_gossipsub_RPC_free(decoded);
    }

    gossipsub_sendq_item_t *item = gossipsub_sendq_item_new(frame, frame_len);
    if (!item)
        return LIBP2P_ERR_INTERNAL;

    if (entry->sendq_tail)
        entry->sendq_tail->next = item;
    else
        entry->sendq_head = item;

    entry->sendq_tail = item;

    if (entry->stream && !entry->write_backpressure && !entry->flush_scheduled)
        gossipsub_peer_schedule_flush_locked(gs, entry);

    return LIBP2P_ERR_OK;
}

libp2p_err_t gossipsub_peer_send_subscription_locked(libp2p_gossipsub_t *gs,
                                                     gossipsub_peer_entry_t *entry,
                                                     const char *topic,
                                                     int subscribe)
{
    if (!gs || !entry || !topic)
        return LIBP2P_ERR_NULL_PTR;

    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
    
    gossipsub_rpc_out_t frame;
    gossipsub_rpc_out_init(&frame);

    libp2p_err_t enc_rc = gossipsub_rpc_encode_subscription(topic, subscribe, &frame);
    if (enc_rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE,
                "send_subscription ENCODE_FAILED peer=%s topic=%s rc=%d",
                peer_repr,
                topic,
                enc_rc);
        return enc_rc;
    }

    libp2p_err_t send_rc = gossipsub_peer_enqueue_frame_locked(gs, entry, frame.frame, frame.frame_len);
    LP_LOGD(GOSSIPSUB_MODULE,
            "send_subscription peer=%s topic=%s subscribe=%d frame_len=%zu enqueue_rc=%d stream=%p",
            peer_repr,
            topic,
            subscribe ? 1 : 0,
            frame.frame_len,
            send_rc,
            (void *)entry->stream);

    gossipsub_rpc_out_clear(&frame);
    return send_rc;
}

static void gossipsub_peer_send_current_subscriptions_locked(libp2p_gossipsub_t *gs,
                                                             gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry)
        return;
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
    
    int has_stream = entry->stream ? 1 : 0;
    LP_LOGD(
        GOSSIPSUB_MODULE,
        "send_current_subscriptions START peer=%s has_stream=%d",
        peer_repr,
        has_stream);

    size_t sent = 0;
    for (gossipsub_topic_state_t *topic = gs->topics; topic; topic = topic->next)
    {
        if (!topic->subscribed || !topic->name)
            continue;
        LP_LOGD(
            GOSSIPSUB_MODULE,
            "send_current_subscriptions peer=%s topic=%s",
            peer_repr,
            topic->name);
        libp2p_err_t rc = gossipsub_peer_send_subscription_locked(gs, entry, topic->name, 1);
        if (rc == LIBP2P_ERR_OK)
            sent++;
    }
    
    LP_LOGD(
        GOSSIPSUB_MODULE,
        "send_current_subscriptions END peer=%s sent=%zu",
        peer_repr,
        sent);
}

void gossipsub_peers_clear(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    gossipsub_peer_entry_t *head = gs->peers;
    gs->peers = NULL;
    while (head)
    {
        gossipsub_peer_entry_t *next = head->next;
        gossipsub_peer_explicit_cancel_timer_locked(gs, head);
        if (head->stream)
        {
            libp2p_stream_on_writable(head->stream, NULL, NULL);
            libp2p_stream_set_user_data(head->stream, NULL);
            head->stream = NULL;
        }
        gossipsub_peer_sendq_clear(head);
        gossipsub_score_on_peer_removed_locked(gs, head);
        gossipsub_peer_topics_clear(head);
        libp2p_gossipsub_rpc_decoder_free(&head->decoder);
        if (head->peer)
            gossipsub_peer_free(head->peer);
        free(head->remote_ip);
        free(head);
        head = next;
    }
}

void gossipsub_peer_retry_backpressure_locked(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    for (gossipsub_peer_entry_t *peer = gs->peers; peer; peer = peer->next)
    {
        if (peer->write_backpressure && peer->stream && peer->sendq_head)
        {
            peer->write_backpressure = 0;
            gossipsub_peer_schedule_flush_locked(gs, peer);
        }
    }
}
