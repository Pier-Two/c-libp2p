#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "gossipsub_host_events.h"

#include <stdio.h>   /* for printf, fflush */
#include <stdlib.h>  /* for malloc, calloc, free */
#include <string.h>  /* for memcpy */

#include "gossipsub_peer.h"
#include "gossipsub_rpc.h"

#include "libp2p/log.h"
#include "libp2p/runtime.h"
#include "libp2p/host.h"
#include "../../../host/host_internal.h"

#define GOSSIPSUB_MODULE "gossipsub"

/* Context for outbound gossipsub stream opening */
typedef struct gossipsub_outbound_dial_ctx
{
    libp2p_gossipsub_t *gs;
    peer_id_t peer;
    size_t protocol_index;
} gossipsub_outbound_dial_ctx_t;

static const char *gossipsub_get_protocol_at_index(libp2p_gossipsub_t *gs, size_t index);
static void gossipsub_outbound_dial_cb(libp2p_stream_t *s, void *user_data, int err);
static void gossipsub_try_open_outbound_stream(libp2p_gossipsub_t *gs, const peer_id_t *peer);

typedef struct gossipsub_decoder_cb_ctx
{
    libp2p_gossipsub_t *gs;
    gossipsub_peer_entry_t *peer;
} gossipsub_decoder_cb_ctx_t;

extern libp2p_err_t gossipsub_handle_rpc_frame(libp2p_gossipsub_t *gs,
                                               gossipsub_peer_entry_t *entry,
                                               const uint8_t *frame,
                                               size_t frame_len);

static libp2p_err_t gossipsub_decoder_cb(const uint8_t *frame, size_t frame_len, void *user_data)
{
    gossipsub_decoder_cb_ctx_t *ctx = (gossipsub_decoder_cb_ctx_t *)user_data;
    if (!ctx || !ctx->gs || !ctx->peer)
        return LIBP2P_ERR_NULL_PTR;
    return gossipsub_handle_rpc_frame(ctx->gs, ctx->peer, frame, frame_len);
}

static const char *const k_gossipsub_protocols[] = {
    "/meshsub/1.1.0",
    "/meshsub/1.2.0",
    "/meshsub/1.0.0"
};

void gossipsub_host_events_populate_protocol_defs(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    const char *const *protocols = gs->cfg.protocol_ids;
    size_t protocol_count = gs->cfg.protocol_id_count;
    if (!protocols || protocol_count == 0)
    {
        protocols = k_gossipsub_protocols;
        protocol_count = sizeof(k_gossipsub_protocols) / sizeof(k_gossipsub_protocols[0]);
    }

    size_t max_defs = sizeof(gs->protocol_defs) / sizeof(gs->protocol_defs[0]);
    gs->num_protocol_defs = 0;
    for (size_t i = 0; i < protocol_count && gs->num_protocol_defs < max_defs; i++)
    {
        const char *pid = protocols[i];
        if (!pid || !pid[0])
            continue;
        libp2p_protocol_def_t *def = &gs->protocol_defs[gs->num_protocol_defs++];
        def->protocol_id = pid;
        def->read_mode = LIBP2P_READ_PUSH;
        def->on_open = gossipsub_on_stream_open;
        def->on_data = gossipsub_on_stream_data;
        def->on_eof = gossipsub_on_stream_eof;
        def->on_close = gossipsub_on_stream_close;
        def->on_error = gossipsub_on_stream_error;
        def->user_data = gs;
    }

    if (gs->num_protocol_defs == 0)
    {
        gs->num_protocol_defs = sizeof(k_gossipsub_protocols) / sizeof(k_gossipsub_protocols[0]);
        if (gs->num_protocol_defs > max_defs)
            gs->num_protocol_defs = max_defs;
        for (size_t i = 0; i < gs->num_protocol_defs; i++)
        {
            libp2p_protocol_def_t *def = &gs->protocol_defs[i];
            def->protocol_id = k_gossipsub_protocols[i];
            def->read_mode = LIBP2P_READ_PUSH;
            def->on_open = gossipsub_on_stream_open;
            def->on_data = gossipsub_on_stream_data;
            def->on_eof = gossipsub_on_stream_eof;
            def->on_close = gossipsub_on_stream_close;
            def->on_error = gossipsub_on_stream_error;
            def->user_data = gs;
        }
    }
}

void *gossipsub_host_events_runtime_thread(void *arg)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)arg;
    if (!gs || !gs->runtime)
        return NULL;
    (void)libp2p_runtime_run(gs->runtime);
    return NULL;
}

void gossipsub_on_stream_open(struct libp2p_stream *s, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (!gs || !s)
        return;

    const char *protocol_id = libp2p_stream_protocol_id(s);
    int is_initiator = libp2p_stream_is_initiator(s);

    pthread_mutex_lock(&gs->lock);
    const peer_id_t *remote = libp2p_stream_remote_peer(s);
    char peer_buf[128] = {0};
    if (remote)
    {
        peer_id_to_string(remote, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
        gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, remote);
        if (entry)
        {
            /* Check for stale stream callback - ignore if this stream was recently detached */
            if (entry->last_detached_stream == s)
            {
                LP_LOGD(GOSSIPSUB_MODULE,
                        "stream_open ignoring stale callback peer=%s stream=%p",
                        peer_buf, (void*)s);
                pthread_mutex_unlock(&gs->lock);
                return;
            }
            entry->connected = 1;
            gossipsub_peer_attach_stream_locked(gs, entry, s);
        }
    }
    pthread_mutex_unlock(&gs->lock);
    LP_LOGD(GOSSIPSUB_MODULE,
            "gossipsub stream opened peer=%s protocol=%s initiator=%d",
            peer_buf[0] ? peer_buf : "(unknown)",
            protocol_id ? protocol_id : "(null)",
            is_initiator);
}

void gossipsub_on_stream_data(struct libp2p_stream *s, const uint8_t *data, size_t len, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (!gs || !s || !data || len == 0)
        return;

    gossipsub_peer_entry_t *entry = NULL;
    pthread_mutex_lock(&gs->lock);
    entry = (gossipsub_peer_entry_t *)libp2p_stream_get_user_data(s);
    pthread_mutex_unlock(&gs->lock);
    if (!entry)
        return;

    gossipsub_decoder_cb_ctx_t ctx = {
        .gs = gs,
        .peer = entry
    };

    /* Log incoming data with hex preview for debugging */
    if (libp2p_log_is_enabled(LIBP2P_LOG_DEBUG))
    {
        static const char hex_digits[] = "0123456789abcdef";
        char preview[130];
        size_t preview_len = len < 64 ? len : 64;
        for (size_t i = 0; i < preview_len; ++i)
        {
            preview[(i * 2) + 0] = hex_digits[(data[i] >> 4) & 0xF];
            preview[(i * 2) + 1] = hex_digits[data[i] & 0xF];
        }
        preview[preview_len * 2] = '\0';
        
        char peer_buf[128] = {0};
        if (entry->peer)
            peer_id_to_string(entry->peer, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
        
        LP_LOGD(GOSSIPSUB_MODULE,
                "stream_data peer=%s len=%zu hex=%s%s",
                peer_buf[0] ? peer_buf : "(unknown)",
                len,
                preview,
                len > 64 ? "..." : "");
    }

    libp2p_err_t rc = libp2p_gossipsub_rpc_decoder_feed(&entry->decoder, data, len, gossipsub_decoder_cb, &ctx);
    if (rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE, "rpc decode error from peer (rc=%d)", rc);
        pthread_mutex_lock(&gs->lock);
        gossipsub_peer_detach_stream_locked(gs, entry, s);
        pthread_mutex_unlock(&gs->lock);
    }
}

void gossipsub_on_stream_eof(struct libp2p_stream *s, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (gs && s)
    {
        pthread_mutex_lock(&gs->lock);
        gossipsub_peer_entry_t *entry = (gossipsub_peer_entry_t *)libp2p_stream_get_user_data(s);
        if (entry)
            gossipsub_peer_detach_stream_locked(gs, entry, s);
        pthread_mutex_unlock(&gs->lock);
    }
    LP_LOGD(GOSSIPSUB_MODULE, "gossipsub stream eof");
}

void gossipsub_on_stream_close(struct libp2p_stream *s, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (gs && s)
    {
        pthread_mutex_lock(&gs->lock);
        gossipsub_peer_entry_t *entry = (gossipsub_peer_entry_t *)libp2p_stream_get_user_data(s);
        if (entry)
            gossipsub_peer_detach_stream_locked(gs, entry, s);
        pthread_mutex_unlock(&gs->lock);
    }
    LP_LOGD(GOSSIPSUB_MODULE, "gossipsub stream closed");
}

void gossipsub_on_stream_error(struct libp2p_stream *s, int err, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (gs && s)
    {
        pthread_mutex_lock(&gs->lock);
        gossipsub_peer_entry_t *entry = (gossipsub_peer_entry_t *)libp2p_stream_get_user_data(s);
        if (entry)
            gossipsub_peer_detach_stream_locked(gs, entry, s);
        pthread_mutex_unlock(&gs->lock);
    }
    LP_LOGW(GOSSIPSUB_MODULE, "gossipsub stream error: %d", err);
}

/* Get protocol ID at given index from gossipsub config */
static const char *gossipsub_get_protocol_at_index(libp2p_gossipsub_t *gs, size_t index)
{
    if (!gs)
        return NULL;
    
    const char *const *protocols = gs->cfg.protocol_ids;
    size_t protocol_count = gs->cfg.protocol_id_count;
    if (!protocols || protocol_count == 0)
    {
        protocols = k_gossipsub_protocols;
        protocol_count = sizeof(k_gossipsub_protocols) / sizeof(k_gossipsub_protocols[0]);
    }
    
    if (index >= protocol_count)
        return NULL;
    return protocols[index];
}

/* Callback when outbound gossipsub stream is opened */
static void gossipsub_outbound_dial_cb(libp2p_stream_t *s, void *user_data, int err)
{
    gossipsub_outbound_dial_ctx_t *ctx = (gossipsub_outbound_dial_ctx_t *)user_data;
    if (!ctx)
        return;
    
    libp2p_gossipsub_t *gs = ctx->gs;
    if (!gs)
    {
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx);
        return;
    }
    
    char peer_buf[128] = {0};
    peer_id_to_string(&ctx->peer, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
    
    if (err == LIBP2P_ERR_OK && s)
    {
        LP_LOGD(GOSSIPSUB_MODULE,
                "outbound gossipsub stream opened peer=%s",
                peer_buf[0] ? peer_buf : "(unknown)");
        gossipsub_on_stream_open(s, gs);
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx);
        return;
    }
    
    LP_LOGD(GOSSIPSUB_MODULE,
            "outbound gossipsub stream failed peer=%s err=%d protocol_index=%zu",
            peer_buf[0] ? peer_buf : "(unknown)",
            err,
            ctx->protocol_index);
    
    /* Try next protocol */
    ctx->protocol_index++;
    const char *next_protocol = gossipsub_get_protocol_at_index(gs, ctx->protocol_index);
    if (next_protocol)
    {
        int rc = libp2p_host_open_stream_async(gs->host, &ctx->peer, next_protocol, gossipsub_outbound_dial_cb, ctx);
        if (rc == LIBP2P_ERR_OK)
            return;
        LP_LOGW(GOSSIPSUB_MODULE, "failed to open next protocol stream (rc=%d)", rc);
    }
    
    /* All protocols exhausted */
    LP_LOGD(GOSSIPSUB_MODULE,
            "outbound gossipsub stream exhausted all protocols peer=%s",
            peer_buf[0] ? peer_buf : "(unknown)");
    if (ctx->peer.bytes)
        peer_id_destroy(&ctx->peer);
    free(ctx);
}

/* Try to open an outbound gossipsub stream to a peer.
 * This is necessary because rust-libp2p only reads from streams where it's the responder.
 * So we need to open an outbound stream (where the remote is the responder) to send our subscriptions.
 * This is independent of any inbound stream the remote may have opened to us.
 */
static void gossipsub_try_open_outbound_stream(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    char peer_buf[128] = {0};
    if (peer)
        peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
    
    if (!gs || !peer || !gs->host)
    {
        LP_LOGW(GOSSIPSUB_MODULE, "try_open_outbound_stream early return: gs=%p peer=%p host=%p",
                (void*)gs, (void*)peer, gs ? (void*)gs->host : NULL);
        return;
    }
    
    LP_LOGI(GOSSIPSUB_MODULE, "try_open_outbound_stream called peer=%s", peer_buf[0] ? peer_buf : "(unknown)");
    
    /* Check if we already initiated an outbound stream to this peer.
     * We track this by checking if the existing stream was initiated by us (initiator=1).
     * If peer has no stream, or has a stream where they initiated (initiator=0),
     * we should open our own outbound stream.
     */
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    int skip_dial = 0;
    int has_stream = 0;
    int is_initiator = 0;
    if (entry && entry->stream)
    {
        has_stream = 1;
        /* If we already have a stream and we're the initiator, skip */
        is_initiator = libp2p_stream_is_initiator(entry->stream);
        if (is_initiator)
            skip_dial = 1;
    }
    pthread_mutex_unlock(&gs->lock);
    
    LP_LOGI(GOSSIPSUB_MODULE, "try_open_outbound peer=%s has_stream=%d is_initiator=%d skip_dial=%d",
            peer_buf[0] ? peer_buf : "(unknown)", has_stream, is_initiator, skip_dial);
    
    if (skip_dial)
    {
        LP_LOGD(GOSSIPSUB_MODULE, "peer already has outbound gossipsub stream, skipping dial");
        return;
    }
    
    const char *protocol = gossipsub_get_protocol_at_index(gs, 0);
    if (!protocol)
    {
        LP_LOGW(GOSSIPSUB_MODULE, "no gossipsub protocols configured");
        return;
    }
    
    gossipsub_outbound_dial_ctx_t *ctx = (gossipsub_outbound_dial_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return;
    
    ctx->gs = gs;
    ctx->protocol_index = 0;
    
    /* Copy peer_id */
    if (peer->bytes && peer->size)
    {
        ctx->peer.bytes = (uint8_t *)malloc(peer->size);
        if (!ctx->peer.bytes)
        {
            free(ctx);
            return;
        }
        memcpy(ctx->peer.bytes, peer->bytes, peer->size);
        ctx->peer.size = peer->size;
    }
    else
    {
        free(ctx);
        return;
    }
    
    LP_LOGI(GOSSIPSUB_MODULE,
            "opening outbound gossipsub stream peer=%s protocol=%s",
            peer_buf[0] ? peer_buf : "(unknown)",
            protocol);
    
    int rc = libp2p_host_open_stream_async(gs->host, peer, protocol, gossipsub_outbound_dial_cb, ctx);
    if (rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE, "failed to open outbound gossipsub stream (rc=%d)", rc);
        if (ctx->peer.bytes)
            peer_id_destroy(&ctx->peer);
        free(ctx);
    }
}

void gossipsub_host_events_on_host_event(const libp2p_event_t *evt, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (!gs || !evt)
        return;

    switch (evt->kind)
    {
        case LIBP2P_EVT_CONN_OPENED:
        {
            char peer_buf[128] = {0};
            if (evt->u.conn_opened.peer)
                peer_id_to_string(evt->u.conn_opened.peer, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
            LP_LOGI(GOSSIPSUB_MODULE, "CONN_OPENED event received peer=%s inbound=%d",
                    peer_buf[0] ? peer_buf : "(null)", evt->u.conn_opened.inbound ? 1 : 0);

            if (evt->u.conn_opened.peer)
            {
                pthread_mutex_lock(&gs->lock);
                gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, evt->u.conn_opened.peer);
                if (entry)
                    entry->connected = 1;
                pthread_mutex_unlock(&gs->lock);

                /* Open an outbound gossipsub stream to the peer.
                 * This ensures we send our subscriptions on a stream where the remote
                 * peer is the responder, which rust-libp2p expects for receiving messages.
                 */
                gossipsub_try_open_outbound_stream(gs, evt->u.conn_opened.peer);
            }
            LP_LOGD(GOSSIPSUB_MODULE, "connection opened (inbound=%d)", evt->u.conn_opened.inbound ? 1 : 0);
            break;
        }
        case LIBP2P_EVT_CONN_CLOSED:
        {
            if (evt->u.conn_closed.peer)
            {
                pthread_mutex_lock(&gs->lock);
                gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, evt->u.conn_closed.peer);
                if (entry)
                {
                    entry->connected = 0;
                    if (entry->explicit_peering)
                        gossipsub_peer_explicit_schedule_dial_locked(gs, entry, 0);
                }
                pthread_mutex_unlock(&gs->lock);
            }
            LP_LOGD(GOSSIPSUB_MODULE, "connection closed (reason=%d)", evt->u.conn_closed.reason);
            break;
        }
        default:
            break;
    }
}
