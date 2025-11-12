#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "gossipsub_host_events.h"

#include "gossipsub_peer.h"
#include "gossipsub_rpc.h"

#include "libp2p/log.h"
#include "libp2p/runtime.h"
#include "../../../host/host_internal.h"

#define GOSSIPSUB_MODULE "gossipsub"

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
    pthread_mutex_lock(&gs->lock);
    const peer_id_t *remote = libp2p_stream_remote_peer(s);
    if (remote)
    {
        gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, remote);
        if (entry)
        {
            entry->connected = 1;
            gossipsub_peer_attach_stream_locked(gs, entry, s);
        }
    }
    pthread_mutex_unlock(&gs->lock);
    LP_LOGD(GOSSIPSUB_MODULE, "incoming gossipsub stream opened");
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

    LP_LOGT(GOSSIPSUB_MODULE,
            "stream data entry=%p len=%zu",
            (void *)entry,
            len);
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

void gossipsub_host_events_on_host_event(const libp2p_event_t *evt, void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (!gs || !evt)
        return;

    switch (evt->kind)
    {
        case LIBP2P_EVT_CONN_OPENED:
            if (evt->u.conn_opened.peer)
            {
                pthread_mutex_lock(&gs->lock);
                gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, evt->u.conn_opened.peer);
                if (entry)
                    entry->connected = 1;
                pthread_mutex_unlock(&gs->lock);
            }
            LP_LOGD(GOSSIPSUB_MODULE, "connection opened (inbound=%d)", evt->u.conn_opened.inbound ? 1 : 0);
            break;
        case LIBP2P_EVT_CONN_CLOSED:
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
        default:
            break;
    }
}
