#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "gossipsub_internal.h"
#include "gossipsub_heartbeat.h"
#include "gossipsub_host_events.h"
#include "gossipsub_peer.h"
#include "gossipsub_propagation.h"
#include "gossipsub_rpc.h"
#include "gossipsub_score.h"
#include "gossipsub_topic.h"
#include "gossipsub_validation.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "libp2p/log.h"
#include "libp2p/protocol.h"
#include "libp2p/stream.h"
#include "../../../host/host_internal.h"

#define GOSSIPSUB_MODULE "gossipsub"
#define GOSSIPSUB_DEFAULT_SEEN_CACHE_CAPACITY 1024U
#define GOSSIPSUB_DEFAULT_SEEN_CACHE_TTL_MS 120000U
#define GOSSIPSUB_DEFAULT_MESSAGE_CACHE_LEN 5U
#define GOSSIPSUB_DEFAULT_MESSAGE_CACHE_GOSSIP 3U
#define GOSSIPSUB_EXPLICIT_ADDR_TTL_MS (10 * 60 * 1000)
#define GOSSIPSUB_DEFAULT_FANOUT_TTL_MS 60000ULL

static const char *gossipsub_peer_to_string(const peer_id_t *peer, char *buffer, size_t length)
{
    if (!peer || !buffer || length == 0)
        return "-";
    int rc = peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, buffer, length);
    if (rc > 0)
        return buffer;
    return "-";
}

static void gossipsub_heartbeat_timer_cb(void *user_data);

static void gossipsub_heartbeat_timer_cb(void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    gossipsub_heartbeat_run(gs);
}

static void gossipsub_opportunistic_timer_cb(void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    gossipsub_opportunistic_run(gs);
}

libp2p_err_t gossipsub_handle_rpc_frame(libp2p_gossipsub_t *gs,
                                               gossipsub_peer_entry_t *entry,
                                               const uint8_t *frame,
                                               size_t frame_len)
{
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t rc = libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &rpc);
    if (rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE,
                "rpc decode failed entry=%p len=%zu rc=%d",
                (void *)entry,
                frame_len,
                rc);
        return rc;
    }

    gossipsub_rpc_parsed_t parsed;
    gossipsub_rpc_parsed_init(&parsed);
    rc = gossipsub_rpc_parse(rpc, &parsed);
    if (rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE,
                "rpc parse failed entry=%p len=%zu rc=%d",
                (void *)entry,
                frame_len,
                rc);
        gossipsub_rpc_parsed_clear(&parsed);
        libp2p_gossipsub_RPC_free(rpc);
        return rc;
    }

    if (libp2p_log_is_enabled(LIBP2P_LOG_TRACE))
    {
        size_t publish_count = libp2p_gossipsub_RPC_has_publish(rpc) ? libp2p_gossipsub_RPC_count_publish(rpc) : 0;
        LP_LOGT(GOSSIPSUB_MODULE,
                "rpc frame entry=%p len=%zu publish=%zu ihave=%zu iwant=%zu graft=%zu prune=%zu",
                (void *)entry,
                frame_len,
                publish_count,
                parsed.ihave_len,
                parsed.iwant_len,
                parsed.graft_len,
                parsed.prune_len);
    }
    if (libp2p_log_is_enabled(LIBP2P_LOG_DEBUG))
    {
        char peer_buf[128];
        const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
        for (size_t i = 0; i < parsed.subscriptions_len; ++i)
        {
            gossipsub_rpc_subscription_t *sub = &parsed.subscriptions[i];
            if (sub && sub->topic)
            {
                LP_LOGD(GOSSIPSUB_MODULE,
                        "rpc trace peer=%s subscribe=%d topic=%s topic_id=%s",
                        peer_repr,
                        sub->subscribe ? 1 : 0,
                        sub->topic,
                        sub->topic_id ? sub->topic_id : "(null)");
            }
        }
        for (size_t i = 0; i < parsed.graft_len; ++i)
        {
            gossipsub_rpc_control_graft_t *g = &parsed.grafts[i];
            if (g && g->topic)
            {
                LP_LOGD(GOSSIPSUB_MODULE,
                        "rpc trace peer=%s graft topic=%s topic_id=%s",
                        peer_repr,
                        g->topic,
                        g->topic_id ? g->topic_id : "(null)");
            }
        }
        for (size_t i = 0; i < parsed.prune_len; ++i)
        {
            gossipsub_rpc_control_prune_t *p = &parsed.prunes[i];
            if (p && p->topic)
            {
                LP_LOGD(GOSSIPSUB_MODULE,
                        "rpc trace peer=%s prune topic=%s topic_id=%s backoff=%" PRIu64 " px=%zu",
                        peer_repr,
                        p->topic,
                        p->topic_id ? p->topic_id : "(null)",
                        (uint64_t)p->backoff,
                        p->px_count);
            }
        }
    }

    rc = gossipsub_propagation_handle_subscriptions(gs, entry, parsed.subscriptions, parsed.subscriptions_len);
    if (rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE,
                "rpc subscription handling failed entry=%p len=%zu rc=%d subs=%zu",
                (void *)entry,
                frame_len,
                rc,
                parsed.subscriptions_len);
        gossipsub_rpc_parsed_clear(&parsed);
        libp2p_gossipsub_RPC_free(rpc);
        return rc;
    }
    /* Ensure mesh is (re)evaluated promptly after learning new subscriptions.
     * The periodic heartbeat will also graft/prune, but running one immediately
     * keeps topic meshes from staying empty when the runtime timer is delayed.
     */
    if (parsed.subscriptions_len > 0)
    {
        LP_LOGD(GOSSIPSUB_MODULE,
                "heartbeat trigger after %zu inbound subscriptions",
                parsed.subscriptions_len);
        LP_LOGD(GOSSIPSUB_MODULE,
                "heartbeat call started=%d",
                gs ? gs->started : -1);
        /* Run a heartbeat inline so we graft immediately after learning
         * about new subscriptions, even if the runtime timer lags.
         */
        if (gs)
        {
            pthread_mutex_lock(&gs->lock);
            int started = gs->started;
            pthread_mutex_unlock(&gs->lock);
            if (started)
            {
                uint64_t now_ms = gossipsub_now_ms();
                LP_LOGD(GOSSIPSUB_MODULE,
                        "heartbeat inline run now_ms=%" PRIu64,
                        now_ms);
                gossipsub_heartbeat_tick(gs, now_ms);
                /* Snapshot mesh state after the heartbeat for debug. */
                pthread_mutex_lock(&gs->lock);
                for (gossipsub_topic_state_t *topic = gs->topics; topic; topic = topic->next)
                {
                    size_t mesh = topic->mesh_size;
                    size_t backoff = topic->backoff_size;
                    size_t fanout = topic->fanout_size;
                    size_t subscribers = 0;
                    for (gossipsub_peer_entry_t *p = gs->peers; p; p = p->next)
                    {
                        if (gossipsub_peer_topic_find(p->topics, topic->name))
                            subscribers++;
                    }
                    LP_LOGD(GOSSIPSUB_MODULE,
                            "mesh snapshot topic=%s mesh=%zu subscribers=%zu backoff=%zu fanout=%zu",
                            topic && topic->name ? topic->name : "(null)",
                            mesh,
                            subscribers,
                            backoff,
                            fanout);
                }
                pthread_mutex_unlock(&gs->lock);
            }
        }
    }

    libp2p_err_t final_rc = LIBP2P_ERR_OK;

    if (libp2p_gossipsub_RPC_has_publish(rpc))
    {
        size_t publish_count = libp2p_gossipsub_RPC_count_publish(rpc);
        char peer_buf[128];
        const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
        LP_LOGD(GOSSIPSUB_MODULE,
                "RPC frame contains %zu publish message(s) from peer=%s",
                publish_count,
                peer_repr);
        for (size_t i = 0; i < publish_count; ++i)
        {
            libp2p_gossipsub_Message *proto_msg = libp2p_gossipsub_RPC_get_at_publish(rpc, i);
            if (!proto_msg)
                continue;
            libp2p_err_t msg_rc = gossipsub_propagation_handle_inbound_publish(gs, entry, proto_msg, frame, frame_len);
            if (msg_rc != LIBP2P_ERR_OK && msg_rc != LIBP2P_ERR_UNSUPPORTED)
            {
                final_rc = msg_rc;
                break;
            }
        }
    }

    libp2p_err_t ctrl_rc = gossipsub_propagation_handle_control_ihave(gs, entry, parsed.ihaves, parsed.ihave_len);
    if (ctrl_rc != LIBP2P_ERR_OK && final_rc == LIBP2P_ERR_OK)
        final_rc = ctrl_rc;

    ctrl_rc = gossipsub_propagation_handle_control_iwant(gs, entry, parsed.iwants, parsed.iwant_len);
    if (ctrl_rc != LIBP2P_ERR_OK && final_rc == LIBP2P_ERR_OK)
        final_rc = ctrl_rc;

    ctrl_rc = gossipsub_propagation_handle_control_graft(gs, entry, parsed.grafts, parsed.graft_len);
    if (ctrl_rc != LIBP2P_ERR_OK && final_rc == LIBP2P_ERR_OK)
        final_rc = ctrl_rc;

    ctrl_rc = gossipsub_propagation_handle_control_prune(gs, entry, parsed.prunes, parsed.prune_len);
    if (ctrl_rc != LIBP2P_ERR_OK && final_rc == LIBP2P_ERR_OK)
        final_rc = ctrl_rc;

    if (final_rc != LIBP2P_ERR_OK)
    {
        size_t ihave_len = parsed.ihave_len;
        size_t iwant_len = parsed.iwant_len;
        size_t graft_len = parsed.graft_len;
        size_t prune_len = parsed.prune_len;
        gossipsub_rpc_parsed_clear(&parsed);
        libp2p_gossipsub_RPC_free(rpc);
        LP_LOGW(GOSSIPSUB_MODULE,
                "rpc handling error entry=%p rc=%d ihave=%zu iwant=%zu graft=%zu prune=%zu",
                (void *)entry,
                final_rc,
                ihave_len,
                iwant_len,
                graft_len,
                prune_len);
        return final_rc;
    }
    gossipsub_rpc_parsed_clear(&parsed);
    libp2p_gossipsub_RPC_free(rpc);
    return final_rc;
}

libp2p_err_t libp2p_gossipsub__inject_frame(libp2p_gossipsub_t *gs,
                                            const peer_id_t *peer,
                                            const uint8_t *frame,
                                            size_t frame_len)
{
    if (!gs || !peer || (frame_len > 0 && !frame))
        return LIBP2P_ERR_NULL_PTR;

    double peer_score = 0.0;
    int explicit_peer = 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, peer);
    if (entry)
    {
        entry->connected = 1;
        peer_score = entry->score;
        explicit_peer = entry->explicit_peering ? 1 : 0;
    }
    pthread_mutex_unlock(&gs->lock);

    if (!entry)
        return LIBP2P_ERR_INTERNAL;

    if (!explicit_peer && peer_score < gs->cfg.graylist_threshold)
    {
        LP_LOGD(GOSSIPSUB_MODULE,
                "graylisting peer rpc (score=%f threshold=%f)",
                peer_score,
                gs->cfg.graylist_threshold);
        return LIBP2P_ERR_OK;
    }

    return gossipsub_handle_rpc_frame(gs, entry, frame, frame_len);
}

static void gossipsub_init_config(libp2p_gossipsub_config_t *dst, const libp2p_gossipsub_config_t *src)
{
    memset(dst, 0, sizeof(*dst));
    if (!src)
    {
        (void)libp2p_gossipsub_config_default(dst);
        return;
    }
    *dst = *src;
    dst->explicit_peers = NULL;
    dst->num_explicit_peers = 0;
    if (dst->message_cache_length == 0)
        dst->message_cache_length = GOSSIPSUB_DEFAULT_MESSAGE_CACHE_LEN;
    if (dst->message_cache_gossip == 0 || dst->message_cache_gossip > dst->message_cache_length)
        dst->message_cache_gossip = (dst->message_cache_length > 0) ? dst->message_cache_length : GOSSIPSUB_DEFAULT_MESSAGE_CACHE_GOSSIP;
    if (dst->px_peer_target == 0)
        dst->px_peer_target = 32;
    size_t publish_threshold_size = offsetof(libp2p_gossipsub_config_t, publish_threshold) + sizeof(dst->publish_threshold);
    if (!src || src->struct_size < publish_threshold_size)
        dst->publish_threshold = 0.0;
    size_t gossip_threshold_size = offsetof(libp2p_gossipsub_config_t, gossip_threshold) + sizeof(dst->gossip_threshold);
    if (!src || src->struct_size < gossip_threshold_size)
        dst->gossip_threshold = 0.0;
    size_t graylist_threshold_size = offsetof(libp2p_gossipsub_config_t, graylist_threshold) + sizeof(dst->graylist_threshold);
    if (!src || src->struct_size < graylist_threshold_size)
        dst->graylist_threshold = -1.0;
    size_t opportunistic_threshold_size = offsetof(libp2p_gossipsub_config_t, opportunistic_graft_threshold) +
                                          sizeof(dst->opportunistic_graft_threshold);
    if (!src || src->struct_size < opportunistic_threshold_size)
        dst->opportunistic_graft_threshold = 0.0;
    size_t opportunistic_peers_size = offsetof(libp2p_gossipsub_config_t, opportunistic_graft_peers) +
                                      sizeof(dst->opportunistic_graft_peers);
    if (!src || src->struct_size < opportunistic_peers_size || dst->opportunistic_graft_peers <= 0)
        dst->opportunistic_graft_peers = 2;
    size_t score_decay_size = offsetof(libp2p_gossipsub_config_t, score_decay_interval_ms) +
                              sizeof(dst->score_decay_interval_ms);
    if (!src || src->struct_size < score_decay_size || dst->score_decay_interval_ms <= 0)
        dst->score_decay_interval_ms = 1000;
    size_t score_cap_size = offsetof(libp2p_gossipsub_config_t, score_time_in_mesh_cap) +
                            sizeof(dst->score_time_in_mesh_cap);
    if (!src || src->struct_size < score_cap_size || dst->score_time_in_mesh_cap <= 0.0)
        dst->score_time_in_mesh_cap = 3600.0;
    size_t followup_size = offsetof(libp2p_gossipsub_config_t, iwant_followup_time_ms) +
                           sizeof(dst->iwant_followup_time_ms);
    if (!src || src->struct_size < followup_size || dst->iwant_followup_time_ms <= 0)
        dst->iwant_followup_time_ms = 3000;
    size_t ihave_msg_size = offsetof(libp2p_gossipsub_config_t, max_ihave_messages) +
                            sizeof(dst->max_ihave_messages);
    if (!src || src->struct_size < ihave_msg_size)
        dst->max_ihave_messages = 10;
    size_t ihave_len_size = offsetof(libp2p_gossipsub_config_t, max_ihave_length) +
                            sizeof(dst->max_ihave_length);
    if (!src || src->struct_size < ihave_len_size)
        dst->max_ihave_length = 5000;
    size_t ihave_penalty_size = offsetof(libp2p_gossipsub_config_t, ihave_spam_penalty) +
                                sizeof(dst->ihave_spam_penalty);
    if (!src || src->struct_size < ihave_penalty_size)
        dst->ihave_spam_penalty = 0.1;
    size_t score_cb_size = offsetof(libp2p_gossipsub_config_t, on_score_update) +
                           sizeof(dst->on_score_update);
    if (!src || src->struct_size < score_cb_size)
        dst->on_score_update = NULL;
    size_t score_cb_ud_size = offsetof(libp2p_gossipsub_config_t, score_update_user_data) +
                              sizeof(dst->score_update_user_data);
    if (!src || src->struct_size < score_cb_ud_size)
        dst->score_update_user_data = NULL;
    size_t app_weight_size = offsetof(libp2p_gossipsub_config_t, app_specific_weight) +
                             sizeof(dst->app_specific_weight);
    if (!src || src->struct_size < app_weight_size)
        dst->app_specific_weight = 1.0;
    size_t ip_weight_size = offsetof(libp2p_gossipsub_config_t, ip_colocation_weight) +
                            sizeof(dst->ip_colocation_weight);
    if (!src || src->struct_size < ip_weight_size)
        dst->ip_colocation_weight = 0.0;
    size_t ip_threshold_size = offsetof(libp2p_gossipsub_config_t, ip_colocation_threshold) +
                               sizeof(dst->ip_colocation_threshold);
    if (!src || src->struct_size < ip_threshold_size || dst->ip_colocation_threshold <= 0)
        dst->ip_colocation_threshold = 1;
    size_t behaviour_weight_size = offsetof(libp2p_gossipsub_config_t, behaviour_penalty_weight) +
                                   sizeof(dst->behaviour_penalty_weight);
    if (!src || src->struct_size < behaviour_weight_size)
        dst->behaviour_penalty_weight = -1.0;
    size_t behaviour_decay_size = offsetof(libp2p_gossipsub_config_t, behaviour_penalty_decay) +
                                  sizeof(dst->behaviour_penalty_decay);
    if (!src || src->struct_size < behaviour_decay_size ||
        dst->behaviour_penalty_decay < 0.0 || dst->behaviour_penalty_decay > 1.0)
        dst->behaviour_penalty_decay = 0.999;

    size_t fanout_ttl_size = offsetof(libp2p_gossipsub_config_t, fanout_ttl_ms) +
                             sizeof(dst->fanout_ttl_ms);
    if (!src || src->struct_size < fanout_ttl_size || dst->fanout_ttl_ms == 0)
        dst->fanout_ttl_ms = GOSSIPSUB_DEFAULT_FANOUT_TTL_MS;

    size_t protocol_ids_field_size = offsetof(libp2p_gossipsub_config_t, protocol_ids) +
                                     sizeof(dst->protocol_ids);
    if (!src || src->struct_size < protocol_ids_field_size)
        dst->protocol_ids = NULL;

    size_t protocol_count_field_size = offsetof(libp2p_gossipsub_config_t, protocol_id_count) +
                                       sizeof(dst->protocol_id_count);
    if (!src || src->struct_size < protocol_count_field_size)
        dst->protocol_id_count = 0;

    size_t anonymous_mode_field_size = offsetof(libp2p_gossipsub_config_t, anonymous_mode) +
                                       sizeof(dst->anonymous_mode);
    if (!src || src->struct_size < anonymous_mode_field_size)
        dst->anonymous_mode = false;
}

libp2p_err_t libp2p_gossipsub_config_default(libp2p_gossipsub_config_t *cfg)
{
    if (!cfg)
        return LIBP2P_ERR_NULL_PTR;

    memset(cfg, 0, sizeof(*cfg));
    cfg->struct_size = sizeof(*cfg);
    cfg->heartbeat_interval_ms = 1000;
    cfg->opportunistic_graft_interval_ms = 60000;
    cfg->score_decay_interval_ms = 1000;
    cfg->prune_backoff_ms = 60000;
    cfg->graft_flood_threshold_ms = 10000;
    cfg->iwant_followup_time_ms = 3000;
    cfg->d = 6;
    cfg->d_lo = 5;
    cfg->d_hi = 12;
    cfg->d_out = 2;
    cfg->d_lazy = 6;
    cfg->d_score = 4;
    cfg->gossip_factor_percent = 25;
    cfg->enable_px = true;
    cfg->enable_flood_publish = false;
    cfg->enable_opportunistic_graft = true;
    cfg->opportunistic_graft_threshold = 0.0;
    cfg->opportunistic_graft_peers = 2;
    cfg->publish_threshold = 0.0;
    cfg->gossip_threshold = 0.0;
    cfg->graylist_threshold = -1.0;
    cfg->accept_px_threshold = 0.0;
    cfg->score_time_in_mesh_cap = 3600.0;
    cfg->seen_cache_capacity = GOSSIPSUB_DEFAULT_SEEN_CACHE_CAPACITY;
    cfg->seen_cache_ttl_ms = GOSSIPSUB_DEFAULT_SEEN_CACHE_TTL_MS;
    cfg->explicit_peers = NULL;
    cfg->num_explicit_peers = 0;
    cfg->runtime = NULL;
    cfg->message_cache_length = GOSSIPSUB_DEFAULT_MESSAGE_CACHE_LEN;
    cfg->message_cache_gossip = GOSSIPSUB_DEFAULT_MESSAGE_CACHE_GOSSIP;
    cfg->px_peer_target = 16;
    cfg->max_ihave_messages = 10;
    cfg->max_ihave_length = 5000;
    cfg->ihave_spam_penalty = 0.1;
    cfg->on_score_update = NULL;
    cfg->score_update_user_data = NULL;
    cfg->app_specific_weight = 1.0;
    cfg->ip_colocation_weight = 0.0;
    cfg->ip_colocation_threshold = 1;
    cfg->behaviour_penalty_weight = -1.0;
    cfg->behaviour_penalty_decay = 0.999;
    cfg->fanout_ttl_ms = GOSSIPSUB_DEFAULT_FANOUT_TTL_MS;
    cfg->protocol_ids = NULL;
    cfg->protocol_id_count = 0;
    cfg->anonymous_mode = false;
    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_validate_config(const libp2p_gossipsub_config_t *cfg)
{
    if (!cfg)
        return LIBP2P_ERR_NULL_PTR;

    if (cfg->d == 0 && cfg->d_lo == 0 && cfg->d_hi == 0 && cfg->d_out == 0)
        return LIBP2P_ERR_OK;

    if (cfg->d <= 0 || cfg->d_lo <= 0 || cfg->d_hi <= 0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid mesh degrees (d=%d d_lo=%d d_hi=%d)",
                cfg->d,
                cfg->d_lo,
                cfg->d_hi);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->d_lo > cfg->d || cfg->d > cfg->d_hi)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "mesh degree out of bounds (d_lo=%d d=%d d_hi=%d)",
                cfg->d_lo,
                cfg->d,
                cfg->d_hi);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->d_score < 0 || cfg->d_score > cfg->d_hi)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid score retention (d_score=%d, d_hi=%d)",
                cfg->d_score,
                cfg->d_hi);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->d_out < 0 || cfg->d_out >= cfg->d_lo || (cfg->d > 0 && (cfg->d_out * 2) >= cfg->d))
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid outbound quota (d_out=%d, d_lo=%d, d=%d)",
                cfg->d_out,
                cfg->d_lo,
                cfg->d);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->d_lazy < 0)
    {
        LP_LOGE(GOSSIPSUB_MODULE, "invalid lazy degree (d_lazy=%d)", cfg->d_lazy);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->gossip_threshold > 0.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE, "invalid gossip threshold (threshold=%f)", cfg->gossip_threshold);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->publish_threshold > cfg->gossip_threshold)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid publish threshold (publish=%f gossip=%f)",
                cfg->publish_threshold,
                cfg->gossip_threshold);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->graylist_threshold > cfg->publish_threshold)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid graylist threshold (graylist=%f publish=%f)",
                cfg->graylist_threshold,
                cfg->publish_threshold);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->accept_px_threshold < 0.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE, "invalid accept PX threshold (threshold=%f)", cfg->accept_px_threshold);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->ihave_spam_penalty < 0.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE, "invalid IHAVE spam penalty (penalty=%f)", cfg->ihave_spam_penalty);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->iwant_followup_time_ms <= 0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid IWANT followup time (followup=%d)",
                cfg->iwant_followup_time_ms);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->app_specific_weight < 0.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid application weight (weight=%f)",
                cfg->app_specific_weight);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->ip_colocation_weight > 0.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid IP colocation weight (weight=%f)",
                cfg->ip_colocation_weight);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->ip_colocation_threshold <= 0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid IP colocation threshold (threshold=%d)",
                cfg->ip_colocation_threshold);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->behaviour_penalty_weight > 0.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid behaviour penalty weight (weight=%f)",
                cfg->behaviour_penalty_weight);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    if (cfg->behaviour_penalty_decay < 0.0 || cfg->behaviour_penalty_decay > 1.0)
    {
        LP_LOGE(GOSSIPSUB_MODULE,
                "invalid behaviour penalty decay (decay=%f)",
                cfg->behaviour_penalty_decay);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_new(libp2p_host_t *host, const libp2p_gossipsub_config_t *cfg, libp2p_gossipsub_t **out)
{
    if (!host || !out)
        return LIBP2P_ERR_NULL_PTR;

    *out = NULL;
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)calloc(1, sizeof(*gs));
    if (!gs)
        return LIBP2P_ERR_INTERNAL;

    gs->host = host;
    gossipsub_init_config(&gs->cfg, cfg);

    libp2p_err_t cfg_rc = gossipsub_validate_config(&gs->cfg);
    if (cfg_rc != LIBP2P_ERR_OK)
    {
        free(gs);
        return cfg_rc;
    }

    if (cfg && cfg->runtime)
    {
        gs->runtime = cfg->runtime;
        gs->owns_runtime = 0;
    }
    else
    {
        gs->runtime = libp2p_runtime_new();
        if (!gs->runtime)
        {
            free(gs);
            return LIBP2P_ERR_INTERNAL;
        }
        gs->owns_runtime = 1;
    }

    if (pthread_mutex_init(&gs->lock, NULL) != 0)
    {
        if (gs->owns_runtime)
            libp2p_runtime_free(gs->runtime);
        free(gs);
        return LIBP2P_ERR_INTERNAL;
    }

    gossipsub_score_init(gs);
    gossipsub_host_events_populate_protocol_defs(gs);

    size_t seen_capacity = gs->cfg.seen_cache_capacity ? gs->cfg.seen_cache_capacity : GOSSIPSUB_DEFAULT_SEEN_CACHE_CAPACITY;
    uint64_t seen_ttl_ms = (gs->cfg.seen_cache_ttl_ms > 0) ? (uint64_t)gs->cfg.seen_cache_ttl_ms : GOSSIPSUB_DEFAULT_SEEN_CACHE_TTL_MS;
    libp2p_err_t seen_rc = gossipsub_seen_cache_init(&gs->seen_cache, seen_capacity, seen_ttl_ms);
    if (seen_rc != LIBP2P_ERR_OK)
    {
        if (gs->owns_runtime)
            libp2p_runtime_free(gs->runtime);
        pthread_mutex_destroy(&gs->lock);
        free(gs);
        return seen_rc;
    }
    atomic_init(&gs->seqno_counter, gossipsub_now_ms());
    gs->gossip_round = 0;
    gossipsub_promises_init(&gs->promises);

    size_t mcache_len = gs->cfg.message_cache_length ? gs->cfg.message_cache_length : GOSSIPSUB_DEFAULT_MESSAGE_CACHE_LEN;
    size_t mcache_gossip = gs->cfg.message_cache_gossip ? gs->cfg.message_cache_gossip : GOSSIPSUB_DEFAULT_MESSAGE_CACHE_GOSSIP;
    if (mcache_gossip > mcache_len)
        mcache_gossip = mcache_len;
    libp2p_err_t cache_rc = gossipsub_message_cache_init(&gs->message_cache, mcache_len, mcache_gossip);
    if (cache_rc != LIBP2P_ERR_OK)
    {
        gossipsub_seen_cache_free(&gs->seen_cache);
        if (gs->owns_runtime)
            libp2p_runtime_free(gs->runtime);
        pthread_mutex_destroy(&gs->lock);
        free(gs);
        return cache_rc;
    }

    if (cfg && cfg->explicit_peers && cfg->num_explicit_peers)
    {
        for (size_t i = 0; i < cfg->num_explicit_peers; i++)
        {
            const libp2p_gossipsub_explicit_peer_t *ep = &cfg->explicit_peers[i];
            if (!ep)
                continue;
            const peer_id_t *peer = ep->peer;
            if (!peer)
                continue;

            peer_id_t *dup = gossipsub_peer_clone(peer);
            if (!dup)
                continue;

            gossipsub_peer_entry_t *entry = (gossipsub_peer_entry_t *)calloc(1, sizeof(*entry));
            if (!entry)
            {
                gossipsub_peer_free(dup);
                continue;
            }
            entry->peer = dup;
            entry->explicit_peering = 1;
            libp2p_gossipsub_rpc_decoder_init(&entry->decoder);
            entry->next = gs->peers;
            gs->peers = entry;

            size_t ep_struct_size = ep->struct_size ? ep->struct_size : sizeof(*ep);
            const char *const *addr_list = NULL;
            size_t addr_count = 0;
            if (ep_struct_size >= offsetof(libp2p_gossipsub_explicit_peer_t, addresses) + sizeof(ep->addresses))
                addr_list = ep->addresses;
            if (ep_struct_size >= offsetof(libp2p_gossipsub_explicit_peer_t, address_count) + sizeof(ep->address_count))
                addr_count = ep->address_count;

            if (gs->host && addr_list && addr_count)
            {
                for (size_t j = 0; j < addr_count; j++)
                {
                    const char *addr_str = addr_list[j];
                    if (!addr_str)
                        continue;
                    int rc = libp2p_host_add_peer_addr_str(gs->host, dup, addr_str, GOSSIPSUB_EXPLICIT_ADDR_TTL_MS);
                    if (rc != LIBP2P_ERR_OK)
                        LP_LOGW(GOSSIPSUB_MODULE, "failed to seed explicit peer addr (rc=%d)", rc);
                }
            }
        }
    }

    *out = gs;
    return LIBP2P_ERR_OK;
}

static void gossipsub_unregister_protocols(libp2p_gossipsub_t *gs)
{
    if (!gs || !gs->host)
        return;
    for (size_t i = 0; i < gs->num_protocol_defs; i++)
    {
        const char *pid = gs->protocol_defs[i].protocol_id;
        if (pid)
            (void)libp2p_unregister_protocol(gs->host, pid);
    }
}

void libp2p_gossipsub_stop(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    int heartbeat_tid = 0;
    int opportunistic_tid = 0;
    pthread_mutex_lock(&gs->lock);
    if (!gs->started)
    {
        pthread_mutex_unlock(&gs->lock);
        return;
    }

    gs->started = 0;
    heartbeat_tid = gs->heartbeat_timer_id;
    gs->heartbeat_timer_id = 0;
    opportunistic_tid = gs->opportunistic_timer_id;
    gs->opportunistic_timer_id = 0;
    gossipsub_promises_clear(&gs->promises);
    pthread_mutex_unlock(&gs->lock);

    if (heartbeat_tid > 0 && gs->runtime)
        libp2p_runtime_cancel_timer(gs->runtime, heartbeat_tid);
    if (opportunistic_tid > 0 && gs->runtime)
        libp2p_runtime_cancel_timer(gs->runtime, opportunistic_tid);

    gossipsub_score_stop_timer(gs);

    gossipsub_unregister_protocols(gs);

    if (gs->host && gs->subscription)
    {
        libp2p_event_unsubscribe(gs->host, gs->subscription);
        gs->subscription = NULL;
    }

    pthread_mutex_lock(&gs->lock);
    for (gossipsub_peer_entry_t *it = gs->peers; it; it = it->next)
        gossipsub_peer_detach_stream_locked(gs, it, it->stream);
    pthread_mutex_unlock(&gs->lock);

    if (gs->owns_runtime && gs->runtime_thread_started)
    {
        libp2p_runtime_stop(gs->runtime);
        pthread_join(gs->runtime_thread, NULL);
        gs->runtime_thread_started = 0;
    }
}

void libp2p_gossipsub_free(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    libp2p_gossipsub_stop(gs);

    gossipsub_score_deinit(gs);
    gossipsub_promises_clear(&gs->promises);
    gossipsub_topics_clear(gs->topics);
    gs->topics = NULL;
    gossipsub_peers_clear(gs);
    gossipsub_seen_cache_free(&gs->seen_cache);
    gossipsub_message_cache_free(&gs->message_cache);

    if (gs->owns_runtime && gs->runtime)
        libp2p_runtime_free(gs->runtime);

    pthread_mutex_destroy(&gs->lock);
    free(gs);
}

libp2p_err_t libp2p_gossipsub_start(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return LIBP2P_ERR_NULL_PTR;

    LP_LOGD(GOSSIPSUB_MODULE, "gossipsub_start num_protocol_defs=%zu", gs->num_protocol_defs);
    for (size_t i = 0; i < gs->num_protocol_defs; i++)
    {
        LP_LOGD(GOSSIPSUB_MODULE, "gossipsub protocol[%zu]=%s", i, gs->protocol_defs[i].protocol_id);
    }

    int need_timer = 0;
    int need_opportunistic_timer = 0;
    pthread_mutex_lock(&gs->lock);
    if (gs->started)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_OK;
    }
    gs->started = 1;
    need_timer = (gs->heartbeat_timer_id <= 0);
    if (gs->cfg.enable_opportunistic_graft && gs->opportunistic_timer_id <= 0 && gs->cfg.opportunistic_graft_interval_ms > 0)
        need_opportunistic_timer = 1;
    pthread_mutex_unlock(&gs->lock);

    for (size_t i = 0; i < gs->num_protocol_defs; i++)
    {
        LP_LOGD(GOSSIPSUB_MODULE, "registering gossipsub protocol %s", gs->protocol_defs[i].protocol_id);
        int rc = libp2p_register_protocol(gs->host, &gs->protocol_defs[i]);
        if (rc != 0)
        {
            LP_LOGE(GOSSIPSUB_MODULE, "failed to register protocol %s (rc=%d)", gs->protocol_defs[i].protocol_id, rc);
            libp2p_gossipsub_stop(gs);
            return LIBP2P_ERR_INTERNAL;
        }
    }

    if (!gs->subscription)
    {
        int rc = libp2p_event_subscribe(gs->host, gossipsub_host_events_on_host_event, gs, &gs->subscription);
        if (rc != 0)
        {
            LP_LOGE(GOSSIPSUB_MODULE, "failed to subscribe to host events (rc=%d)", rc);
            libp2p_gossipsub_stop(gs);
            return LIBP2P_ERR_INTERNAL;
        }
    }

    if (gs->owns_runtime && !gs->runtime_thread_started && gs->runtime)
    {
        if (pthread_create(&gs->runtime_thread, NULL, gossipsub_host_events_runtime_thread, gs) != 0)
        {
            LP_LOGE(GOSSIPSUB_MODULE, "failed to start gossipsub runtime thread");
            libp2p_gossipsub_stop(gs);
            return LIBP2P_ERR_INTERNAL;
        }
        gs->runtime_thread_started = 1;
    }

    if (need_timer && gs->runtime)
    {
        uint64_t interval_ms = (gs->cfg.heartbeat_interval_ms > 0) ? (uint64_t)gs->cfg.heartbeat_interval_ms : 1000ULL;
        int tid = libp2p_runtime_add_timer(gs->runtime, interval_ms, 1, gossipsub_heartbeat_timer_cb, gs);
        if (tid <= 0)
        {
            LP_LOGW(GOSSIPSUB_MODULE, "failed to schedule heartbeat timer");
        }
        else
        {
            pthread_mutex_lock(&gs->lock);
            gs->heartbeat_timer_id = tid;
            pthread_mutex_unlock(&gs->lock);
            gossipsub_heartbeat_run(gs);
        }
    }

    if (need_opportunistic_timer && gs->runtime && gs->cfg.enable_opportunistic_graft)
    {
        uint64_t interval_ms = (gs->cfg.opportunistic_graft_interval_ms > 0) ? (uint64_t)gs->cfg.opportunistic_graft_interval_ms : 60000ULL;
        int tid = libp2p_runtime_add_timer(gs->runtime, interval_ms, 1, gossipsub_opportunistic_timer_cb, gs);
        if (tid <= 0)
        {
            LP_LOGW(GOSSIPSUB_MODULE, "failed to schedule opportunistic graft timer");
        }
        else
        {
            pthread_mutex_lock(&gs->lock);
            gs->opportunistic_timer_id = tid;
            pthread_mutex_unlock(&gs->lock);
            gossipsub_opportunistic_run(gs);
        }
    }

    gossipsub_score_start_timer(gs);

    pthread_mutex_lock(&gs->lock);
    for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
    {
        if (entry->explicit_peering && (!entry->connected || !entry->stream))
            gossipsub_peer_explicit_schedule_dial_locked(gs, entry, 0);
    }
    pthread_mutex_unlock(&gs->lock);

    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_subscribe(libp2p_gossipsub_t *gs, const libp2p_gossipsub_topic_config_t *topic_cfg)
{
    if (!gs)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = NULL;
    libp2p_err_t rc = gossipsub_topic_ensure(gs, topic_cfg, &topic);
    if (rc == LIBP2P_ERR_OK && topic)
    {
        int already_subscribed = topic->subscribed ? 1 : 0;
        if (!already_subscribed)
        {
            topic->subscribed = 1;
            if (topic->name)
            {
                for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
                {
                    if (!entry->connected)
                        continue;
                    (void)gossipsub_peer_send_subscription_locked(gs, entry, topic->name, 1);
                }
            }
        }
    }
    pthread_mutex_unlock(&gs->lock);

    if (rc == LIBP2P_ERR_OK)
        LP_LOGD(GOSSIPSUB_MODULE, "subscribed to topic %s", topic_cfg->descriptor.topic);
    return rc;
}

libp2p_err_t libp2p_gossipsub_unsubscribe(libp2p_gossipsub_t *gs, const char *topic_name)
{
    if (!gs || !topic_name)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    int was_subscribed = topic->subscribed ? 1 : 0;
    topic->subscribed = 0;
    if (was_subscribed)
    {
        for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
        {
            if (!entry->connected)
                continue;
            (void)gossipsub_peer_send_subscription_locked(gs, entry, topic_name, 0);
        }
    }
    pthread_mutex_unlock(&gs->lock);
    LP_LOGD(GOSSIPSUB_MODULE, "unsubscribed from topic %s", topic_name);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_update_topic(libp2p_gossipsub_t *gs,
                                           const libp2p_gossipsub_topic_config_t *topic_cfg)
{
    if (!gs || !topic_cfg)
        return LIBP2P_ERR_NULL_PTR;

    size_t descriptor_size = offsetof(libp2p_gossipsub_topic_config_t, descriptor) + sizeof(topic_cfg->descriptor);
    if (topic_cfg->struct_size < descriptor_size)
        return LIBP2P_ERR_UNSUPPORTED;

    const char *topic_name = topic_cfg->descriptor.topic;
    if (!topic_name)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    size_t score_field_size = offsetof(libp2p_gossipsub_topic_config_t, score_params) +
                              sizeof(topic_cfg->score_params);
    if (topic_cfg->struct_size >= score_field_size)
    {
        if (topic_cfg->score_params)
        {
            topic->score_params = *topic_cfg->score_params;
            topic->has_score_params = 1;
        }
        else
        {
            memset(&topic->score_params, 0, sizeof(topic->score_params));
            topic->has_score_params = 0;
        }
    }
    else if (topic_cfg->score_params)
    {
        topic->score_params = *topic_cfg->score_params;
        topic->has_score_params = 1;
    }

    size_t publish_field_size = offsetof(libp2p_gossipsub_topic_config_t, publish_threshold) +
                                sizeof(topic_cfg->publish_threshold);
    if (topic_cfg->struct_size >= publish_field_size)
    {
        topic->publish_threshold = topic_cfg->publish_threshold;
        topic->has_publish_threshold = 1;
    }

    size_t message_id_field_size = offsetof(libp2p_gossipsub_topic_config_t, message_id_user_data) +
                                   sizeof(topic_cfg->message_id_user_data);
    if (topic_cfg->struct_size >= message_id_field_size)
    {
        topic->message_id_fn = topic_cfg->message_id_fn;
        topic->message_id_user_data = topic_cfg->message_id_user_data;
    }

    uint64_t now_ms = gossipsub_now_ms();
    gossipsub_score_on_heartbeat_locked(gs, now_ms);
    pthread_mutex_unlock(&gs->lock);

    LP_LOGD(GOSSIPSUB_MODULE, "updated topic configuration for %s", topic_name);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_publish(libp2p_gossipsub_t *gs, const libp2p_gossipsub_message_t *msg)
{
    if (!gs || !msg || !msg->topic.topic)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_topic_state_t *topic = NULL;
    libp2p_gossipsub_validator_handle_t **validators = NULL;
    size_t validator_count = 0;
    libp2p_err_t rc = gossipsub_validation_collect(gs, msg->topic.topic, &topic, &validators, &validator_count);
    if (rc != LIBP2P_ERR_OK)
        return (rc == LIBP2P_ERR_UNSUPPORTED) ? LIBP2P_ERR_INTERNAL : rc;

    return gossipsub_validation_schedule(gs, topic, validators, validator_count, msg, 1);
}

libp2p_err_t libp2p_gossipsub_peering_add(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
    {
        peer_id_t *dup = gossipsub_peer_clone(peer);
        if (!dup)
        {
            pthread_mutex_unlock(&gs->lock);
            return LIBP2P_ERR_INTERNAL;
        }
        entry = (gossipsub_peer_entry_t *)calloc(1, sizeof(*entry));
        if (!entry)
        {
            pthread_mutex_unlock(&gs->lock);
            gossipsub_peer_free(dup);
            return LIBP2P_ERR_INTERNAL;
        }
        entry->peer = dup;
        entry->explicit_peering = 1;
        entry->connected = 0;
        libp2p_gossipsub_rpc_decoder_init(&entry->decoder);
        entry->next = gs->peers;
        gs->peers = entry;
    }
    else
    {
        entry->explicit_peering = 1;
    }
    gossipsub_topics_remove_peer_locked(gs, entry->peer);
    if (gs->started)
        gossipsub_peer_explicit_schedule_dial_locked(gs, entry, 0);
    pthread_mutex_unlock(&gs->lock);

    LP_LOGD(GOSSIPSUB_MODULE, "added explicit peer");
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_peering_remove(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t **pp = &gs->peers;
    while (*pp)
    {
        if (peer_id_equals((*pp)->peer, peer) == 1)
        {
            gossipsub_peer_entry_t *victim = *pp;
            *pp = victim->next;
            gossipsub_peer_explicit_cancel_timer_locked(gs, victim);
            gossipsub_peer_detach_stream_locked(gs, victim, victim->stream);
            gossipsub_peer_sendq_clear(victim);
            gossipsub_topics_remove_peer_locked(gs, victim->peer);
            gossipsub_score_on_peer_removed_locked(gs, victim);
            gossipsub_peer_topics_clear(victim);
            libp2p_gossipsub_rpc_decoder_free(&victim->decoder);
            free(victim->remote_ip);
            pthread_mutex_unlock(&gs->lock);
            gossipsub_peer_free(victim->peer);
            free(victim);
            LP_LOGD(GOSSIPSUB_MODULE, "removed explicit peer");
            return LIBP2P_ERR_OK;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_INTERNAL;
}

libp2p_err_t libp2p_gossipsub_set_peer_application_score(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer,
                                                         double score)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    uint64_t now_ms = gossipsub_now_ms();
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->application_score = score;
    gossipsub_score_recompute_peer_locked(gs, entry, now_ms);
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_set_peer_behaviour_penalty(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer,
                                                         double penalty)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    uint64_t now_ms = gossipsub_now_ms();
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    if (penalty < 0.0)
        penalty = 0.0;
    entry->behaviour_penalty = penalty;
    gossipsub_score_recompute_peer_locked(gs, entry, now_ms);
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_add_peer_behaviour_penalty(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer,
                                                         double delta)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;
    if (delta == 0.0)
        return LIBP2P_ERR_OK;

    uint64_t now_ms = gossipsub_now_ms();
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->behaviour_penalty += delta;
    if (entry->behaviour_penalty < 0.0)
        entry->behaviour_penalty = 0.0;
    gossipsub_score_recompute_peer_locked(gs, entry, now_ms);
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

int libp2p_gossipsub__peer_has_subscription(libp2p_gossipsub_t *gs,
                                             const peer_id_t *peer,
                                             const char *topic_name)
{
    if (!gs || !peer || !topic_name)
        return 0;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    gossipsub_peer_topic_t *node = entry ? gossipsub_peer_topic_find(entry->topics, topic_name) : NULL;
    pthread_mutex_unlock(&gs->lock);
    return node ? 1 : 0;
}

size_t libp2p_gossipsub__topic_mesh_size(libp2p_gossipsub_t *gs, const char *topic_name)
{
    if (!gs || !topic_name)
        return 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    size_t size = topic ? topic->mesh_size : 0;
    pthread_mutex_unlock(&gs->lock);
    return size;
}

int libp2p_gossipsub__topic_mesh_contains(libp2p_gossipsub_t *gs,
                                          const char *topic_name,
                                          const peer_id_t *peer,
                                          int *out_outbound,
                                          uint64_t *out_last_heartbeat_ms)
{
    if (!gs || !topic_name || !peer)
        return 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    gossipsub_mesh_member_t *member = topic ? gossipsub_mesh_member_find(topic->mesh, peer) : NULL;
    if (member)
    {
        if (out_outbound)
            *out_outbound = member->outbound;
        if (out_last_heartbeat_ms)
            *out_last_heartbeat_ms = member->last_heartbeat_ms;
    }
    pthread_mutex_unlock(&gs->lock);
    return member ? 1 : 0;
}

libp2p_err_t libp2p_gossipsub__topic_mesh_add_peer(libp2p_gossipsub_t *gs,
                                                   const char *topic_name,
                                                   const peer_id_t *peer,
                                                   int outbound_hint)
{
    if (!gs || !topic_name || !peer)
        return LIBP2P_ERR_NULL_PTR;

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

    gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }

    int outbound = outbound_hint;
    if (outbound < 0)
        outbound = entry->outbound_stream;
    outbound = outbound ? 1 : 0;
    uint64_t now_ms = gossipsub_now_ms();
    if (!gossipsub_mesh_member_insert(topic, entry, outbound, now_ms))
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }

    gossipsub_score_on_mesh_join_locked(gs, topic, entry, now_ms);

    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__topic_mesh_remove_peer(libp2p_gossipsub_t *gs,
                                                      const char *topic_name,
                                                      const peer_id_t *peer)
{
    if (!gs || !topic_name || !peer)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_OK;
    }
    int removed = gossipsub_mesh_member_remove(topic, peer);
    if (removed)
    {
        uint64_t now_ms = gossipsub_now_ms();
        gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
        if (entry && !entry->explicit_peering && entry->score < 0.0)
            gossipsub_score_on_prune_negative_locked(gs, topic, entry, now_ms);
        gossipsub_score_on_mesh_leave_locked(gs, topic, peer, now_ms);
    }
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

size_t libp2p_gossipsub__topic_fanout_size(libp2p_gossipsub_t *gs, const char *topic_name)
{
    if (!gs || !topic_name)
        return 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    size_t size = topic ? topic->fanout_size : 0;
    pthread_mutex_unlock(&gs->lock);
    return size;
}

uint64_t libp2p_gossipsub__topic_fanout_expire_ms(libp2p_gossipsub_t *gs, const char *topic_name)
{
    if (!gs || !topic_name)
        return 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    uint64_t expire = topic ? topic->fanout_expire_ms : 0;
    pthread_mutex_unlock(&gs->lock);
    return expire;
}

int libp2p_gossipsub__topic_fanout_contains(libp2p_gossipsub_t *gs,
                                            const char *topic_name,
                                            const peer_id_t *peer,
                                            int *out_outbound,
                                            uint64_t *out_last_publish_ms)
{
    if (!gs || !topic_name || !peer)
        return 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    gossipsub_fanout_peer_t *node = topic ? gossipsub_fanout_find(topic->fanout, peer) : NULL;
    if (node)
    {
        if (out_outbound)
            *out_outbound = node->outbound;
        if (out_last_publish_ms)
            *out_last_publish_ms = node->last_publish_ms;
    }
    pthread_mutex_unlock(&gs->lock);
    return node ? 1 : 0;
}

libp2p_err_t libp2p_gossipsub__topic_fanout_add_peer(libp2p_gossipsub_t *gs,
                                                     const char *topic_name,
                                                     const peer_id_t *peer,
                                                     int outbound_hint,
                                                     uint64_t ttl_ms)
{
    if (!gs || !topic_name || !peer)
        return LIBP2P_ERR_NULL_PTR;

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

    gossipsub_peer_entry_t *entry = gossipsub_peer_find_or_add_locked(gs, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }

    int outbound = outbound_hint;
    if (outbound < 0)
        outbound = entry->outbound_stream;
    outbound = outbound ? 1 : 0;
    uint64_t now_ms = gossipsub_now_ms();
    if (!gossipsub_fanout_add(topic, entry, outbound, now_ms))
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }

    uint64_t effective_ttl = ttl_ms;
    if (effective_ttl == 0)
    {
        uint64_t cfg_ttl = (gs->cfg.fanout_ttl_ms > 0) ? gs->cfg.fanout_ttl_ms : GOSSIPSUB_DEFAULT_FANOUT_TTL_MS;
        effective_ttl = cfg_ttl;
    }

    if (effective_ttl >= UINT64_MAX - now_ms)
        topic->fanout_expire_ms = UINT64_MAX;
    else
        topic->fanout_expire_ms = now_ms + effective_ttl;

    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__topic_fanout_remove_peer(libp2p_gossipsub_t *gs,
                                                        const char *topic_name,
                                                        const peer_id_t *peer)
{
    if (!gs || !topic_name || !peer)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_OK;
    }
    (void)gossipsub_fanout_remove(topic, peer);
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__heartbeat(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_heartbeat_run(gs);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__opportunistic(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_opportunistic_run(gs);
    return LIBP2P_ERR_OK;
}

int libp2p_gossipsub__message_in_cache(libp2p_gossipsub_t *gs,
                                       const uint8_t *message_id,
                                       size_t message_id_len)
{
    if (!gs || !message_id || message_id_len == 0)
        return 0;
    int found = 0;
    pthread_mutex_lock(&gs->lock);
    if (gossipsub_message_cache_find(&gs->message_cache, message_id, message_id_len))
        found = 1;
    pthread_mutex_unlock(&gs->lock);
    return found;
}

size_t libp2p_gossipsub__peer_sendq_len(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer)
        return 0;
    size_t count = 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (entry)
    {
        for (gossipsub_sendq_item_t *it = entry->sendq_head; it; it = it->next)
            count++;
    }
    pthread_mutex_unlock(&gs->lock);
    return count;
}

libp2p_err_t libp2p_gossipsub__peer_set_connected(libp2p_gossipsub_t *gs,
                                                  const peer_id_t *peer,
                                                  int connected)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->connected = connected ? 1 : 0;
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__peer_set_score(libp2p_gossipsub_t *gs,
                                              const peer_id_t *peer,
                                              double score)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->score = score;
    entry->score_override = 1;
    gossipsub_score_emit_update_locked(gs, entry);
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__peer_clear_score_override(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->score_override = 0;
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

void libp2p_gossipsub__set_publish_threshold(libp2p_gossipsub_t *gs, double threshold)
{
    if (!gs)
        return;
    pthread_mutex_lock(&gs->lock);
    gs->cfg.publish_threshold = threshold;
    pthread_mutex_unlock(&gs->lock);
}

void libp2p_gossipsub__set_gossip_threshold(libp2p_gossipsub_t *gs, double threshold)
{
    if (!gs)
        return;
    pthread_mutex_lock(&gs->lock);
    gs->cfg.gossip_threshold = threshold;
    pthread_mutex_unlock(&gs->lock);
}

void libp2p_gossipsub__set_graylist_threshold(libp2p_gossipsub_t *gs, double threshold)
{
    if (!gs)
        return;
    pthread_mutex_lock(&gs->lock);
    gs->cfg.graylist_threshold = threshold;
    pthread_mutex_unlock(&gs->lock);
}

double libp2p_gossipsub__peer_get_score(libp2p_gossipsub_t *gs,
                                        const peer_id_t *peer,
                                        int *out_override)
{
    if (out_override)
        *out_override = 0;
    if (!gs || !peer)
        return 0.0;

    double score = 0.0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (entry)
    {
        score = entry->score;
        if (out_override)
            *out_override = entry->score_override ? 1 : 0;
    }
    pthread_mutex_unlock(&gs->lock);
    return score;
}

libp2p_err_t libp2p_gossipsub__peer_set_remote_ip(libp2p_gossipsub_t *gs,
                                                  const peer_id_t *peer,
                                                  const char *ip)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }

    char *dup = NULL;
    if (ip)
    {
        dup = strdup(ip);
        if (!dup)
        {
            pthread_mutex_unlock(&gs->lock);
            return LIBP2P_ERR_INTERNAL;
        }
    }

    free(entry->remote_ip);
    entry->remote_ip = dup;
    gossipsub_score_recompute_peer_locked(gs, entry, gossipsub_now_ms());
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

void libp2p_gossipsub__set_flood_publish(libp2p_gossipsub_t *gs, int enable)
{
    if (!gs)
        return;
    pthread_mutex_lock(&gs->lock);
    gs->cfg.enable_flood_publish = enable ? true : false;
    pthread_mutex_unlock(&gs->lock);
}

libp2p_err_t libp2p_gossipsub__topic_set_publish_threshold(libp2p_gossipsub_t *gs,
                                                           const char *topic_name,
                                                           double threshold)
{
    if (!gs || !topic_name)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    topic->publish_threshold = threshold;
    topic->has_publish_threshold = 1;
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__peer_clear_sendq(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    gossipsub_peer_sendq_clear(entry);
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub__peer_pop_sendq(libp2p_gossipsub_t *gs,
                                              const peer_id_t *peer,
                                              uint8_t **out_buf,
                                              size_t *out_len)
{
    if (!gs || !peer || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    libp2p_err_t rc = entry ? gossipsub_peer_sendq_pop_locked(entry, out_buf, out_len) : LIBP2P_ERR_INTERNAL;
    pthread_mutex_unlock(&gs->lock);
    return rc;
}

int libp2p_gossipsub__topic_backoff_contains(libp2p_gossipsub_t *gs,
                                             const char *topic_name,
                                             const peer_id_t *peer)
{
    if (!gs || !topic_name || !peer)
        return 0;

    int present = 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (topic)
    {
        uint64_t now_ms = gossipsub_now_ms();
        present = gossipsub_backoff_contains(topic, peer, now_ms);
    }
    pthread_mutex_unlock(&gs->lock);
    return present;
}

int libp2p_gossipsub__peer_explicit_timer_id(libp2p_gossipsub_t *gs,
                                             const peer_id_t *peer)
{
    if (!gs || !peer)
        return 0;
    int timer_id = 0;
    pthread_mutex_lock(&gs->lock);
    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (entry)
        timer_id = entry->explicit_dial_timer_id;
    pthread_mutex_unlock(&gs->lock);
    return timer_id;
}
