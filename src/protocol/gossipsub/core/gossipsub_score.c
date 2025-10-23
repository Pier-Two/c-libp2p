#include "gossipsub_score.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libp2p/runtime.h"
#include "gossipsub_peer.h"

#define PARAM_HAS(params, field)                                                                                       \
    ((params) &&                                                                                                       \
     (params)->struct_size >= offsetof(libp2p_gossipsub_topic_score_params_t, field) +                                 \
                                    sizeof((params)->field))

static double gossipsub_score_param_topic_weight(const libp2p_gossipsub_topic_score_params_t *params)
{
    if (PARAM_HAS(params, topic_weight) && params->topic_weight != 0.0)
        return params->topic_weight;
    return 1.0;
}

static void gossipsub_score_notify_locked(libp2p_gossipsub_t *gs,
                                          gossipsub_peer_entry_t *entry,
                                          double score,
                                          int override_flag)
{
    if (!gs || !entry || !entry->peer || !gs->cfg.on_score_update)
        return;

    libp2p_gossipsub_score_update_t update = {
        .struct_size = sizeof(update),
        .peer = entry->peer,
        .score = score,
        .score_override = override_flag ? 1 : 0
    };
    gs->cfg.on_score_update(gs, &update, gs->cfg.score_update_user_data);
}

static double gossipsub_score_param_time_in_mesh_weight(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, time_in_mesh_weight) ? params->time_in_mesh_weight : 0.0;
}

static double gossipsub_score_param_time_in_mesh_cap(const libp2p_gossipsub_topic_score_params_t *params,
                                                     const libp2p_gossipsub_config_t *cfg)
{
    if (PARAM_HAS(params, time_in_mesh_cap) && params->time_in_mesh_cap > 0.0)
        return params->time_in_mesh_cap;
    if (cfg && cfg->score_time_in_mesh_cap > 0.0)
        return cfg->score_time_in_mesh_cap;
    return 0.0;
}

static double gossipsub_score_param_first_weight(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, first_message_deliveries_weight) ? params->first_message_deliveries_weight : 0.0;
}

static double gossipsub_score_param_first_decay(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, first_message_deliveries_decay) ? params->first_message_deliveries_decay : 1.0;
}

static double gossipsub_score_param_first_cap(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, first_message_deliveries_cap) ? params->first_message_deliveries_cap : 0.0;
}

static double gossipsub_score_param_mesh_weight(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, mesh_message_deliveries_weight) ? params->mesh_message_deliveries_weight : 0.0;
}

static double gossipsub_score_param_mesh_decay(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, mesh_message_deliveries_decay) ? params->mesh_message_deliveries_decay : 1.0;
}

static double gossipsub_score_param_mesh_threshold(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, mesh_message_delivery_threshold) ? params->mesh_message_delivery_threshold : 0.0;
}

static double gossipsub_score_param_mesh_cap(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, mesh_message_deliveries_cap) ? params->mesh_message_deliveries_cap : 0.0;
}

static double gossipsub_score_param_mesh_failure_weight(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, mesh_failure_penalty_weight) ? params->mesh_failure_penalty_weight : 0.0;
}

static double gossipsub_score_param_mesh_failure_decay(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, mesh_failure_penalty_decay) ? params->mesh_failure_penalty_decay : 1.0;
}

static double gossipsub_score_param_invalid_weight(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, invalid_message_deliveries_weight) ? params->invalid_message_deliveries_weight : 0.0;
}

static double gossipsub_score_param_invalid_decay(const libp2p_gossipsub_topic_score_params_t *params)
{
    return PARAM_HAS(params, invalid_message_deliveries_decay) ? params->invalid_message_deliveries_decay : 1.0;
}

static double gossipsub_score_decay_value(double value, double decay)
{
    if (decay <= 0.0 || decay >= 1.0)
        return value;
    value *= decay;
    if (value > -1e-9 && value < 1e-9)
        return 0.0;
    return value;
}

static gossipsub_peer_topic_t *gossipsub_score_find_topic(gossipsub_peer_entry_t *entry,
                                                          const char *topic_name)
{
    if (!entry || !topic_name)
        return NULL;
    for (gossipsub_peer_topic_t *node = entry->topics; node; node = node->next)
    {
        if (node->name && strcmp(node->name, topic_name) == 0)
            return node;
    }
    return NULL;
}

static void gossipsub_score_touch_topic(gossipsub_peer_topic_t *topic_state, uint64_t now_ms)
{
    if (!topic_state)
        return;
    if (topic_state->in_mesh)
    {
        if (now_ms >= topic_state->last_mesh_update_ms)
            topic_state->mesh_time_accum_ms += now_ms - topic_state->last_mesh_update_ms;
        topic_state->last_mesh_update_ms = now_ms;
    }
    else
    {
        topic_state->last_mesh_update_ms = now_ms;
    }
}

static gossipsub_topic_state_t *gossipsub_score_lookup_topic(libp2p_gossipsub_t *gs,
                                                             const char *topic_name)
{
    if (!gs || !topic_name)
        return NULL;
    for (gossipsub_topic_state_t *topic = gs->topics; topic; topic = topic->next)
    {
        if (topic->name && strcmp(topic->name, topic_name) == 0)
            return topic;
    }
    return NULL;
}

static double gossipsub_score_compute_time_in_mesh_seconds(libp2p_gossipsub_t *gs,
                                                           gossipsub_peer_topic_t *topic_state,
                                                           const libp2p_gossipsub_topic_score_params_t *params)
{
    if (!gs || !topic_state || !topic_state->in_mesh)
        return 0.0;

    double cap_seconds = gossipsub_score_param_time_in_mesh_cap(params, &gs->cfg);
    uint64_t accum_ms = topic_state->mesh_time_accum_ms;
    if (cap_seconds > 0.0)
    {
        double cap_ms_d = cap_seconds * 1000.0;
        if (cap_ms_d > (double)UINT64_MAX)
            cap_ms_d = (double)UINT64_MAX;
        uint64_t cap_ms = (uint64_t)cap_ms_d;
        if (cap_ms > 0 && accum_ms > cap_ms)
        {
            accum_ms = cap_ms;
            topic_state->mesh_time_accum_ms = cap_ms;
        }
    }

    return (double)accum_ms / 1000.0;
}

static void gossipsub_score_apply_caps(gossipsub_peer_topic_t *topic_state,
                                       const libp2p_gossipsub_topic_score_params_t *params)
{
    if (!topic_state || !params)
        return;

    double first_cap = gossipsub_score_param_first_cap(params);
    if (first_cap > 0.0 && topic_state->first_message_deliveries > first_cap)
        topic_state->first_message_deliveries = first_cap;

    double mesh_cap = gossipsub_score_param_mesh_cap(params);
    if (mesh_cap > 0.0 && topic_state->mesh_message_deliveries > mesh_cap)
        topic_state->mesh_message_deliveries = mesh_cap;
}

static double gossipsub_score_compute_ip_colocation_locked(libp2p_gossipsub_t *gs,
                                                           gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry || !entry->remote_ip)
        return 0.0;
    if (gs->cfg.ip_colocation_threshold <= 0)
        return 0.0;

    size_t count = 0;
    for (gossipsub_peer_entry_t *node = gs->peers; node; node = node->next)
    {
        if (node->remote_ip && strcmp(node->remote_ip, entry->remote_ip) == 0)
            count++;
    }

    if (count <= (size_t)gs->cfg.ip_colocation_threshold)
        return 0.0;

    double surplus = (double)(count - (size_t)gs->cfg.ip_colocation_threshold);
    return surplus * surplus;
}

static double gossipsub_score_compute_topic_score(libp2p_gossipsub_t *gs,
                                                  gossipsub_topic_state_t *topic,
                                                  gossipsub_peer_topic_t *topic_state)
{
    if (!gs || !topic_state || !topic || !topic->has_score_params)
        return 0.0;

    const libp2p_gossipsub_topic_score_params_t *params = &topic->score_params;
    double topic_weight = gossipsub_score_param_topic_weight(params);
    double total = 0.0;

    double time_weight = gossipsub_score_param_time_in_mesh_weight(params);
    if (time_weight != 0.0)
    {
        double seconds = gossipsub_score_compute_time_in_mesh_seconds(gs, topic_state, params);
        total += time_weight * seconds;
    }

    double first_weight = gossipsub_score_param_first_weight(params);
    if (first_weight != 0.0)
        total += first_weight * topic_state->first_message_deliveries;

    double mesh_weight = gossipsub_score_param_mesh_weight(params);
    if (mesh_weight != 0.0)
    {
        double threshold = gossipsub_score_param_mesh_threshold(params);
        double p3 = 0.0;
        if (threshold > 0.0)
        {
            double deficit = threshold - topic_state->mesh_message_deliveries;
            if (deficit > 0.0)
                p3 = deficit * deficit;
        }
        total += mesh_weight * p3;
    }

    double failure_weight = gossipsub_score_param_mesh_failure_weight(params);
    if (failure_weight != 0.0)
        total += failure_weight * topic_state->mesh_failure_penalty;

    double invalid_weight = gossipsub_score_param_invalid_weight(params);
    if (invalid_weight != 0.0)
        total += invalid_weight * topic_state->invalid_message_deliveries;

    return topic_weight * total;
}

static void gossipsub_score_update_entry_locked(libp2p_gossipsub_t *gs,
                                                gossipsub_peer_entry_t *entry,
                                                uint64_t now_ms)
{
    if (!gs || !entry)
        return;

    double total = 0.0;
    if (gs->cfg.app_specific_weight != 0.0)
        total += gs->cfg.app_specific_weight * entry->application_score;

    if (gs->cfg.behaviour_penalty_weight != 0.0 && entry->behaviour_penalty != 0.0)
    {
        double penalty = entry->behaviour_penalty;
        if (penalty < 0.0)
            penalty = -penalty;
        total += gs->cfg.behaviour_penalty_weight * (penalty * penalty);
    }

    if (gs->cfg.ip_colocation_weight != 0.0)
    {
        double ip_factor = gossipsub_score_compute_ip_colocation_locked(gs, entry);
        if (ip_factor != 0.0)
            total += gs->cfg.ip_colocation_weight * ip_factor;
    }

    for (gossipsub_peer_topic_t *topic_state = entry->topics; topic_state; topic_state = topic_state->next)
    {
        gossipsub_score_touch_topic(topic_state, now_ms);
        gossipsub_topic_state_t *topic = gossipsub_score_lookup_topic(gs, topic_state->name);
        double topic_score = gossipsub_score_compute_topic_score(gs, topic, topic_state);
        topic_state->topic_score = topic_score;
        total += topic_score;
    }

    if (!entry->score_override)
    {
        double previous = entry->score;
        entry->score = total;
        if (fabs(previous - entry->score) > 1e-9)
            gossipsub_score_notify_locked(gs, entry, entry->score, 0);
    }
}

static void gossipsub_score_apply_topic_decay(gossipsub_peer_topic_t *topic_state,
                                              gossipsub_topic_state_t *topic)
{
    if (!topic_state || !topic || !topic->has_score_params)
        return;

    const libp2p_gossipsub_topic_score_params_t *params = &topic->score_params;

    topic_state->first_message_deliveries =
        gossipsub_score_decay_value(topic_state->first_message_deliveries,
                                    gossipsub_score_param_first_decay(params));
    topic_state->mesh_message_deliveries =
        gossipsub_score_decay_value(topic_state->mesh_message_deliveries,
                                    gossipsub_score_param_mesh_decay(params));
    topic_state->mesh_failure_penalty =
        gossipsub_score_decay_value(topic_state->mesh_failure_penalty,
                                    gossipsub_score_param_mesh_failure_decay(params));
    topic_state->invalid_message_deliveries =
        gossipsub_score_decay_value(topic_state->invalid_message_deliveries,
                                    gossipsub_score_param_invalid_decay(params));

    gossipsub_score_apply_caps(topic_state, params);
}

static void gossipsub_score_apply_decay_locked(libp2p_gossipsub_t *gs, uint64_t now_ms)
{
    if (!gs)
        return;

    for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
    {
        for (gossipsub_peer_topic_t *topic_state = entry->topics; topic_state; topic_state = topic_state->next)
        {
            gossipsub_topic_state_t *topic = gossipsub_score_lookup_topic(gs, topic_state->name);
            gossipsub_score_apply_topic_decay(topic_state, topic);
        }
        if (gs->cfg.behaviour_penalty_decay >= 0.0 && gs->cfg.behaviour_penalty_decay < 1.0)
            entry->behaviour_penalty =
                gossipsub_score_decay_value(entry->behaviour_penalty, gs->cfg.behaviour_penalty_decay);
        if (entry->behaviour_penalty < 0.0)
            entry->behaviour_penalty = 0.0;
        gossipsub_score_update_entry_locked(gs, entry, now_ms);
    }
}

void gossipsub_score_init(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;
    gs->score_timer_id = 0;
    gs->last_score_tick_ms = gossipsub_now_ms();
}

void gossipsub_score_deinit(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;
    gossipsub_score_stop_timer(gs);
    gs->last_score_tick_ms = 0;
}

void gossipsub_score_on_mesh_join_locked(libp2p_gossipsub_t *gs,
                                         gossipsub_topic_state_t *topic,
                                         gossipsub_peer_entry_t *entry,
                                         uint64_t now_ms)
{
    (void)gs;
    if (!topic || !topic->name || !entry)
        return;

    gossipsub_peer_topic_t *topic_state = gossipsub_score_find_topic(entry, topic->name);
    if (!topic_state)
        return;

    gossipsub_score_touch_topic(topic_state, now_ms);
    topic_state->mesh_time_accum_ms = 0;
    topic_state->first_message_deliveries = 0.0;
    topic_state->mesh_message_deliveries = 0.0;
    topic_state->mesh_failure_penalty = 0.0;
    topic_state->invalid_message_deliveries = 0.0;
    topic_state->topic_score = 0.0;
    topic_state->mesh_join_time_ms = now_ms;
    topic_state->last_mesh_update_ms = now_ms;
    topic_state->in_mesh = 1;
}

void gossipsub_score_on_mesh_leave_locked(libp2p_gossipsub_t *gs,
                                          gossipsub_topic_state_t *topic,
                                          const peer_id_t *peer,
                                          uint64_t now_ms)
{
    if (!gs || !topic || !topic->name || !peer)
        return;

    gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
    if (!entry)
        return;

    gossipsub_peer_topic_t *topic_state = gossipsub_score_find_topic(entry, topic->name);
    if (!topic_state)
        return;

    gossipsub_score_touch_topic(topic_state, now_ms);
    topic_state->in_mesh = 0;
    topic_state->mesh_join_time_ms = 0;
    topic_state->mesh_time_accum_ms = 0;
    topic_state->topic_score = 0.0;
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_on_prune_negative_locked(libp2p_gossipsub_t *gs,
                                              gossipsub_topic_state_t *topic,
                                              gossipsub_peer_entry_t *entry,
                                              uint64_t now_ms)
{
    if (!gs || !topic || !topic->name || !entry)
        return;

    if (entry->explicit_peering)
        return;

    gossipsub_peer_topic_t *topic_state = gossipsub_score_find_topic(entry, topic->name);
    if (!topic_state)
        return;

    gossipsub_score_touch_topic(topic_state, now_ms);

    if (!topic->has_score_params)
        return;

    double threshold = gossipsub_score_param_mesh_threshold(&topic->score_params);
    if (threshold <= 0.0)
        return;

    double deficit = threshold - topic_state->mesh_message_deliveries;
    if (deficit <= 0.0)
        return;

    double penalty = deficit * deficit;
    if (penalty <= 0.0)
        return;

    topic_state->mesh_failure_penalty += penalty;
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_on_peer_removed_locked(libp2p_gossipsub_t *gs,
                                            gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry)
        return;

    uint64_t now_ms = gossipsub_now_ms();
    for (gossipsub_peer_topic_t *topic_state = entry->topics; topic_state; topic_state = topic_state->next)
    {
        gossipsub_score_touch_topic(topic_state, now_ms);
        topic_state->in_mesh = 0;
        topic_state->mesh_join_time_ms = 0;
        topic_state->mesh_time_accum_ms = 0;
        topic_state->topic_score = 0.0;
    }
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_on_topic_unsubscribe_locked(libp2p_gossipsub_t *gs,
                                                 gossipsub_peer_entry_t *entry,
                                                 const char *topic_name)
{
    if (!gs || !entry || !topic_name)
        return;

    gossipsub_peer_topic_t *topic_state = gossipsub_score_find_topic(entry, topic_name);
    if (!topic_state)
        return;

    uint64_t now_ms = gossipsub_now_ms();
    gossipsub_score_touch_topic(topic_state, now_ms);
    topic_state->in_mesh = 0;
    topic_state->mesh_join_time_ms = 0;
    topic_state->mesh_time_accum_ms = 0;
    topic_state->topic_score = 0.0;
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_on_heartbeat_locked(libp2p_gossipsub_t *gs,
                                         uint64_t now_ms)
{
    if (!gs)
        return;

    for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
        gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_on_first_delivery_locked(libp2p_gossipsub_t *gs,
                                              gossipsub_topic_state_t *topic,
                                              gossipsub_peer_entry_t *entry,
                                              int mesh_delivery,
                                              uint64_t now_ms)
{
    if (!gs || !topic || !entry || !topic->name)
        return;

    gossipsub_peer_topic_t *topic_state = gossipsub_score_find_topic(entry, topic->name);
    if (!topic_state)
        return;

    topic_state->first_message_deliveries += 1.0;
    if (mesh_delivery)
        topic_state->mesh_message_deliveries += 1.0;

    if (topic->has_score_params)
        gossipsub_score_apply_caps(topic_state, &topic->score_params);

    gossipsub_score_touch_topic(topic_state, now_ms);
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_on_invalid_message_locked(libp2p_gossipsub_t *gs,
                                               gossipsub_topic_state_t *topic,
                                               gossipsub_peer_entry_t *entry,
                                               uint64_t now_ms)
{
    if (!gs || !topic || !entry || !topic->name)
        return;

    gossipsub_peer_topic_t *topic_state = gossipsub_score_find_topic(entry, topic->name);
    if (!topic_state)
        return;

    topic_state->invalid_message_deliveries += 1.0;
    gossipsub_score_touch_topic(topic_state, now_ms);
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

static void gossipsub_score_timer_cb(void *user_data)
{
    libp2p_gossipsub_t *gs = (libp2p_gossipsub_t *)user_data;
    if (!gs)
        return;

    uint64_t now_ms = gossipsub_now_ms();
    pthread_mutex_lock(&gs->lock);
    gossipsub_score_apply_decay_locked(gs, now_ms);
    gs->last_score_tick_ms = now_ms;
    pthread_mutex_unlock(&gs->lock);
}

void gossipsub_score_start_timer(libp2p_gossipsub_t *gs)
{
    if (!gs || !gs->runtime)
        return;

    if (gs->cfg.score_decay_interval_ms <= 0)
        return;

    pthread_mutex_lock(&gs->lock);
    if (gs->score_timer_id > 0)
    {
        pthread_mutex_unlock(&gs->lock);
        return;
    }
    pthread_mutex_unlock(&gs->lock);

    uint64_t interval_ms = (uint64_t)gs->cfg.score_decay_interval_ms;
    int tid = libp2p_runtime_add_timer(gs->runtime, interval_ms, 1, gossipsub_score_timer_cb, gs);
    if (tid <= 0)
        return;

    pthread_mutex_lock(&gs->lock);
    if (gs->score_timer_id > 0)
    {
        pthread_mutex_unlock(&gs->lock);
        libp2p_runtime_cancel_timer(gs->runtime, tid);
        return;
    }
    gs->score_timer_id = tid;
    gs->last_score_tick_ms = gossipsub_now_ms();
    pthread_mutex_unlock(&gs->lock);
}

void gossipsub_score_stop_timer(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    int tid = 0;
    pthread_mutex_lock(&gs->lock);
    if (gs->score_timer_id > 0)
    {
        tid = gs->score_timer_id;
        gs->score_timer_id = 0;
    }
    pthread_mutex_unlock(&gs->lock);

    if (tid > 0 && gs->runtime)
        libp2p_runtime_cancel_timer(gs->runtime, tid);
}

void gossipsub_score_recompute_peer_locked(libp2p_gossipsub_t *gs,
                                           gossipsub_peer_entry_t *entry,
                                           uint64_t now_ms)
{
    if (!gs || !entry)
        return;
    gossipsub_score_update_entry_locked(gs, entry, now_ms);
}

void gossipsub_score_emit_update_locked(libp2p_gossipsub_t *gs,
                                        gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry)
        return;
    gossipsub_score_notify_locked(gs, entry, entry->score, entry->score_override);
}
