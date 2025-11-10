#include "gossipsub_heartbeat.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libp2p/log.h"

#include "gossipsub_cache.h"
#include "gossipsub_peer.h"
#include "gossipsub_propagation.h"
#include "gossipsub_rpc.h"
#include "gossipsub_score.h"
#include "gossipsub_topic.h"

#define GOSSIPSUB_MODULE "gossipsub"

typedef struct gossipsub_mesh_prune_candidate
{
    peer_id_t *peer;
    gossipsub_peer_entry_t *entry;
    int outbound;
    double score;
    uint64_t last_heartbeat_ms;
    int protect;
} gossipsub_mesh_prune_candidate_t;

static size_t gossipsub_topic_count_outbound(const gossipsub_topic_state_t *topic)
{
    if (!topic)
        return 0;
    size_t count = 0;
    for (const gossipsub_mesh_member_t *member = topic->mesh; member; member = member->next)
    {
        if (member->outbound)
            count++;
    }
    return count;
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

static gossipsub_peer_entry_t **gossipsub_heartbeat_collect_candidates(libp2p_gossipsub_t *gs,
                                                                       gossipsub_topic_state_t *topic,
                                                                       uint64_t now_ms,
                                                                       int require_outbound,
                                                                       int ignore_backoff,
                                                                       size_t *out_count)
{
    if (out_count)
        *out_count = 0;
    if (!gs || !topic || !topic->name || !out_count)
        return NULL;

    gossipsub_peer_entry_t **list = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
    {
        if (!entry->connected)
            continue;
        if (!gossipsub_peer_topic_find(entry->topics, topic->name))
            continue;
        if (gossipsub_mesh_member_find(topic->mesh, entry->peer))
            continue;
        if (!ignore_backoff && gossipsub_backoff_contains(topic, entry->peer, now_ms))
            continue;
        int outbound = entry->outbound_stream ? 1 : 0;
        if (require_outbound && !outbound)
            continue;

        if (count == capacity)
        {
            size_t new_cap = capacity ? capacity * 2 : 8;
            gossipsub_peer_entry_t **new_list = (gossipsub_peer_entry_t **)realloc(list, new_cap * sizeof(*new_list));
            if (!new_list)
            {
                free(list);
                return NULL;
            }
            list = new_list;
            capacity = new_cap;
        }
        list[count++] = entry;
    }

    if (count == 0)
    {
        free(list);
        return NULL;
    }

    *out_count = count;
    return list;
}

static void gossipsub_heartbeat_try_graft_from_candidates(libp2p_gossipsub_t *gs,
                                                          gossipsub_topic_state_t *topic,
                                                          gossipsub_peer_entry_t *const *candidates,
                                                          size_t candidate_count,
                                                          size_t *needed,
                                                          size_t *outbound_needed,
                                                          size_t *current_outbound,
                                                          uint64_t now_ms,
                                                          int allow_inbound_fallback,
                                                          int ignore_backoff)
{
    if (!gs || !topic || !topic->name || !candidates || !needed || *needed == 0)
        return;

    const char *topics[1] = { topic->name };

    for (size_t i = 0; i < candidate_count && *needed > 0; ++i)
    {
        gossipsub_peer_entry_t *entry = candidates[i];
        if (!entry || !entry->connected)
            continue;
        if (!gossipsub_peer_topic_find(entry->topics, topic->name))
            continue;
        if (gossipsub_mesh_member_find(topic->mesh, entry->peer))
            continue;
        if (!ignore_backoff && gossipsub_backoff_contains(topic, entry->peer, now_ms))
            continue;

        int outbound = entry->outbound_stream ? 1 : 0;
        if (outbound_needed && *outbound_needed > 0 && !outbound)
        {
            if (!allow_inbound_fallback)
                continue;
        }

        if (!gossipsub_mesh_member_insert(topic, entry, outbound, now_ms))
            continue;

        gossipsub_score_on_mesh_join_locked(gs, topic, entry, now_ms);

        gossipsub_backoff_remove(topic, entry->peer);
        (void)gossipsub_fanout_remove(topic, entry->peer);

        gossipsub_rpc_out_t frame;
        gossipsub_rpc_out_init(&frame);
        libp2p_err_t enc_rc = gossipsub_rpc_encode_control_graft(topics, 1, &frame);
        if (enc_rc != LIBP2P_ERR_OK || !frame.frame || frame.frame_len == 0)
        {
            if (gossipsub_mesh_member_remove(topic, entry->peer))
                gossipsub_score_on_mesh_leave_locked(gs, topic, entry->peer, now_ms);
            gossipsub_rpc_out_clear(&frame);
            continue;
        }

        libp2p_err_t send_rc = gossipsub_peer_enqueue_frame_locked(gs, entry, frame.frame, frame.frame_len);
        if (send_rc == LIBP2P_ERR_OK)
        {
            char peer_buf[128];
            const char *peer_repr = gossipsub_peer_to_string(entry->peer, peer_buf, sizeof(peer_buf));
            LP_LOGT(GOSSIPSUB_MODULE,
                    "send_graft peer=%s topic=%s",
                    peer_repr,
                    topic && topic->name ? topic->name : "(null)");
        }
        gossipsub_rpc_out_clear(&frame);
        if (send_rc != LIBP2P_ERR_OK)
        {
            if (gossipsub_mesh_member_remove(topic, entry->peer))
                gossipsub_score_on_mesh_leave_locked(gs, topic, entry->peer, now_ms);
            continue;
        }

        (*needed)--;
        if (outbound)
        {
            if (current_outbound)
                (*current_outbound)++;
            if (outbound_needed && *outbound_needed > 0)
                (*outbound_needed)--;
        }
    }
}

static int gossipsub_prune_cmp_score_desc(const void *a, const void *b)
{
    const gossipsub_mesh_prune_candidate_t *const *lhs = (const gossipsub_mesh_prune_candidate_t *const *)a;
    const gossipsub_mesh_prune_candidate_t *const *rhs = (const gossipsub_mesh_prune_candidate_t *const *)b;
    double la = (*lhs)->score;
    double rb = (*rhs)->score;
    if (la < rb)
        return 1;
    if (la > rb)
        return -1;
    if ((*lhs)->peer < (*rhs)->peer)
        return -1;
    if ((*lhs)->peer > (*rhs)->peer)
        return 1;
    return 0;
}

static int gossipsub_prune_cmp_priority(const void *a, const void *b)
{
    const gossipsub_mesh_prune_candidate_t *const *lhs = (const gossipsub_mesh_prune_candidate_t *const *)a;
    const gossipsub_mesh_prune_candidate_t *const *rhs = (const gossipsub_mesh_prune_candidate_t *const *)b;
    if ((*lhs)->protect != (*rhs)->protect)
        return (*lhs)->protect - (*rhs)->protect;
    if ((*lhs)->outbound != (*rhs)->outbound)
        return (*lhs)->outbound - (*rhs)->outbound;
    if ((*lhs)->score < (*rhs)->score)
        return -1;
    if ((*lhs)->score > (*rhs)->score)
        return 1;
    if ((*lhs)->last_heartbeat_ms < (*rhs)->last_heartbeat_ms)
        return -1;
    if ((*lhs)->last_heartbeat_ms > (*rhs)->last_heartbeat_ms)
        return 1;
    if ((*lhs)->peer < (*rhs)->peer)
        return -1;
    if ((*lhs)->peer > (*rhs)->peer)
        return 1;
    return 0;
}

static void gossipsub_heartbeat_graft_locked(libp2p_gossipsub_t *gs,
                                             gossipsub_topic_state_t *topic,
                                             size_t needed,
                                             uint64_t now_ms)
{
    if (!gs || !topic || !topic->name || needed == 0)
        return;
    size_t remaining = needed;
    size_t current_outbound = gossipsub_topic_count_outbound(topic);
    size_t d_out = (gs->cfg.d_out > 0) ? (size_t)gs->cfg.d_out : 0;
    size_t outbound_needed = 0;
    if (d_out > current_outbound)
        outbound_needed = d_out - current_outbound;
    if (outbound_needed > remaining)
        outbound_needed = remaining;

    if (outbound_needed > 0)
    {
        size_t candidate_count = 0;
        gossipsub_peer_entry_t **candidates = gossipsub_heartbeat_collect_candidates(gs,
                                                                                     topic,
                                                                                     now_ms,
                                                                                     1,
                                                                                     0,
                                                                                     &candidate_count);
        if (candidates)
        {
            gossipsub_heartbeat_try_graft_from_candidates(gs,
                                                          topic,
                                                          candidates,
                                                          candidate_count,
                                                          &remaining,
                                                          &outbound_needed,
                                                          &current_outbound,
                                                          now_ms,
                                                          0,
                                                          0);
            free(candidates);
        }
    }

    if (remaining > 0)
    {
        size_t candidate_count = 0;
        gossipsub_peer_entry_t **candidates = gossipsub_heartbeat_collect_candidates(gs,
                                                                                     topic,
                                                                                     now_ms,
                                                                                     0,
                                                                                     0,
                                                                                     &candidate_count);
        if (candidates)
        {
            gossipsub_heartbeat_try_graft_from_candidates(gs,
                                                          topic,
                                                          candidates,
                                                          candidate_count,
                                                          &remaining,
                                                          &outbound_needed,
                                                          &current_outbound,
                                                          now_ms,
                                                          (outbound_needed > 0) ? 1 : 0,
                                                          0);
            free(candidates);
        }
    }
}

static void gossipsub_heartbeat_prune_locked(libp2p_gossipsub_t *gs,
                                             gossipsub_topic_state_t *topic,
                                             size_t target_mesh,
                                             uint64_t now_ms)
{
    if (!gs || !topic || !topic->name)
        return;
    if (topic->mesh_size <= target_mesh)
        return;

    size_t prune_needed = topic->mesh_size > target_mesh ? topic->mesh_size - target_mesh : 0;
    if (prune_needed == 0)
        return;

    size_t candidate_capacity = topic->mesh_size;
    gossipsub_mesh_prune_candidate_t *candidates = NULL;
    gossipsub_mesh_prune_candidate_t **candidate_ptrs = NULL;

    if (candidate_capacity > 0)
    {
        candidates = (gossipsub_mesh_prune_candidate_t *)calloc(candidate_capacity, sizeof(*candidates));
        candidate_ptrs = (gossipsub_mesh_prune_candidate_t **)calloc(candidate_capacity, sizeof(*candidate_ptrs));
    }

    if (!candidates || !candidate_ptrs)
    {
        free(candidates);
        free(candidate_ptrs);
        return;
    }

    size_t used = 0;
    size_t current_outbound = 0;
    for (gossipsub_mesh_member_t *member = topic->mesh; member && used < candidate_capacity; member = member->next)
    {
        peer_id_t *dup = member->peer ? gossipsub_peer_clone(member->peer) : NULL;
        if (!dup)
            continue;

        candidates[used].peer = dup;
        candidates[used].entry = member->peer_entry;
        candidates[used].outbound = member->outbound ? 1 : 0;
        candidates[used].score = (member->peer_entry) ? member->peer_entry->score : 0.0;
        candidates[used].last_heartbeat_ms = member->last_heartbeat_ms;
        candidates[used].protect = 0;
        candidate_ptrs[used] = &candidates[used];
        if (member->outbound)
            current_outbound++;
        used++;
    }

    size_t d_score = (gs->cfg.d_score > 0) ? (size_t)gs->cfg.d_score : 0;
    if (d_score > used)
        d_score = used;
    if (d_score > 0 && used > 0)
    {
        qsort(candidate_ptrs, used, sizeof(*candidate_ptrs), gossipsub_prune_cmp_score_desc);
        for (size_t i = 0; i < d_score; ++i)
            candidate_ptrs[i]->protect = 1;
    }

    qsort(candidate_ptrs, used, sizeof(*candidate_ptrs), gossipsub_prune_cmp_priority);

    uint64_t backoff_ms = (gs->cfg.prune_backoff_ms > 0) ? (uint64_t)gs->cfg.prune_backoff_ms : 0;
    uint64_t backoff_seconds = gossipsub_propagation_backoff_seconds(gs);
    size_t d_out = (gs->cfg.d_out > 0) ? (size_t)gs->cfg.d_out : 0;
    double accept_threshold = gs->cfg.accept_px_threshold;

    for (size_t i = 0; i < used && prune_needed > 0; ++i)
    {
        gossipsub_mesh_prune_candidate_t *cand = candidate_ptrs[i];
        if (!cand || !cand->peer)
            continue;
        if (cand->protect)
            continue;
        if (cand->outbound && current_outbound <= d_out)
            continue;

        if (cand->entry && !cand->entry->explicit_peering && cand->entry->score < 0.0)
            gossipsub_score_on_prune_negative_locked(gs, topic, cand->entry, now_ms);

        if (!gossipsub_mesh_member_remove(topic, cand->peer))
            continue;

        gossipsub_score_on_mesh_leave_locked(gs, topic, cand->peer, now_ms);

        if (cand->outbound && current_outbound > 0)
            current_outbound--;

        gossipsub_peer_entry_t *entry = cand->entry;
        if (entry)
        {
            (void)gossipsub_fanout_remove(topic, entry->peer);
            if (backoff_ms > 0)
            {
                uint64_t expire_ms = gossipsub_propagation_compute_backoff_expiry(now_ms, backoff_ms);
                (void)gossipsub_backoff_add(topic, entry->peer, expire_ms);
            }
        }

        peer_id_t **px_peers = NULL;
        size_t px_len = 0;
        if (gs->cfg.enable_px && entry && entry->score >= accept_threshold)
        {
            size_t limit = gs->cfg.px_peer_target ? gs->cfg.px_peer_target : 0;
            if (limit > 0)
                px_peers = gossipsub_topic_collect_px_locked(topic, cand->peer, limit, &px_len);
        }

        gossipsub_prune_target_t *target = (gossipsub_prune_target_t *)calloc(1, sizeof(*target));
        if (!target)
        {
            gossipsub_px_list_free(px_peers, px_len);
            gossipsub_peer_free(cand->peer);
            cand->peer = NULL;
            continue;
        }

        size_t topic_name_len = strlen(topic->name);
        target->topic = (char *)malloc(topic_name_len + 1);
        if (!target->topic)
        {
            gossipsub_prune_target_free(target);
            gossipsub_peer_free(cand->peer);
            cand->peer = NULL;
            continue;
        }
        memcpy(target->topic, topic->name, topic_name_len + 1);
        target->px_peers = px_peers;
        target->px_len = px_len;

        const gossipsub_prune_target_t *targets[1] = { target };
        gossipsub_rpc_out_t frame;
        gossipsub_rpc_out_init(&frame);
        libp2p_err_t enc_rc = gossipsub_rpc_encode_control_prune(targets,
                                                                 1,
                                                                 backoff_seconds,
                                                                 &frame);

        if (enc_rc == LIBP2P_ERR_OK && frame.frame && frame.frame_len && entry)
            (void)gossipsub_peer_enqueue_frame_locked(gs, entry, frame.frame, frame.frame_len);

        gossipsub_rpc_out_clear(&frame);
        gossipsub_prune_target_free(target);

        prune_needed--;
        gossipsub_peer_free(cand->peer);
        cand->peer = NULL;
    }

    for (size_t i = 0; i < used; ++i)
    {
        if (candidates[i].peer)
        {
            gossipsub_peer_free(candidates[i].peer);
            candidates[i].peer = NULL;
        }
    }

    free(candidate_ptrs);
    free(candidates);
}

static int gossipsub_double_cmp_asc(const void *a, const void *b)
{
    double lhs = *(const double *)a;
    double rhs = *(const double *)b;
    if (lhs < rhs)
        return -1;
    if (lhs > rhs)
        return 1;
    return 0;
}

static int gossipsub_peer_entry_cmp_score_desc(const void *a, const void *b)
{
    const gossipsub_peer_entry_t *const *lhs = (const gossipsub_peer_entry_t *const *)a;
    const gossipsub_peer_entry_t *const *rhs = (const gossipsub_peer_entry_t *const *)b;
    double la = (*lhs) ? (*lhs)->score : 0.0;
    double rb = (*rhs) ? (*rhs)->score : 0.0;
    if (la < rb)
        return 1;
    if (la > rb)
        return -1;
    if (*lhs < *rhs)
        return -1;
    if (*lhs > *rhs)
        return 1;
    return 0;
}

static double gossipsub_compute_median(double *values, size_t count)
{
    if (!values || count == 0)
        return 0.0;
    qsort(values, count, sizeof(*values), gossipsub_double_cmp_asc);
    if ((count & 1U) != 0)
        return values[count / 2];
    double lower = values[(count / 2) - 1];
    double upper = values[count / 2];
    return (lower + upper) * 0.5;
}

void gossipsub_opportunistic_tick(libp2p_gossipsub_t *gs, uint64_t now_ms)
{
    if (!gs || !gs->cfg.enable_opportunistic_graft)
        return;

    size_t graft_target = (gs->cfg.opportunistic_graft_peers > 0) ? (size_t)gs->cfg.opportunistic_graft_peers : 2;
    if (graft_target == 0)
        return;

    double threshold = gs->cfg.opportunistic_graft_threshold;

    for (gossipsub_topic_state_t *topic = gs->topics; topic; topic = topic->next)
    {
        if (!topic->subscribed || !topic->mesh)
            continue;
        if (topic->mesh_size == 0)
            continue;

        size_t mesh_capacity = topic->mesh_size;
        double *scores = NULL;
        if (mesh_capacity > 0)
        {
            scores = (double *)malloc(mesh_capacity * sizeof(*scores));
            if (!scores)
                continue;
        }

        size_t score_count = 0;
        for (gossipsub_mesh_member_t *member = topic->mesh; member && score_count < mesh_capacity; member = member->next)
        {
            if (!member->peer_entry || !member->peer_entry->connected)
                continue;
            scores[score_count++] = member->peer_entry->score;
        }

        if (score_count == 0)
        {
            free(scores);
            continue;
        }

        double median = gossipsub_compute_median(scores, score_count);
        free(scores);

        if (median >= threshold)
            continue;

        size_t candidate_count = 0;
        gossipsub_peer_entry_t **candidates = gossipsub_heartbeat_collect_candidates(gs,
                                                                                     topic,
                                                                                     now_ms,
                                                                                     0,
                                                                                     1,
                                                                                     &candidate_count);
        if (!candidates)
            continue;

        size_t filtered = 0;
        for (size_t i = 0; i < candidate_count; ++i)
        {
            gossipsub_peer_entry_t *entry = candidates[i];
            if (!entry || !entry->connected)
                continue;
            if (entry->score <= median)
                continue;
            candidates[filtered++] = entry;
        }

        if (filtered == 0)
        {
            free(candidates);
            continue;
        }

        qsort(candidates, filtered, sizeof(*candidates), gossipsub_peer_entry_cmp_score_desc);

        size_t needed = graft_target;
        size_t current_outbound = gossipsub_topic_count_outbound(topic);
        size_t d_out = (gs->cfg.d_out > 0) ? (size_t)gs->cfg.d_out : 0;
        size_t outbound_needed = 0;
        if (d_out > current_outbound)
        {
            outbound_needed = d_out - current_outbound;
            if (outbound_needed > needed)
                outbound_needed = needed;
        }

        size_t before = needed;
        gossipsub_heartbeat_try_graft_from_candidates(gs,
                                                      topic,
                                                      candidates,
                                                      filtered,
                                                      &needed,
                                                      &outbound_needed,
                                                      &current_outbound,
                                                      now_ms,
                                                      1,
                                                      1);
        size_t grafted = before - needed;
        if (grafted > 0)
        {
            topic->last_opportunistic_graft_ms = now_ms;
            gs->last_opportunistic_graft_ms = now_ms;
            LP_LOGD(GOSSIPSUB_MODULE,
                    "opportunistic grafted %zu peers on topic %s (median=%.3f threshold=%.3f)",
                    grafted,
                    topic->name ? topic->name : "<unnamed>",
                    median,
                    threshold);
        }

        free(candidates);
    }
}

void gossipsub_opportunistic_run(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    pthread_mutex_lock(&gs->lock);
    if (!gs->started || !gs->cfg.enable_opportunistic_graft)
    {
        pthread_mutex_unlock(&gs->lock);
        return;
    }
    uint64_t now_ms = gossipsub_now_ms();
    gossipsub_opportunistic_tick(gs, now_ms);
    pthread_mutex_unlock(&gs->lock);
}

void gossipsub_heartbeat_tick(libp2p_gossipsub_t *gs, uint64_t now_ms)
{
    if (!gs)
        return;
    for (gossipsub_peer_entry_t *peer = gs->peers; peer; peer = peer->next)
    {
        peer->ihave_advertisements = 0;
        peer->ihave_ids_asked = 0;
    }
    gossipsub_promises_apply_penalties(gs, now_ms);
    gossipsub_score_on_heartbeat_locked(gs, now_ms);
    uint64_t gossip_round = ++gs->gossip_round;
    for (gossipsub_topic_state_t *topic = gs->topics; topic; topic = topic->next)
    {
        gossipsub_topic_heartbeat_mesh_locked(topic, now_ms);
        gossipsub_topic_heartbeat_fanout_locked(topic, now_ms);
        gossipsub_backoff_gc_locked(topic, now_ms);
        if (!topic->subscribed || !topic->name)
            continue;

        gossipsub_topic_mesh_params_t mesh_params = {0};
        gossipsub_topic_compute_mesh_params(&gs->cfg, topic, &mesh_params);
        size_t d_lo = mesh_params.d_lo;
        size_t desired = mesh_params.d;
        size_t d_hi = mesh_params.d_hi;

        if (topic->mesh_size < d_lo && desired > topic->mesh_size)
        {
            size_t needed = desired - topic->mesh_size;
            gossipsub_heartbeat_graft_locked(gs, topic, needed, now_ms);
        }

        if (topic->mesh_size > d_hi)
        {
            size_t target_mesh = desired > 0 ? desired : d_hi;
            if (target_mesh < d_lo)
                target_mesh = d_lo;
            gossipsub_heartbeat_prune_locked(gs, topic, target_mesh, now_ms);
        }

        gossipsub_propagation_emit_gossip_locked(gs, topic, gossip_round);
    }
    libp2p_err_t cache_rc = gossipsub_message_cache_shift(&gs->message_cache);
    if (cache_rc != LIBP2P_ERR_OK)
        LP_LOGW(GOSSIPSUB_MODULE, "message cache shift failed (rc=%d)", cache_rc);
}

void gossipsub_heartbeat_run(libp2p_gossipsub_t *gs)
{
    if (!gs)
        return;

    pthread_mutex_lock(&gs->lock);
    if (!gs->started)
    {
        pthread_mutex_unlock(&gs->lock);
        return;
    }
    uint64_t now_ms = gossipsub_now_ms();
    gossipsub_heartbeat_tick(gs, now_ms);
    pthread_mutex_unlock(&gs->lock);
}
