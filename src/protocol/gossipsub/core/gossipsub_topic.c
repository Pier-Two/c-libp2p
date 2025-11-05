#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "gossipsub_topic.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/log.h"
#include "gossipsub_score.h"

#define GOSSIPSUB_MODULE "gossipsub"
static void gossipsub_mesh_member_free(gossipsub_mesh_member_t *node)
{
    if (!node)
        return;
    if (node->peer)
        gossipsub_peer_free(node->peer);
    free(node);
}

static void gossipsub_mesh_clear(gossipsub_mesh_member_t **head_ptr)
{
    if (!head_ptr)
        return;
    gossipsub_mesh_member_t *head = *head_ptr;
    while (head)
    {
        gossipsub_mesh_member_t *next = head->next;
        gossipsub_mesh_member_free(head);
        head = next;
    }
    *head_ptr = NULL;
}

static void gossipsub_fanout_peer_free(gossipsub_fanout_peer_t *node)
{
    if (!node)
        return;
    if (node->peer)
        gossipsub_peer_free(node->peer);
    free(node);
}

static void gossipsub_backoff_entry_free(gossipsub_backoff_entry_t *entry)
{
    if (!entry)
        return;
    if (entry->peer)
        gossipsub_peer_free(entry->peer);
    free(entry);
}

static gossipsub_backoff_entry_t *gossipsub_backoff_find(gossipsub_backoff_entry_t *head, const peer_id_t *peer)
{
    for (; head; head = head->next)
    {
        if (gossipsub_peer_equals(head->peer, peer))
            return head;
    }
    return NULL;
}

static void gossipsub_backoff_clear(gossipsub_backoff_entry_t **head_ptr)
{
    if (!head_ptr)
        return;
    gossipsub_backoff_entry_t *node = *head_ptr;
    while (node)
    {
        gossipsub_backoff_entry_t *next = node->next;
        gossipsub_backoff_entry_free(node);
        node = next;
    }
    *head_ptr = NULL;
}

static void gossipsub_fanout_clear_internal(gossipsub_fanout_peer_t **head_ptr)
{
    if (!head_ptr)
        return;
    gossipsub_fanout_peer_t *head = *head_ptr;
    while (head)
    {
        gossipsub_fanout_peer_t *next = head->next;
        gossipsub_fanout_peer_free(head);
        head = next;
    }
    *head_ptr = NULL;
}

gossipsub_topic_state_t *gossipsub_topic_find(gossipsub_topic_state_t *head, const char *topic)
{
    for (; head; head = head->next)
    {
        if (head->name && topic && strcmp(head->name, topic) == 0)
            return head;
    }
    return NULL;
}

libp2p_err_t gossipsub_topic_ensure(libp2p_gossipsub_t *gs,
                                    const libp2p_gossipsub_topic_config_t *topic_cfg,
                                    gossipsub_topic_state_t **out_topic)
{
    if (!gs || !topic_cfg || !topic_cfg->descriptor.topic)
        return LIBP2P_ERR_NULL_PTR;

    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_cfg->descriptor.topic);
    if (!topic)
    {
        topic = (gossipsub_topic_state_t *)calloc(1, sizeof(*topic));
        if (!topic)
            return LIBP2P_ERR_INTERNAL;
        topic->name = strdup(topic_cfg->descriptor.topic);
        if (!topic->name)
        {
            free(topic);
            return LIBP2P_ERR_INTERNAL;
        }
        topic->mesh = NULL;
        topic->mesh_size = 0;
        topic->fanout = NULL;
        topic->fanout_size = 0;
        topic->fanout_expire_ms = 0;
        topic->last_opportunistic_graft_ms = 0;
        topic->next = gs->topics;
        gs->topics = topic;
        topic->publish_threshold = 0.0;
        topic->has_publish_threshold = 0;
    }

    if (topic_cfg->score_params)
    {
        topic->score_params = *topic_cfg->score_params;
        topic->has_score_params = 1;
    }

    size_t publish_field_size = offsetof(libp2p_gossipsub_topic_config_t, publish_threshold) + sizeof(topic_cfg->publish_threshold);
    if (topic_cfg->struct_size >= publish_field_size)
    {
        topic->publish_threshold = topic_cfg->publish_threshold;
        topic->has_publish_threshold = 1;
    }

    if (topic_cfg)
    {
        size_t required_size = offsetof(libp2p_gossipsub_topic_config_t, message_id_user_data) + sizeof(topic_cfg->message_id_user_data);
        if (topic_cfg->struct_size >= required_size)
        {
            topic->message_id_fn = topic_cfg->message_id_fn;
            topic->message_id_user_data = topic_cfg->message_id_user_data;
        }
    }

    if (out_topic)
        *out_topic = topic;

    return LIBP2P_ERR_OK;
}

gossipsub_mesh_member_t *gossipsub_mesh_member_find(gossipsub_mesh_member_t *head, const peer_id_t *peer)
{
    for (; head; head = head->next)
    {
        if (gossipsub_peer_equals(head->peer, peer))
            return head;
    }
    return NULL;
}

gossipsub_mesh_member_t *gossipsub_mesh_member_insert(gossipsub_topic_state_t *topic,
                                                      gossipsub_peer_entry_t *entry,
                                                      int outbound,
                                                      uint64_t now_ms)
{
    if (!topic || !entry || !entry->peer)
        return NULL;

    gossipsub_mesh_member_t *member = gossipsub_mesh_member_find(topic->mesh, entry->peer);
    if (member)
    {
        member->peer_entry = entry;
        member->outbound = outbound;
        member->last_heartbeat_ms = now_ms;
        return member;
    }

    peer_id_t *dup = gossipsub_peer_clone(entry->peer);
    if (!dup)
        return NULL;

    member = (gossipsub_mesh_member_t *)calloc(1, sizeof(*member));
    if (!member)
    {
        gossipsub_peer_free(dup);
        return NULL;
    }

    member->peer = dup;
    member->peer_entry = entry;
    member->outbound = outbound;
    member->last_heartbeat_ms = now_ms;
    member->next = topic->mesh;
    topic->mesh = member;
    topic->mesh_size++;
    return member;
}

int gossipsub_mesh_member_remove(gossipsub_topic_state_t *topic, const peer_id_t *peer)
{
    if (!topic || !peer)
        return 0;
    gossipsub_mesh_member_t **pp = &topic->mesh;
    while (*pp)
    {
        if (gossipsub_peer_equals((*pp)->peer, peer))
        {
            gossipsub_mesh_member_t *victim = *pp;
            *pp = victim->next;
            gossipsub_mesh_member_free(victim);
            if (topic->mesh_size > 0)
                topic->mesh_size--;
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}

void gossipsub_mesh_member_touch(gossipsub_mesh_member_t *member, uint64_t now_ms)
{
    if (!member)
        return;
    member->last_heartbeat_ms = now_ms;
}

gossipsub_fanout_peer_t *gossipsub_fanout_find(gossipsub_fanout_peer_t *head, const peer_id_t *peer)
{
    for (; head; head = head->next)
    {
        if (gossipsub_peer_equals(head->peer, peer))
            return head;
    }
    return NULL;
}

void gossipsub_fanout_clear(gossipsub_fanout_peer_t **head_ptr)
{
    gossipsub_fanout_clear_internal(head_ptr);
}

gossipsub_fanout_peer_t *gossipsub_fanout_add(gossipsub_topic_state_t *topic,
                                              gossipsub_peer_entry_t *entry,
                                              int outbound,
                                              uint64_t now_ms)
{
    if (!topic || !entry || !entry->peer)
        return NULL;

    gossipsub_fanout_peer_t *node = gossipsub_fanout_find(topic->fanout, entry->peer);
    if (node)
    {
        node->peer_entry = entry;
        node->outbound = outbound;
        node->last_publish_ms = now_ms;
        return node;
    }

    peer_id_t *dup = gossipsub_peer_clone(entry->peer);
    if (!dup)
        return NULL;

    node = (gossipsub_fanout_peer_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        gossipsub_peer_free(dup);
        return NULL;
    }

    node->peer = dup;
    node->peer_entry = entry;
    node->outbound = outbound;
    node->last_publish_ms = now_ms;
    node->next = topic->fanout;
    topic->fanout = node;
    topic->fanout_size++;
    return node;
}

int gossipsub_fanout_remove(gossipsub_topic_state_t *topic, const peer_id_t *peer)
{
    if (!topic || !peer)
        return 0;
    gossipsub_fanout_peer_t **pp = &topic->fanout;
    while (*pp)
    {
        if (gossipsub_peer_equals((*pp)->peer, peer))
        {
            gossipsub_fanout_peer_t *victim = *pp;
            *pp = victim->next;
            gossipsub_fanout_peer_free(victim);
            if (topic->fanout_size > 0)
                topic->fanout_size--;
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}

void gossipsub_topic_remove_peer(libp2p_gossipsub_t *gs,
                                 gossipsub_topic_state_t *topic,
                                 const peer_id_t *peer)
{
    if (!topic || !peer)
        return;
    if (gs)
    {
        uint64_t now_ms = gossipsub_now_ms();
        gossipsub_score_on_mesh_leave_locked(gs, topic, peer, now_ms);
    }
    (void)gossipsub_mesh_member_remove(topic, peer);
    (void)gossipsub_fanout_remove(topic, peer);
}

void gossipsub_backoff_gc_locked(gossipsub_topic_state_t *topic, uint64_t now_ms)
{
    if (!topic)
        return;
    gossipsub_backoff_entry_t **link = &topic->backoff;
    while (*link)
    {
        gossipsub_backoff_entry_t *node = *link;
        if (node->expire_ms && node->expire_ms <= now_ms)
        {
            *link = node->next;
            gossipsub_backoff_entry_free(node);
            if (topic->backoff_size > 0)
                topic->backoff_size--;
            continue;
        }
        link = &node->next;
    }
}

int gossipsub_backoff_add(gossipsub_topic_state_t *topic, const peer_id_t *peer, uint64_t expire_ms)
{
    if (!topic || !peer)
        return 0;

    gossipsub_backoff_entry_t *existing = gossipsub_backoff_find(topic->backoff, peer);
    if (existing)
    {
        existing->expire_ms = expire_ms;
        return 1;
    }

    peer_id_t *dup = gossipsub_peer_clone(peer);
    if (!dup)
        return 0;

    gossipsub_backoff_entry_t *node = (gossipsub_backoff_entry_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        gossipsub_peer_free(dup);
        return 0;
    }

    node->peer = dup;
    node->expire_ms = expire_ms;
    node->next = topic->backoff;
    topic->backoff = node;
    topic->backoff_size++;
    return 1;
}

void gossipsub_backoff_remove(gossipsub_topic_state_t *topic, const peer_id_t *peer)
{
    if (!topic || !peer)
        return;
    gossipsub_backoff_entry_t **link = &topic->backoff;
    while (*link)
    {
        if (gossipsub_peer_equals((*link)->peer, peer))
        {
            gossipsub_backoff_entry_t *victim = *link;
            *link = victim->next;
            gossipsub_backoff_entry_free(victim);
            if (topic->backoff_size > 0)
                topic->backoff_size--;
            return;
        }
        link = &(*link)->next;
    }
}

int gossipsub_backoff_contains(gossipsub_topic_state_t *topic,
                               const peer_id_t *peer,
                               uint64_t now_ms)
{
    if (!topic || !peer)
        return 0;
    gossipsub_backoff_gc_locked(topic, now_ms);
    return gossipsub_backoff_find(topic->backoff, peer) ? 1 : 0;
}

void gossipsub_topic_heartbeat_mesh_locked(gossipsub_topic_state_t *topic, uint64_t now_ms)
{
    if (!topic)
        return;

    gossipsub_mesh_member_t **link = &topic->mesh;
    while (*link)
    {
        gossipsub_mesh_member_t *member = *link;
        if (!member->peer_entry || !member->peer_entry->connected)
        {
            *link = member->next;
            gossipsub_mesh_member_free(member);
            if (topic->mesh_size > 0)
                topic->mesh_size--;
            continue;
        }
        gossipsub_mesh_member_touch(member, now_ms);
        link = &member->next;
    }
}

void gossipsub_topic_heartbeat_fanout_locked(gossipsub_topic_state_t *topic, uint64_t now_ms)
{
    if (!topic)
        return;

    if (topic->fanout && topic->fanout_expire_ms && topic->fanout_expire_ms != UINT64_MAX &&
        now_ms >= topic->fanout_expire_ms)
    {
        gossipsub_fanout_clear_internal(&topic->fanout);
        topic->fanout_size = 0;
        topic->fanout_expire_ms = 0;
        return;
    }

    gossipsub_fanout_peer_t **link = &topic->fanout;
    while (*link)
    {
        gossipsub_fanout_peer_t *node = *link;
        if (!node->peer_entry || !node->peer_entry->connected)
        {
            *link = node->next;
            gossipsub_fanout_peer_free(node);
            if (topic->fanout_size > 0)
                topic->fanout_size--;
            continue;
        }
        link = &node->next;
    }

    if (!topic->fanout)
        topic->fanout_expire_ms = 0;
}

peer_id_t **gossipsub_topic_collect_px_locked(gossipsub_topic_state_t *topic,
                                              const peer_id_t *exclude_peer,
                                              size_t limit,
                                              size_t *out_len)
{
    if (!out_len)
        return NULL;
    *out_len = 0;
    if (!topic || limit == 0)
        return NULL;

    peer_id_t **list = (peer_id_t **)calloc(limit, sizeof(*list));
    if (!list)
        return NULL;

    size_t count = 0;
    for (gossipsub_mesh_member_t *member = topic->mesh; member && count < limit; member = member->next)
    {
        if (!member->peer)
            continue;
        if (exclude_peer && gossipsub_peer_equals(member->peer, exclude_peer))
            continue;
        if (member->peer_entry && !member->peer_entry->connected)
            continue;

        int duplicate = 0;
        for (size_t i = 0; i < count; ++i)
        {
            if (gossipsub_peer_equals(list[i], member->peer))
            {
                duplicate = 1;
                break;
            }
        }
        if (duplicate)
            continue;

        peer_id_t *dup = gossipsub_peer_clone(member->peer);
        if (!dup)
        {
            gossipsub_px_list_free(list, count);
            return NULL;
        }
        list[count++] = dup;
    }

    if (count == 0)
    {
        free(list);
        return NULL;
    }

    peer_id_t **shrunk = (peer_id_t **)realloc(list, count * sizeof(*list));
    if (shrunk)
        list = shrunk;
    *out_len = count;
    return list;
}

void gossipsub_px_list_free(peer_id_t **list, size_t len)
{
    if (!list)
        return;
    for (size_t i = 0; i < len; ++i)
    {
        if (list[i])
            gossipsub_peer_free(list[i]);
    }
    free(list);
}

void gossipsub_topics_remove_peer_locked(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer)
        return;
    for (gossipsub_topic_state_t *topic = gs->topics; topic; topic = topic->next)
        gossipsub_topic_remove_peer(gs, topic, peer);
}

static void gossipsub_topic_free(gossipsub_topic_state_t *topic)
{
    if (!topic)
        return;
    if (topic->name)
        free(topic->name);
    gossipsub_mesh_clear(&topic->mesh);
    topic->mesh_size = 0;
    gossipsub_fanout_clear_internal(&topic->fanout);
    topic->fanout_size = 0;
    topic->fanout_expire_ms = 0;
    gossipsub_backoff_clear(&topic->backoff);
    topic->backoff_size = 0;

    gossipsub_validator_node_t *node = topic->validators;
    while (node)
    {
        gossipsub_validator_node_t *next = node->next;
        gossipsub_validator_handle_release(node->handle);
        free(node);
        node = next;
    }
    topic->validators = NULL;
}

void gossipsub_topics_clear(gossipsub_topic_state_t *head)
{
    while (head)
    {
        gossipsub_topic_state_t *next = head->next;
        gossipsub_topic_free(head);
        free(head);
        head = next;
    }
}

void gossipsub_topic_compute_mesh_params(const libp2p_gossipsub_config_t *cfg,
                                         const gossipsub_topic_state_t *topic,
                                         gossipsub_topic_mesh_params_t *out)
{
    if (!out)
        return;
    size_t d = 0;
    size_t d_lo = 0;
    size_t d_hi = 0;

    if (cfg)
    {
        if (cfg->d_lo > 0)
            d_lo = (size_t)cfg->d_lo;
        if (cfg->d > 0)
            d = (size_t)cfg->d;
        if (cfg->d_hi > 0)
            d_hi = (size_t)cfg->d_hi;
    }

    size_t mesh_size = topic ? topic->mesh_size : 0;

    if (d_lo == 0)
        d_lo = d ? d : mesh_size;
    if (d == 0)
        d = d_lo;
    if (d_hi == 0)
        d_hi = d ? d : d_lo;

    out->d_lo = d_lo;
    out->d = d;
    out->d_hi = d_hi;
}
