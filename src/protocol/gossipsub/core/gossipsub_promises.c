#include "gossipsub_promises.h"

#include <stdlib.h>
#include <string.h>

#include "gossipsub_internal.h"
#include "gossipsub_peer.h"
#include "gossipsub_score.h"

static gossipsub_promise_entry_t *gossipsub_promises_find(gossipsub_promises_t *promises,
                                                          const uint8_t *id,
                                                          size_t id_len)
{
    if (!promises || !id || id_len == 0)
        return NULL;
    for (gossipsub_promise_entry_t *entry = promises->head; entry; entry = entry->next)
    {
        if (entry->message_id_len == id_len && memcmp(entry->message_id, id, id_len) == 0)
            return entry;
    }
    return NULL;
}

static int gossipsub_promises_add_peer(gossipsub_promise_entry_t *entry,
                                       const peer_id_t *peer,
                                       uint64_t expire_ms)
{
    if (!entry || !peer)
        return 0;
    gossipsub_promise_peer_t *node = entry->peers;
    while (node)
    {
        if (gossipsub_peer_equals(node->peer, peer))
        {
            if (expire_ms > node->expire_ms)
                node->expire_ms = expire_ms;
            return 1;
        }
        node = node->next;
    }

    peer_id_t *dup = gossipsub_peer_clone(peer);
    if (!dup)
        return 0;
    node = (gossipsub_promise_peer_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        gossipsub_peer_free(dup);
        return 0;
    }
    node->peer = dup;
    node->expire_ms = expire_ms;
    node->next = entry->peers;
    entry->peers = node;
    return 1;
}

static gossipsub_promise_entry_t *gossipsub_promises_insert(gossipsub_promises_t *promises,
                                                            const uint8_t *id,
                                                            size_t id_len)
{
    if (!promises || !id || id_len == 0)
        return NULL;

    gossipsub_promise_entry_t *entry = (gossipsub_promise_entry_t *)calloc(1, sizeof(*entry));
    if (!entry)
        return NULL;
    entry->message_id = (uint8_t *)malloc(id_len);
    if (!entry->message_id)
    {
        free(entry);
        return NULL;
    }
    memcpy(entry->message_id, id, id_len);
    entry->message_id_len = id_len;
    entry->next = promises->head;
    promises->head = entry;
    return entry;
}

static void gossipsub_promises_entry_free(gossipsub_promise_entry_t *entry)
{
    if (!entry)
        return;
    gossipsub_promise_peer_t *peer = entry->peers;
    while (peer)
    {
        gossipsub_promise_peer_t *next = peer->next;
        gossipsub_peer_free(peer->peer);
        free(peer);
        peer = next;
    }
    free(entry->message_id);
    free(entry);
}

void gossipsub_promises_init(gossipsub_promises_t *promises)
{
    if (!promises)
        return;
    promises->head = NULL;
}

void gossipsub_promises_clear(gossipsub_promises_t *promises)
{
    if (!promises)
        return;
    gossipsub_promise_entry_t *entry = promises->head;
    promises->head = NULL;
    while (entry)
    {
        gossipsub_promise_entry_t *next = entry->next;
        gossipsub_promises_entry_free(entry);
        entry = next;
    }
}

void gossipsub_promises_track(gossipsub_promises_t *promises,
                              const peer_id_t *peer,
                              const uint8_t *const *ids,
                              const size_t *lens,
                              size_t count,
                              uint64_t expire_ms)
{
    if (!promises || !peer || !ids || !lens || count == 0)
        return;

    size_t selected = 0;
    if (count > 1)
    {
        uint64_t rnd = gossipsub_random_u64();
        selected = (size_t)(rnd % count);
    }

    const uint8_t *id = ids[selected];
    size_t id_len = lens[selected];
    if (!id || id_len == 0)
        return;

    gossipsub_promise_entry_t *entry = gossipsub_promises_find(promises, id, id_len);
    if (!entry)
        entry = gossipsub_promises_insert(promises, id, id_len);
    if (!entry)
        return;

    if (!gossipsub_promises_add_peer(entry, peer, expire_ms))
    {
        /* If adding fails, and entry has no peers, remove it */
        if (!entry->peers)
        {
            if (promises->head == entry)
                promises->head = entry->next;
            else
            {
                gossipsub_promise_entry_t *prev = promises->head;
                while (prev && prev->next != entry)
                    prev = prev->next;
                if (prev)
                    prev->next = entry->next;
            }
            gossipsub_promises_entry_free(entry);
        }
    }
}

void gossipsub_promises_message_delivered(gossipsub_promises_t *promises,
                                          const uint8_t *id,
                                          size_t id_len)
{
    if (!promises || !id || id_len == 0)
        return;

    gossipsub_promise_entry_t *prev = NULL;
    gossipsub_promise_entry_t *entry = promises->head;
    while (entry)
    {
        if (entry->message_id_len == id_len && memcmp(entry->message_id, id, id_len) == 0)
        {
            if (prev)
                prev->next = entry->next;
            else
                promises->head = entry->next;
            gossipsub_promises_entry_free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

void gossipsub_promises_apply_penalties(libp2p_gossipsub_t *gs,
                                        uint64_t now_ms)
{
    if (!gs)
        return;

    gossipsub_promises_t *promises = &gs->promises;
    gossipsub_promise_entry_t *entry = promises->head;
    gossipsub_promise_entry_t *prev = NULL;
    while (entry)
    {
        gossipsub_promise_peer_t **link = &entry->peers;
        while (*link)
        {
            gossipsub_promise_peer_t *peer_node = *link;
            if (peer_node->expire_ms <= now_ms)
            {
                gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer_node->peer);
                if (entry)
                {
                    entry->behaviour_penalty += 1.0;
                    gossipsub_score_recompute_peer_locked(gs, entry, now_ms);
                }
                *link = peer_node->next;
                gossipsub_peer_free(peer_node->peer);
                free(peer_node);
                continue;
            }
            link = &(*link)->next;
        }

        if (!entry->peers)
        {
            gossipsub_promise_entry_t *victim = entry;
            entry = entry->next;
            if (prev)
                prev->next = entry;
            else
                promises->head = entry;
            gossipsub_promises_entry_free(victim);
            continue;
        }

        prev = entry;
        entry = entry->next;
    }
}
