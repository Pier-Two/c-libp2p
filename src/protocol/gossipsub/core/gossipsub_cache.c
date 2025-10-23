#include "gossipsub_cache.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void gossipsub_cache_entry_detach(gossipsub_message_cache_t *cache, gossipsub_cache_entry_t *entry)
{
    if (!cache || !entry)
        return;
    if (entry->all_prev)
        entry->all_prev->all_next = entry->all_next;
    else
        cache->all_head = entry->all_next;
    if (entry->all_next)
        entry->all_next->all_prev = entry->all_prev;
    entry->all_prev = NULL;
    entry->all_next = NULL;
}

static void gossipsub_cache_entry_free(gossipsub_message_cache_t *cache, gossipsub_cache_entry_t *entry)
{
    if (!entry)
        return;
    gossipsub_cache_entry_detach(cache, entry);
    if (entry->id)
        free(entry->id);
    if (entry->topic)
        free(entry->topic);
    if (entry->frame)
        free(entry->frame);
    free(entry);
}

static void gossipsub_message_cache_clear_window(gossipsub_message_cache_t *cache,
                                                 gossipsub_cache_entry_t *head)
{
    while (head)
    {
        gossipsub_cache_entry_t *next = head->window_next;
        gossipsub_cache_entry_free(cache, head);
        head = next;
    }
}

libp2p_err_t gossipsub_seen_cache_init(gossipsub_seen_cache_t *cache, size_t capacity, uint64_t ttl_ms)
{
    if (!cache || capacity == 0)
        return LIBP2P_ERR_NULL_PTR;

    if (cache->entries)
        gossipsub_seen_cache_free(cache);

    cache->entries = (gossipsub_seen_entry_t *)calloc(capacity, sizeof(*cache->entries));
    if (!cache->entries)
        return LIBP2P_ERR_INTERNAL;

    cache->capacity = capacity;
    cache->size = 0;
    cache->ttl_ms = ttl_ms;
    return LIBP2P_ERR_OK;
}

void gossipsub_seen_cache_clear(gossipsub_seen_cache_t *cache)
{
    if (!cache || !cache->entries)
    {
        if (cache)
            cache->size = 0;
        return;
    }

    for (size_t i = 0; i < cache->capacity; ++i)
    {
        gossipsub_seen_entry_t *entry = &cache->entries[i];
        if (entry->id)
        {
            free(entry->id);
            entry->id = NULL;
        }
        entry->id_len = 0;
        entry->timestamp_ms = 0;
    }
    cache->size = 0;
}

void gossipsub_seen_cache_free(gossipsub_seen_cache_t *cache)
{
    if (!cache)
        return;
    if (cache->entries)
    {
        gossipsub_seen_cache_clear(cache);
        free(cache->entries);
    }
    cache->entries = NULL;
    cache->capacity = 0;
    cache->size = 0;
    cache->ttl_ms = 0;
}

static void gossipsub_seen_cache_gc_entry(gossipsub_seen_cache_t *cache,
                                          gossipsub_seen_entry_t *entry,
                                          uint64_t now_ms)
{
    if (!cache || !entry || !entry->id)
        return;
    if (cache->ttl_ms > 0 && entry->timestamp_ms + cache->ttl_ms <= now_ms)
    {
        free(entry->id);
        entry->id = NULL;
        entry->id_len = 0;
        entry->timestamp_ms = 0;
        if (cache->size > 0)
            cache->size--;
    }
}

int gossipsub_seen_cache_contains(gossipsub_seen_cache_t *cache,
                                  const uint8_t *id,
                                  size_t id_len,
                                  uint64_t now_ms)
{
    if (!cache || !id || id_len == 0 || !cache->entries || cache->capacity == 0)
        return 0;

    for (size_t i = 0; i < cache->capacity; ++i)
    {
        gossipsub_seen_entry_t *entry = &cache->entries[i];
        if (!entry->id)
            continue;

        gossipsub_seen_cache_gc_entry(cache, entry, now_ms);
        if (!entry->id)
            continue;

        if (entry->id_len == id_len && memcmp(entry->id, id, id_len) == 0)
            return 1;
    }

    return 0;
}

libp2p_err_t gossipsub_seen_cache_check_and_add(gossipsub_seen_cache_t *cache,
                                                const uint8_t *id,
                                                size_t id_len,
                                                uint64_t now_ms,
                                                int *out_was_present)
{
    if (!cache || !id || id_len == 0 || !out_was_present)
        return LIBP2P_ERR_NULL_PTR;
    *out_was_present = 0;
    if (!cache->entries || cache->capacity == 0)
        return LIBP2P_ERR_INTERNAL;

    size_t reuse_idx = SIZE_MAX;
    size_t oldest_idx = SIZE_MAX;
    uint64_t oldest_ts = UINT64_MAX;

    for (size_t i = 0; i < cache->capacity; ++i)
    {
        gossipsub_seen_entry_t *entry = &cache->entries[i];
        if (!entry->id)
        {
            if (reuse_idx == SIZE_MAX)
                reuse_idx = i;
            continue;
        }

        gossipsub_seen_cache_gc_entry(cache, entry, now_ms);
        if (!entry->id)
        {
            if (reuse_idx == SIZE_MAX)
                reuse_idx = i;
            continue;
        }

        if (entry->id_len == id_len && memcmp(entry->id, id, id_len) == 0)
        {
            entry->timestamp_ms = now_ms;
            *out_was_present = 1;
            return LIBP2P_ERR_OK;
        }

        if (entry->timestamp_ms < oldest_ts)
        {
            oldest_ts = entry->timestamp_ms;
            oldest_idx = i;
        }
    }

    if (reuse_idx == SIZE_MAX)
        reuse_idx = (oldest_idx != SIZE_MAX) ? oldest_idx : 0;

    gossipsub_seen_entry_t *slot = &cache->entries[reuse_idx];
    if (!slot->id)
    {
        slot->id = (uint8_t *)malloc(id_len);
        if (!slot->id)
            return LIBP2P_ERR_INTERNAL;
        cache->size++;
    }
    else if (slot->id_len != id_len)
    {
        uint8_t *resized = (uint8_t *)realloc(slot->id, id_len);
        if (!resized)
            return LIBP2P_ERR_INTERNAL;
        slot->id = resized;
    }

    memcpy(slot->id, id, id_len);
    slot->id_len = id_len;
    slot->timestamp_ms = now_ms;
    return LIBP2P_ERR_OK;
}

libp2p_err_t gossipsub_message_cache_init(gossipsub_message_cache_t *cache,
                                          size_t windows_len,
                                          size_t gossip_windows)
{
    if (!cache)
        return LIBP2P_ERR_NULL_PTR;
    if (windows_len == 0 || gossip_windows == 0 || gossip_windows > windows_len)
        return LIBP2P_ERR_INTERNAL;

    if (cache->windows)
        gossipsub_message_cache_free(cache);

    cache->windows = (gossipsub_cache_entry_t **)calloc(windows_len, sizeof(*cache->windows));
    if (!cache->windows)
        return LIBP2P_ERR_INTERNAL;

    cache->windows_len = windows_len;
    cache->gossip_windows = gossip_windows;
    cache->all_head = NULL;
    return LIBP2P_ERR_OK;
}

void gossipsub_message_cache_free(gossipsub_message_cache_t *cache)
{
    if (!cache)
        return;
    if (cache->windows && cache->windows_len)
    {
        for (size_t i = 0; i < cache->windows_len; ++i)
        {
            gossipsub_message_cache_clear_window(cache, cache->windows[i]);
            cache->windows[i] = NULL;
        }
        free(cache->windows);
    }
    cache->windows = NULL;
    cache->windows_len = 0;
    cache->gossip_windows = 0;
    cache->all_head = NULL;
}

gossipsub_cache_entry_t *gossipsub_message_cache_find(gossipsub_message_cache_t *cache,
                                                      const uint8_t *id,
                                                      size_t id_len)
{
    if (!cache || !id || id_len == 0)
        return NULL;

    for (gossipsub_cache_entry_t *it = cache->all_head; it; it = it->all_next)
    {
        if (it->id_len == id_len && memcmp(it->id, id, id_len) == 0)
            return it;
    }
    return NULL;
}

libp2p_err_t gossipsub_message_cache_put(gossipsub_message_cache_t *cache,
                                         const uint8_t *id,
                                         size_t id_len,
                                         const char *topic,
                                         const uint8_t *frame,
                                         size_t frame_len)
{
    if (!cache || !id || id_len == 0 || !frame || frame_len == 0)
        return LIBP2P_ERR_NULL_PTR;
    if (!cache->windows || cache->windows_len == 0)
        return LIBP2P_ERR_INTERNAL;

    if (gossipsub_message_cache_find(cache, id, id_len))
        return LIBP2P_ERR_OK;

    gossipsub_cache_entry_t *entry = (gossipsub_cache_entry_t *)calloc(1, sizeof(*entry));
    if (!entry)
        return LIBP2P_ERR_INTERNAL;

    entry->id = (uint8_t *)malloc(id_len);
    if (!entry->id)
    {
        free(entry);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(entry->id, id, id_len);
    entry->id_len = id_len;

    if (topic)
    {
        entry->topic = strdup(topic);
        if (!entry->topic)
        {
            free(entry->id);
            free(entry);
            return LIBP2P_ERR_INTERNAL;
        }
    }

    entry->frame = (uint8_t *)malloc(frame_len);
    if (!entry->frame)
    {
        if (entry->topic)
            free(entry->topic);
        free(entry->id);
        free(entry);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(entry->frame, frame, frame_len);
    entry->frame_len = frame_len;

    entry->window_next = cache->windows[0];
    cache->windows[0] = entry;

    entry->all_prev = NULL;
    entry->all_next = cache->all_head;
    if (cache->all_head)
        cache->all_head->all_prev = entry;
    cache->all_head = entry;
    return LIBP2P_ERR_OK;
}

libp2p_err_t gossipsub_message_cache_shift(gossipsub_message_cache_t *cache)
{
    if (!cache)
        return LIBP2P_ERR_NULL_PTR;
    if (!cache->windows || cache->windows_len == 0)
        return LIBP2P_ERR_INTERNAL;

    size_t last = cache->windows_len - 1;
    gossipsub_message_cache_clear_window(cache, cache->windows[last]);
    for (size_t i = last; i > 0; --i)
        cache->windows[i] = cache->windows[i - 1];
    cache->windows[0] = NULL;
    return LIBP2P_ERR_OK;
}

libp2p_err_t gossipsub_message_cache_collect_ids(gossipsub_message_cache_t *cache,
                                                 const char *topic,
                                                 uint8_t ***out_ids,
                                                 size_t **out_lengths,
                                                 size_t *out_count,
                                                 uint64_t current_round)
{
    if (!cache || !out_ids || !out_lengths || !out_count)
        return LIBP2P_ERR_NULL_PTR;

    *out_ids = NULL;
    *out_lengths = NULL;
    *out_count = 0;

    if (!cache->windows || cache->windows_len == 0 || cache->gossip_windows == 0)
        return LIBP2P_ERR_OK;

    size_t capacity = 16;
    size_t count = 0;
    uint8_t **ids = (uint8_t **)malloc(capacity * sizeof(uint8_t *));
    size_t *lengths = (size_t *)malloc(capacity * sizeof(size_t));
    if (!ids || !lengths)
    {
        if (ids)
            free(ids);
        if (lengths)
            free(lengths);
        return LIBP2P_ERR_INTERNAL;
    }

    for (size_t w = 0; w < cache->gossip_windows && w < cache->windows_len; ++w)
    {
        for (gossipsub_cache_entry_t *it = cache->windows[w]; it; it = it->window_next)
        {
            if (topic && it->topic && strcmp(it->topic, topic) != 0)
                continue;
            if (current_round != 0 && it->last_gossip_round == current_round)
                continue;
            if (count == capacity)
            {
                capacity *= 2;
                uint8_t **new_ids = (uint8_t **)realloc(ids, capacity * sizeof(uint8_t *));
                size_t *new_lengths = (size_t *)realloc(lengths, capacity * sizeof(size_t));
                if (!new_ids || !new_lengths)
                {
                    for (size_t i = 0; i < count; ++i)
                        free(ids[i]);
                    if (new_ids)
                        ids = new_ids;
                    if (new_lengths)
                        lengths = new_lengths;
                    free(ids);
                    free(lengths);
                    return LIBP2P_ERR_INTERNAL;
                }
                ids = new_ids;
                lengths = new_lengths;
            }
            uint8_t *dup = (uint8_t *)malloc(it->id_len);
            if (!dup)
            {
                for (size_t i = 0; i < count; ++i)
                    free(ids[i]);
                free(ids);
                free(lengths);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(dup, it->id, it->id_len);
            ids[count] = dup;
            lengths[count] = it->id_len;
            if (current_round != 0)
                it->last_gossip_round = current_round;
            count++;
        }
    }

    if (count == 0)
    {
        free(ids);
        free(lengths);
        return LIBP2P_ERR_OK;
    }

    *out_ids = ids;
    *out_lengths = lengths;
    *out_count = count;
    return LIBP2P_ERR_OK;
}

void gossipsub_message_cache_free_ids(uint8_t **ids, size_t count)
{
    if (!ids)
        return;
    for (size_t i = 0; i < count; ++i)
    {
        if (ids[i])
            free(ids[i]);
    }
    free(ids);
}
