#ifndef LIBP2P_GOSSIPSUB_CACHE_H
#define LIBP2P_GOSSIPSUB_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/errors.h"

typedef struct gossipsub_seen_entry
{
    uint8_t *id;
    size_t id_len;
    uint64_t timestamp_ms;
} gossipsub_seen_entry_t;

typedef struct gossipsub_seen_cache
{
    gossipsub_seen_entry_t *entries;
    size_t capacity;
    size_t size;
    uint64_t ttl_ms;
} gossipsub_seen_cache_t;

typedef struct gossipsub_cache_entry
{
    uint8_t *id;
    size_t id_len;
    char *topic;
    uint8_t *frame;
    size_t frame_len;
    uint64_t last_gossip_round;
    struct gossipsub_cache_entry *window_next;
    struct gossipsub_cache_entry *all_prev;
    struct gossipsub_cache_entry *all_next;
} gossipsub_cache_entry_t;

typedef struct gossipsub_message_cache
{
    gossipsub_cache_entry_t **windows;
    size_t windows_len;
    size_t gossip_windows;
    gossipsub_cache_entry_t *all_head;
} gossipsub_message_cache_t;

libp2p_err_t gossipsub_seen_cache_init(gossipsub_seen_cache_t *cache, size_t capacity, uint64_t ttl_ms);
void gossipsub_seen_cache_clear(gossipsub_seen_cache_t *cache);
void gossipsub_seen_cache_free(gossipsub_seen_cache_t *cache);
int gossipsub_seen_cache_contains(gossipsub_seen_cache_t *cache, const uint8_t *id, size_t id_len, uint64_t now_ms);
libp2p_err_t gossipsub_seen_cache_check_and_add(gossipsub_seen_cache_t *cache,
                                                const uint8_t *id,
                                                size_t id_len,
                                                uint64_t now_ms,
                                                int *out_was_present);

libp2p_err_t gossipsub_message_cache_init(gossipsub_message_cache_t *cache, size_t windows_len, size_t gossip_windows);
void gossipsub_message_cache_free(gossipsub_message_cache_t *cache);
gossipsub_cache_entry_t *gossipsub_message_cache_find(gossipsub_message_cache_t *cache, const uint8_t *id, size_t id_len);
libp2p_err_t gossipsub_message_cache_put(gossipsub_message_cache_t *cache,
                                         const uint8_t *id,
                                         size_t id_len,
                                         const char *topic,
                                         const uint8_t *frame,
                                         size_t frame_len);
libp2p_err_t gossipsub_message_cache_shift(gossipsub_message_cache_t *cache);
libp2p_err_t gossipsub_message_cache_collect_ids(gossipsub_message_cache_t *cache,
                                                 const char *topic,
                                                 uint8_t ***out_ids,
                                                 size_t **out_lengths,
                                                 size_t *out_count,
                                                 uint64_t current_round);
void gossipsub_message_cache_free_ids(uint8_t **ids, size_t count);

#endif /* LIBP2P_GOSSIPSUB_CACHE_H */
