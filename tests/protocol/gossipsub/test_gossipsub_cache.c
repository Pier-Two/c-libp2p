#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gossipsub_cache.h"

static void test_message_cache_put_and_find(void)
{
    gossipsub_message_cache_t cache = {0};
    assert(gossipsub_message_cache_init(&cache, 3, 2) == LIBP2P_ERR_OK);

    const uint8_t id1[] = {0x01, 0x02};
    const uint8_t frame1[] = {0xAA};
    assert(gossipsub_message_cache_put(&cache, id1, sizeof(id1), "topic-a", frame1, sizeof(frame1)) == LIBP2P_ERR_OK);
    assert(gossipsub_message_cache_find(&cache, id1, sizeof(id1)) != NULL);

    /* second insert should be ignored but still succeed */
    assert(gossipsub_message_cache_put(&cache, id1, sizeof(id1), "topic-a", frame1, sizeof(frame1)) == LIBP2P_ERR_OK);

    gossipsub_message_cache_free(&cache);
}

static void test_message_cache_shift_eviction(void)
{
    gossipsub_message_cache_t cache = {0};
    assert(gossipsub_message_cache_init(&cache, 2, 1) == LIBP2P_ERR_OK);

    const uint8_t id1[] = {0x10};
    const uint8_t frame1[] = {0xBB};
    assert(gossipsub_message_cache_put(&cache, id1, sizeof(id1), "topic-b", frame1, sizeof(frame1)) == LIBP2P_ERR_OK);
    assert(gossipsub_message_cache_find(&cache, id1, sizeof(id1)) != NULL);

    assert(gossipsub_message_cache_shift(&cache) == LIBP2P_ERR_OK);
    assert(gossipsub_message_cache_find(&cache, id1, sizeof(id1)) != NULL);

    assert(gossipsub_message_cache_shift(&cache) == LIBP2P_ERR_OK);
    assert(gossipsub_message_cache_find(&cache, id1, sizeof(id1)) == NULL);

    gossipsub_message_cache_free(&cache);
}

static void test_message_cache_collect_ids_filter(void)
{
    gossipsub_message_cache_t cache = {0};
    assert(gossipsub_message_cache_init(&cache, 3, 3) == LIBP2P_ERR_OK);

    const uint8_t id_a1[] = {0x21};
    const uint8_t id_a2[] = {0x22};
    const uint8_t id_b1[] = {0x31};
    const uint8_t frame[] = {0xCC};

    assert(gossipsub_message_cache_put(&cache, id_a1, sizeof(id_a1), "topic-a", frame, sizeof(frame)) == LIBP2P_ERR_OK);
    assert(gossipsub_message_cache_put(&cache, id_a2, sizeof(id_a2), "topic-a", frame, sizeof(frame)) == LIBP2P_ERR_OK);
    assert(gossipsub_message_cache_put(&cache, id_b1, sizeof(id_b1), "topic-b", frame, sizeof(frame)) == LIBP2P_ERR_OK);

    uint8_t **ids = NULL;
    size_t *lengths = NULL;
    size_t count = 0;
    assert(gossipsub_message_cache_collect_ids(&cache, "topic-a", &ids, &lengths, &count, 1) == LIBP2P_ERR_OK);
    assert(count == 2);

    /* the order is insertion order within the same window */
    assert(lengths[0] == sizeof(id_a2) || lengths[0] == sizeof(id_a1));
    assert(lengths[1] == sizeof(id_a1) || lengths[1] == sizeof(id_a2));

    size_t matches = 0;
    for (size_t i = 0; i < count; ++i)
    {
        if (lengths[i] == sizeof(id_a1) && memcmp(ids[i], id_a1, sizeof(id_a1)) == 0)
            matches++;
        else if (lengths[i] == sizeof(id_a2) && memcmp(ids[i], id_a2, sizeof(id_a2)) == 0)
            matches++;
    }
    assert(matches == 2);

    gossipsub_message_cache_free_ids(ids, count);
    free(lengths);
    gossipsub_message_cache_free(&cache);
}

static void test_message_cache_collect_ids_round_gate(void)
{
    gossipsub_message_cache_t cache = {0};
    assert(gossipsub_message_cache_init(&cache, 4, 2) == LIBP2P_ERR_OK);

    const uint8_t msg_id[] = {0x51};
    const uint8_t frame[] = {0xDD};
    assert(gossipsub_message_cache_put(&cache, msg_id, sizeof(msg_id), "topic-x", frame, sizeof(frame)) == LIBP2P_ERR_OK);

    uint8_t **ids = NULL;
    size_t *lengths = NULL;
    size_t count = 0;
    assert(gossipsub_message_cache_collect_ids(&cache, "topic-x", &ids, &lengths, &count, 9) == LIBP2P_ERR_OK);
    assert(count == 1);
    assert(lengths != NULL);
    assert(lengths[0] == sizeof(msg_id));
    assert(memcmp(ids[0], msg_id, sizeof(msg_id)) == 0);
    gossipsub_message_cache_free_ids(ids, count);
    free(lengths);

    ids = NULL;
    lengths = NULL;
    count = 0;
    assert(gossipsub_message_cache_collect_ids(&cache, "topic-x", &ids, &lengths, &count, 9) == LIBP2P_ERR_OK);
    assert(count == 0);
    assert(ids == NULL);
    assert(lengths == NULL);

    assert(gossipsub_message_cache_collect_ids(&cache, "topic-x", &ids, &lengths, &count, 10) == LIBP2P_ERR_OK);
    assert(count == 1);
    assert(lengths != NULL);
    assert(lengths[0] == sizeof(msg_id));
    assert(memcmp(ids[0], msg_id, sizeof(msg_id)) == 0);

    gossipsub_message_cache_free_ids(ids, count);
    free(lengths);
    gossipsub_message_cache_free(&cache);
}

static void test_seen_cache_ttl_and_capacity(void)
{
    gossipsub_seen_cache_t cache = {0};
    assert(gossipsub_seen_cache_init(&cache, 2, 100) == LIBP2P_ERR_OK);

    const uint8_t id1[] = {0x41};
    int was_present = -1;
    assert(gossipsub_seen_cache_check_and_add(&cache, id1, sizeof(id1), 1000, &was_present) == LIBP2P_ERR_OK);
    assert(was_present == 0);
    assert(gossipsub_seen_cache_contains(&cache, id1, sizeof(id1), 1050) == 1);
    assert(gossipsub_seen_cache_contains(&cache, id1, sizeof(id1), 1100) == 0);

    gossipsub_seen_cache_free(&cache);
    assert(gossipsub_seen_cache_init(&cache, 2, 0) == LIBP2P_ERR_OK);

    const uint8_t id2[] = {0x42};
    const uint8_t id3[] = {0x43};
    const uint8_t id4[] = {0x44};

    assert(gossipsub_seen_cache_check_and_add(&cache, id1, sizeof(id1), 0, &was_present) == LIBP2P_ERR_OK);
    assert(was_present == 0);
    assert(gossipsub_seen_cache_check_and_add(&cache, id2, sizeof(id2), 1, &was_present) == LIBP2P_ERR_OK);
    assert(was_present == 0);
    assert(gossipsub_seen_cache_check_and_add(&cache, id3, sizeof(id3), 2, &was_present) == LIBP2P_ERR_OK);
    assert(was_present == 0);

    /* cache capacity is 2, so the oldest (id1) should be evicted */
    assert(gossipsub_seen_cache_contains(&cache, id1, sizeof(id1), 3) == 0);
    assert(gossipsub_seen_cache_contains(&cache, id2, sizeof(id2), 3) == 1);
    assert(gossipsub_seen_cache_contains(&cache, id3, sizeof(id3), 3) == 1);

    assert(gossipsub_seen_cache_check_and_add(&cache, id4, sizeof(id4), 4, &was_present) == LIBP2P_ERR_OK);
    assert(was_present == 0);
    assert(gossipsub_seen_cache_contains(&cache, id2, sizeof(id2), 5) == 0);
    assert(gossipsub_seen_cache_contains(&cache, id3, sizeof(id3), 5) == 1);
    assert(gossipsub_seen_cache_contains(&cache, id4, sizeof(id4), 5) == 1);

    gossipsub_seen_cache_free(&cache);
}

int main(void)
{
    test_message_cache_put_and_find();
    test_message_cache_shift_eviction();
    test_message_cache_collect_ids_filter();
    test_message_cache_collect_ids_round_gate();
    test_seen_cache_ttl_and_capacity();
    return 0;
}
