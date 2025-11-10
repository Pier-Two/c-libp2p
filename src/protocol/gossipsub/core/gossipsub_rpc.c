#include "gossipsub_rpc.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/log.h"

#include "noise/protobufs.h"

#define GOSSIPSUB_MODULE "gossipsub"

static libp2p_err_t gossipsub_rpc_encode_finalize(libp2p_gossipsub_RPC *rpc, gossipsub_rpc_out_t *out)
{
    if (!rpc || !out)
        return LIBP2P_ERR_NULL_PTR;

    NoiseProtobuf measure;
    int noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        return LIBP2P_ERR_INTERNAL;

    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_measure(&measure, NULL);
        return LIBP2P_ERR_INTERNAL;
    }

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        return LIBP2P_ERR_INTERNAL;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        return LIBP2P_ERR_INTERNAL;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        return LIBP2P_ERR_INTERNAL;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        return LIBP2P_ERR_INTERNAL;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        return LIBP2P_ERR_INTERNAL;
    }

    out->frame = encoded;
    out->frame_len = encoded_len;
    return LIBP2P_ERR_OK;
}

static void gossipsub_rpc_free_subscription_array(gossipsub_rpc_subscription_t *subs, size_t len)
{
    if (!subs)
        return;
    for (size_t i = 0; i < len; ++i)
    {
        if (subs[i].topic)
            free(subs[i].topic);
        if (subs[i].topic_id)
            free(subs[i].topic_id);
        subs[i].topic = NULL;
        subs[i].topic_id = NULL;
    }
    free(subs);
}

static void gossipsub_rpc_free_ihave_entry(gossipsub_rpc_control_ihave_t *entry)
{
    if (!entry)
        return;
    if (entry->topic)
        free(entry->topic);
    if (entry->topic_id)
        free(entry->topic_id);
    if (entry->ids)
        gossipsub_message_cache_free_ids(entry->ids, entry->count);
    if (entry->lengths)
        free(entry->lengths);
    entry->topic = NULL;
    entry->topic_id = NULL;
    entry->ids = NULL;
    entry->lengths = NULL;
    entry->count = 0;
}

static void gossipsub_rpc_free_iwant_entry(gossipsub_rpc_control_iwant_t *entry)
{
    if (!entry)
        return;
    if (entry->ids)
        gossipsub_message_cache_free_ids(entry->ids, entry->count);
    if (entry->lengths)
        free(entry->lengths);
    entry->ids = NULL;
    entry->lengths = NULL;
    entry->count = 0;
}

static void gossipsub_rpc_free_graft_entry(gossipsub_rpc_control_graft_t *entry)
{
    if (!entry)
        return;
    if (entry->topic)
        free(entry->topic);
    if (entry->topic_id)
        free(entry->topic_id);
    entry->topic = NULL;
    entry->topic_id = NULL;
}

static void gossipsub_rpc_free_prune_entry(gossipsub_rpc_control_prune_t *entry)
{
    if (!entry)
        return;
    if (entry->topic)
        free(entry->topic);
    if (entry->topic_id)
        free(entry->topic_id);
    if (entry->px)
    {
        for (size_t i = 0; i < entry->px_count; ++i)
        {
            gossipsub_rpc_px_record_t *px = &entry->px[i];
            if (px->peer)
                gossipsub_peer_free(px->peer);
            if (px->signed_peer_record)
                free(px->signed_peer_record);
        }
        free(entry->px);
    }
    entry->topic = NULL;
    entry->topic_id = NULL;
    entry->px = NULL;
    entry->px_count = 0;
}

void gossipsub_rpc_out_init(gossipsub_rpc_out_t *out)
{
    if (!out)
        return;
    out->frame = NULL;
    out->frame_len = 0;
}

void gossipsub_rpc_out_clear(gossipsub_rpc_out_t *out)
{
    if (!out)
        return;
    if (out->frame)
        free(out->frame);
    out->frame = NULL;
    out->frame_len = 0;
}

libp2p_err_t gossipsub_rpc_encode_control_iwant(uint8_t **ids,
                                                const size_t *id_lengths,
                                                size_t count,
                                                gossipsub_rpc_out_t *out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_rpc_out_init(out);
    if (!ids || !id_lengths || count == 0)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_gossipsub_ControlMessage *control = NULL;
    libp2p_gossipsub_ControlIWant *iwant = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;

    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlMessage_add_iwant(control, &iwant);
    if (noise_rc != NOISE_ERROR_NONE || !iwant)
        goto cleanup;

    for (size_t i = 0; i < count; ++i)
    {
        if (!ids[i] || id_lengths[i] == 0)
            continue;
        noise_rc = libp2p_gossipsub_ControlIWant_add_message_ids(iwant, ids[i], id_lengths[i]);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;
    }

    result = gossipsub_rpc_encode_finalize(rpc, out);

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    if (result != LIBP2P_ERR_OK)
        gossipsub_rpc_out_clear(out);
    return result;
}

libp2p_err_t gossipsub_rpc_encode_control_prune(const gossipsub_prune_target_t *const *targets,
                                                size_t count,
                                                uint64_t backoff_seconds,
                                                gossipsub_rpc_out_t *out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_rpc_out_init(out);
    if (!targets || count == 0)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_gossipsub_ControlMessage *control = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;

    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    for (size_t i = 0; i < count; ++i)
    {
        const gossipsub_prune_target_t *target = targets[i];
        if (!target || !target->topic)
            continue;

        libp2p_gossipsub_ControlPrune *prune = NULL;
        noise_rc = libp2p_gossipsub_ControlMessage_add_prune(control, &prune);
        if (noise_rc != NOISE_ERROR_NONE || !prune)
            goto cleanup;

        size_t topic_len = strlen(target->topic);
        if (topic_len == 0)
            continue;
        noise_rc = libp2p_gossipsub_ControlPrune_set_topic(prune, target->topic, topic_len);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;
        noise_rc = libp2p_gossipsub_ControlPrune_set_topic_id(prune, target->topic, topic_len);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;

        if (backoff_seconds > 0)
        {
            noise_rc = libp2p_gossipsub_ControlPrune_set_backoff(prune, backoff_seconds);
            if (noise_rc != NOISE_ERROR_NONE)
                goto cleanup;
        }

        if (target->px_peers && target->px_len > 0)
        {
            for (size_t j = 0; j < target->px_len; ++j)
            {
                peer_id_t *pid = target->px_peers[j];
                if (!pid || !pid->bytes || pid->size == 0)
                    continue;

                libp2p_gossipsub_PeerInfo *info = NULL;
                noise_rc = libp2p_gossipsub_ControlPrune_add_peers(prune, &info);
                if (noise_rc != NOISE_ERROR_NONE || !info)
                    goto cleanup;

                noise_rc = libp2p_gossipsub_PeerInfo_set_peer_id(info, pid->bytes, pid->size);
                if (noise_rc != NOISE_ERROR_NONE)
                    goto cleanup;
            }
        }
    }

    result = gossipsub_rpc_encode_finalize(rpc, out);

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    if (result != LIBP2P_ERR_OK)
        gossipsub_rpc_out_clear(out);
    return result;
}

libp2p_err_t gossipsub_rpc_encode_control_graft(const char *const *topics,
                                                size_t count,
                                                gossipsub_rpc_out_t *out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_rpc_out_init(out);
    if (!topics || count == 0)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_gossipsub_ControlMessage *control = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;

    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    for (size_t i = 0; i < count; ++i)
    {
        const char *topic = topics[i];
        if (!topic)
            continue;

        libp2p_gossipsub_ControlGraft *graft = NULL;
        noise_rc = libp2p_gossipsub_ControlMessage_add_graft(control, &graft);
        if (noise_rc != NOISE_ERROR_NONE || !graft)
            goto cleanup;

        size_t topic_len = strlen(topic);
        if (topic_len == 0)
            continue;
        noise_rc = libp2p_gossipsub_ControlGraft_set_topic(graft, topic, topic_len);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;
        noise_rc = libp2p_gossipsub_ControlGraft_set_topic_id(graft, topic, topic_len);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;
    }

    result = gossipsub_rpc_encode_finalize(rpc, out);

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    if (result != LIBP2P_ERR_OK)
        gossipsub_rpc_out_clear(out);
    return result;
}

libp2p_err_t gossipsub_rpc_encode_subscription(const char *topic,
                                               int subscribe,
                                               gossipsub_rpc_out_t *out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_rpc_out_init(out);
    if (!topic)
        return LIBP2P_ERR_NULL_PTR;

    size_t topic_len = strlen(topic);
    if (topic_len == 0)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;

    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    libp2p_gossipsub_RPC_SubOpts *sub = NULL;
    noise_rc = libp2p_gossipsub_RPC_add_subscriptions(rpc, &sub);
    if (noise_rc != NOISE_ERROR_NONE || !sub)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_SubOpts_set_topic(sub, topic, topic_len);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;
    noise_rc = libp2p_gossipsub_RPC_SubOpts_set_topic_id(sub, topic, topic_len);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_SubOpts_set_subscribe(sub, subscribe ? 1 : 0);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    result = gossipsub_rpc_encode_finalize(rpc, out);

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    if (result != LIBP2P_ERR_OK)
        gossipsub_rpc_out_clear(out);
    return result;
}

libp2p_err_t gossipsub_rpc_encode_control_ihave(const char *topic,
                                                uint8_t **ids,
                                                const size_t *id_lengths,
                                                size_t count,
                                                gossipsub_rpc_out_t *out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    gossipsub_rpc_out_init(out);
    if (!topic || !ids || !id_lengths || count == 0)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_gossipsub_ControlMessage *control = NULL;
    libp2p_gossipsub_ControlIHave *ihave = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;

    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlMessage_add_ihave(control, &ihave);
    if (noise_rc != NOISE_ERROR_NONE || !ihave)
        goto cleanup;

    size_t topic_len = strlen(topic);
    if (topic_len == 0)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlIHave_set_topic(ihave, topic, topic_len);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;
    noise_rc = libp2p_gossipsub_ControlIHave_set_topic_id(ihave, topic, topic_len);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    for (size_t i = 0; i < count; ++i)
    {
        if (!ids[i] || id_lengths[i] == 0)
            continue;
        noise_rc = libp2p_gossipsub_ControlIHave_add_message_ids(ihave, ids[i], id_lengths[i]);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;
    }

    result = gossipsub_rpc_encode_finalize(rpc, out);

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    if (result != LIBP2P_ERR_OK)
        gossipsub_rpc_out_clear(out);
    return result;
}

void gossipsub_rpc_parsed_init(gossipsub_rpc_parsed_t *parsed)
{
    if (!parsed)
        return;
    parsed->subscriptions = NULL;
    parsed->subscriptions_len = 0;
    parsed->iwants = NULL;
    parsed->iwant_len = 0;
    parsed->ihaves = NULL;
    parsed->ihave_len = 0;
    parsed->grafts = NULL;
    parsed->graft_len = 0;
    parsed->prunes = NULL;
    parsed->prune_len = 0;
}

void gossipsub_rpc_parsed_clear(gossipsub_rpc_parsed_t *parsed)
{
    if (!parsed)
        return;

    gossipsub_rpc_free_subscription_array(parsed->subscriptions, parsed->subscriptions_len);
    parsed->subscriptions = NULL;
    parsed->subscriptions_len = 0;

    if (parsed->iwants)
    {
        for (size_t i = 0; i < parsed->iwant_len; ++i)
            gossipsub_rpc_free_iwant_entry(&parsed->iwants[i]);
        free(parsed->iwants);
    }
    parsed->iwants = NULL;
    parsed->iwant_len = 0;

    if (parsed->ihaves)
    {
        for (size_t i = 0; i < parsed->ihave_len; ++i)
            gossipsub_rpc_free_ihave_entry(&parsed->ihaves[i]);
        free(parsed->ihaves);
    }
    parsed->ihaves = NULL;
    parsed->ihave_len = 0;

    if (parsed->grafts)
    {
        for (size_t i = 0; i < parsed->graft_len; ++i)
            gossipsub_rpc_free_graft_entry(&parsed->grafts[i]);
        free(parsed->grafts);
    }
    parsed->grafts = NULL;
    parsed->graft_len = 0;

    if (parsed->prunes)
    {
        for (size_t i = 0; i < parsed->prune_len; ++i)
            gossipsub_rpc_free_prune_entry(&parsed->prunes[i]);
        free(parsed->prunes);
    }
    parsed->prunes = NULL;
    parsed->prune_len = 0;
}

static libp2p_err_t gossipsub_rpc_parse_subscriptions(const libp2p_gossipsub_RPC *rpc,
                                                      gossipsub_rpc_parsed_t *out)
{
    size_t raw_count = libp2p_gossipsub_RPC_count_subscriptions(rpc);
    if (raw_count == 0)
        return LIBP2P_ERR_OK;

    gossipsub_rpc_subscription_t *subs = (gossipsub_rpc_subscription_t *)calloc(raw_count, sizeof(*subs));
    if (!subs)
        return LIBP2P_ERR_INTERNAL;

    size_t used = 0;
    for (size_t i = 0; i < raw_count; ++i)
    {
        libp2p_gossipsub_RPC_SubOpts *sub = libp2p_gossipsub_RPC_get_at_subscriptions(rpc, i);
        int has_topic = sub ? libp2p_gossipsub_RPC_SubOpts_has_topic(sub) : 0;
        size_t topic_len = has_topic ? libp2p_gossipsub_RPC_SubOpts_get_size_topic(sub) : 0;
        const char *topic_raw = has_topic ? libp2p_gossipsub_RPC_SubOpts_get_topic(sub) : NULL;
        int has_topic_id = sub ? libp2p_gossipsub_RPC_SubOpts_has_topic_id(sub) : 0;
        size_t topic_id_len = has_topic_id ? libp2p_gossipsub_RPC_SubOpts_get_size_topic_id(sub) : 0;
        const char *topic_id_raw = has_topic_id ? libp2p_gossipsub_RPC_SubOpts_get_topic_id(sub) : NULL;
        int has_subscribe = sub ? libp2p_gossipsub_RPC_SubOpts_has_subscribe(sub) : 0;
        int subscribe_value = has_subscribe ? (libp2p_gossipsub_RPC_SubOpts_get_subscribe(sub) ? 1 : 0) : -1;
        LP_LOGT(GOSSIPSUB_MODULE,
                "parse_sub raw index=%zu has_topic=%d topic_len=%zu has_topic_id=%d topic_id_len=%zu subscribe_present=%d subscribe_value=%d",
                i,
                has_topic ? 1 : 0,
                topic_len,
                has_topic_id ? 1 : 0,
                topic_id_len,
                has_subscribe ? 1 : 0,
                subscribe_value);
        if (!sub)
            continue;

        const char *selected_topic = topic_raw;
        size_t selected_len = topic_len;
        if ((!selected_topic || selected_len == 0) && topic_id_raw && topic_id_len > 0)
        {
            selected_topic = topic_id_raw;
            selected_len = topic_id_len;
        }
        if (!selected_topic || selected_len == 0)
            continue;

        char *topic = (char *)malloc(selected_len + 1);
        if (!topic)
        {
            gossipsub_rpc_free_subscription_array(subs, used);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(topic, selected_topic, selected_len);
        topic[selected_len] = '\0';

        char *topic_id = NULL;
        if (topic_id_raw && topic_id_len > 0)
        {
            topic_id = (char *)malloc(topic_id_len + 1);
            if (!topic_id)
            {
                free(topic);
                gossipsub_rpc_free_subscription_array(subs, used);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic_id_raw, topic_id_len);
            topic_id[topic_id_len] = '\0';
        }
        else
        {
            size_t fallback_len = strlen(topic);
            topic_id = (char *)malloc(fallback_len + 1);
            if (!topic_id)
            {
                free(topic);
                gossipsub_rpc_free_subscription_array(subs, used);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic, fallback_len + 1);
        }

        subs[used].topic = topic;
        subs[used].topic_id = topic_id;
        subs[used].subscribe = (subscribe_value >= 0) ? (subscribe_value ? 1 : 0) : 0;
        used++;
    }

    if (used == 0)
    {
        gossipsub_rpc_free_subscription_array(subs, raw_count);
        return LIBP2P_ERR_OK;
    }

    gossipsub_rpc_subscription_t *shrunk = (gossipsub_rpc_subscription_t *)realloc(subs, used * sizeof(*subs));
    if (shrunk)
        subs = shrunk;

    out->subscriptions = subs;
    out->subscriptions_len = used;
    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_rpc_parse_control_iwant(const libp2p_gossipsub_ControlMessage *control,
                                                      gossipsub_rpc_parsed_t *out)
{
    if (!libp2p_gossipsub_ControlMessage_has_iwant(control))
        return LIBP2P_ERR_OK;

    size_t raw_count = libp2p_gossipsub_ControlMessage_count_iwant(control);
    if (raw_count == 0)
        return LIBP2P_ERR_OK;

    gossipsub_rpc_control_iwant_t *iwants = (gossipsub_rpc_control_iwant_t *)calloc(raw_count, sizeof(*iwants));
    if (!iwants)
        return LIBP2P_ERR_INTERNAL;

    size_t used = 0;
    for (size_t i = 0; i < raw_count; ++i)
    {
        libp2p_gossipsub_ControlIWant *iwant = libp2p_gossipsub_ControlMessage_get_at_iwant(control, i);
        if (!iwant || !libp2p_gossipsub_ControlIWant_has_message_ids(iwant))
            continue;

        size_t msg_count = libp2p_gossipsub_ControlIWant_count_message_ids(iwant);
        if (msg_count == 0)
            continue;

        uint8_t **ids = (uint8_t **)calloc(msg_count, sizeof(*ids));
        size_t *lengths = (size_t *)calloc(msg_count, sizeof(*lengths));
        if (!ids || !lengths)
        {
            if (ids)
                free(ids);
            if (lengths)
                free(lengths);
            for (size_t j = 0; j < used; ++j)
                gossipsub_rpc_free_iwant_entry(&iwants[j]);
            free(iwants);
            return LIBP2P_ERR_INTERNAL;
        }

        size_t collected = 0;
        for (size_t j = 0; j < msg_count; ++j)
        {
            const void *id = libp2p_gossipsub_ControlIWant_get_at_message_ids(iwant, j);
            size_t id_len = libp2p_gossipsub_ControlIWant_get_size_at_message_ids(iwant, j);
            if (!id || id_len == 0)
                continue;
            uint8_t *dup = (uint8_t *)malloc(id_len);
            if (!dup)
            {
                gossipsub_message_cache_free_ids(ids, collected);
                free(lengths);
                for (size_t k = 0; k < used; ++k)
                    gossipsub_rpc_free_iwant_entry(&iwants[k]);
                free(iwants);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(dup, id, id_len);
            ids[collected] = dup;
            lengths[collected] = id_len;
            collected++;
        }

        if (collected == 0)
        {
            gossipsub_message_cache_free_ids(ids, msg_count);
            free(lengths);
            continue;
        }

        uint8_t **ids_shrunk = (uint8_t **)realloc(ids, collected * sizeof(*ids));
        if (ids_shrunk)
            ids = ids_shrunk;
        size_t *lengths_shrunk = (size_t *)realloc(lengths, collected * sizeof(*lengths));
        if (lengths_shrunk)
            lengths = lengths_shrunk;

        iwants[used].ids = ids;
        iwants[used].lengths = lengths;
        iwants[used].count = collected;
        used++;
    }

    if (used == 0)
    {
        for (size_t j = 0; j < raw_count; ++j)
            gossipsub_rpc_free_iwant_entry(&iwants[j]);
        free(iwants);
        return LIBP2P_ERR_OK;
    }

    gossipsub_rpc_control_iwant_t *shrunk = (gossipsub_rpc_control_iwant_t *)realloc(iwants, used * sizeof(*iwants));
    if (shrunk)
        iwants = shrunk;

    out->iwants = iwants;
    out->iwant_len = used;
    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_rpc_parse_control_ihave(const libp2p_gossipsub_ControlMessage *control,
                                                      gossipsub_rpc_parsed_t *out)
{
    if (!libp2p_gossipsub_ControlMessage_has_ihave(control))
        return LIBP2P_ERR_OK;

    size_t raw_count = libp2p_gossipsub_ControlMessage_count_ihave(control);
    if (raw_count == 0)
        return LIBP2P_ERR_OK;

    gossipsub_rpc_control_ihave_t *ihaves = (gossipsub_rpc_control_ihave_t *)calloc(raw_count, sizeof(*ihaves));
    if (!ihaves)
        return LIBP2P_ERR_INTERNAL;

    size_t used = 0;
    for (size_t i = 0; i < raw_count; ++i)
    {
        libp2p_gossipsub_ControlIHave *ihave = libp2p_gossipsub_ControlMessage_get_at_ihave(control, i);
        int has_topic = ihave ? libp2p_gossipsub_ControlIHave_has_topic(ihave) : 0;
        int has_topic_id = ihave ? libp2p_gossipsub_ControlIHave_has_topic_id(ihave) : 0;
        if (!ihave || (!has_topic && !has_topic_id) || !libp2p_gossipsub_ControlIHave_has_message_ids(ihave))
            continue;

        size_t topic_len = has_topic ? libp2p_gossipsub_ControlIHave_get_size_topic(ihave) : 0;
        const char *topic_raw = has_topic ? libp2p_gossipsub_ControlIHave_get_topic(ihave) : NULL;
        size_t topic_id_len = has_topic_id ? libp2p_gossipsub_ControlIHave_get_size_topic_id(ihave) : 0;
        const char *topic_id_raw = has_topic_id ? libp2p_gossipsub_ControlIHave_get_topic_id(ihave) : NULL;

        const char *selected_topic = topic_raw;
        size_t selected_len = topic_len;
        if ((!selected_topic || selected_len == 0) && topic_id_raw && topic_id_len > 0)
        {
            selected_topic = topic_id_raw;
            selected_len = topic_id_len;
        }
        if (!selected_topic || selected_len == 0)
            continue;

        char *topic = (char *)malloc(selected_len + 1);
        if (!topic)
        {
            for (size_t j = 0; j < used; ++j)
                gossipsub_rpc_free_ihave_entry(&ihaves[j]);
            free(ihaves);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(topic, selected_topic, selected_len);
        topic[selected_len] = '\0';

        char *topic_id = NULL;
        if (topic_id_raw && topic_id_len > 0)
        {
            topic_id = (char *)malloc(topic_id_len + 1);
            if (!topic_id)
            {
                free(topic);
                for (size_t j = 0; j < used; ++j)
                    gossipsub_rpc_free_ihave_entry(&ihaves[j]);
                free(ihaves);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic_id_raw, topic_id_len);
            topic_id[topic_id_len] = '\0';
        }
        else
        {
            size_t fallback_len = strlen(topic);
            topic_id = (char *)malloc(fallback_len + 1);
            if (!topic_id)
            {
                free(topic);
                for (size_t j = 0; j < used; ++j)
                    gossipsub_rpc_free_ihave_entry(&ihaves[j]);
                free(ihaves);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic, fallback_len + 1);
        }

        size_t msg_count = libp2p_gossipsub_ControlIHave_count_message_ids(ihave);
        if (msg_count == 0)
        {
            free(topic);
            free(topic_id);
            continue;
        }

        uint8_t **ids = (uint8_t **)calloc(msg_count, sizeof(*ids));
        size_t *lengths = (size_t *)calloc(msg_count, sizeof(*lengths));
        if (!ids || !lengths)
        {
            if (ids)
                free(ids);
            if (lengths)
                free(lengths);
            free(topic);
            for (size_t j = 0; j < used; ++j)
                gossipsub_rpc_free_ihave_entry(&ihaves[j]);
            free(ihaves);
            return LIBP2P_ERR_INTERNAL;
        }

        size_t collected = 0;
        for (size_t j = 0; j < msg_count; ++j)
        {
            const void *id = libp2p_gossipsub_ControlIHave_get_at_message_ids(ihave, j);
            size_t id_len = libp2p_gossipsub_ControlIHave_get_size_at_message_ids(ihave, j);
            if (!id || id_len == 0)
                continue;
            uint8_t *dup = (uint8_t *)malloc(id_len);
            if (!dup)
            {
                gossipsub_message_cache_free_ids(ids, collected);
                free(lengths);
                free(topic);
                free(topic_id);
                for (size_t k = 0; k < used; ++k)
                    gossipsub_rpc_free_ihave_entry(&ihaves[k]);
                free(ihaves);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(dup, id, id_len);
            ids[collected] = dup;
            lengths[collected] = id_len;
            collected++;
        }

        if (collected == 0)
        {
            gossipsub_message_cache_free_ids(ids, msg_count);
            free(lengths);
            free(topic);
            free(topic_id);
            continue;
        }

        uint8_t **ids_shrunk = (uint8_t **)realloc(ids, collected * sizeof(*ids));
        if (ids_shrunk)
            ids = ids_shrunk;
        size_t *lengths_shrunk = (size_t *)realloc(lengths, collected * sizeof(*lengths));
        if (lengths_shrunk)
            lengths = lengths_shrunk;

        ihaves[used].topic = topic;
        ihaves[used].topic_id = topic_id;
        ihaves[used].ids = ids;
        ihaves[used].lengths = lengths;
        ihaves[used].count = collected;
        used++;
    }

    if (used == 0)
    {
        for (size_t j = 0; j < raw_count; ++j)
            gossipsub_rpc_free_ihave_entry(&ihaves[j]);
        free(ihaves);
        return LIBP2P_ERR_OK;
    }

    gossipsub_rpc_control_ihave_t *shrunk = (gossipsub_rpc_control_ihave_t *)realloc(ihaves, used * sizeof(*ihaves));
    if (shrunk)
        ihaves = shrunk;

    out->ihaves = ihaves;
    out->ihave_len = used;
    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_rpc_parse_control_graft(const libp2p_gossipsub_ControlMessage *control,
                                                      gossipsub_rpc_parsed_t *out)
{
    if (!libp2p_gossipsub_ControlMessage_has_graft(control))
        return LIBP2P_ERR_OK;

    size_t raw_count = libp2p_gossipsub_ControlMessage_count_graft(control);
    if (raw_count == 0)
        return LIBP2P_ERR_OK;

    gossipsub_rpc_control_graft_t *grafts = (gossipsub_rpc_control_graft_t *)calloc(raw_count, sizeof(*grafts));
    if (!grafts)
        return LIBP2P_ERR_INTERNAL;

    size_t used = 0;
    for (size_t i = 0; i < raw_count; ++i)
    {
        libp2p_gossipsub_ControlGraft *graft = libp2p_gossipsub_ControlMessage_get_at_graft(control, i);
        int has_topic = graft ? libp2p_gossipsub_ControlGraft_has_topic(graft) : 0;
        int has_topic_id = graft ? libp2p_gossipsub_ControlGraft_has_topic_id(graft) : 0;
        if (!graft || (!has_topic && !has_topic_id))
            continue;

        size_t topic_len = has_topic ? libp2p_gossipsub_ControlGraft_get_size_topic(graft) : 0;
        const char *topic_raw = has_topic ? libp2p_gossipsub_ControlGraft_get_topic(graft) : NULL;
        size_t topic_id_len = has_topic_id ? libp2p_gossipsub_ControlGraft_get_size_topic_id(graft) : 0;
        const char *topic_id_raw = has_topic_id ? libp2p_gossipsub_ControlGraft_get_topic_id(graft) : NULL;

        const char *selected_topic = topic_raw;
        size_t selected_len = topic_len;
        if ((!selected_topic || selected_len == 0) && topic_id_raw && topic_id_len > 0)
        {
            selected_topic = topic_id_raw;
            selected_len = topic_id_len;
        }
        if (!selected_topic || selected_len == 0)
            continue;

        char *topic = (char *)malloc(selected_len + 1);
        if (!topic)
        {
            for (size_t j = 0; j < used; ++j)
                gossipsub_rpc_free_graft_entry(&grafts[j]);
            free(grafts);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(topic, selected_topic, selected_len);
        topic[selected_len] = '\0';

        char *topic_id = NULL;
        if (topic_id_raw && topic_id_len > 0)
        {
            topic_id = (char *)malloc(topic_id_len + 1);
            if (!topic_id)
            {
                free(topic);
                for (size_t j = 0; j < used; ++j)
                    gossipsub_rpc_free_graft_entry(&grafts[j]);
                free(grafts);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic_id_raw, topic_id_len);
            topic_id[topic_id_len] = '\0';
        }
        else
        {
            size_t fallback_len = strlen(topic);
            topic_id = (char *)malloc(fallback_len + 1);
            if (!topic_id)
            {
                free(topic);
                for (size_t j = 0; j < used; ++j)
                    gossipsub_rpc_free_graft_entry(&grafts[j]);
                free(grafts);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic, fallback_len + 1);
        }

        grafts[used].topic = topic;
        grafts[used].topic_id = topic_id;
        used++;
    }

    if (used == 0)
    {
        for (size_t j = 0; j < raw_count; ++j)
            gossipsub_rpc_free_graft_entry(&grafts[j]);
        free(grafts);
        return LIBP2P_ERR_OK;
    }

    gossipsub_rpc_control_graft_t *shrunk = (gossipsub_rpc_control_graft_t *)realloc(grafts, used * sizeof(*grafts));
    if (shrunk)
        grafts = shrunk;

    out->grafts = grafts;
    out->graft_len = used;
    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_rpc_parse_control_prune(const libp2p_gossipsub_ControlMessage *control,
                                                      gossipsub_rpc_parsed_t *out)
{
    if (!libp2p_gossipsub_ControlMessage_has_prune(control))
        return LIBP2P_ERR_OK;

    size_t raw_count = libp2p_gossipsub_ControlMessage_count_prune(control);
    if (raw_count == 0)
        return LIBP2P_ERR_OK;

    gossipsub_rpc_control_prune_t *prunes = (gossipsub_rpc_control_prune_t *)calloc(raw_count, sizeof(*prunes));
    if (!prunes)
        return LIBP2P_ERR_INTERNAL;

    size_t used = 0;
    for (size_t i = 0; i < raw_count; ++i)
    {
        libp2p_gossipsub_ControlPrune *prune = libp2p_gossipsub_ControlMessage_get_at_prune(control, i);
        int has_topic = prune ? libp2p_gossipsub_ControlPrune_has_topic(prune) : 0;
        int has_topic_id = prune ? libp2p_gossipsub_ControlPrune_has_topic_id(prune) : 0;
        if (!prune || (!has_topic && !has_topic_id))
            continue;

        size_t topic_len = has_topic ? libp2p_gossipsub_ControlPrune_get_size_topic(prune) : 0;
        const char *topic_raw = has_topic ? libp2p_gossipsub_ControlPrune_get_topic(prune) : NULL;
        size_t topic_id_len = has_topic_id ? libp2p_gossipsub_ControlPrune_get_size_topic_id(prune) : 0;
        const char *topic_id_raw = has_topic_id ? libp2p_gossipsub_ControlPrune_get_topic_id(prune) : NULL;

        const char *selected_topic = topic_raw;
        size_t selected_len = topic_len;
        if ((!selected_topic || selected_len == 0) && topic_id_raw && topic_id_len > 0)
        {
            selected_topic = topic_id_raw;
            selected_len = topic_id_len;
        }
        if (!selected_topic || selected_len == 0)
            continue;

        char *topic = (char *)malloc(selected_len + 1);
        if (!topic)
        {
            for (size_t j = 0; j < used; ++j)
                gossipsub_rpc_free_prune_entry(&prunes[j]);
            free(prunes);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(topic, selected_topic, selected_len);
        topic[selected_len] = '\0';

        char *topic_id = NULL;
        if (topic_id_raw && topic_id_len > 0)
        {
            topic_id = (char *)malloc(topic_id_len + 1);
            if (!topic_id)
            {
                free(topic);
                for (size_t j = 0; j < used; ++j)
                    gossipsub_rpc_free_prune_entry(&prunes[j]);
                free(prunes);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic_id_raw, topic_id_len);
            topic_id[topic_id_len] = '\0';
        }
        else
        {
            size_t fallback_len = strlen(topic);
            topic_id = (char *)malloc(fallback_len + 1);
            if (!topic_id)
            {
                free(topic);
                for (size_t j = 0; j < used; ++j)
                    gossipsub_rpc_free_prune_entry(&prunes[j]);
                free(prunes);
                return LIBP2P_ERR_INTERNAL;
            }
            memcpy(topic_id, topic, fallback_len + 1);
        }

        prunes[used].topic = topic;
        prunes[used].topic_id = topic_id;
        prunes[used].backoff = libp2p_gossipsub_ControlPrune_has_backoff(prune) ? libp2p_gossipsub_ControlPrune_get_backoff(prune) : 0;

        if (libp2p_gossipsub_ControlPrune_has_peers(prune))
        {
            size_t px_count = libp2p_gossipsub_ControlPrune_count_peers(prune);
            if (px_count > 0)
            {
                gossipsub_rpc_px_record_t *records = (gossipsub_rpc_px_record_t *)calloc(px_count, sizeof(*records));
                if (!records)
                {
                    free(prunes[used].topic);
                    free(prunes[used].topic_id);
                    prunes[used].topic = NULL;
                    prunes[used].topic_id = NULL;
                    for (size_t j = 0; j < used; ++j)
                        gossipsub_rpc_free_prune_entry(&prunes[j]);
                    free(prunes);
                    return LIBP2P_ERR_INTERNAL;
                }

                size_t collected = 0;
                for (size_t j = 0; j < px_count; ++j)
                {
                    libp2p_gossipsub_PeerInfo *info = libp2p_gossipsub_ControlPrune_get_at_peers(prune, j);
                    if (!info || !libp2p_gossipsub_PeerInfo_has_peer_id(info))
                        continue;

                    const void *peer_bytes = libp2p_gossipsub_PeerInfo_get_peer_id(info);
                    size_t peer_len = libp2p_gossipsub_PeerInfo_get_size_peer_id(info);
                    if (!peer_bytes || peer_len == 0)
                        continue;

                    peer_id_t tmp = {
                        .bytes = (uint8_t *)peer_bytes,
                        .size = peer_len
                    };
                    peer_id_t *dup = gossipsub_peer_clone(&tmp);
                    if (!dup)
                    {
                        for (size_t k = 0; k < collected; ++k)
                        {
                            if (records[k].peer)
                                gossipsub_peer_free(records[k].peer);
                            if (records[k].signed_peer_record)
                                free(records[k].signed_peer_record);
                        }
                        free(records);
                        free(prunes[used].topic);
                        free(prunes[used].topic_id);
                        prunes[used].topic = NULL;
                        prunes[used].topic_id = NULL;
                        for (size_t k = 0; k < used; ++k)
                            gossipsub_rpc_free_prune_entry(&prunes[k]);
                        free(prunes);
                        return LIBP2P_ERR_INTERNAL;
                    }

                    records[collected].peer = dup;

                    if (libp2p_gossipsub_PeerInfo_has_signed_peer_record(info))
                    {
                        const void *record_bytes = libp2p_gossipsub_PeerInfo_get_signed_peer_record(info);
                        size_t record_len = libp2p_gossipsub_PeerInfo_get_size_signed_peer_record(info);
                        if (record_bytes && record_len > 0)
                        {
                            uint8_t *dup_record = (uint8_t *)malloc(record_len);
                            if (!dup_record)
                            {
                                for (size_t k = 0; k <= collected; ++k)
                                {
                                    if (records[k].peer)
                                        gossipsub_peer_free(records[k].peer);
                                    if (records[k].signed_peer_record)
                                        free(records[k].signed_peer_record);
                                }
                                free(records);
                                free(prunes[used].topic);
                                free(prunes[used].topic_id);
                                prunes[used].topic = NULL;
                                prunes[used].topic_id = NULL;
                                for (size_t k = 0; k < used; ++k)
                                    gossipsub_rpc_free_prune_entry(&prunes[k]);
                                free(prunes);
                                return LIBP2P_ERR_INTERNAL;
                            }
                            memcpy(dup_record, record_bytes, record_len);
                            records[collected].signed_peer_record = dup_record;
                            records[collected].signed_peer_record_len = record_len;
                        }
                    }

                    collected++;
                }

                if (collected == 0)
                {
                    free(records);
                }
                else
                {
                    gossipsub_rpc_px_record_t *shrunk = (gossipsub_rpc_px_record_t *)realloc(records, collected * sizeof(*records));
                    if (shrunk)
                        records = shrunk;
                    prunes[used].px = records;
                    prunes[used].px_count = collected;
                }
            }
        }

        used++;
    }

    if (used == 0)
    {
        for (size_t j = 0; j < raw_count; ++j)
            gossipsub_rpc_free_prune_entry(&prunes[j]);
        free(prunes);
        return LIBP2P_ERR_OK;
    }

    gossipsub_rpc_control_prune_t *shrunk = (gossipsub_rpc_control_prune_t *)realloc(prunes, used * sizeof(*prunes));
    if (shrunk)
        prunes = shrunk;

    out->prunes = prunes;
    out->prune_len = used;
    return LIBP2P_ERR_OK;
}

libp2p_err_t gossipsub_rpc_parse(const libp2p_gossipsub_RPC *rpc, gossipsub_rpc_parsed_t *out)
{
    if (!rpc || !out)
        return LIBP2P_ERR_NULL_PTR;

    gossipsub_rpc_parsed_init(out);

    libp2p_err_t result = LIBP2P_ERR_OK;

    if (libp2p_gossipsub_RPC_has_subscriptions(rpc))
    {
        result = gossipsub_rpc_parse_subscriptions(rpc, out);
        if (result != LIBP2P_ERR_OK)
        {
            gossipsub_rpc_parsed_clear(out);
            return result;
        }
    }

    if (libp2p_gossipsub_RPC_has_control(rpc))
    {
        const libp2p_gossipsub_ControlMessage *control = libp2p_gossipsub_RPC_get_control(rpc);
        if (control)
        {
            result = gossipsub_rpc_parse_control_iwant(control, out);
            if (result != LIBP2P_ERR_OK)
            {
                gossipsub_rpc_parsed_clear(out);
                return result;
            }

            result = gossipsub_rpc_parse_control_ihave(control, out);
            if (result != LIBP2P_ERR_OK)
            {
                gossipsub_rpc_parsed_clear(out);
                return result;
            }

            result = gossipsub_rpc_parse_control_graft(control, out);
            if (result != LIBP2P_ERR_OK)
            {
                gossipsub_rpc_parsed_clear(out);
                return result;
            }

            result = gossipsub_rpc_parse_control_prune(control, out);
            if (result != LIBP2P_ERR_OK)
            {
                gossipsub_rpc_parsed_clear(out);
                return result;
            }
        }
    }

    return LIBP2P_ERR_OK;
}
