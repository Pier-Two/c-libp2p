#include "test_gossipsub_service_common.h"

static const uint8_t kPeerRecordPayloadType[] = { 0x03, 0x01 };

const uint8_t kTestPxSecretKey[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

atomic_int g_sync_called;
atomic_int g_async_called;

void gossipsub_test_score_update_cb(libp2p_gossipsub_t *gs,
                                    const libp2p_gossipsub_score_update_t *update,
                                    void *user_data)
{
    (void)gs;
    if (!update || !user_data)
        return;
    gossipsub_service_test_env_t *env = (gossipsub_service_test_env_t *)user_data;
    env->score_update_count++;
    env->score_update_last_value = update->score;
    env->score_update_last_override = update->score_override ? 1 : 0;
}

void print_result(const char *name, int ok)
{
    printf("TEST: %-40s | %s\n", name, ok ? "PASS" : "FAIL");
}

libp2p_err_t encode_subscription_rpc(const char *topic,
                                     int subscribe,
                                     uint8_t **out_buf,
                                     size_t *out_len)
{
    if (!topic || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        return LIBP2P_ERR_INTERNAL;

    libp2p_err_t result = LIBP2P_ERR_INTERNAL;
    libp2p_gossipsub_RPC_SubOpts *sub = NULL;
    noise_rc = libp2p_gossipsub_RPC_add_subscriptions(rpc, &sub);
    if (noise_rc != NOISE_ERROR_NONE || !sub)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_SubOpts_set_topic(sub, topic, strlen(topic));
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_SubOpts_set_subscribe(sub, subscribe ? 1 : 0);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    NoiseProtobuf measure;
    noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        goto cleanup;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        goto cleanup;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        goto cleanup;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    result = LIBP2P_ERR_OK;

cleanup:
    libp2p_gossipsub_RPC_free(rpc);
    return result;
}

size_t compute_expected_gossip_targets(size_t eligible, int gossip_percent, int d_lazy)
{
    if (eligible == 0)
        return 0;

    size_t expected = 0;
    if (gossip_percent > 0)
    {
        size_t numerator = eligible * (size_t)gossip_percent;
        expected = numerator / 100;
        if (numerator % 100 != 0)
            expected++;
    }

    size_t lazy_target = (d_lazy > 0) ? (size_t)d_lazy : 0;
    if (expected < lazy_target)
        expected = lazy_target;
    if (expected == 0 || expected > eligible)
        expected = eligible;
    return expected;
}

int decode_prune_px_count(const uint8_t *frame,
                          size_t frame_len,
                          const char *topic,
                          size_t *out_px_count)
{
    if (out_px_count)
        *out_px_count = 0;
    if (!frame || frame_len == 0 || !topic)
        return 0;

    NoiseProtobuf in_pb;
    int noise_rc = noise_protobuf_prepare_input(&in_pb, frame, frame_len);
    if (noise_rc != NOISE_ERROR_NONE)
        return 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    noise_rc = libp2p_gossipsub_RPC_read(&in_pb, 0, &rpc);
    noise_protobuf_finish_input(&in_pb);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        return 0;

    const libp2p_gossipsub_ControlMessage *control = libp2p_gossipsub_RPC_get_control(rpc);
    if (!control)
    {
        libp2p_gossipsub_RPC_free(rpc);
        return 0;
    }

    size_t prune_count = libp2p_gossipsub_ControlMessage_count_prune(control);
    int match_found = 0;
    size_t px_count = 0;

    for (size_t i = 0; i < prune_count; ++i)
    {
        const libp2p_gossipsub_ControlPrune *prune = libp2p_gossipsub_ControlMessage_get_at_prune(control, i);
        if (!prune)
            continue;

        size_t topic_len = libp2p_gossipsub_ControlPrune_get_size_topic(prune);
        const char *prune_topic = libp2p_gossipsub_ControlPrune_get_topic(prune);
        if (!prune_topic || topic_len == 0)
            continue;
        if (strncmp(prune_topic, topic, topic_len) != 0)
            continue;

        match_found = 1;
        px_count = libp2p_gossipsub_ControlPrune_count_peers(prune);
        break;
    }

    if (match_found && out_px_count)
        *out_px_count = px_count;

    libp2p_gossipsub_RPC_free(rpc);
    return match_found;
}

int setup_gossip_peer(libp2p_gossipsub_t *gs,
                      const char *topic,
                      const char *peer_str,
                      peer_id_t *out_peer)
{
    if (!gs || !topic || !peer_str || !out_peer)
        return 0;

    memset(out_peer, 0, sizeof(*out_peer));
    if (peer_id_create_from_string(peer_str, out_peer) != PEER_ID_SUCCESS)
        return 0;

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    libp2p_err_t enc_rc = encode_subscription_rpc(topic, 1, &frame, &frame_len);
    if (enc_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
    {
        peer_id_destroy(out_peer);
        if (frame)
            free(frame);
        return 0;
    }

    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, out_peer, frame, frame_len);
    free(frame);
    if (inj_rc != LIBP2P_ERR_OK)
    {
        peer_id_destroy(out_peer);
        return 0;
    }

    libp2p_err_t conn_rc = libp2p_gossipsub__peer_set_connected(gs, out_peer, 1);
    if (conn_rc != LIBP2P_ERR_OK)
    {
        peer_id_destroy(out_peer);
        return 0;
    }

    (void)libp2p_gossipsub__peer_clear_sendq(gs, out_peer);
    return 1;
}

int run_gossip_factor_scenario(libp2p_gossipsub_t *gs,
                               const char *topic,
                               peer_id_t *peers,
                               size_t count,
                               const uint8_t *payload,
                               size_t payload_len,
                               size_t expected,
                               size_t *out_selected,
                               size_t *out_limit)
{
    if (!gs || !topic || !peers || !payload || payload_len == 0)
        return 0;

    libp2p_gossipsub_message_t msg = {
        .topic = {
            .struct_size = sizeof(msg.topic),
            .topic = topic
        },
        .data = payload,
        .data_len = payload_len,
        .from = NULL,
        .seqno = NULL,
        .seqno_len = 0,
        .raw_message = NULL,
        .raw_message_len = 0
    };

    if (libp2p_gossipsub_publish(gs, &msg) != LIBP2P_ERR_OK)
        return 0;

    usleep(10000);
    for (size_t i = 0; i < count; ++i)
        (void)libp2p_gossipsub__peer_clear_sendq(gs, &peers[i]);

    if (libp2p_gossipsub__heartbeat(gs) != LIBP2P_ERR_OK)
        return 0;

    size_t selected = 0;
    int queue_shape_ok = 1;
    const int max_attempts = 50;

    for (int attempt = 0; attempt < max_attempts; ++attempt)
    {
        selected = 0;
        queue_shape_ok = 1;
        for (size_t i = 0; i < count; ++i)
        {
            size_t qlen = libp2p_gossipsub__peer_sendq_len(gs, &peers[i]);
            if (qlen > 0)
            {
                if (qlen != 1)
                    queue_shape_ok = 0;
                selected++;
            }
        }
        if (selected == expected && queue_shape_ok)
            break;
        usleep(1000);
    }

    if (out_selected)
        *out_selected = selected;
    if (out_limit)
        *out_limit = gossipsub_debug_last_limit;

    return (selected == expected) && queue_shape_ok;
}

libp2p_err_t encode_control_ihave_rpc(const char *topic,
                                      const uint8_t *msg_id,
                                      size_t msg_id_len,
                                      uint8_t **out_buf,
                                      size_t *out_len)
{
    if (!topic || !msg_id || msg_id_len == 0 || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;
    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    libp2p_gossipsub_ControlMessage *control = NULL;
    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    libp2p_gossipsub_ControlIHave *ihave = NULL;
    noise_rc = libp2p_gossipsub_ControlMessage_add_ihave(control, &ihave);
    if (noise_rc != NOISE_ERROR_NONE || !ihave)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlIHave_set_topic(ihave, topic, strlen(topic));
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlIHave_add_message_ids(ihave, msg_id, msg_id_len);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    NoiseProtobuf measure;
    noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;
    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        goto cleanup;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        goto cleanup;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        goto cleanup;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    result = LIBP2P_ERR_OK;

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    return result;
}

int gossipsub_wait_for_peer_frame(libp2p_gossipsub_t *gs,
                                  const peer_id_t *peer,
                                  uint64_t timeout_ms,
                                  size_t *out_frame_len)
{
    if (!gs || !peer)
        return 0;
    if (out_frame_len)
        *out_frame_len = 0;

    const useconds_t sleep_us = 1000;
    for (uint64_t elapsed = 0; elapsed < timeout_ms; ++elapsed)
    {
        uint8_t *frame_buf = NULL;
        size_t frame_len = 0;
        libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, peer, &frame_buf, &frame_len);
        if (pop_rc == LIBP2P_ERR_OK)
        {
            if (out_frame_len)
                *out_frame_len = frame_len;
            free(frame_buf);
            return 1;
        }
        if (pop_rc != LIBP2P_ERR_UNSUPPORTED)
            break;
        usleep(sleep_us);
    }
    return 0;
}

int gossipsub_wait_for_peer_idle(libp2p_gossipsub_t *gs,
                                 const peer_id_t *peer,
                                 uint64_t duration_ms,
                                 size_t *out_queue_len)
{
    if (!gs || !peer)
        return 0;
    if (out_queue_len)
        *out_queue_len = 0;

    size_t queue_len = 0;
    const useconds_t sleep_us = 1000;

    for (uint64_t elapsed = 0; elapsed < duration_ms; ++elapsed)
    {
        queue_len = libp2p_gossipsub__peer_sendq_len(gs, peer);
        if (queue_len == 0)
            break;
        usleep(sleep_us);
    }

    if (out_queue_len)
        *out_queue_len = queue_len;
    return (queue_len == 0);
}

libp2p_err_t encode_graft_rpc(const char *topic,
                              uint8_t **out_buf,
                              size_t *out_len)
{
    if (!topic || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;
    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    libp2p_gossipsub_ControlMessage *control = NULL;
    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    libp2p_gossipsub_ControlGraft *graft = NULL;
    noise_rc = libp2p_gossipsub_ControlMessage_add_graft(control, &graft);
    if (noise_rc != NOISE_ERROR_NONE || !graft)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlGraft_set_topic(graft, topic, strlen(topic));
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    NoiseProtobuf measure;
    noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        goto cleanup;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        goto cleanup;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        goto cleanup;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    result = LIBP2P_ERR_OK;

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    return result;
}

static libp2p_err_t build_peer_record_unsigned(const uint8_t *payload_type,
                                               size_t payload_type_len,
                                               const uint8_t *payload,
                                               size_t payload_len,
                                               uint8_t **out_buf,
                                               size_t *out_len)
{
    if (!payload_type || payload_type_len == 0 || !payload || payload_len == 0 || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    const uint8_t *fields[] = {
        (const uint8_t *)"libp2p-peer-record",
        payload_type,
        payload
    };
    size_t lengths[] = {
        strlen("libp2p-peer-record"),
        payload_type_len,
        payload_len
    };
    const size_t field_count = sizeof(fields) / sizeof(fields[0]);

    size_t total = 0;
    uint8_t varint_buf[10];
    for (size_t i = 0; i < field_count; ++i)
    {
        size_t len_sz = 0;
        if (unsigned_varint_encode((uint64_t)lengths[i], varint_buf, sizeof(varint_buf), &len_sz) != UNSIGNED_VARINT_OK)
            return LIBP2P_ERR_INTERNAL;
        if (len_sz > SIZE_MAX - total)
            return LIBP2P_ERR_INTERNAL;
        total += len_sz;
        if (lengths[i] > SIZE_MAX - total)
            return LIBP2P_ERR_INTERNAL;
        total += lengths[i];
    }

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
        return LIBP2P_ERR_INTERNAL;

    size_t offset = 0;
    for (size_t i = 0; i < field_count; ++i)
    {
        size_t len_sz = 0;
        if (unsigned_varint_encode((uint64_t)lengths[i], varint_buf, sizeof(varint_buf), &len_sz) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(buf + offset, varint_buf, len_sz);
        offset += len_sz;
        if (lengths[i])
        {
            memcpy(buf + offset, fields[i], lengths[i]);
            offset += lengths[i];
        }
    }

    *out_buf = buf;
    *out_len = total;
    return LIBP2P_ERR_OK;
}

static int peer_record_write_fields(NoiseProtobuf *pbuf,
                                    const peer_id_t *peer,
                                    const multiaddr_t *const *addrs,
                                    size_t addr_count)
{
    if (!pbuf || !peer || !peer->bytes || peer->size == 0)
        return 0;
    if (noise_protobuf_write_bytes(pbuf, 1, peer->bytes, peer->size) != NOISE_ERROR_NONE)
        return 0;
    if (noise_protobuf_write_uint64(pbuf, 2, 1) != NOISE_ERROR_NONE)
        return 0;
    for (size_t i = 0; i < addr_count; ++i)
    {
        const multiaddr_t *ma = addrs ? addrs[i] : NULL;
        if (!ma || !ma->bytes || ma->size == 0)
            continue;
        size_t end_posn = 0;
        if (noise_protobuf_write_end_element(pbuf, &end_posn) != NOISE_ERROR_NONE)
            return 0;
        if (noise_protobuf_write_bytes(pbuf, 1, ma->bytes, ma->size) != NOISE_ERROR_NONE)
            return 0;
        if (noise_protobuf_write_start_element(pbuf, 3, end_posn) != NOISE_ERROR_NONE)
            return 0;
    }
    return 1;
}

libp2p_err_t encode_peer_record_proto(const peer_id_t *peer,
                                      const multiaddr_t *const *addrs,
                                      size_t addr_count,
                                      uint8_t **out_buf,
                                      size_t *out_len)
{
    if (!peer || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    NoiseProtobuf measure;
    if (noise_protobuf_prepare_measure(&measure, SIZE_MAX) != NOISE_ERROR_NONE)
        return LIBP2P_ERR_INTERNAL;

    if (!peer_record_write_fields(&measure, peer, addrs, addr_count))
    {
        noise_protobuf_finish_measure(&measure, NULL);
        return LIBP2P_ERR_INTERNAL;
    }

    size_t encoded_size = 0;
    if (noise_protobuf_finish_measure(&measure, &encoded_size) != NOISE_ERROR_NONE || encoded_size == 0)
        return LIBP2P_ERR_INTERNAL;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        return LIBP2P_ERR_INTERNAL;

    NoiseProtobuf out_pb;
    if (noise_protobuf_prepare_output(&out_pb, buffer, encoded_size) != NOISE_ERROR_NONE)
    {
        free(buffer);
        return LIBP2P_ERR_INTERNAL;
    }

    if (!peer_record_write_fields(&out_pb, peer, addrs, addr_count))
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        return LIBP2P_ERR_INTERNAL;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    if (noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len) != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        return LIBP2P_ERR_INTERNAL;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    return LIBP2P_ERR_OK;
}

libp2p_err_t encode_signed_peer_record(const peer_id_t *peer,
                                       const multiaddr_t *const *addrs,
                                       size_t addr_count,
                                       const uint8_t *secret_key,
                                       size_t secret_key_len,
                                       uint8_t **out_buf,
                                       size_t *out_len)
{
    if (!out_buf || !out_len || !secret_key)
        return LIBP2P_ERR_NULL_PTR;
    if (secret_key_len != sizeof(ed25519_secret_key))
        return LIBP2P_ERR_UNSUPPORTED;

    *out_buf = NULL;
    *out_len = 0;

    libp2p_err_t result = LIBP2P_ERR_INTERNAL;
    uint8_t *record_buf = NULL;
    size_t record_len = 0;
    uint8_t *pubkey_pb = NULL;
    size_t pubkey_pb_len = 0;
    uint8_t *unsigned_buf = NULL;
    size_t unsigned_len = 0;
    uint8_t *buffer = NULL;
    uint8_t *encoded = NULL;

    ed25519_secret_key sk;
    memcpy(sk, secret_key, sizeof(sk));
    ed25519_public_key pk;
    ed25519_publickey(sk, pk);

    libp2p_err_t rc = encode_peer_record_proto(peer, addrs, addr_count, &record_buf, &record_len);
    if (rc != LIBP2P_ERR_OK || !record_buf || record_len == 0)
        goto cleanup;

    peer_id_error_t pb_rc = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE,
                                                              pk,
                                                              sizeof(pk),
                                                              &pubkey_pb,
                                                              &pubkey_pb_len);
    if (pb_rc != PEER_ID_SUCCESS || !pubkey_pb || pubkey_pb_len == 0)
        goto cleanup;

    if (peer)
    {
        peer_id_t derived = { 0 };
        if (peer_id_create_from_public_key(pubkey_pb, pubkey_pb_len, &derived) != PEER_ID_SUCCESS)
        {
            peer_id_destroy(&derived);
            goto cleanup;
        }
        int equal = peer_id_equals(peer, &derived);
        peer_id_destroy(&derived);
        if (!equal)
        {
            result = LIBP2P_ERR_UNSUPPORTED;
            goto cleanup;
        }
    }

    rc = build_peer_record_unsigned(kPeerRecordPayloadType,
                                    sizeof(kPeerRecordPayloadType),
                                    record_buf,
                                    record_len,
                                    &unsigned_buf,
                                    &unsigned_len);
    if (rc != LIBP2P_ERR_OK || !unsigned_buf || unsigned_len == 0)
    {
        result = rc;
        goto cleanup;
    }

    ed25519_signature signature;
    ed25519_sign(unsigned_buf, unsigned_len, sk, pk, signature);
    free(unsigned_buf);
    unsigned_buf = NULL;

    NoiseProtobuf measure;
    if (noise_protobuf_prepare_measure(&measure, SIZE_MAX) != NOISE_ERROR_NONE)
        goto cleanup;

    if (noise_protobuf_write_bytes(&measure, 1, pubkey_pb, pubkey_pb_len) != NOISE_ERROR_NONE ||
        noise_protobuf_write_bytes(&measure, 2, kPeerRecordPayloadType, sizeof(kPeerRecordPayloadType)) != NOISE_ERROR_NONE ||
        noise_protobuf_write_bytes(&measure, 3, record_buf, record_len) != NOISE_ERROR_NONE ||
        noise_protobuf_write_bytes(&measure, 5, signature, sizeof(signature)) != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_measure(&measure, NULL);
        goto cleanup;
    }

    size_t encoded_size = 0;
    if (noise_protobuf_finish_measure(&measure, &encoded_size) != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    if (noise_protobuf_prepare_output(&out_pb, buffer, encoded_size) != NOISE_ERROR_NONE)
        goto cleanup;

    if (noise_protobuf_write_bytes(&out_pb, 1, pubkey_pb, pubkey_pb_len) != NOISE_ERROR_NONE ||
        noise_protobuf_write_bytes(&out_pb, 2, kPeerRecordPayloadType, sizeof(kPeerRecordPayloadType)) != NOISE_ERROR_NONE ||
        noise_protobuf_write_bytes(&out_pb, 3, record_buf, record_len) != NOISE_ERROR_NONE ||
        noise_protobuf_write_bytes(&out_pb, 5, signature, sizeof(signature)) != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        goto cleanup;
    }

    size_t encoded_len = 0;
    if (noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len) != NOISE_ERROR_NONE || !encoded)
        goto cleanup;

    result = LIBP2P_ERR_OK;
    *out_buf = encoded;
    *out_len = encoded_len;

cleanup:
    if (result != LIBP2P_ERR_OK && encoded)
        free(encoded);
    if (buffer && (!encoded || result != LIBP2P_ERR_OK))
        free(buffer);
    if (record_buf)
        free(record_buf);
    if (pubkey_pb)
        free(pubkey_pb);
    if (unsigned_buf)
        free(unsigned_buf);
    return result;
}

libp2p_err_t encode_prune_px_rpc(const char *topic,
                                 const peer_id_t *px_peer,
                                 const uint8_t *signed_record,
                                 size_t signed_record_len,
                                 uint8_t **out_buf,
                                 size_t *out_len)
{
    if (!topic || !px_peer || !px_peer->bytes || px_peer->size == 0 || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;
    *out_buf = NULL;
    *out_len = 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;

    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    libp2p_gossipsub_ControlMessage *control = NULL;
    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    libp2p_gossipsub_ControlPrune *prune = NULL;
    noise_rc = libp2p_gossipsub_ControlMessage_add_prune(control, &prune);
    if (noise_rc != NOISE_ERROR_NONE || !prune)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlPrune_set_topic(prune, topic, strlen(topic));
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    libp2p_gossipsub_PeerInfo *info = NULL;
    noise_rc = libp2p_gossipsub_ControlPrune_add_peers(prune, &info);
    if (noise_rc != NOISE_ERROR_NONE || !info)
        goto cleanup;

    noise_rc = libp2p_gossipsub_PeerInfo_set_peer_id(info, px_peer->bytes, px_peer->size);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    if (signed_record && signed_record_len > 0)
    {
        noise_rc = libp2p_gossipsub_PeerInfo_set_signed_peer_record(info, signed_record, signed_record_len);
        if (noise_rc != NOISE_ERROR_NONE)
            goto cleanup;
    }

    NoiseProtobuf measure;
    noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_measure(&measure, NULL);
        goto cleanup;
    }

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        goto cleanup;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        goto cleanup;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        goto cleanup;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    result = LIBP2P_ERR_OK;

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    return result;
}

libp2p_err_t encode_prune_rpc(const char *topic,
                              int include_px,
                              uint8_t **out_buf,
                              size_t *out_len)
{
    if (!topic || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;
    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    libp2p_gossipsub_ControlMessage *control = NULL;
    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    libp2p_gossipsub_ControlPrune *prune = NULL;
    noise_rc = libp2p_gossipsub_ControlMessage_add_prune(control, &prune);
    if (noise_rc != NOISE_ERROR_NONE || !prune)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlPrune_set_topic(prune, topic, strlen(topic));
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    if (include_px)
    {
        static const char *const px_peer_id = "12D3KooWMFFPRc3yLVaM76FUQojVKkD2VwGdMan3ZDV4SSQdlqzC";
        peer_id_t px_peer = { 0 };
        if (peer_id_create_from_string(px_peer_id, &px_peer) == PEER_ID_SUCCESS)
        {
            libp2p_gossipsub_PeerInfo *px_info = NULL;
            noise_rc = libp2p_gossipsub_ControlPrune_add_peers(prune, &px_info);
            if (noise_rc == NOISE_ERROR_NONE && px_info)
            {
                noise_rc = libp2p_gossipsub_PeerInfo_set_peer_id(px_info, px_peer.bytes, px_peer.size);
            }
            peer_id_destroy(&px_peer);
            if (noise_rc != NOISE_ERROR_NONE)
                goto cleanup;
        }
    }

    NoiseProtobuf measure;
    noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;
    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        goto cleanup;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        goto cleanup;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        goto cleanup;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    result = LIBP2P_ERR_OK;

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    return result;
}

libp2p_err_t encode_control_iwant_rpc(const uint8_t *msg_id,
                                      size_t msg_id_len,
                                      uint8_t **out_buf,
                                      size_t *out_len)
{
    if (!msg_id || msg_id_len == 0 || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_buf = NULL;
    *out_len = 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t result = LIBP2P_ERR_INTERNAL;
    int noise_rc = libp2p_gossipsub_RPC_new(&rpc);
    if (noise_rc != NOISE_ERROR_NONE || !rpc)
        goto cleanup;

    libp2p_gossipsub_ControlMessage *control = NULL;
    noise_rc = libp2p_gossipsub_RPC_get_new_control(rpc, &control);
    if (noise_rc != NOISE_ERROR_NONE || !control)
        goto cleanup;

    libp2p_gossipsub_ControlIWant *iwant = NULL;
    noise_rc = libp2p_gossipsub_ControlMessage_add_iwant(control, &iwant);
    if (noise_rc != NOISE_ERROR_NONE || !iwant)
        goto cleanup;

    noise_rc = libp2p_gossipsub_ControlIWant_add_message_ids(iwant, msg_id, msg_id_len);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    NoiseProtobuf measure;
    noise_rc = noise_protobuf_prepare_measure(&measure, SIZE_MAX);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;
    noise_rc = libp2p_gossipsub_RPC_write(&measure, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
        goto cleanup;

    size_t encoded_size = 0;
    noise_rc = noise_protobuf_finish_measure(&measure, &encoded_size);
    if (noise_rc != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    uint8_t *buffer = (uint8_t *)malloc(encoded_size);
    if (!buffer)
        goto cleanup;

    NoiseProtobuf out_pb;
    noise_rc = noise_protobuf_prepare_output(&out_pb, buffer, encoded_size);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        free(buffer);
        goto cleanup;
    }

    noise_rc = libp2p_gossipsub_RPC_write(&out_pb, 0, rpc);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_output_shift(&out_pb, NULL, NULL);
        free(buffer);
        goto cleanup;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    noise_rc = noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len);
    if (noise_rc != NOISE_ERROR_NONE || !encoded)
    {
        free(buffer);
        goto cleanup;
    }

    *out_buf = encoded;
    *out_len = encoded_len;
    result = LIBP2P_ERR_OK;

cleanup:
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    return result;
}

libp2p_err_t first_byte_message_id_fn(const libp2p_gossipsub_message_t *msg,
                                      uint8_t **out_id,
                                      size_t *out_len,
                                      void *user_data)
{
    (void)user_data;
    if (!msg || !out_id || !out_len)
        return LIBP2P_ERR_NULL_PTR;
    *out_id = NULL;
    *out_len = 0;
    if (!msg->data || msg->data_len == 0)
        return LIBP2P_ERR_UNSUPPORTED;
    uint8_t *buf = (uint8_t *)malloc(1);
    if (!buf)
        return LIBP2P_ERR_INTERNAL;
    buf[0] = msg->data[0];
    *out_id = buf;
    *out_len = 1;
    return LIBP2P_ERR_OK;
}

void gossipsub_service_free_env(gossipsub_service_test_env_t *env)
{
    if (!env)
        return;

    if (env->gs)
    {
        libp2p_gossipsub_free(env->gs);
        env->gs = NULL;
    }

    if (env->host)
    {
        libp2p_host_free(env->host);
        env->host = NULL;
    }

    if (env->config_peer_ok)
    {
        peer_id_destroy(&env->config_peer);
        env->config_peer_ok = 0;
    }

    env->sync_handle = NULL;
    env->async_handle = NULL;
    env->cfg_initialized = 0;
    env->fatal_failure = 0;
    memset(&env->cfg, 0, sizeof(env->cfg));
    memset(&env->cfg_explicit_peer, 0, sizeof(env->cfg_explicit_peer));
}
