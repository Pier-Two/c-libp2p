#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "gossipsub_propagation.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "libp2p/log.h"
#include "libp2p/stream.h"
#include "noise/protobufs.h"
#include "peer_id/peer_id_proto.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "../../../external/noise-c/src/crypto/ed25519/ed25519.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"
#include "../../../host/host_internal.h"

#include "gossipsub_host_events.h"
#include "gossipsub_cache.h"
#include "gossipsub_peer.h"
#include "gossipsub_rpc.h"
#include "gossipsub_score.h"
#include "gossipsub_topic.h"
#include "gossipsub_validation.h"

#define GOSSIPSUB_MODULE "gossipsub"
#define GOSSIPSUB_PX_ADDR_TTL_MS (10 * 60 * 1000)

static const uint8_t GOSSIPSUB_PX_PAYLOAD_TYPE[] = {0x03, 0x01};
static const char GOSSIPSUB_PX_ENVELOPE_DOMAIN[] = "libp2p-peer-record";

size_t gossipsub_debug_last_eligible = 0;
size_t gossipsub_debug_last_limit = 0;

static const char *gossipsub_px_protocol_at(const libp2p_gossipsub_t *gs, size_t index)
{
    if (!gs || index >= gs->num_protocol_defs)
        return NULL;
    const char *protocol = gs->protocol_defs[index].protocol_id;
    if (!protocol || protocol[0] == '\0')
        return NULL;
    return protocol;
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

static void gossipsub_px_ctx_destroy(gossipsub_px_dial_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->peer)
        gossipsub_peer_free(ctx->peer);
    free(ctx);
}

static void gossipsub_px_schedule_attempt(libp2p_gossipsub_t *gs, gossipsub_px_dial_ctx_t *ctx);
static void gossipsub_px_dial_cb(libp2p_stream_t *s, void *user_data, int err);

static int gossipsub_px_should_retry_protocol(libp2p_err_t err)
{
    switch (err)
    {
        case LIBP2P_ERR_PROTO_NEGOTIATION_FAILED:
        case LIBP2P_ERR_TIMEOUT:
        case LIBP2P_ERR_INTERNAL:
        case LIBP2P_ERR_CLOSED:
        case LIBP2P_ERR_RESET:
            return 1;
        default:
            return 0;
    }
}

static double gossipsub_topic_publish_threshold(const libp2p_gossipsub_t *gs,
                                                const gossipsub_topic_state_t *topic)
{
    if (topic && topic->has_publish_threshold)
        return topic->publish_threshold;
    if (gs)
        return gs->cfg.publish_threshold;
    return 0.0;
}

void gossipsub_prune_target_free(gossipsub_prune_target_t *target)
{
    if (!target)
        return;
    if (target->topic)
        free(target->topic);
    if (target->px_peers)
        gossipsub_px_list_free(target->px_peers, target->px_len);
    free(target);
}

uint64_t gossipsub_propagation_backoff_seconds(const libp2p_gossipsub_t *gs)
{
    if (!gs || gs->cfg.prune_backoff_ms <= 0)
        return 0;
    uint64_t backoff_ms = (uint64_t)gs->cfg.prune_backoff_ms;
    return (backoff_ms + 999ULL) / 1000ULL;
}

uint64_t gossipsub_propagation_compute_backoff_expiry(uint64_t now_ms, uint64_t backoff_ms)
{
    if (backoff_ms == 0)
        return now_ms;
    if (backoff_ms >= UINT64_MAX - now_ms)
        return UINT64_MAX;
    return now_ms + backoff_ms;
}

static void gossipsub_px_free_addr_list(multiaddr_t **addrs, size_t count)
{
    if (!addrs)
        return;
    for (size_t i = 0; i < count; ++i)
    {
        if (addrs[i])
            multiaddr_free(addrs[i]);
    }
    free(addrs);
}

static libp2p_err_t gossipsub_px_parse_peer_record_payload(const peer_id_t *expected_peer,
                                                           const uint8_t *payload,
                                                           size_t payload_len,
                                                           multiaddr_t ***out_addrs,
                                                           size_t *out_count)
{
    if (!payload || payload_len == 0 || !out_addrs || !out_count)
        return LIBP2P_ERR_NULL_PTR;

    *out_addrs = NULL;
    *out_count = 0;

    NoiseProtobuf pb;
    int noise_rc = noise_protobuf_prepare_input(&pb, (uint8_t *)payload, payload_len);
    if (noise_rc != NOISE_ERROR_NONE)
        return LIBP2P_ERR_INTERNAL;

    size_t end_posn = 0;
    noise_rc = noise_protobuf_read_start_element(&pb, 0, &end_posn);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_input(&pb);
        return LIBP2P_ERR_INTERNAL;
    }

    int peer_status = expected_peer ? 0 : 1;
    multiaddr_t **addr_list = NULL;
    size_t addr_count = 0;
    size_t addr_cap = 0;

    while (!noise_protobuf_read_at_end_element(&pb, end_posn))
    {
        int tag = noise_protobuf_peek_tag(&pb);
        switch (tag)
        {
            case 1:
            {
                void *peer_buf = NULL;
                size_t peer_sz = 0;
                noise_rc = noise_protobuf_read_alloc_bytes(&pb, 1, &peer_buf, 0, &peer_sz);
                if (noise_rc != NOISE_ERROR_NONE || !peer_buf || peer_sz == 0)
                {
                    if (peer_buf)
                        noise_protobuf_free_memory(peer_buf, peer_sz);
                    peer_status = -1;
                }
                else if (expected_peer)
                {
                    peer_id_t tmp = {
                        .bytes = (uint8_t *)peer_buf,
                        .size = peer_sz
                    };
                    peer_status = gossipsub_peer_equals(expected_peer, &tmp) ? 1 : -1;
                }
                else
                {
                    peer_status = 1;
                }
                if (peer_buf)
                    noise_protobuf_free_memory(peer_buf, peer_sz);
                break;
            }
            case 2:
            {
                uint64_t seq_dummy = 0;
                if (noise_protobuf_read_uint64(&pb, 2, &seq_dummy) != NOISE_ERROR_NONE)
                    noise_protobuf_read_skip(&pb);
                break;
            }
            case 3:
            {
                size_t addr_end = 0;
                noise_rc = noise_protobuf_read_start_element(&pb, 3, &addr_end);
                if (noise_rc != NOISE_ERROR_NONE)
                {
                    noise_protobuf_read_skip(&pb);
                    break;
                }
                while (!noise_protobuf_read_at_end_element(&pb, addr_end))
                {
                    int addr_tag = noise_protobuf_peek_tag(&pb);
                    if (addr_tag == 1)
                    {
                        void *addr_buf = NULL;
                        size_t addr_len = 0;
                        noise_rc = noise_protobuf_read_alloc_bytes(&pb, 1, &addr_buf, 0, &addr_len);
                        if (noise_rc == NOISE_ERROR_NONE && addr_buf && addr_len > 0)
                        {
                            int ma_err = 0;
                            multiaddr_t *ma = multiaddr_new_from_bytes((const uint8_t *)addr_buf, addr_len, &ma_err);
                            noise_protobuf_free_memory(addr_buf, addr_len);
                            if (!ma)
                                continue;
                            if (addr_count == addr_cap)
                            {
                                size_t new_cap = addr_cap ? addr_cap * 2 : 4;
                                multiaddr_t **new_list = (multiaddr_t **)realloc(addr_list, new_cap * sizeof(*new_list));
                                if (!new_list)
                                {
                                    multiaddr_free(ma);
                                    continue;
                                }
                                addr_list = new_list;
                                addr_cap = new_cap;
                            }
                            addr_list[addr_count++] = ma;
                        }
                        else
                        {
                            if (addr_buf)
                                noise_protobuf_free_memory(addr_buf, addr_len);
                        }
                    }
                    else
                    {
                        noise_protobuf_read_skip(&pb);
                    }
                }
                if (noise_protobuf_read_end_element(&pb, addr_end) != NOISE_ERROR_NONE)
                {
                    gossipsub_px_free_addr_list(addr_list, addr_count);
                    noise_protobuf_finish_input(&pb);
                    return LIBP2P_ERR_INTERNAL;
                }
                break;
            }
            default:
                noise_protobuf_read_skip(&pb);
                break;
        }
    }

    if (noise_protobuf_read_end_element(&pb, end_posn) != NOISE_ERROR_NONE)
    {
        gossipsub_px_free_addr_list(addr_list, addr_count);
        noise_protobuf_finish_input(&pb);
        return LIBP2P_ERR_INTERNAL;
    }

    noise_protobuf_finish_input(&pb);

    if (expected_peer && peer_status != 1)
    {
        gossipsub_px_free_addr_list(addr_list, addr_count);
        return LIBP2P_ERR_INTERNAL;
    }

    if (addr_count == 0)
    {
        free(addr_list);
        addr_list = NULL;
    }

    *out_addrs = addr_list;
    *out_count = addr_count;
    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_px_build_unsigned(const uint8_t *payload_type,
                                                size_t payload_type_len,
                                                const uint8_t *payload,
                                                size_t payload_len,
                                                uint8_t **out_buf,
                                                size_t *out_len)
{
    if (!payload_type || payload_type_len == 0 || !payload || payload_len == 0 || !out_buf || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    static const uint8_t *fields[] = {
        (const uint8_t *)GOSSIPSUB_PX_ENVELOPE_DOMAIN,
        NULL,
        NULL
    };
    static const size_t field_count = sizeof(fields) / sizeof(fields[0]);

    size_t lengths[field_count];
    fields[1] = payload_type;
    fields[2] = payload;
    lengths[0] = strlen(GOSSIPSUB_PX_ENVELOPE_DOMAIN);
    lengths[1] = payload_type_len;
    lengths[2] = payload_len;

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

static libp2p_err_t gossipsub_px_verify_signed_record(const peer_id_t *expected_peer,
                                                      const uint8_t *public_key_pb,
                                                      size_t public_key_pb_len,
                                                      const uint8_t *payload_type,
                                                      size_t payload_type_len,
                                                      const uint8_t *payload,
                                                      size_t payload_len,
                                                      const uint8_t *signature,
                                                      size_t signature_len)
{
    if (!public_key_pb || public_key_pb_len == 0 || !payload_type || payload_type_len == 0 ||
        !payload || payload_len == 0 || !signature || signature_len == 0)
        return LIBP2P_ERR_NULL_PTR;

    if (signature_len != 64)
        return LIBP2P_ERR_UNSUPPORTED;

    uint64_t key_type = 0;
    const uint8_t *raw_key = NULL;
    size_t raw_key_len = 0;
    if (parse_public_key_proto(public_key_pb, public_key_pb_len, &key_type, &raw_key, &raw_key_len) != 0)
        return LIBP2P_ERR_UNSUPPORTED;

    if (key_type != PEER_ID_ED25519_KEY_TYPE || raw_key_len != 32)
        return LIBP2P_ERR_UNSUPPORTED;

    if (expected_peer)
    {
        peer_id_t derived = {0};
        peer_id_error_t pid_rc = peer_id_create_from_public_key(public_key_pb, public_key_pb_len, &derived);
        if (pid_rc != PEER_ID_SUCCESS)
            return LIBP2P_ERR_UNSUPPORTED;
        int match = gossipsub_peer_equals(expected_peer, &derived);
        peer_id_destroy(&derived);
        if (!match)
            return LIBP2P_ERR_UNSUPPORTED;
    }

    uint8_t *unsigned_buf = NULL;
    size_t unsigned_len = 0;
    libp2p_err_t build_rc = gossipsub_px_build_unsigned(payload_type,
                                                        payload_type_len,
                                                        payload,
                                                        payload_len,
                                                        &unsigned_buf,
                                                        &unsigned_len);
    if (build_rc != LIBP2P_ERR_OK)
        return build_rc;

    ed25519_public_key ed_pub;
    memcpy(ed_pub, raw_key, raw_key_len);
    ed25519_signature ed_sig;
    memcpy(ed_sig, signature, signature_len);

    int verify_rc = ed25519_sign_open(unsigned_buf, unsigned_len, ed_pub, ed_sig);
    free(unsigned_buf);
    if (verify_rc != 0)
        return LIBP2P_ERR_UNSUPPORTED;

    return LIBP2P_ERR_OK;
}

static libp2p_err_t gossipsub_px_parse_signed_peer_record(const peer_id_t *expected_peer,
                                                          const uint8_t *signed_record,
                                                          size_t signed_record_len,
                                                          multiaddr_t ***out_addrs,
                                                          size_t *out_count)
{
    if (!signed_record || signed_record_len == 0 || !out_addrs || !out_count)
        return LIBP2P_ERR_NULL_PTR;

    *out_addrs = NULL;
    *out_count = 0;

    NoiseProtobuf pb;
    int noise_rc = noise_protobuf_prepare_input(&pb, (uint8_t *)signed_record, signed_record_len);
    if (noise_rc != NOISE_ERROR_NONE)
        return LIBP2P_ERR_INTERNAL;

    size_t end_posn = 0;
    noise_rc = noise_protobuf_read_start_element(&pb, 0, &end_posn);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        noise_protobuf_finish_input(&pb);
        return LIBP2P_ERR_INTERNAL;
    }

    void *payload_type = NULL;
    size_t payload_type_len = 0;
    void *payload = NULL;
    size_t payload_len = 0;
    void *public_key = NULL;
    size_t public_key_len = 0;
    void *signature = NULL;
    size_t signature_len = 0;

    while (!noise_protobuf_read_at_end_element(&pb, end_posn))
    {
        int tag = noise_protobuf_peek_tag(&pb);
        switch (tag)
        {
            case 1:
                noise_rc = noise_protobuf_read_alloc_bytes(&pb, 1, &public_key, 0, &public_key_len);
                if (noise_rc != NOISE_ERROR_NONE)
                {
                    public_key = NULL;
                    public_key_len = 0;
                }
                break;
            case 2:
                noise_rc = noise_protobuf_read_alloc_bytes(&pb, 2, &payload_type, 0, &payload_type_len);
                if (noise_rc != NOISE_ERROR_NONE)
                {
                    payload_type = NULL;
                    payload_type_len = 0;
                }
                break;
            case 3:
                noise_rc = noise_protobuf_read_alloc_bytes(&pb, 3, &payload, 0, &payload_len);
                if (noise_rc != NOISE_ERROR_NONE)
                {
                    payload = NULL;
                    payload_len = 0;
                }
                break;
            case 5:
                noise_rc = noise_protobuf_read_alloc_bytes(&pb, 5, &signature, 0, &signature_len);
                if (noise_rc != NOISE_ERROR_NONE)
                {
                    signature = NULL;
                    signature_len = 0;
                }
                break;
            default:
                noise_protobuf_read_skip(&pb);
                break;
        }
    }

    noise_rc = noise_protobuf_read_end_element(&pb, end_posn);
    noise_protobuf_finish_input(&pb);
    if (noise_rc != NOISE_ERROR_NONE)
    {
        if (payload_type)
            noise_protobuf_free_memory(payload_type, payload_type_len);
        if (payload)
            noise_protobuf_free_memory(payload, payload_len);
        if (public_key)
            noise_protobuf_free_memory(public_key, public_key_len);
        if (signature)
            noise_protobuf_free_memory(signature, signature_len);
        return LIBP2P_ERR_INTERNAL;
    }

    if (!payload || payload_len == 0 || !payload_type || payload_type_len == 0 || !public_key || public_key_len == 0 ||
        !signature || signature_len == 0)
    {
        if (payload_type)
            noise_protobuf_free_memory(payload_type, payload_type_len);
        if (payload)
            noise_protobuf_free_memory(payload, payload_len);
        if (public_key)
            noise_protobuf_free_memory(public_key, public_key_len);
        if (signature)
            noise_protobuf_free_memory(signature, signature_len);
        return LIBP2P_ERR_INTERNAL;
    }

    if (payload_type && (payload_type_len != sizeof(GOSSIPSUB_PX_PAYLOAD_TYPE) ||
                         memcmp(payload_type, GOSSIPSUB_PX_PAYLOAD_TYPE, payload_type_len) != 0))
    {
        noise_protobuf_free_memory(payload_type, payload_type_len);
        noise_protobuf_free_memory(payload, payload_len);
        noise_protobuf_free_memory(public_key, public_key_len);
        noise_protobuf_free_memory(signature, signature_len);
        return LIBP2P_ERR_INTERNAL;
    }

    libp2p_err_t verify_rc = gossipsub_px_verify_signed_record(expected_peer,
                                                               public_key,
                                                               public_key_len,
                                                               payload_type,
                                                               payload_type_len,
                                                               payload,
                                                               payload_len,
                                                               signature,
                                                               signature_len);
    if (verify_rc != LIBP2P_ERR_OK)
    {
        noise_protobuf_free_memory(payload_type, payload_type_len);
        noise_protobuf_free_memory(payload, payload_len);
        noise_protobuf_free_memory(public_key, public_key_len);
        noise_protobuf_free_memory(signature, signature_len);
        return verify_rc;
    }

    multiaddr_t **addr_list = NULL;
    size_t addr_count = 0;
    libp2p_err_t rc = gossipsub_px_parse_peer_record_payload(expected_peer,
                                                             (const uint8_t *)payload,
                                                             payload_len,
                                                             &addr_list,
                                                             &addr_count);

    if (payload_type)
        noise_protobuf_free_memory(payload_type, payload_type_len);
    if (payload)
        noise_protobuf_free_memory(payload, payload_len);
    if (public_key)
        noise_protobuf_free_memory(public_key, public_key_len);
    if (signature)
        noise_protobuf_free_memory(signature, signature_len);

    if (rc != LIBP2P_ERR_OK)
        return rc;

    *out_addrs = addr_list;
    *out_count = addr_count;
    return LIBP2P_ERR_OK;
}

static void gossipsub_propagation_ingest_px_record(libp2p_gossipsub_t *gs,
                                                   const peer_id_t *peer,
                                                   const uint8_t *record,
                                                   size_t record_len)
{
    if (!gs || !gs->host || !peer || !record || record_len == 0)
        return;

    multiaddr_t **addr_list = NULL;
    size_t addr_count = 0;
    libp2p_err_t rc = gossipsub_px_parse_signed_peer_record(peer, record, record_len, &addr_list, &addr_count);
    if (rc != LIBP2P_ERR_OK)
    {
        LP_LOGW(GOSSIPSUB_MODULE, "failed to parse PX peer record (rc=%d)", rc);
        return;
    }

    for (size_t i = 0; i < addr_count; ++i)
    {
        multiaddr_t *ma = addr_list[i];
        if (!ma)
            continue;
        int host_rc = libp2p_host_add_peer_addr(gs->host, peer, ma, GOSSIPSUB_PX_ADDR_TTL_MS);
        if (host_rc != LIBP2P_ERR_OK)
            LP_LOGW(GOSSIPSUB_MODULE, "failed to ingest PX address (rc=%d)", host_rc);
    }

    gossipsub_px_free_addr_list(addr_list, addr_count);
}

static void gossipsub_px_schedule_attempt(libp2p_gossipsub_t *gs, gossipsub_px_dial_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (!gs || !gs->host)
    {
        gossipsub_px_ctx_destroy(ctx);
        return;
    }

    peer_id_t *peer = ctx->peer;
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(peer, peer_buf, sizeof(peer_buf));

    LP_LOGT(GOSSIPSUB_MODULE,
            "PX dial schedule start peer=%s index=%zu count=%zu",
            peer_repr,
            ctx->protocol_index,
            ctx->protocol_count);

    while (ctx->protocol_index < ctx->protocol_count)
    {
        const char *protocol = gossipsub_px_protocol_at(gs, ctx->protocol_index);
        if (!protocol)
        {
            ctx->protocol_index++;
            continue;
        }

        ctx->current_protocol = protocol;
        LP_LOGT(GOSSIPSUB_MODULE,
                "PX dial attempting peer=%s protocol=%s",
                peer_repr,
                protocol);

        int rc = libp2p_host_open_stream_async(gs->host, ctx->peer, protocol, gossipsub_px_dial_cb, ctx);
        if (rc == LIBP2P_ERR_OK)
            return;

        LP_LOGT(GOSSIPSUB_MODULE,
                "PX dial immediate failure peer=%s protocol=%s rc=%d",
                peer_repr,
                protocol,
                rc);

        ctx->protocol_index++;
        ctx->current_protocol = NULL;
    }

    if (peer)
    {
        pthread_mutex_lock(&gs->lock);
        gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
        if (entry)
            entry->connected = 0;
        pthread_mutex_unlock(&gs->lock);
    }

    LP_LOGT(GOSSIPSUB_MODULE,
            "PX dial exhausted protocols peer=%s attempts=%zu",
            peer_repr,
            ctx->protocol_count);

    gossipsub_px_ctx_destroy(ctx);
}

static void gossipsub_px_dial_cb(libp2p_stream_t *s, void *user_data, int err)
{
    gossipsub_px_dial_ctx_t *ctx = (gossipsub_px_dial_ctx_t *)user_data;
    if (!ctx)
        return;

    libp2p_gossipsub_t *gs = ctx->gs;
    peer_id_t *peer = ctx->peer;
    if (!gs)
    {
        gossipsub_px_ctx_destroy(ctx);
        return;
    }

    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(peer, peer_buf, sizeof(peer_buf));
    const char *protocol = ctx->current_protocol ? ctx->current_protocol : "(unknown)";

    if (err == LIBP2P_ERR_OK && s)
    {
        LP_LOGT(GOSSIPSUB_MODULE,
                "PX dial succeeded peer=%s protocol=%s",
                peer_repr,
                protocol);
        gossipsub_on_stream_open(s, gs);
        gossipsub_px_ctx_destroy(ctx);
        return;
    }

    LP_LOGT(GOSSIPSUB_MODULE,
            "PX dial failed peer=%s protocol=%s err=%d",
            peer_repr,
            protocol,
            err);

    if (gossipsub_px_should_retry_protocol(err) && ctx->protocol_index + 1 < ctx->protocol_count)
    {
        ctx->protocol_index++;
        ctx->current_protocol = NULL;
        gossipsub_px_schedule_attempt(gs, ctx);
        return;
    }

    if (peer)
    {
        pthread_mutex_lock(&gs->lock);
        gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, peer);
        if (entry)
            entry->connected = 0;
        pthread_mutex_unlock(&gs->lock);
    }

    gossipsub_px_ctx_destroy(ctx);
}

void gossipsub_propagation_try_connect_px(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry)
{
    if (!gs || !entry || !entry->peer)
        return;
    if (entry->stream || entry->connected)
        return;

    gossipsub_propagation_try_connect_peer(gs, entry->peer);
}

void gossipsub_propagation_try_connect_peer(libp2p_gossipsub_t *gs,
                                            const peer_id_t *peer)
{
    if (!gs || !peer || !gs->host)
        return;

    gossipsub_px_dial_ctx_t *ctx = (gossipsub_px_dial_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return;
    ctx->gs = gs;
    ctx->peer = gossipsub_peer_clone(peer);
    ctx->protocol_index = 0;
    ctx->protocol_count = gs->num_protocol_defs;
    ctx->current_protocol = NULL;
    if (!ctx->peer)
    {
        gossipsub_px_ctx_destroy(ctx);
        return;
    }
    if (ctx->protocol_count == 0)
        ctx->protocol_count = 1;

    gossipsub_px_schedule_attempt(gs, ctx);
}

void gossipsub_propagation_propagate_frame(libp2p_gossipsub_t *gs,
                                           gossipsub_topic_state_t *topic,
                                           const peer_id_t *exclude_peer,
                                           const uint8_t *frame,
                                           size_t frame_len)
{
    if (!gs || !frame || frame_len == 0)
        return;

    pthread_mutex_lock(&gs->lock);
    int flood_enabled = gs->cfg.enable_flood_publish ? 1 : 0;
    int has_topic = (topic && topic->name);
    double publish_threshold = gossipsub_topic_publish_threshold(gs, topic);

    size_t mesh_sent = 0;
    if (topic)
    {
        for (gossipsub_mesh_member_t *member = topic->mesh; member; member = member->next)
        {
            gossipsub_peer_entry_t *peer_entry = member->peer_entry;
            if (!peer_entry || !peer_entry->connected)
                continue;
            if (peer_entry->explicit_peering)
                continue;
            if (exclude_peer && gossipsub_peer_equals(member->peer, exclude_peer))
                continue;
            if (flood_enabled && has_topic && peer_entry->score < publish_threshold)
                continue;
            (void)gossipsub_peer_enqueue_frame_locked(gs, peer_entry, frame, frame_len);
            mesh_sent++;
        }
    }

    for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
    {
        if (!entry->explicit_peering)
            continue;
        if (!entry->connected)
            continue;
        if (exclude_peer && gossipsub_peer_equals(entry->peer, exclude_peer))
            continue;
        if (topic && gossipsub_mesh_member_find(topic->mesh, entry->peer))
            continue;
        (void)gossipsub_peer_enqueue_frame_locked(gs, entry, frame, frame_len);
    }

    if (mesh_sent == 0 || flood_enabled)
    {
        for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
        {
            if (!entry->connected)
                continue;
            if (entry->explicit_peering)
                continue;
            if (exclude_peer && gossipsub_peer_equals(entry->peer, exclude_peer))
                continue;
            if (topic && gossipsub_mesh_member_find(topic->mesh, entry->peer))
                continue;
            if (has_topic && !gossipsub_peer_topic_find(entry->topics, topic->name))
                continue;

            if (flood_enabled && has_topic)
            {
                if (entry->score < publish_threshold)
                    continue;
            }
            else if (!has_topic)
            {
                if (!flood_enabled)
                    continue;
            }
            (void)gossipsub_peer_enqueue_frame_locked(gs, entry, frame, frame_len);
        }
    }
    pthread_mutex_unlock(&gs->lock);
}

void gossipsub_propagation_emit_gossip_locked(libp2p_gossipsub_t *gs,
                                              gossipsub_topic_state_t *topic,
                                              uint64_t gossip_round)
{
    if (!gs || !topic || !topic->name)
        return;

    uint8_t **ids = NULL;
    size_t *lengths = NULL;
    size_t count = 0;
    libp2p_err_t cache_rc = gossipsub_message_cache_collect_ids(&gs->message_cache,
                                                                topic->name,
                                                                &ids,
                                                                &lengths,
                                                                &count,
                                                                gossip_round);

    if (cache_rc != LIBP2P_ERR_OK || count == 0 || !ids || !lengths)
    {
        if (cache_rc != LIBP2P_ERR_OK)
            LP_LOGW(GOSSIPSUB_MODULE, "failed to collect gossip ids (rc=%d)", cache_rc);
        if (lengths)
            free(lengths);
        if (ids)
            gossipsub_message_cache_free_ids(ids, count);
        return;
    }

    gossipsub_rpc_out_t frame;
    gossipsub_rpc_out_init(&frame);
    libp2p_err_t enc_rc = gossipsub_rpc_encode_control_ihave(topic->name,
                                                             ids,
                                                             lengths,
                                                             count,
                                                             &frame);

    if (enc_rc == LIBP2P_ERR_OK && frame.frame && frame.frame_len)
    {
        size_t d_lazy = (gs->cfg.d_lazy > 0) ? (size_t)gs->cfg.d_lazy : 0;
        gossipsub_peer_entry_t **eligible = NULL;
        size_t eligible_count = 0;
        size_t eligible_capacity = 0;

        for (gossipsub_peer_entry_t *entry = gs->peers; entry; entry = entry->next)
        {
            if (!entry->connected)
                continue;
            if (gossipsub_mesh_member_find(topic->mesh, entry->peer))
                continue;
            if (!gossipsub_peer_topic_find(entry->topics, topic->name))
                continue;
            if (!entry->explicit_peering && entry->score < gs->cfg.gossip_threshold)
                continue;
            if (eligible_count == eligible_capacity)
            {
                size_t new_cap = eligible_capacity ? eligible_capacity * 2 : 8;
                gossipsub_peer_entry_t **new_list = (gossipsub_peer_entry_t **)realloc(eligible, new_cap * sizeof(*new_list));
                if (!new_list)
                {
                    free(eligible);
                    eligible = NULL;
                    eligible_count = 0;
                    eligible_capacity = 0;
                    break;
                }
                eligible = new_list;
                eligible_capacity = new_cap;
            }
            eligible[eligible_count++] = entry;
        }

        if (eligible && eligible_count > 0)
        {
            size_t gossip_percent = (gs->cfg.gossip_factor_percent > 0) ? (size_t)gs->cfg.gossip_factor_percent : 0;
            size_t factor_count = 0;
            if (gossip_percent > 0)
            {
                size_t numerator = eligible_count * gossip_percent;
                factor_count = numerator / 100;
                if (numerator % 100 != 0)
                    factor_count++;
            }

            size_t limit = d_lazy;
            if (factor_count > limit)
                limit = factor_count;
            if (limit == 0 || limit > eligible_count)
                limit = eligible_count;

            gossipsub_debug_last_eligible = eligible_count;
            gossipsub_debug_last_limit = limit;

            size_t start_index = eligible_count ? (size_t)(gossipsub_now_ms() % eligible_count) : 0;
            for (size_t i = 0, sent = 0; i < limit && sent < limit; ++i)
            {
                size_t idx = (start_index + i) % eligible_count;
                gossipsub_peer_entry_t *entry = eligible[idx];
                if (!entry)
                    continue;
                if (!entry->explicit_peering && entry->score < gs->cfg.gossip_threshold)
                    continue;
                if (gossipsub_peer_enqueue_frame_locked(gs, entry, frame.frame, frame.frame_len) == LIBP2P_ERR_OK)
                    sent++;
            }
        }

        free(eligible);
    }

    gossipsub_rpc_out_clear(&frame);
    if (lengths)
        free(lengths);
    if (ids)
        gossipsub_message_cache_free_ids(ids, count);
}

libp2p_err_t gossipsub_propagation_handle_inbound_publish(libp2p_gossipsub_t *gs,
                                                          gossipsub_peer_entry_t *entry,
                                                          libp2p_gossipsub_Message *proto_msg,
                                                          const uint8_t *frame,
                                                          size_t frame_len)
{
    if (!gs || !entry || !proto_msg)
        return LIBP2P_ERR_NULL_PTR;

    const char *topic_raw = NULL;
    size_t topic_len = 0;
    if (libp2p_gossipsub_Message_has_topic(proto_msg))
    {
        topic_raw = libp2p_gossipsub_Message_get_topic(proto_msg);
        topic_len = libp2p_gossipsub_Message_get_size_topic(proto_msg);
    }
    if ((!topic_raw || topic_len == 0) && libp2p_gossipsub_Message_count_topic_ids(proto_msg) > 0)
    {
        topic_raw = libp2p_gossipsub_Message_get_at_topic_ids(proto_msg, 0);
        topic_len = libp2p_gossipsub_Message_get_size_at_topic_ids(proto_msg, 0);
    }
    if (!topic_raw || topic_len == 0)
    {
        char peer_buf[128];
        const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
        LP_LOGW(GOSSIPSUB_MODULE,
                "inbound publish has no topic peer=%s has_topic=%d topic_ids_count=%zu",
                peer_repr,
                libp2p_gossipsub_Message_has_topic(proto_msg),
                libp2p_gossipsub_Message_count_topic_ids(proto_msg));
        return LIBP2P_ERR_UNSUPPORTED;
    }

    char *topic_str = (char *)malloc(topic_len + 1);
    if (!topic_str)
        return LIBP2P_ERR_INTERNAL;
    memcpy(topic_str, topic_raw, topic_len);
    topic_str[topic_len] = '\0';

    libp2p_gossipsub_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.topic.struct_size = sizeof(msg.topic);
    msg.topic.topic = topic_str;

    if (libp2p_gossipsub_Message_has_data(proto_msg))
    {
        msg.data = (const uint8_t *)libp2p_gossipsub_Message_get_data(proto_msg);
        msg.data_len = libp2p_gossipsub_Message_get_size_data(proto_msg);
    }
    if (libp2p_gossipsub_Message_has_seqno(proto_msg))
    {
        msg.seqno = (const uint8_t *)libp2p_gossipsub_Message_get_seqno(proto_msg);
        msg.seqno_len = libp2p_gossipsub_Message_get_size_seqno(proto_msg);
    }
    msg.from = entry->peer;
    msg.raw_message = frame;
    msg.raw_message_len = frame_len;
    if (topic_str)
    {
        char peer_buf[128];
        const char *peer_repr = "-";
        if (entry && entry->peer)
        {
            int rc = peer_id_to_string(entry->peer, PEER_ID_FMT_BASE58_LEGACY, peer_buf, sizeof(peer_buf));
            if (rc > 0)
                peer_repr = peer_buf;
        }
        LP_LOGD(GOSSIPSUB_MODULE,
                "inbound publish topic=%s peer=%s data_len=%zu",
                topic_str,
                peer_repr,
                msg.data_len);
    }

    gossipsub_topic_state_t *topic = NULL;
    libp2p_gossipsub_validator_handle_t **validators = NULL;
    size_t validator_count = 0;
    libp2p_err_t rc = gossipsub_validation_collect(gs, topic_str, &topic, &validators, &validator_count);
    if (rc != LIBP2P_ERR_OK)
    {
        char peer_buf[128];
        const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
        LP_LOGW(GOSSIPSUB_MODULE,
                "validation_collect failed peer=%s topic=%s rc=%d (topic not subscribed?)",
                peer_repr,
                topic_str,
                rc);
        free(topic_str);
        return rc;
    }

    LP_LOGD(GOSSIPSUB_MODULE,
            "scheduling validation topic=%s validators=%zu has_msg_id_fn=%d data_len=%zu",
            topic_str,
            validator_count,
            topic && topic->message_id_fn ? 1 : 0,
            msg.data_len);

    rc = gossipsub_validation_schedule(gs, topic, validators, validator_count, &msg, 0);
    free(topic_str);
    return rc;
}

libp2p_err_t gossipsub_propagation_handle_subscriptions(libp2p_gossipsub_t *gs,
                                                         gossipsub_peer_entry_t *entry,
                                                         gossipsub_rpc_subscription_t *subs,
                                                         size_t count)
{
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
    LP_LOGT(GOSSIPSUB_MODULE,
            "handle_subscriptions peer=%s count=%zu",
            peer_repr,
            count);
    for (size_t i = 0; i < count; ++i) {
        gossipsub_rpc_subscription_t *sub = &subs[i];
        if (!sub || !sub->topic)
            continue;
        LP_LOGD(
            GOSSIPSUB_MODULE,
            "subscription_inbound peer=%s topic=%s subscribe=%d",
            peer_repr,
            sub->topic ? sub->topic : "(null)",
            sub->subscribe ? 1 : 0);
    }
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;
    if (!subs || count == 0)
        return LIBP2P_ERR_OK;

    libp2p_err_t result = LIBP2P_ERR_OK;
    for (size_t i = 0; i < count; ++i)
    {
        gossipsub_rpc_subscription_t *sub = &subs[i];
        if (!sub || !sub->topic)
            continue;

        if (sub->subscribe)
        {
            char peer_buf[128];
            const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
            LP_LOGT(GOSSIPSUB_MODULE,
                    "subscription peer=%s topic=%s topic_id=%s subscribe=1",
                    peer_repr,
                    sub->topic ? sub->topic : "(null)",
                    sub->topic_id ? sub->topic_id : "(null)");
            libp2p_err_t rc = gossipsub_peer_topic_subscribe(gs, entry, &sub->topic);
            if (rc != LIBP2P_ERR_OK && result == LIBP2P_ERR_OK)
                result = rc;
        }
        else
        {
            char peer_buf[128];
            const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
            LP_LOGT(GOSSIPSUB_MODULE,
                    "subscription peer=%s topic=%s topic_id=%s subscribe=0",
                    peer_repr,
                    sub->topic ? sub->topic : "(null)",
                    sub->topic_id ? sub->topic_id : "(null)");
            gossipsub_peer_topic_unsubscribe(gs, entry, sub->topic);
        }
    }
    return result;
}

libp2p_err_t gossipsub_propagation_handle_control_iwant(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_iwant_t *iwants,
                                                        size_t count)
{
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;
    if (!iwants || count == 0)
        return LIBP2P_ERR_OK;

    libp2p_err_t result = LIBP2P_ERR_OK;
    for (size_t i = 0; i < count; ++i)
    {
        const gossipsub_rpc_control_iwant_t *iwant = &iwants[i];
        if (!iwant || !iwant->ids || !iwant->lengths || iwant->count == 0)
            continue;

        for (size_t j = 0; j < iwant->count; ++j)
        {
            const uint8_t *id = iwant->ids[j];
            size_t id_len = iwant->lengths[j];
            if (!id || id_len == 0)
                continue;

            pthread_mutex_lock(&gs->lock);
            gossipsub_cache_entry_t *cached = gossipsub_message_cache_find(&gs->message_cache, id, id_len);
            if (cached && cached->frame && cached->frame_len)
            {
                libp2p_err_t send_rc = gossipsub_peer_enqueue_frame_locked(gs, entry, cached->frame, cached->frame_len);
                if (send_rc != LIBP2P_ERR_OK && result == LIBP2P_ERR_OK)
                    result = send_rc;
            }
            pthread_mutex_unlock(&gs->lock);
        }
    }
    return result;
}

libp2p_err_t gossipsub_propagation_handle_control_ihave(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_ihave_t *ihaves,
                                                        size_t count)
{
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;
    if (!ihaves || count == 0)
        return LIBP2P_ERR_OK;

    double peer_score = 0.0;
    int explicit_peer = 0;
    pthread_mutex_lock(&gs->lock);
    peer_score = entry->score;
    explicit_peer = entry->explicit_peering ? 1 : 0;
    pthread_mutex_unlock(&gs->lock);

    if (!explicit_peer && peer_score < gs->cfg.gossip_threshold)
        return LIBP2P_ERR_OK;

    size_t want_capacity = 0;
    size_t want_count = 0;
    uint8_t **want_ids = NULL;
    size_t *want_lens = NULL;
    libp2p_err_t result = LIBP2P_ERR_OK;
    size_t max_ihave_messages = gs->cfg.max_ihave_messages;
    size_t max_ihave_length = gs->cfg.max_ihave_length;
    size_t id_budget = SIZE_MAX;
    int allow_processing = 1;
    int apply_penalty = 0;
    double penalty_value = (gs && gs->cfg.ihave_spam_penalty > 0.0) ? gs->cfg.ihave_spam_penalty : 0.0;

    if (gs)
    {
        pthread_mutex_lock(&gs->lock);
        if (entry->ihave_advertisements < SIZE_MAX)
            entry->ihave_advertisements++;
        size_t adv_count = entry->ihave_advertisements;
        if (max_ihave_messages > 0 && adv_count > max_ihave_messages)
        {
            allow_processing = 0;
            if (penalty_value > 0.0)
                apply_penalty = 1;
        }
        if (allow_processing && max_ihave_length > 0)
        {
            if (entry->ihave_ids_asked >= max_ihave_length)
            {
                allow_processing = 0;
                if (penalty_value > 0.0)
                    apply_penalty = 1;
            }
            else
                id_budget = max_ihave_length - entry->ihave_ids_asked;
        }
        pthread_mutex_unlock(&gs->lock);
    }

    if (!allow_processing || id_budget == 0)
    {
        if (apply_penalty && penalty_value > 0.0 && entry && entry->peer)
            (void)libp2p_gossipsub_add_peer_behaviour_penalty(gs, entry->peer, penalty_value);
        return LIBP2P_ERR_OK;
    }

    size_t per_message_limit = (max_ihave_length > 0) ? max_ihave_length : SIZE_MAX;
    size_t total_budget = (max_ihave_length > 0) ? id_budget : SIZE_MAX;

    for (size_t i = 0; i < count; ++i)
    {
        const gossipsub_rpc_control_ihave_t *ihave = &ihaves[i];
        if (!ihave || !ihave->ids || !ihave->lengths || ihave->count == 0)
            continue;
        if (max_ihave_length > 0 && total_budget == 0)
            break;

        for (size_t j = 0; j < ihave->count; ++j)
        {
            const uint8_t *id = ihave->ids[j];
            size_t id_len = ihave->lengths[j];
            if (!id || id_len == 0)
                continue;
            if (max_ihave_length > 0 && j >= per_message_limit)
                break;

            int duplicate = 0;
            for (size_t k = 0; k < want_count; ++k)
            {
                if (want_lens[k] == id_len && memcmp(want_ids[k], id, id_len) == 0)
                {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate)
                continue;

            uint64_t now_ms = gossipsub_now_ms();
            int should_request = 0;
            pthread_mutex_lock(&gs->lock);
            int seen = gossipsub_seen_cache_contains(&gs->seen_cache, id, id_len, now_ms);
            int cached = gossipsub_message_cache_find(&gs->message_cache, id, id_len) != NULL;
            pthread_mutex_unlock(&gs->lock);
            if (!seen && !cached)
                should_request = 1;

            if (!should_request)
                continue;

            if (want_count == want_capacity)
            {
                size_t new_cap = want_capacity ? want_capacity * 2 : 8;
                uint8_t **new_ids = (uint8_t **)realloc(want_ids, new_cap * sizeof(uint8_t *));
                size_t *new_lens = (size_t *)realloc(want_lens, new_cap * sizeof(size_t));
                if (!new_ids || !new_lens)
                {
                    if (new_ids)
                        want_ids = new_ids;
                    if (new_lens)
                        want_lens = new_lens;
                    if (result == LIBP2P_ERR_OK)
                        result = LIBP2P_ERR_INTERNAL;
                    goto cleanup;
                }
                want_ids = new_ids;
                want_lens = new_lens;
                want_capacity = new_cap;
            }

            uint8_t *dup = (uint8_t *)malloc(id_len);
            if (!dup)
            {
                if (result == LIBP2P_ERR_OK)
                    result = LIBP2P_ERR_INTERNAL;
                goto cleanup;
            }
            memcpy(dup, id, id_len);
            want_ids[want_count] = dup;
            want_lens[want_count] = id_len;
            want_count++;
            if (max_ihave_length > 0 && total_budget > 0)
            {
                total_budget--;
                if (total_budget == 0)
                    goto budget_exhausted;
            }
        }
    }

budget_exhausted:
    if (want_count > 0)
    {
        size_t send_count = want_count;
        pthread_mutex_lock(&gs->lock);
        if (max_ihave_length > 0)
        {
            if (entry->ihave_ids_asked >= max_ihave_length)
            {
                send_count = 0;
            }
            else
            {
                size_t allowance = max_ihave_length - entry->ihave_ids_asked;
                if (allowance < send_count)
                    send_count = allowance;
                if (send_count > 0)
                {
                    size_t current = entry->ihave_ids_asked;
                    if (current > SIZE_MAX - send_count)
                        entry->ihave_ids_asked = SIZE_MAX;
                    else
                        entry->ihave_ids_asked = current + send_count;
                }
            }
        }
        if (send_count > 0)
        {
            uint64_t expire_ms = gossipsub_propagation_compute_backoff_expiry(gossipsub_now_ms(),
                                                                               (uint64_t)gs->cfg.iwant_followup_time_ms);
            gossipsub_promises_track(&gs->promises,
                                     entry->peer,
                                     (const uint8_t *const *)want_ids,
                                     want_lens,
                                     send_count,
                                     expire_ms);
        }
        pthread_mutex_unlock(&gs->lock);

        if (send_count == 0)
        {
            for (size_t i = 0; i < want_count; ++i)
                free(want_ids[i]);
            want_count = 0;
            goto cleanup;
        }

        if (send_count < want_count)
        {
            for (size_t i = send_count; i < want_count; ++i)
                free(want_ids[i]);
            want_count = send_count;
        }

        gossipsub_rpc_out_t frame;
        gossipsub_rpc_out_init(&frame);
        libp2p_err_t enc_rc = gossipsub_rpc_encode_control_iwant(want_ids, want_lens, want_count, &frame);
        if (enc_rc == LIBP2P_ERR_OK && frame.frame && frame.frame_len)
        {
            pthread_mutex_lock(&gs->lock);
            libp2p_err_t send_rc = gossipsub_peer_enqueue_frame_locked(gs, entry, frame.frame, frame.frame_len);
            pthread_mutex_unlock(&gs->lock);
            if (send_rc != LIBP2P_ERR_OK && result == LIBP2P_ERR_OK)
                result = send_rc;
        }
        else if (result == LIBP2P_ERR_OK)
        {
            result = enc_rc;
        }
        gossipsub_rpc_out_clear(&frame);
    }

cleanup:
    if (want_lens)
        free(want_lens);
    if (want_ids)
        gossipsub_message_cache_free_ids(want_ids, want_count);
    return result;
}

libp2p_err_t gossipsub_propagation_handle_control_graft(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_graft_t *grafts,
                                                        size_t count)
{
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;
    if (!grafts || count == 0)
        return LIBP2P_ERR_OK;
    if (entry->explicit_peering)
        return LIBP2P_ERR_OK;

    gossipsub_prune_target_t **prune_targets = NULL;
    size_t prune_count = 0;
    size_t prune_cap = 0;
    libp2p_err_t result = LIBP2P_ERR_OK;
    uint64_t config_backoff_seconds = gossipsub_propagation_backoff_seconds(gs);
    uint64_t config_backoff_ms = (gs->cfg.prune_backoff_ms > 0) ? (uint64_t)gs->cfg.prune_backoff_ms : 0;
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));

    for (size_t i = 0; i < count; ++i)
    {
        const char *topic_name = grafts[i].topic;
        if (!topic_name)
            continue;

        int store_for_prune = 0;
        int extend_backoff = 0;
        peer_id_t **px_peers = NULL;
        size_t px_len = 0;
        uint64_t now_ms = gossipsub_now_ms();
        double peer_score = 0.0;
        const char *decision = "unknown";

        pthread_mutex_lock(&gs->lock);
        gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
        if (!topic || !topic->subscribed)
        {
            store_for_prune = 1;
            decision = "not_subscribed";
        }
        else if (gossipsub_mesh_member_find(topic->mesh, entry->peer))
        {
            store_for_prune = 0;
            decision = "already_in_mesh";
        }
        else if (gossipsub_backoff_contains(topic, entry->peer, now_ms))
        {
            store_for_prune = 1;
            extend_backoff = 1;
            decision = "in_backoff";
        }
        else
        {
            int outbound = entry->outbound_stream ? 1 : 0;
            if (!gossipsub_mesh_member_insert(topic, entry, outbound, now_ms))
            {
                store_for_prune = 1;
                decision = "mesh_insert_failed";
            }
            else
            {
                gossipsub_score_on_mesh_join_locked(gs, topic, entry, now_ms);
                gossipsub_backoff_remove(topic, entry->peer);
                (void)gossipsub_fanout_remove(topic, entry->peer);
                store_for_prune = 0;
                decision = outbound ? "graft_accept_outbound" : "graft_accept_inbound";
            }
        }

        int allow_px = gs->cfg.enable_px ? 1 : 0;
        if (allow_px && entry && entry->score < gs->cfg.accept_px_threshold)
            allow_px = 0;
        if (store_for_prune && allow_px && topic && topic->subscribed)
        {
            size_t limit = gs->cfg.px_peer_target ? gs->cfg.px_peer_target : 0;
            if (limit > 0)
                px_peers = gossipsub_topic_collect_px_locked(topic, entry->peer, limit, &px_len);
        }
        if (store_for_prune && extend_backoff && topic && config_backoff_ms > 0)
        {
            uint64_t expire_ms = gossipsub_propagation_compute_backoff_expiry(now_ms, config_backoff_ms);
            (void)gossipsub_backoff_add(topic, entry->peer, expire_ms);
        }
        peer_score = entry ? entry->score : 0.0;
        pthread_mutex_unlock(&gs->lock);

        if (!store_for_prune)
        {
            LP_LOGD(GOSSIPSUB_MODULE,
                    "graft_accept peer=%s topic=%s score=%.3f decision=%s outbound=%d",
                    peer_repr,
                    topic_name,
                    peer_score,
                    decision,
                    entry && entry->outbound_stream ? 1 : 0);
            if (px_peers)
                gossipsub_px_list_free(px_peers, px_len);
            continue;
        }

        gossipsub_prune_target_t *target = (gossipsub_prune_target_t *)calloc(1, sizeof(*target));
        if (!target)
        {
            if (px_peers)
                gossipsub_px_list_free(px_peers, px_len);
            if (result == LIBP2P_ERR_OK)
                result = LIBP2P_ERR_INTERNAL;
            break;
        }

        size_t topic_len = strlen(topic_name);
        target->topic = (char *)malloc(topic_len + 1);
        if (!target->topic)
        {
            gossipsub_prune_target_free(target);
            if (result == LIBP2P_ERR_OK)
                result = LIBP2P_ERR_INTERNAL;
            break;
        }
        memcpy(target->topic, topic_name, topic_len + 1);
        target->px_peers = px_peers;
        target->px_len = px_len;

        if (prune_count == prune_cap)
        {
            size_t new_cap = prune_cap ? prune_cap * 2 : 4;
            gossipsub_prune_target_t **new_array = (gossipsub_prune_target_t **)realloc(prune_targets, new_cap * sizeof(*new_array));
            if (!new_array)
            {
                gossipsub_prune_target_free(target);
                if (result == LIBP2P_ERR_OK)
                    result = LIBP2P_ERR_INTERNAL;
                break;
            }
            prune_targets = new_array;
            prune_cap = new_cap;
        }
        prune_targets[prune_count++] = target;

        LP_LOGD(GOSSIPSUB_MODULE,
                "graft_reject peer=%s topic=%s score=%.3f decision=%s extend_backoff=%d px_suggested=%zu",
                peer_repr,
                topic_name,
                peer_score,
                decision,
                extend_backoff,
                px_len);
    }

    if (prune_count > 0)
    {
        gossipsub_rpc_out_t frame;
        gossipsub_rpc_out_init(&frame);
        libp2p_err_t enc_rc = gossipsub_rpc_encode_control_prune((const gossipsub_prune_target_t *const *)prune_targets,
                                                                 prune_count,
                                                                 config_backoff_seconds,
                                                                 &frame);
        if (enc_rc == LIBP2P_ERR_OK && frame.frame && frame.frame_len)
        {
            pthread_mutex_lock(&gs->lock);
            libp2p_err_t send_rc = gossipsub_peer_enqueue_frame_locked(gs, entry, frame.frame, frame.frame_len);
            pthread_mutex_unlock(&gs->lock);
            if (send_rc != LIBP2P_ERR_OK && result == LIBP2P_ERR_OK)
                result = send_rc;
        }
        else if (result == LIBP2P_ERR_OK)
        {
            result = enc_rc;
        }
        gossipsub_rpc_out_clear(&frame);
    }

    for (size_t i = 0; i < prune_count; ++i)
        gossipsub_prune_target_free(prune_targets[i]);
    free(prune_targets);

    return result;
}

libp2p_err_t gossipsub_propagation_handle_control_prune(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_prune_t *prunes,
                                                        size_t count)
{
    if (!gs || !entry)
        return LIBP2P_ERR_NULL_PTR;
    if (!prunes || count == 0)
        return LIBP2P_ERR_OK;
    if (entry->explicit_peering)
        return LIBP2P_ERR_OK;

    libp2p_err_t result = LIBP2P_ERR_OK;
    char peer_buf[128];
    const char *peer_repr = gossipsub_peer_to_string(entry ? entry->peer : NULL, peer_buf, sizeof(peer_buf));
    peer_id_t *self_id = NULL;
    if (gs->host)
    {
        if (libp2p_host_get_peer_id(gs->host, &self_id) != LIBP2P_ERR_OK && self_id)
        {
            gossipsub_peer_free(self_id);
            self_id = NULL;
        }
    }

    for (size_t i = 0; i < count; ++i)
    {
        const gossipsub_rpc_control_prune_t *prune = &prunes[i];
       if (!prune || !prune->topic)
           continue;

        gossipsub_peer_entry_t **dial_peers = NULL;
        size_t dial_count = 0;
        size_t dial_cap = 0;
        const gossipsub_rpc_px_record_t **ingest_records = NULL;
        size_t ingest_count = 0;
        size_t ingest_cap = 0;

        uint64_t backoff_seconds = prune->backoff;
        if (backoff_seconds == 0)
            backoff_seconds = gossipsub_propagation_backoff_seconds(gs);

        uint64_t backoff_ms = 0;
        if (backoff_seconds > 0)
        {
            if (backoff_seconds > UINT64_MAX / 1000ULL)
                backoff_ms = UINT64_MAX;
            else
                backoff_ms = backoff_seconds * 1000ULL;
        }

        uint64_t now_ms = gossipsub_now_ms();
        uint64_t expire_ms = gossipsub_propagation_compute_backoff_expiry(now_ms, backoff_ms);

        pthread_mutex_lock(&gs->lock);
        gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, prune->topic);
        if (topic)
        {
            if (gossipsub_mesh_member_remove(topic, entry->peer))
                gossipsub_score_on_mesh_leave_locked(gs, topic, entry->peer, now_ms);
            (void)gossipsub_fanout_remove(topic, entry->peer);
            if (!gossipsub_backoff_add(topic, entry->peer, expire_ms) && result == LIBP2P_ERR_OK)
                result = LIBP2P_ERR_INTERNAL;
            LP_LOGD(GOSSIPSUB_MODULE,
                    "prune_recv peer=%s topic=%s backoff_ms=%" PRIu64 " px_count=%zu score=%.3f",
                    peer_repr,
                    prune->topic,
                    backoff_ms,
                    prune->px_count,
                    entry ? entry->score : 0.0);
        }

        int allow_px = (gs->cfg.enable_px && entry && entry->score >= gs->cfg.accept_px_threshold) ? 1 : 0;
        if (allow_px && prune->px && prune->px_count > 0)
        {
            for (size_t j = 0; j < prune->px_count; ++j)
            {
                const gossipsub_rpc_px_record_t *px = &prune->px[j];
                if (!px || !px->peer)
                    continue;

                gossipsub_peer_entry_t *px_entry = gossipsub_peer_find_or_add_locked(gs, px->peer);
                if (!px_entry || px_entry == entry)
                    continue;

                if (px_entry->peer && gossipsub_peer_equals(px_entry->peer, entry->peer))
                    continue;

                if (self_id && px_entry->peer && gossipsub_peer_equals(px_entry->peer, self_id))
                    continue;

                int already = 0;
                for (size_t k = 0; k < dial_count; ++k)
                {
                    if (dial_peers[k] == px_entry)
                    {
                        already = 1;
                        break;
                    }
                }
                if (already)
                    continue;

                if (dial_count == dial_cap)
                {
                    size_t new_cap = dial_cap ? dial_cap * 2 : 4;
                    gossipsub_peer_entry_t **new_list = (gossipsub_peer_entry_t **)realloc(dial_peers, new_cap * sizeof(*new_list));
                    if (!new_list)
                        continue;
                    dial_peers = new_list;
                    dial_cap = new_cap;
                }
                dial_peers[dial_count++] = px_entry;

                if (px->signed_peer_record && px->signed_peer_record_len > 0)
                {
                    if (ingest_count == ingest_cap)
                    {
                        size_t new_cap = ingest_cap ? ingest_cap * 2 : 4;
                        const gossipsub_rpc_px_record_t **new_list =
                            (const gossipsub_rpc_px_record_t **)realloc(ingest_records, new_cap * sizeof(*new_list));
                        if (new_list)
                        {
                            ingest_records = new_list;
                            ingest_cap = new_cap;
                        }
                    }
                    if (ingest_count < ingest_cap)
                        ingest_records[ingest_count++] = px;
                }
            }
        }
        pthread_mutex_unlock(&gs->lock);

        for (size_t j = 0; j < ingest_count; ++j)
        {
            const gossipsub_rpc_px_record_t *px = ingest_records[j];
            if (px && px->peer && px->signed_peer_record && px->signed_peer_record_len > 0)
                gossipsub_propagation_ingest_px_record(gs, px->peer, px->signed_peer_record, px->signed_peer_record_len);
        }

        for (size_t j = 0; j < dial_count; ++j)
            gossipsub_propagation_try_connect_px(gs, dial_peers[j]);
        free(dial_peers);
        free(ingest_records);
    }

    if (self_id)
        gossipsub_peer_free(self_id);

    return result;
}
