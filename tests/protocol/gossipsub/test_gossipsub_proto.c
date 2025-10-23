#include "gossipsub_proto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gossipsub_rpc.pb.h"
#include "noise/protobufs.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

static int test_roundtrip(void)
{
    const char *topic = "test/topic";
    const uint8_t data[] = { 0xaa, 0xbb, 0xcc };
    const uint8_t seqno[] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t from_bytes[] = { 0x12, 0x34, 0x56, 0x78 };

    peer_id_t from = {
        .bytes = (uint8_t *)from_bytes,
        .size = sizeof(from_bytes)
    };

    libp2p_gossipsub_message_t msg = {
        .topic = {
            .struct_size = sizeof(msg.topic),
            .topic = topic
        },
        .data = data,
        .data_len = sizeof(data),
        .from = &from,
        .seqno = seqno,
        .seqno_len = sizeof(seqno),
        .raw_message = NULL,
        .raw_message_len = 0
    };

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    libp2p_err_t err = libp2p_gossipsub_rpc_encode_publish(&msg, &encoded, &encoded_len);
    if (err != LIBP2P_ERR_OK || !encoded || !encoded_len)
        return 0;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t derr = libp2p_gossipsub_rpc_decode_frame(encoded, encoded_len, &rpc);

    int ok = 1;
    if (derr != LIBP2P_ERR_OK || !rpc)
    {
        fprintf(stderr, "roundtrip: decode failed\n");
        ok = 0;
    }
    else if (libp2p_gossipsub_RPC_count_publish(rpc) != 1)
    {
        fprintf(stderr, "roundtrip: publish count=%zu\n", libp2p_gossipsub_RPC_count_publish(rpc));
        ok = 0;
    }

    libp2p_gossipsub_Message *decoded = libp2p_gossipsub_RPC_get_at_publish(rpc, 0);
    if (!decoded)
    {
        fprintf(stderr, "roundtrip: missing publish message\n");
        ok = 0;
    }

    size_t expect_topic_len = strlen(topic);
    if (ok && (!libp2p_gossipsub_Message_has_topic(decoded) ||
               libp2p_gossipsub_Message_get_size_topic(decoded) != expect_topic_len ||
               memcmp(libp2p_gossipsub_Message_get_topic(decoded), topic, expect_topic_len) != 0))
    {
        fprintf(stderr, "roundtrip: topic mismatch\n");
        ok = 0;
    }

    if (ok && (!libp2p_gossipsub_Message_has_data(decoded) ||
               libp2p_gossipsub_Message_get_size_data(decoded) != sizeof(data) ||
               memcmp(libp2p_gossipsub_Message_get_data(decoded), data, sizeof(data)) != 0))
    {
        fprintf(stderr, "roundtrip: data mismatch\n");
        ok = 0;
    }

    if (ok && (!libp2p_gossipsub_Message_has_seqno(decoded) ||
               libp2p_gossipsub_Message_get_size_seqno(decoded) != sizeof(seqno) ||
               memcmp(libp2p_gossipsub_Message_get_seqno(decoded), seqno, sizeof(seqno)) != 0))
    {
        fprintf(stderr, "roundtrip: seqno mismatch\n");
        ok = 0;
    }

    if (ok && (!libp2p_gossipsub_Message_has_from(decoded) ||
               libp2p_gossipsub_Message_get_size_from(decoded) != sizeof(from_bytes) ||
               memcmp(libp2p_gossipsub_Message_get_from(decoded), from_bytes, sizeof(from_bytes)) != 0))
    {
        fprintf(stderr, "roundtrip: from mismatch\n");
        ok = 0;
    }

    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    free(encoded);
    return ok;
}

static int test_reject_empty_topic(void)
{
    libp2p_gossipsub_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.topic.struct_size = sizeof(msg.topic);
    msg.topic.topic = "";

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
libp2p_err_t err = libp2p_gossipsub_rpc_encode_publish(&msg, &encoded, &encoded_len);
    return err != LIBP2P_ERR_OK;
}

typedef struct
{
    const char *topic;
    const uint8_t *data;
    size_t data_len;
    const uint8_t *seqno;
    size_t seqno_len;
    const uint8_t *from;
    size_t from_len;
    int ok;
    int frames_seen;
} decoder_test_ctx_t;

static libp2p_err_t decoder_capture_cb(const uint8_t *frame, size_t frame_len, void *user_data)
{
    decoder_test_ctx_t *ctx = (decoder_test_ctx_t *)user_data;
    ctx->frames_seen++;

    libp2p_gossipsub_RPC *rpc = NULL;
    libp2p_err_t derr = libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &rpc);
    if (derr != LIBP2P_ERR_OK || !rpc)
    {
        ctx->ok = 0;
        return derr != LIBP2P_ERR_OK ? derr : LIBP2P_ERR_INTERNAL;
    }

    int ok = 1;
    if (libp2p_gossipsub_RPC_count_publish(rpc) != 1)
    {
        ok = 0;
    }
    libp2p_gossipsub_Message *decoded = ok ? libp2p_gossipsub_RPC_get_at_publish(rpc, 0) : NULL;
    if (!decoded)
        ok = 0;

    if (ok)
    {
        size_t topic_len = strlen(ctx->topic);
        ok = libp2p_gossipsub_Message_has_topic(decoded) &&
             libp2p_gossipsub_Message_get_size_topic(decoded) == topic_len &&
             memcmp(libp2p_gossipsub_Message_get_topic(decoded), ctx->topic, topic_len) == 0;
    }

    if (ok && ctx->data_len)
    {
        ok = libp2p_gossipsub_Message_has_data(decoded) &&
             libp2p_gossipsub_Message_get_size_data(decoded) == ctx->data_len &&
             memcmp(libp2p_gossipsub_Message_get_data(decoded), ctx->data, ctx->data_len) == 0;
    }

    if (ok && ctx->seqno_len)
    {
        ok = libp2p_gossipsub_Message_has_seqno(decoded) &&
             libp2p_gossipsub_Message_get_size_seqno(decoded) == ctx->seqno_len &&
             memcmp(libp2p_gossipsub_Message_get_seqno(decoded), ctx->seqno, ctx->seqno_len) == 0;
    }

    if (ok && ctx->from_len)
    {
        ok = libp2p_gossipsub_Message_has_from(decoded) &&
             libp2p_gossipsub_Message_get_size_from(decoded) == ctx->from_len &&
             memcmp(libp2p_gossipsub_Message_get_from(decoded), ctx->from, ctx->from_len) == 0;
    }

    libp2p_gossipsub_RPC_free(rpc);
    if (!ok)
    {
        ctx->ok = 0;
        return LIBP2P_ERR_INTERNAL;
    }
    return LIBP2P_ERR_OK;
}

static int test_decoder_handles_chunked_frames(void)
{
    const char *topic = "chunk/topic";
    const uint8_t data[] = { 0x42, 0x43, 0x44, 0x45, 0x46 };
    const uint8_t seqno[] = { 0x10, 0x20 };
    const uint8_t from_bytes[] = { 0x99, 0x88, 0x77 };

    peer_id_t from = {
        .bytes = (uint8_t *)from_bytes,
        .size = sizeof(from_bytes)
    };

    libp2p_gossipsub_message_t msg = {
        .topic = {
            .struct_size = sizeof(msg.topic),
            .topic = topic
        },
        .data = data,
        .data_len = sizeof(data),
        .from = &from,
        .seqno = seqno,
        .seqno_len = sizeof(seqno),
        .raw_message = NULL,
        .raw_message_len = 0
    };

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    if (libp2p_gossipsub_rpc_encode_publish(&msg, &encoded, &encoded_len) != LIBP2P_ERR_OK)
        return 0;

    uint8_t header[10];
    size_t header_len = 0;
    if (unsigned_varint_encode(encoded_len, header, sizeof(header), &header_len) != UNSIGNED_VARINT_OK)
    {
        free(encoded);
        return 0;
    }

    const size_t frame_len = header_len + encoded_len;
    uint8_t *wire = (uint8_t *)malloc(frame_len * 2);
    if (!wire)
    {
        free(encoded);
        return 0;
    }

    for (size_t i = 0; i < 2; ++i)
    {
        size_t offset = i * frame_len;
        memcpy(wire + offset, header, header_len);
        memcpy(wire + offset + header_len, encoded, encoded_len);
    }

    libp2p_gossipsub_rpc_decoder_t decoder;
    libp2p_gossipsub_rpc_decoder_init(&decoder);

    decoder_test_ctx_t ctx = {
        .topic = topic,
        .data = data,
        .data_len = sizeof(data),
        .seqno = seqno,
        .seqno_len = sizeof(seqno),
        .from = from_bytes,
        .from_len = sizeof(from_bytes),
        .ok = 1,
        .frames_seen = 0
    };

    size_t slices[] = { 1, 2, 1, 4, 7, 9, frame_len * 2 };
    size_t pos = 0;
    size_t total = frame_len * 2;
    size_t slices_count = sizeof(slices) / sizeof(slices[0]);
    for (size_t i = 0; i < slices_count && pos < total; ++i)
    {
        size_t take = slices[i];
        if (take > total - pos)
            take = total - pos;
        if (take == 0)
            break;
        libp2p_err_t rc = libp2p_gossipsub_rpc_decoder_feed(&decoder,
                                                            wire + pos,
                                                            take,
                                                            decoder_capture_cb,
                                                            &ctx);
        if (rc != LIBP2P_ERR_OK)
        {
            ctx.ok = 0;
            break;
        }
        pos += take;
    }

    libp2p_gossipsub_rpc_decoder_free(&decoder);
    free(encoded);
    free(wire);

    return ctx.ok && ctx.frames_seen == 2 && pos == total;
}

static int test_control_idontwant_roundtrip(void)
{
    libp2p_gossipsub_RPC *rpc = NULL;
    if (libp2p_gossipsub_RPC_new(&rpc) != NOISE_ERROR_NONE || !rpc)
        return 0;

    int ok = 0;
    uint8_t *scratch = NULL;
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    libp2p_gossipsub_RPC *decoded = NULL;

    libp2p_gossipsub_ControlMessage *control = NULL;
    if (libp2p_gossipsub_RPC_get_new_control(rpc, &control) != NOISE_ERROR_NONE || !control)
        goto cleanup;

    libp2p_gossipsub_ControlIDontWant *idontwant = NULL;
    if (libp2p_gossipsub_ControlMessage_add_idontwant(control, &idontwant) != NOISE_ERROR_NONE || !idontwant)
        goto cleanup;

    const uint8_t msg_id[] = { 0xde, 0xad, 0xbe, 0xef };
    if (libp2p_gossipsub_ControlIDontWant_add_message_ids(idontwant, msg_id, sizeof(msg_id)) != NOISE_ERROR_NONE)
        goto cleanup;

    libp2p_gossipsub_ControlExtensions *extensions = NULL;
    if (libp2p_gossipsub_ControlMessage_get_new_extensions(control, &extensions) != NOISE_ERROR_NONE || !extensions)
        goto cleanup;
    if (libp2p_gossipsub_ControlExtensions_set_placeholder(extensions, 1) != NOISE_ERROR_NONE)
        goto cleanup;

    NoiseProtobuf measure;
    if (noise_protobuf_prepare_measure(&measure, SIZE_MAX) != NOISE_ERROR_NONE)
        goto cleanup;
    if (libp2p_gossipsub_RPC_write(&measure, 0, rpc) != NOISE_ERROR_NONE)
        goto cleanup;

    size_t encoded_size = 0;
    if (noise_protobuf_finish_measure(&measure, &encoded_size) != NOISE_ERROR_NONE || encoded_size == 0)
        goto cleanup;

    scratch = (uint8_t *)malloc(encoded_size);
    if (!scratch)
        goto cleanup;

    NoiseProtobuf out_pb;
    if (noise_protobuf_prepare_output(&out_pb, scratch, encoded_size) != NOISE_ERROR_NONE)
        goto cleanup;
    if (libp2p_gossipsub_RPC_write(&out_pb, 0, rpc) != NOISE_ERROR_NONE)
        goto cleanup;
    if (noise_protobuf_finish_output_shift(&out_pb, &encoded, &encoded_len) != NOISE_ERROR_NONE || !encoded)
        goto cleanup;
    scratch = NULL;

    libp2p_err_t derr = libp2p_gossipsub_rpc_decode_frame(encoded, encoded_len, &decoded);
    if (derr != LIBP2P_ERR_OK || !decoded)
        goto cleanup;

    libp2p_gossipsub_ControlMessage *decoded_ctrl = libp2p_gossipsub_RPC_get_control(decoded);
    if (!decoded_ctrl)
        goto cleanup;

    if (libp2p_gossipsub_ControlMessage_count_idontwant(decoded_ctrl) != 1)
        goto cleanup;

    libp2p_gossipsub_ControlIDontWant *decoded_idw = libp2p_gossipsub_ControlMessage_get_at_idontwant(decoded_ctrl, 0);
    if (!decoded_idw)
        goto cleanup;
    if (libp2p_gossipsub_ControlIDontWant_count_message_ids(decoded_idw) != 1)
        goto cleanup;
    if (libp2p_gossipsub_ControlIDontWant_get_size_at_message_ids(decoded_idw, 0) != sizeof(msg_id))
        goto cleanup;
    if (memcmp(libp2p_gossipsub_ControlIDontWant_get_at_message_ids(decoded_idw, 0), msg_id, sizeof(msg_id)) != 0)
        goto cleanup;

    libp2p_gossipsub_ControlExtensions *decoded_ext = libp2p_gossipsub_ControlMessage_get_extensions(decoded_ctrl);
    if (!decoded_ext)
        goto cleanup;
    if (!libp2p_gossipsub_ControlExtensions_has_placeholder(decoded_ext) ||
        libp2p_gossipsub_ControlExtensions_get_placeholder(decoded_ext) != 1)
        goto cleanup;

    ok = 1;

cleanup:
    if (decoded)
        libp2p_gossipsub_RPC_free(decoded);
    if (rpc)
        libp2p_gossipsub_RPC_free(rpc);
    if (encoded)
        free(encoded);
    if (scratch)
        free(scratch);
    return ok;
}

static void print_result(const char *name, int ok)
{
    printf("TEST: %-40s | %s\n", name, ok ? "PASS" : "FAIL");
}

int main(void)
{
    int failures = 0;
    int ok = test_roundtrip();
    print_result("gossipsub_proto_roundtrip", ok);
    if (!ok)
        failures++;

    ok = test_reject_empty_topic();
    print_result("gossipsub_proto_reject_empty_topic", ok);
    if (!ok)
        failures++;

    ok = test_decoder_handles_chunked_frames();
    print_result("gossipsub_proto_decoder_chunked_frames", ok);
    if (!ok)
        failures++;

    ok = test_control_idontwant_roundtrip();
    print_result("gossipsub_proto_control_idontwant_roundtrip", ok);
    if (!ok)
        failures++;

    return failures ? 1 : 0;
}
