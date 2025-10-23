#ifndef LIBP2P_GOSSIPSUB_PROTO_H
#define LIBP2P_GOSSIPSUB_PROTO_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/errors.h"
#include "protocol/gossipsub/message.h"
#include "gossipsub_rpc.pb.h"

struct libp2p_stream;

#ifdef __cplusplus
extern "C" {
#endif

typedef libp2p_err_t (*libp2p_gossipsub_rpc_decoder_cb)(const uint8_t *frame,
                                                        size_t frame_len,
                                                        void *user_data);

typedef struct libp2p_gossipsub_rpc_decoder
{
    uint8_t header[10];
    size_t header_used;
    int have_length;
    size_t frame_len;
    size_t frame_used;
    size_t frame_cap;
    size_t max_frame_len;
    uint8_t *frame_buf;
} libp2p_gossipsub_rpc_decoder_t;

/**
 * @brief Encode a single publish RPC carrying @p msg.
 *
 * The returned buffer contains the protobuf-encoded RPC message without
 * the outer length-prefix. The caller owns the buffer and must free(3) it.
 *
 * @param[in]  msg      Message metadata and payload to encode.
 * @param[out] out_buf  Newly allocated buffer with the encoded RPC.
 * @param[out] out_len  Length of @p out_buf in bytes.
 *
 * @return LIBP2P_ERR_OK on success or an error code on failure.
 */
libp2p_err_t libp2p_gossipsub_rpc_encode_publish(const libp2p_gossipsub_message_t *msg,
                                                 uint8_t **out_buf,
                                                 size_t *out_len);

/**
 * @brief Decode a protobuf RPC frame into the generated RPC struct.
 *
 * The caller owns the returned RPC object and must free it with
 * libp2p_gossipsub_RPC_free().
 */
libp2p_err_t libp2p_gossipsub_rpc_decode_frame(const uint8_t *frame,
                                               size_t frame_len,
                                               libp2p_gossipsub_RPC **out_rpc);

/**
 * @brief Read a single RPC frame from @p stream using LP framing and decode it.
 *
 * When @p out_buf is non-NULL the function transfers ownership of the raw
 * payload buffer to the caller which must free(3) it.
 */
libp2p_err_t libp2p_gossipsub_rpc_read_stream(struct libp2p_stream *stream,
                                              uint8_t **out_buf,
                                              size_t *out_len,
                                              libp2p_gossipsub_RPC **out_rpc);

void libp2p_gossipsub_rpc_decoder_init(libp2p_gossipsub_rpc_decoder_t *dec);
void libp2p_gossipsub_rpc_decoder_reset(libp2p_gossipsub_rpc_decoder_t *dec);
void libp2p_gossipsub_rpc_decoder_free(libp2p_gossipsub_rpc_decoder_t *dec);
void libp2p_gossipsub_rpc_decoder_set_max_frame(libp2p_gossipsub_rpc_decoder_t *dec,
                                                size_t max_frame_len);
libp2p_err_t libp2p_gossipsub_rpc_decoder_feed(libp2p_gossipsub_rpc_decoder_t *dec,
                                               const uint8_t *data,
                                               size_t len,
                                               libp2p_gossipsub_rpc_decoder_cb cb,
                                               void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_PROTO_H */
