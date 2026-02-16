#ifndef PEER_ID_PROTO_H
#define PEER_ID_PROTO_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"

peer_id_error_t peer_id_build_public_key_protobuf(uint64_t key_type, const uint8_t *raw_key_data, size_t raw_key_len,
						  uint8_t **out_buf, size_t *out_size);

int parse_public_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data,
			   size_t *out_key_data_len);

int parse_private_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data,
			    size_t *out_key_data_len);

#endif /* PEER_ID_PROTO_H */
