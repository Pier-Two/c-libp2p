#ifndef PEER_ID_INTERNAL_H
#define PEER_ID_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"

typedef struct peer_id_proto_view
{
    peer_id_key_type_t key_type;
    const uint8_t *key_data;
    size_t key_data_len;
} peer_id_proto_view_t;

struct peer_id
{
    uint8_t *multihash;
    size_t multihash_len;
};

peer_id_error_t peer_id_internal_parse_public_key_pb(const uint8_t *buf, size_t len, peer_id_proto_view_t *out_view);
peer_id_error_t peer_id_internal_parse_private_key_pb(const uint8_t *buf, size_t len, peer_id_proto_view_t *out_view);
peer_id_error_t peer_id_internal_build_public_key_pb(peer_id_key_type_t type,
                                                      const uint8_t *raw_key_data,
                                                      size_t raw_key_len,
                                                      uint8_t **out_buf,
                                                      size_t *out_size);

peer_id_error_t peer_id_internal_keyops_public_from_private_raw(peer_id_key_type_t type,
                                                                 const uint8_t *private_key_raw,
                                                                 size_t private_key_raw_len,
                                                                 uint8_t **out_pub_pb,
                                                                 size_t *out_pub_pb_len);

peer_id_error_t peer_id_internal_text_parse(const char *text, peer_id_t **out);
peer_id_error_t peer_id_internal_text_write(const peer_id_t *pid,
                                            peer_id_text_format_t fmt,
                                            char *out,
                                            size_t out_cap,
                                            size_t *out_len);

peer_id_error_t peer_id_internal_validate_multihash(const uint8_t *mh, size_t mh_len);

#endif /* PEER_ID_INTERNAL_H */
