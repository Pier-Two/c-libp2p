#ifndef PEER_ID_H
#define PEER_ID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct peer_id peer_id_t;

typedef enum peer_id_error
{
	PEER_ID_OK = 0,
	PEER_ID_ERR_NULL_PTR,
	PEER_ID_ERR_INVALID_INPUT,
	PEER_ID_ERR_INVALID_PROTOBUF,
	PEER_ID_ERR_INVALID_STRING,
	PEER_ID_ERR_UNSUPPORTED_KEY,
	PEER_ID_ERR_ENCODING,
	PEER_ID_ERR_BUFFER_TOO_SMALL,
	PEER_ID_ERR_ALLOC,
	PEER_ID_ERR_CRYPTO,
	PEER_ID_ERR_RANGE
} peer_id_error_t;

typedef enum peer_id_key_type
{
	PEER_ID_KEY_RSA = 0,
	PEER_ID_KEY_ED25519 = 1,
	PEER_ID_KEY_SECP256K1 = 2,
	PEER_ID_KEY_ECDSA = 3
} peer_id_key_type_t;

typedef enum peer_id_text_format
{
	PEER_ID_TEXT_LEGACY_BASE58 = 0,
	PEER_ID_TEXT_CIDV1_BASE32 = 1
} peer_id_text_format_t;

peer_id_error_t peer_id_new_from_public_key_pb(const uint8_t *pb, size_t pb_len, peer_id_t **out);
peer_id_error_t peer_id_new_from_private_key_pb(const uint8_t *pb, size_t pb_len, peer_id_t **out);
peer_id_error_t peer_id_new_from_text(const char *text, peer_id_t **out);
peer_id_error_t peer_id_new_from_multihash(const uint8_t *mh, size_t mh_len, peer_id_t **out);

void peer_id_free(peer_id_t *pid);
peer_id_error_t peer_id_clone(const peer_id_t *src, peer_id_t **out);

peer_id_error_t peer_id_multihash_view(const peer_id_t *pid, const uint8_t **bytes, size_t *len);
peer_id_error_t peer_id_multihash_copy(const peer_id_t *pid, uint8_t *out, size_t out_cap, size_t *out_len);

int peer_id_equal(const peer_id_t *a, const peer_id_t *b);

peer_id_error_t peer_id_text_write(const peer_id_t *pid, peer_id_text_format_t fmt, char *out, size_t out_cap,
				   size_t *out_len);
peer_id_error_t peer_id_text_write_default(const peer_id_t *pid, char *out, size_t out_cap, size_t *out_len);

peer_id_error_t peer_id_public_key_pb_from_private_raw(peer_id_key_type_t type, const uint8_t *private_key_raw,
						       size_t private_key_raw_len, uint8_t **out_pub_pb,
						       size_t *out_pub_pb_len);

#ifdef __cplusplus
}
#endif

#endif /* PEER_ID_H */
