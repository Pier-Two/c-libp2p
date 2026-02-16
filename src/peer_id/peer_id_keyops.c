#include <stddef.h>
#include <stdint.h>

#include "peer_id_internal.h"

peer_id_error_t peer_id_internal_pub_from_private_rsa(const uint8_t *key_data, size_t key_data_len,
						      uint8_t **pubkey_buf, size_t *pubkey_len);
peer_id_error_t peer_id_internal_pub_from_private_ed25519(const uint8_t *key_data, size_t key_data_len,
							  uint8_t **pubkey_buf, size_t *pubkey_len);
peer_id_error_t peer_id_internal_pub_from_private_secp256k1(const uint8_t *key_data, size_t key_data_len,
							    uint8_t **pubkey_buf, size_t *pubkey_len);
peer_id_error_t peer_id_internal_pub_from_private_ecdsa(const uint8_t *key_data, size_t key_data_len,
							uint8_t **pubkey_buf, size_t *pubkey_len);

peer_id_error_t peer_id_internal_keyops_public_from_private_raw(peer_id_key_type_t type, const uint8_t *private_key_raw,
								size_t private_key_raw_len, uint8_t **out_pub_pb,
								size_t *out_pub_pb_len)
{
	peer_id_error_t status;

	if ((private_key_raw == NULL) || (out_pub_pb == NULL) || (out_pub_pb_len == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*out_pub_pb = NULL;
	*out_pub_pb_len = (size_t)0U;

	switch (type)
	{
	case PEER_ID_KEY_RSA:
		status = peer_id_internal_pub_from_private_rsa(private_key_raw, private_key_raw_len, out_pub_pb,
							       out_pub_pb_len);
		break;
	case PEER_ID_KEY_ED25519:
		status = peer_id_internal_pub_from_private_ed25519(private_key_raw, private_key_raw_len, out_pub_pb,
								   out_pub_pb_len);
		break;
	case PEER_ID_KEY_SECP256K1:
		status = peer_id_internal_pub_from_private_secp256k1(private_key_raw, private_key_raw_len, out_pub_pb,
								     out_pub_pb_len);
		break;
	case PEER_ID_KEY_ECDSA:
		status = peer_id_internal_pub_from_private_ecdsa(private_key_raw, private_key_raw_len, out_pub_pb,
								 out_pub_pb_len);
		break;
	default:
		status = PEER_ID_ERR_UNSUPPORTED_KEY;
		break;
	}

	return status;
}

peer_id_error_t peer_id_public_key_pb_from_private_raw(peer_id_key_type_t type, const uint8_t *private_key_raw,
						       size_t private_key_raw_len, uint8_t **out_pub_pb,
						       size_t *out_pub_pb_len)
{
	return peer_id_internal_keyops_public_from_private_raw(type, private_key_raw, private_key_raw_len, out_pub_pb,
							       out_pub_pb_len);
}
