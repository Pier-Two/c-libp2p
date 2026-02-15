#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multibase/encoding/base16.h"
#include "multiformats/multibase/encoding/base16_upper.h"
#include "multiformats/multibase/encoding/base32.h"
#include "multiformats/multibase/encoding/base32_upper.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multibase/encoding/base64.h"
#include "multiformats/multibase/encoding/base64_url.h"
#include "multiformats/multibase/encoding/base64_url_pad.h"
#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ecdsa.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_rsa.h"
#include "peer_id/peer_id_secp256k1.h"

#define PEER_ID_IDENTITY_HASH_MAX_SIZE ((size_t)42U)
#define PEER_ID_MAX_PUBLIC_KEY_PROTO_SIZE ((size_t)(64U * 1024U))
#define PEER_ID_SHA2_256_DIGEST_SIZE ((size_t)32U)
#define PEER_ID_MULTIBASE_INVALID ((multibase_t) - 1)

static int peer_id_to_string_error(peer_id_error_t error)
{
	return -((int)error);
}

static void peer_id_reset_output(peer_id_t *pid)
{
	if (pid != NULL)
	{
		pid->bytes = NULL;
		pid->size = (size_t)0U;
	}
}

static int peer_id_size_add(size_t left, size_t right, size_t *sum)
{
	int status;

	status = 0;
	if ((sum != NULL) && (left <= (SIZE_MAX - right)))
	{
		*sum = left + right;
		status = 1;
	}

	return status;
}

static int peer_id_is_supported_multihash_code(uint64_t hash_code)
{
	int supported;

	supported = 1;
	switch (hash_code)
	{
	case MULTIHASH_CODE_IDENTITY:
	case MULTIHASH_CODE_SHA2_256:
	case MULTIHASH_CODE_SHA2_512:
	case MULTIHASH_CODE_SHA3_224:
	case MULTIHASH_CODE_SHA3_256:
	case MULTIHASH_CODE_SHA3_384:
	case MULTIHASH_CODE_SHA3_512:
		break;
	default:
		supported = 0;
		break;
	}

	return supported;
}

static peer_id_error_t peer_id_map_multihash_error(int multihash_status)
{
	peer_id_error_t status;

	switch (multihash_status)
	{
	case MULTIHASH_ERR_NULL_POINTER:
		status = PEER_ID_E_NULL_PTR;
		break;
	case MULTIHASH_ERR_INVALID_INPUT:
		status = PEER_ID_E_INVALID_PROTOBUF;
		break;
	case MULTIHASH_ERR_UNSUPPORTED_FUN:
		status = PEER_ID_E_UNSUPPORTED_KEY;
		break;
	case MULTIHASH_ERR_DIGEST_TOO_LARGE:
		status = PEER_ID_E_INVALID_RANGE;
		break;
	case MULTIHASH_ERR_ALLOC_FAILURE:
		status = PEER_ID_E_ALLOC_FAILED;
		break;
	default:
		status = PEER_ID_E_CRYPTO_FAILED;
		break;
	}

	return status;
}

static peer_id_error_t peer_id_copy_bytes(peer_id_t *pid, const uint8_t *src, size_t src_size)
{
	peer_id_error_t status;
	uint8_t *copy;

	status = PEER_ID_SUCCESS;
	copy = NULL;
	if ((pid == NULL) || (src == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}
	else if (src_size == (size_t)0U)
	{
		status = PEER_ID_E_INVALID_RANGE;
	}
	else
	{
		copy = (uint8_t *)malloc(src_size);
		if (copy == NULL)
		{
			status = PEER_ID_E_ALLOC_FAILED;
		}
		else
		{
			(void)memcpy(copy, src, src_size);
			pid->bytes = copy;
			pid->size = src_size;
		}
	}

	return status;
}

static peer_id_error_t peer_id_validate_multihash_bytes(const uint8_t *multihash, size_t multihash_size)
{
	peer_id_error_t status;
	uint64_t hash_code;
	uint64_t digest_len_u64;
	size_t hash_code_size;
	size_t digest_len_size;
	size_t payload_offset;
	size_t payload_size;
	size_t expected_size;
	unsigned_varint_err_t varint_status;

	status = PEER_ID_SUCCESS;
	hash_code = (uint64_t)0U;
	digest_len_u64 = (uint64_t)0U;
	hash_code_size = (size_t)0U;
	digest_len_size = (size_t)0U;
	payload_offset = (size_t)0U;
	expected_size = (size_t)0U;
	if ((multihash == NULL) || (multihash_size == (size_t)0U))
	{
		status = PEER_ID_E_INVALID_STRING;
	}
	else
	{
		varint_status = unsigned_varint_decode(multihash, multihash_size, &hash_code, &hash_code_size);
		if ((varint_status != UNSIGNED_VARINT_OK) || (hash_code_size >= multihash_size) ||
		    (peer_id_is_supported_multihash_code(hash_code) == 0))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		payload_size = multihash_size - hash_code_size;
		varint_status = unsigned_varint_decode(multihash + hash_code_size, payload_size, &digest_len_u64,
						       &digest_len_size);
		if ((varint_status != UNSIGNED_VARINT_OK) || (digest_len_size >= payload_size))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
		else if (digest_len_u64 > (uint64_t)(payload_size - digest_len_size))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		payload_offset = hash_code_size + digest_len_size;
		if ((payload_offset > multihash_size) || (digest_len_u64 > SIZE_MAX))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
		else
		{
			expected_size = payload_offset + (size_t)digest_len_u64;
			if (expected_size != multihash_size)
			{
				status = PEER_ID_E_INVALID_STRING;
			}
		}
	}

	return status;
}

static multibase_t peer_id_multibase_from_prefix(char prefix)
{
	multibase_t base;

	base = PEER_ID_MULTIBASE_INVALID;
	switch (prefix)
	{
	case BASE32_CHARACTER:
		base = MULTIBASE_BASE32;
		break;
	case BASE32_UPPER_CHARACTER:
		base = MULTIBASE_BASE32_UPPER;
		break;
	case BASE58_BTC_CHARACTER:
		base = MULTIBASE_BASE58_BTC;
		break;
	case BASE64_CHARACTER:
		base = MULTIBASE_BASE64;
		break;
	case BASE64_URL_CHARACTER:
		base = MULTIBASE_BASE64_URL;
		break;
	case BASE64_URL_PAD_CHARACTER:
		base = MULTIBASE_BASE64_URL_PAD;
		break;
	case BASE16_CHARACTER:
		base = MULTIBASE_BASE16;
		break;
	case BASE16_UPPER_CHARACTER:
		base = MULTIBASE_BASE16_UPPER;
		break;
	default:
		break;
	}

	return base;
}

static peer_id_error_t peer_id_decode_multibase_string(multibase_t base, const char *input, uint8_t **decoded_out,
						       size_t *decoded_size_out)
{
	peer_id_error_t status;
	size_t input_len;
	uint8_t *decoded;
	ptrdiff_t decode_result;

	status = PEER_ID_SUCCESS;
	input_len = (size_t)0U;
	decoded = NULL;
	decode_result = (ptrdiff_t)0;
	if ((input == NULL) || (decoded_out == NULL) || (decoded_size_out == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}
	else
	{
		*decoded_out = NULL;
		*decoded_size_out = (size_t)0U;
		input_len = strlen(input);
		if (input_len == (size_t)0U)
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		decoded = (uint8_t *)malloc(input_len);
		if (decoded == NULL)
		{
			status = PEER_ID_E_ALLOC_FAILED;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		decode_result = multibase_decode(base, input, decoded, input_len);
		if ((decode_result <= 0) || ((size_t)decode_result > input_len))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
		else
		{
			*decoded_out = decoded;
			*decoded_size_out = (size_t)decode_result;
			decoded = NULL;
		}
	}

	if (decoded != NULL)
	{
		free(decoded);
	}

	return status;
}

static peer_id_error_t peer_id_decode_legacy_string(const char *str, peer_id_t *pid)
{
	peer_id_error_t status;
	size_t str_len;
	size_t prefixed_len;
	char *prefixed;
	uint8_t *decoded;
	size_t decoded_len;

	status = PEER_ID_SUCCESS;
	str_len = (size_t)0U;
	prefixed_len = (size_t)0U;
	prefixed = NULL;
	decoded = NULL;
	decoded_len = (size_t)0U;
	if ((str == NULL) || (pid == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}
	else
	{
		str_len = strlen(str);
		if (str_len == (size_t)0U)
		{
			status = PEER_ID_E_INVALID_STRING;
		}
		else if (peer_id_size_add(str_len, (size_t)2U, &prefixed_len) == 0)
		{
			status = PEER_ID_E_INVALID_RANGE;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		prefixed = (char *)malloc(prefixed_len);
		if (prefixed == NULL)
		{
			status = PEER_ID_E_ALLOC_FAILED;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		prefixed[0] = BASE58_BTC_CHARACTER;
		(void)memcpy(prefixed + 1, str, str_len + (size_t)1U);

		status = peer_id_decode_multibase_string(MULTIBASE_BASE58_BTC, prefixed, &decoded, &decoded_len);
	}

	if (status == PEER_ID_SUCCESS)
	{
		status = peer_id_validate_multihash_bytes(decoded, decoded_len);
	}

	if (status == PEER_ID_SUCCESS)
	{
		status = peer_id_copy_bytes(pid, decoded, decoded_len);
	}

	if (decoded != NULL)
	{
		free(decoded);
	}
	if (prefixed != NULL)
	{
		free(prefixed);
	}

	return status;
}

static peer_id_error_t peer_id_decode_cid_string(const char *str, multibase_t base, peer_id_t *pid)
{
	peer_id_error_t status;
	uint8_t *decoded;
	size_t decoded_size;
	uint64_t codec;
	size_t codec_size;
	size_t multihash_offset;
	unsigned_varint_err_t varint_status;

	status = PEER_ID_SUCCESS;
	decoded = NULL;
	decoded_size = (size_t)0U;
	codec = (uint64_t)0U;
	codec_size = (size_t)0U;
	multihash_offset = (size_t)0U;
	if ((str == NULL) || (pid == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}

	if (status == PEER_ID_SUCCESS)
	{
		status = peer_id_decode_multibase_string(base, str, &decoded, &decoded_size);
	}

	if (status == PEER_ID_SUCCESS)
	{
		if ((decoded_size < (size_t)2U) || (decoded[0] != (uint8_t)MULTICODEC_CIDV1))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		varint_status = unsigned_varint_decode(decoded + 1, decoded_size - 1, &codec, &codec_size);
		if ((varint_status != UNSIGNED_VARINT_OK) || (codec != (uint64_t)MULTICODEC_LIBP2P_KEY))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		multihash_offset = (size_t)1U + codec_size;
		if ((multihash_offset >= decoded_size) || (multihash_offset < codec_size))
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		status = peer_id_validate_multihash_bytes(decoded + multihash_offset, decoded_size - multihash_offset);
	}

	if (status == PEER_ID_SUCCESS)
	{
		status = peer_id_copy_bytes(pid, decoded + multihash_offset, decoded_size - multihash_offset);
	}

	if (decoded != NULL)
	{
		free(decoded);
	}

	return status;
}

peer_id_error_t peer_id_create_from_public_key(const uint8_t *pubkey_buf, size_t pubkey_len, peer_id_t *pid)
{
	peer_id_error_t status;
	uint64_t key_type;
	const uint8_t *key_data;
	size_t key_data_len;
	uint64_t hash_function_code;
	size_t digest_len;
	size_t hash_varint_size;
	size_t digest_varint_size;
	size_t required_size;
	uint8_t *multihash;
	int encode_result;

	status = PEER_ID_SUCCESS;
	key_type = (uint64_t)0U;
	key_data = NULL;
	key_data_len = (size_t)0U;
	hash_function_code = MULTIHASH_CODE_SHA2_256;
	digest_len = (size_t)0U;
	hash_varint_size = (size_t)0U;
	digest_varint_size = (size_t)0U;
	required_size = (size_t)0U;
	multihash = NULL;
	encode_result = 0;
	if ((pubkey_buf == NULL) || (pid == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}
	else
	{
		peer_id_reset_output(pid);
		if ((pubkey_len == (size_t)0U) || (pubkey_len > PEER_ID_MAX_PUBLIC_KEY_PROTO_SIZE))
		{
			status = PEER_ID_E_INVALID_RANGE;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		if (parse_public_key_proto(pubkey_buf, pubkey_len, &key_type, &key_data, &key_data_len) < 0)
		{
			status = PEER_ID_E_INVALID_PROTOBUF;
		}
		else if (key_type > (uint64_t)PEER_ID_ECDSA_KEY_TYPE)
		{
			status = PEER_ID_E_UNSUPPORTED_KEY;
		}
		else if ((key_data == NULL) || (key_data_len == (size_t)0U))
		{
			status = PEER_ID_E_INVALID_PROTOBUF;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		if (pubkey_len <= PEER_ID_IDENTITY_HASH_MAX_SIZE)
		{
			hash_function_code = MULTIHASH_CODE_IDENTITY;
			digest_len = pubkey_len;
		}
		else
		{
			hash_function_code = MULTIHASH_CODE_SHA2_256;
			digest_len = PEER_ID_SHA2_256_DIGEST_SIZE;
		}

		hash_varint_size = unsigned_varint_size(hash_function_code);
		digest_varint_size = unsigned_varint_size((uint64_t)digest_len);
		if ((peer_id_size_add(hash_varint_size, digest_varint_size, &required_size) == 0) ||
		    (peer_id_size_add(required_size, digest_len, &required_size) == 0))
		{
			status = PEER_ID_E_INVALID_RANGE;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		multihash = (uint8_t *)malloc(required_size);
		if (multihash == NULL)
		{
			status = PEER_ID_E_ALLOC_FAILED;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		encode_result = multihash_encode(hash_function_code, pubkey_buf, pubkey_len, multihash, required_size);
		if (encode_result <= 0)
		{
			status = peer_id_map_multihash_error(encode_result);
		}
		else if ((size_t)encode_result > required_size)
		{
			status = PEER_ID_E_ENCODING_FAILED;
		}
		else
		{
			pid->bytes = multihash;
			pid->size = (size_t)encode_result;
			multihash = NULL;
		}
	}

	if (multihash != NULL)
	{
		free(multihash);
	}

	return status;
}

peer_id_error_t peer_id_create_from_private_key(const uint8_t *privkey_buf, size_t privkey_len, peer_id_t *pid)
{
	peer_id_error_t status;
	peer_id_error_t derive_status;
	uint64_t key_type;
	const uint8_t *key_data;
	size_t key_data_len;
	uint8_t *pubkey_buf;
	size_t pubkey_len;

	status = PEER_ID_SUCCESS;
	derive_status = PEER_ID_SUCCESS;
	key_type = (uint64_t)0U;
	key_data = NULL;
	key_data_len = (size_t)0U;
	pubkey_buf = NULL;
	pubkey_len = (size_t)0U;
	if ((privkey_buf == NULL) || (pid == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}
	else
	{
		peer_id_reset_output(pid);
	}

	if (status == PEER_ID_SUCCESS)
	{
		if (parse_private_key_proto(privkey_buf, privkey_len, &key_type, &key_data, &key_data_len) < 0)
		{
			status = PEER_ID_E_INVALID_PROTOBUF;
		}
		else if ((key_data == NULL) || (key_data_len == (size_t)0U))
		{
			status = PEER_ID_E_INVALID_PROTOBUF;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		switch (key_type)
		{
		case PEER_ID_RSA_KEY_TYPE:
			derive_status =
				peer_id_create_from_private_key_rsa(key_data, key_data_len, &pubkey_buf, &pubkey_len);
			break;
		case PEER_ID_ED25519_KEY_TYPE:
			derive_status = peer_id_create_from_private_key_ed25519(key_data, key_data_len, &pubkey_buf,
										&pubkey_len);
			break;
		case PEER_ID_SECP256K1_KEY_TYPE:
			derive_status = peer_id_create_from_private_key_secp256k1(key_data, key_data_len, &pubkey_buf,
										  &pubkey_len);
			break;
		case PEER_ID_ECDSA_KEY_TYPE:
			derive_status =
				peer_id_create_from_private_key_ecdsa(key_data, key_data_len, &pubkey_buf, &pubkey_len);
			break;
		default:
			derive_status = PEER_ID_E_UNSUPPORTED_KEY;
			break;
		}

		if (derive_status != PEER_ID_SUCCESS)
		{
			status = derive_status;
		}
		else if ((pubkey_buf == NULL) || (pubkey_len == (size_t)0U))
		{
			status = PEER_ID_E_CRYPTO_FAILED;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		status = peer_id_create_from_public_key(pubkey_buf, pubkey_len, pid);
	}

	if (pubkey_buf != NULL)
	{
		free(pubkey_buf);
	}

	return status;
}

peer_id_error_t peer_id_create_from_string(const char *str, peer_id_t *pid)
{
	peer_id_error_t status;
	multibase_t base;

	status = PEER_ID_SUCCESS;
	base = PEER_ID_MULTIBASE_INVALID;
	if ((str == NULL) || (pid == NULL))
	{
		status = PEER_ID_E_NULL_PTR;
	}
	else
	{
		peer_id_reset_output(pid);
		if (str[0] == '\0')
		{
			status = PEER_ID_E_INVALID_STRING;
		}
	}

	if (status == PEER_ID_SUCCESS)
	{
		base = peer_id_multibase_from_prefix(str[0]);
		if (base != PEER_ID_MULTIBASE_INVALID)
		{
			status = peer_id_decode_cid_string(str, base, pid);
			if (status == PEER_ID_SUCCESS)
			{
				return PEER_ID_SUCCESS;
			}
			if (status != PEER_ID_E_INVALID_STRING)
			{
				return status;
			}
		}

		status = peer_id_decode_legacy_string(str, pid);
	}

	return status;
}

int peer_id_to_string(const peer_id_t *pid, peer_id_format_t format, char *out, size_t out_size)
{
	int result;
	size_t codec_varint_size;
	size_t prefix_size;
	size_t cid_size;
	size_t written;
	uint8_t *cid;
	ptrdiff_t encode_result;

	result = peer_id_to_string_error(PEER_ID_E_ENCODING_FAILED);
	codec_varint_size = (size_t)0U;
	prefix_size = (size_t)0U;
	cid_size = (size_t)0U;
	written = (size_t)0U;
	cid = NULL;
	encode_result = (ptrdiff_t)0;
	if ((pid == NULL) || (out == NULL) || (pid->bytes == NULL))
	{
		result = peer_id_to_string_error(PEER_ID_E_NULL_PTR);
	}
	else if (out_size == (size_t)0U)
	{
		result = peer_id_to_string_error(PEER_ID_E_BUFFER_TOO_SMALL);
	}
	else
	{
		out[0] = '\0';
		if (pid->size == (size_t)0U)
		{
			result = peer_id_to_string_error(PEER_ID_E_INVALID_RANGE);
		}
		else if (format == PEER_ID_FMT_BASE58_LEGACY)
		{
			encode_result = multibase_encode(MULTIBASE_BASE58_BTC, pid->bytes, pid->size, out, out_size);
			if ((encode_result <= 1) || (out[0] != BASE58_BTC_CHARACTER))
			{
				result = peer_id_to_string_error(PEER_ID_E_ENCODING_FAILED);
			}
			else
			{
				(void)memmove(out, out + 1, (size_t)encode_result);
				result = (int)encode_result - 1;
			}
		}
		else if (format == PEER_ID_FMT_MULTIBASE_CIDv1)
		{
			codec_varint_size = unsigned_varint_size((uint64_t)MULTICODEC_LIBP2P_KEY);
			if ((peer_id_size_add((size_t)1U, codec_varint_size, &prefix_size) == 0) ||
			    (peer_id_size_add(prefix_size, pid->size, &cid_size) == 0))
			{
				result = peer_id_to_string_error(PEER_ID_E_INVALID_RANGE);
			}
			else
			{
				cid = (uint8_t *)malloc(cid_size);
				if (cid == NULL)
				{
					result = peer_id_to_string_error(PEER_ID_E_ALLOC_FAILED);
				}
				else
				{
					cid[0] = (uint8_t)MULTICODEC_CIDV1;
					if (unsigned_varint_encode((uint64_t)MULTICODEC_LIBP2P_KEY, cid + 1,
								   codec_varint_size, &written) != UNSIGNED_VARINT_OK)
					{
						result = peer_id_to_string_error(PEER_ID_E_ENCODING_FAILED);
					}
					else
					{
						prefix_size = (size_t)1U + written;
						(void)memcpy(cid + prefix_size, pid->bytes, pid->size);
						encode_result = multibase_encode(
							MULTIBASE_BASE32, cid, prefix_size + pid->size, out, out_size);
						if (encode_result <= 0)
						{
							result = peer_id_to_string_error(PEER_ID_E_ENCODING_FAILED);
						}
						else
						{
							result = (int)encode_result;
						}
					}
				}
			}
		}
		else
		{
			result = peer_id_to_string_error(PEER_ID_E_ENCODING_FAILED);
		}
	}

	if (cid != NULL)
	{
		free(cid);
	}
	if ((result < 0) && (out != NULL) && (out_size > (size_t)0U))
	{
		out[0] = '\0';
	}

	return result;
}

int peer_id_equals(const peer_id_t *a, const peer_id_t *b)
{
	uint8_t diff;
	size_t index;

	if ((a == NULL) || (b == NULL) || (a->bytes == NULL) || (b->bytes == NULL))
	{
		return -1;
	}
	if (a->size != b->size)
	{
		return 0;
	}

	diff = (uint8_t)0U;
	for (index = (size_t)0U; index < a->size; ++index)
	{
		diff = (uint8_t)(diff | (uint8_t)(a->bytes[index] ^ b->bytes[index]));
	}

	return (diff == (uint8_t)0U) ? 1 : 0;
}

void peer_id_destroy(peer_id_t *pid)
{
	if (pid != NULL)
	{
		if (pid->bytes != NULL)
		{
			free(pid->bytes);
			pid->bytes = NULL;
		}
		pid->size = (size_t)0U;
	}
}
