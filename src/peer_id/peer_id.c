#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id_internal.h"

#define PEER_ID_IDENTITY_MAX_PUBLIC_KEY_PB ((size_t)42U)

static bool peer_id_size_add(size_t left, size_t right, size_t *sum)
{
	if ((sum == NULL) || (left > (SIZE_MAX - right)))
	{
		return false;
	}
	*sum = left + right;
	return true;
}

static int peer_id_is_supported_multihash_code(uint64_t hash_code)
{
	return (hash_code == MULTIHASH_CODE_IDENTITY) || (hash_code == MULTIHASH_CODE_SHA2_256);
}

static peer_id_error_t peer_id_map_multihash_error(int rc)
{
	switch (rc)
	{
	case MULTIHASH_ERR_NULL_POINTER:
		return PEER_ID_ERR_NULL_PTR;
	case MULTIHASH_ERR_INVALID_INPUT:
		return PEER_ID_ERR_INVALID_INPUT;
	case MULTIHASH_ERR_UNSUPPORTED_FUN:
		return PEER_ID_ERR_UNSUPPORTED_KEY;
	case MULTIHASH_ERR_DIGEST_TOO_LARGE:
		return PEER_ID_ERR_RANGE;
	case MULTIHASH_ERR_ALLOC_FAILURE:
		return PEER_ID_ERR_ALLOC;
	default:
		return PEER_ID_ERR_CRYPTO;
	}
}

static peer_id_error_t peer_id_alloc(size_t mh_len, peer_id_t **out)
{
	peer_id_t *pid;

	if ((out == NULL) || (mh_len == (size_t)0U))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*out = NULL;

	pid = (peer_id_t *)calloc(1, sizeof(*pid));
	if (pid == NULL)
	{
		return PEER_ID_ERR_ALLOC;
	}

	pid->multihash = (uint8_t *)malloc(mh_len);
	if (pid->multihash == NULL)
	{
		free(pid);
		return PEER_ID_ERR_ALLOC;
	}

	pid->multihash_len = mh_len;
	*out = pid;
	return PEER_ID_OK;
}

peer_id_error_t peer_id_internal_validate_multihash(const uint8_t *mh, size_t mh_len)
{
	peer_id_error_t status;
	uint64_t hash_code;
	size_t hash_code_size;
	uint64_t digest_len_u64;
	size_t digest_len_size;
	size_t payload_left;
	unsigned_varint_err_t uv_status;

	status = PEER_ID_OK;
	hash_code = (uint64_t)0U;
	hash_code_size = (size_t)0U;
	digest_len_u64 = (uint64_t)0U;
	digest_len_size = (size_t)0U;
	payload_left = (size_t)0U;

	if ((mh == NULL) || (mh_len == (size_t)0U))
	{
		return PEER_ID_ERR_INVALID_STRING;
	}

	uv_status = unsigned_varint_decode(mh, mh_len, &hash_code, &hash_code_size);
	if ((uv_status != UNSIGNED_VARINT_OK) || (hash_code_size >= mh_len) ||
	    (peer_id_is_supported_multihash_code(hash_code) == 0))
	{
		status = PEER_ID_ERR_INVALID_STRING;
	}

	if (status == PEER_ID_OK)
	{
		payload_left = mh_len - hash_code_size;
		uv_status =
			unsigned_varint_decode(mh + hash_code_size, payload_left, &digest_len_u64, &digest_len_size);
		if ((uv_status != UNSIGNED_VARINT_OK) || (digest_len_size >= payload_left))
		{
			status = PEER_ID_ERR_INVALID_STRING;
		}
		else if (digest_len_u64 > (uint64_t)(payload_left - digest_len_size))
		{
			status = PEER_ID_ERR_INVALID_STRING;
		}
		else if ((hash_code == MULTIHASH_CODE_SHA2_256) && (digest_len_u64 != (uint64_t)32U))
		{
			status = PEER_ID_ERR_INVALID_STRING;
		}
	}

	if (status == PEER_ID_OK)
	{
		size_t payload_offset;
		size_t expected_size;

		payload_offset = hash_code_size + digest_len_size;
		if ((digest_len_u64 > (uint64_t)SIZE_MAX) || (payload_offset > mh_len))
		{
			status = PEER_ID_ERR_INVALID_STRING;
		}
		else
		{
			expected_size = payload_offset + (size_t)digest_len_u64;
			if (expected_size != mh_len)
			{
				status = PEER_ID_ERR_INVALID_STRING;
			}
		}
	}

	return status;
}

peer_id_error_t peer_id_new_from_multihash(const uint8_t *mh, size_t mh_len, peer_id_t **out)
{
	peer_id_error_t status;
	peer_id_t *pid;

	status = PEER_ID_OK;
	pid = NULL;

	if (out == NULL)
	{
		return PEER_ID_ERR_NULL_PTR;
	}
	*out = NULL;

	status = peer_id_internal_validate_multihash(mh, mh_len);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	status = peer_id_alloc(mh_len, &pid);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	(void)memcpy(pid->multihash, mh, mh_len);
	*out = pid;
	return PEER_ID_OK;
}

peer_id_error_t peer_id_new_from_public_key_pb(const uint8_t *pb, size_t pb_len, peer_id_t **out)
{
	peer_id_error_t status;
	peer_id_proto_view_t view;
	uint64_t hash_code;
	size_t digest_len;
	size_t mh_len;
	uint8_t *mh;
	int rc;

	status = PEER_ID_OK;
	view.key_type = PEER_ID_KEY_RSA;
	view.key_data = NULL;
	view.key_data_len = (size_t)0U;
	hash_code = (uint64_t)0U;
	digest_len = (size_t)0U;
	mh_len = (size_t)0U;
	mh = NULL;
	rc = 0;

	if ((pb == NULL) || (out == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*out = NULL;

	status = peer_id_internal_parse_public_key_pb(pb, pb_len, &view);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	if (pb_len <= PEER_ID_IDENTITY_MAX_PUBLIC_KEY_PB)
	{
		hash_code = MULTIHASH_CODE_IDENTITY;
		digest_len = pb_len;
	}
	else
	{
		hash_code = MULTIHASH_CODE_SHA2_256;
		digest_len = (size_t)32U;
	}

	if ((peer_id_size_add(unsigned_varint_size(hash_code), unsigned_varint_size((uint64_t)digest_len), &mh_len) ==
	     false) ||
	    (peer_id_size_add(mh_len, digest_len, &mh_len) == false))
	{
		return PEER_ID_ERR_RANGE;
	}

	mh = (uint8_t *)malloc(mh_len);
	if (mh == NULL)
	{
		return PEER_ID_ERR_ALLOC;
	}

	rc = multihash_encode(hash_code, pb, pb_len, mh, mh_len);
	if (rc <= 0)
	{
		status = peer_id_map_multihash_error(rc);
	}
	else if ((size_t)rc > mh_len)
	{
		status = PEER_ID_ERR_ENCODING;
	}
	else
	{
		status = peer_id_new_from_multihash(mh, (size_t)rc, out);
	}

	free(mh);
	return status;
}

peer_id_error_t peer_id_new_from_private_key_pb(const uint8_t *pb, size_t pb_len, peer_id_t **out)
{
	peer_id_error_t status;
	peer_id_proto_view_t view;
	uint8_t *pub_pb;
	size_t pub_pb_len;

	status = PEER_ID_OK;
	view.key_type = PEER_ID_KEY_RSA;
	view.key_data = NULL;
	view.key_data_len = (size_t)0U;
	pub_pb = NULL;
	pub_pb_len = (size_t)0U;

	if ((pb == NULL) || (out == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}
	*out = NULL;

	status = peer_id_internal_parse_private_key_pb(pb, pb_len, &view);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	status = peer_id_internal_keyops_public_from_private_raw(view.key_type, view.key_data, view.key_data_len,
								 &pub_pb, &pub_pb_len);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	status = peer_id_new_from_public_key_pb(pub_pb, pub_pb_len, out);
	free(pub_pb);
	return status;
}

peer_id_error_t peer_id_new_from_text(const char *text, peer_id_t **out)
{
	return peer_id_internal_text_parse(text, out);
}

void peer_id_free(peer_id_t *pid)
{
	if (pid != NULL)
	{
		if (pid->multihash != NULL)
		{
			free(pid->multihash);
			pid->multihash = NULL;
		}
		pid->multihash_len = (size_t)0U;
		free(pid);
	}
}

peer_id_error_t peer_id_clone(const peer_id_t *src, peer_id_t **out)
{
	peer_id_t *dup;
	peer_id_error_t status;

	dup = NULL;
	status = PEER_ID_OK;

	if ((src == NULL) || (out == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}
	*out = NULL;

	if ((src->multihash == NULL) || (src->multihash_len == (size_t)0U))
	{
		return PEER_ID_ERR_INVALID_INPUT;
	}

	status = peer_id_alloc(src->multihash_len, &dup);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	(void)memcpy(dup->multihash, src->multihash, src->multihash_len);
	*out = dup;
	return PEER_ID_OK;
}

peer_id_error_t peer_id_multihash_view(const peer_id_t *pid, const uint8_t **bytes, size_t *len)
{
	if ((pid == NULL) || (bytes == NULL) || (len == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	if ((pid->multihash == NULL) || (pid->multihash_len == (size_t)0U))
	{
		*bytes = NULL;
		*len = (size_t)0U;
		return PEER_ID_ERR_INVALID_INPUT;
	}

	*bytes = pid->multihash;
	*len = pid->multihash_len;
	return PEER_ID_OK;
}

peer_id_error_t peer_id_multihash_copy(const peer_id_t *pid, uint8_t *out, size_t out_cap, size_t *out_len)
{
	const uint8_t *bytes;
	size_t len;
	peer_id_error_t status;

	bytes = NULL;
	len = (size_t)0U;

	if (out_len != NULL)
	{
		*out_len = (size_t)0U;
	}

	status = peer_id_multihash_view(pid, &bytes, &len);
	if (status != PEER_ID_OK)
	{
		return status;
	}

	if ((out == NULL) || (out_len == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	if (out_cap < len)
	{
		return PEER_ID_ERR_BUFFER_TOO_SMALL;
	}

	(void)memcpy(out, bytes, len);
	*out_len = len;
	return PEER_ID_OK;
}

int peer_id_equal(const peer_id_t *a, const peer_id_t *b)
{
	uint8_t diff;
	size_t idx;

	if ((a == NULL) || (b == NULL) || (a->multihash == NULL) || (b->multihash == NULL))
	{
		return -1;
	}

	if (a->multihash_len != b->multihash_len)
	{
		return 0;
	}

	diff = (uint8_t)0U;
	for (idx = (size_t)0U; idx < a->multihash_len; ++idx)
	{
		diff = (uint8_t)(diff | (uint8_t)(a->multihash[idx] ^ b->multihash[idx]));
	}

	return (diff == (uint8_t)0U) ? 1 : 0;
}

peer_id_error_t peer_id_text_write(const peer_id_t *pid, peer_id_text_format_t fmt, char *out, size_t out_cap,
				   size_t *out_len)
{
	peer_id_error_t status;

	status = peer_id_internal_text_write(pid, fmt, out, out_cap, out_len);
	if ((status != PEER_ID_OK) && (out != NULL) && (out_cap > (size_t)0U))
	{
		out[0] = '\0';
	}
	return status;
}

peer_id_error_t peer_id_text_write_default(const peer_id_t *pid, char *out, size_t out_cap, size_t *out_len)
{
	return peer_id_text_write(pid, PEER_ID_TEXT_LEGACY_BASE58, out, out_cap, out_len);
}
