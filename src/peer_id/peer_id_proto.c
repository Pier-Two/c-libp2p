#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id_internal.h"

#define PEER_ID_PROTO_TYPE_TAG ((uint64_t)0x08U)
#define PEER_ID_PROTO_DATA_TAG ((uint64_t)0x12U)

static bool peer_id_size_add(size_t left, size_t right, size_t *sum)
{
	if ((sum == NULL) || (left > (SIZE_MAX - right)))
	{
		return false;
	}
	*sum = left + right;
	return true;
}

static bool peer_id_varint_is_minimal(uint64_t value, size_t decoded_size)
{
	uint8_t encoded[UNSIGNED_VARINT_MAX_ENCODED_SIZE];
	size_t encoded_size;

	encoded_size = (size_t)0U;
	if (unsigned_varint_encode(value, encoded, sizeof(encoded), &encoded_size) != UNSIGNED_VARINT_OK)
	{
		return false;
	}
	return encoded_size == decoded_size;
}

static peer_id_error_t peer_id_parse_key_pb_common(const uint8_t *buf, size_t len, peer_id_proto_view_t *out_view)
{
	peer_id_error_t status;
	unsigned_varint_err_t uv_status;
	size_t offset;
	uint64_t tag;
	size_t tag_size;
	uint64_t key_type_u64;
	size_t key_type_size;
	uint64_t data_len_u64;
	size_t data_len_size;

	status = PEER_ID_OK;
	offset = (size_t)0U;
	tag = (uint64_t)0U;
	tag_size = (size_t)0U;
	key_type_u64 = (uint64_t)0U;
	key_type_size = (size_t)0U;
	data_len_u64 = (uint64_t)0U;
	data_len_size = (size_t)0U;

	if ((buf == NULL) || (out_view == NULL) || (len == (size_t)0U))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	out_view->key_type = PEER_ID_KEY_RSA;
	out_view->key_data = NULL;
	out_view->key_data_len = (size_t)0U;

	uv_status = unsigned_varint_decode(buf + offset, len - offset, &tag, &tag_size);
	if ((uv_status != UNSIGNED_VARINT_OK) || (tag != PEER_ID_PROTO_TYPE_TAG) ||
	    (peer_id_varint_is_minimal(tag, tag_size) == false))
	{
		status = PEER_ID_ERR_INVALID_PROTOBUF;
	}
	else
	{
		offset += tag_size;
	}

	if (status == PEER_ID_OK)
	{
		uv_status = unsigned_varint_decode(buf + offset, len - offset, &key_type_u64, &key_type_size);
		if ((uv_status != UNSIGNED_VARINT_OK) ||
		    (peer_id_varint_is_minimal(key_type_u64, key_type_size) == false) ||
		    (key_type_u64 > (uint64_t)PEER_ID_KEY_ECDSA))
		{
			status = PEER_ID_ERR_INVALID_PROTOBUF;
		}
		else
		{
			offset += key_type_size;
		}
	}

	if (status == PEER_ID_OK)
	{
		uv_status = unsigned_varint_decode(buf + offset, len - offset, &tag, &tag_size);
		if ((uv_status != UNSIGNED_VARINT_OK) || (tag != PEER_ID_PROTO_DATA_TAG) ||
		    (peer_id_varint_is_minimal(tag, tag_size) == false))
		{
			status = PEER_ID_ERR_INVALID_PROTOBUF;
		}
		else
		{
			offset += tag_size;
		}
	}

	if (status == PEER_ID_OK)
	{
		uv_status = unsigned_varint_decode(buf + offset, len - offset, &data_len_u64, &data_len_size);
		if ((uv_status != UNSIGNED_VARINT_OK) ||
		    (peer_id_varint_is_minimal(data_len_u64, data_len_size) == false))
		{
			status = PEER_ID_ERR_INVALID_PROTOBUF;
		}
		else
		{
			offset += data_len_size;
			if ((data_len_u64 == (uint64_t)0U) || (data_len_u64 > (uint64_t)(len - offset)))
			{
				status = PEER_ID_ERR_INVALID_PROTOBUF;
			}
			else
			{
				out_view->key_type = (peer_id_key_type_t)key_type_u64;
				out_view->key_data = buf + offset;
				out_view->key_data_len = (size_t)data_len_u64;
				offset += (size_t)data_len_u64;
				if (offset != len)
				{
					status = PEER_ID_ERR_INVALID_PROTOBUF;
					out_view->key_data = NULL;
					out_view->key_data_len = (size_t)0U;
				}
			}
		}
	}

	return status;
}

peer_id_error_t peer_id_internal_parse_public_key_pb(const uint8_t *buf, size_t len, peer_id_proto_view_t *out_view)
{
	return peer_id_parse_key_pb_common(buf, len, out_view);
}

peer_id_error_t peer_id_internal_parse_private_key_pb(const uint8_t *buf, size_t len, peer_id_proto_view_t *out_view)
{
	return peer_id_parse_key_pb_common(buf, len, out_view);
}

peer_id_error_t peer_id_internal_build_public_key_pb(peer_id_key_type_t type, const uint8_t *raw_key_data,
						     size_t raw_key_len, uint8_t **out_buf, size_t *out_size)
{
	peer_id_error_t status;
	uint64_t raw_key_len_u64;
	uint8_t type_buf[UNSIGNED_VARINT_MAX_ENCODED_SIZE];
	size_t type_size;
	uint8_t len_buf[UNSIGNED_VARINT_MAX_ENCODED_SIZE];
	size_t len_size;
	size_t header_size;
	size_t total_size;
	uint8_t *buf;
	size_t offset;

	status = PEER_ID_OK;
	raw_key_len_u64 = (uint64_t)0U;
	type_size = (size_t)0U;
	len_size = (size_t)0U;
	header_size = (size_t)0U;
	total_size = (size_t)0U;
	buf = NULL;
	offset = (size_t)0U;

	if ((raw_key_data == NULL) || (out_buf == NULL) || (out_size == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*out_buf = NULL;
	*out_size = (size_t)0U;

	if (raw_key_len == (size_t)0U)
	{
		return PEER_ID_ERR_INVALID_INPUT;
	}
	if ((type < PEER_ID_KEY_RSA) || (type > PEER_ID_KEY_ECDSA))
	{
		return PEER_ID_ERR_UNSUPPORTED_KEY;
	}

	raw_key_len_u64 = (uint64_t)raw_key_len;
	if ((size_t)raw_key_len_u64 != raw_key_len)
	{
		return PEER_ID_ERR_RANGE;
	}

	if (unsigned_varint_encode((uint64_t)type, type_buf, sizeof(type_buf), &type_size) != UNSIGNED_VARINT_OK)
	{
		status = PEER_ID_ERR_ENCODING;
	}
	if ((status == PEER_ID_OK) &&
	    (unsigned_varint_encode(raw_key_len_u64, len_buf, sizeof(len_buf), &len_size) != UNSIGNED_VARINT_OK))
	{
		status = PEER_ID_ERR_ENCODING;
	}

	if (status == PEER_ID_OK)
	{
		if ((peer_id_size_add((size_t)1U, type_size, &header_size) == false) ||
		    (peer_id_size_add(header_size, (size_t)1U, &header_size) == false) ||
		    (peer_id_size_add(header_size, len_size, &header_size) == false) ||
		    (peer_id_size_add(header_size, raw_key_len, &total_size) == false))
		{
			status = PEER_ID_ERR_RANGE;
		}
	}

	if (status == PEER_ID_OK)
	{
		buf = (uint8_t *)malloc(total_size);
		if (buf == NULL)
		{
			status = PEER_ID_ERR_ALLOC;
		}
	}

	if (status == PEER_ID_OK)
	{
		buf[offset++] = (uint8_t)PEER_ID_PROTO_TYPE_TAG;
		(void)memcpy(buf + offset, type_buf, type_size);
		offset += type_size;

		buf[offset++] = (uint8_t)PEER_ID_PROTO_DATA_TAG;
		(void)memcpy(buf + offset, len_buf, len_size);
		offset += len_size;

		(void)memcpy(buf + offset, raw_key_data, raw_key_len);
		offset += raw_key_len;

		if (offset != total_size)
		{
			status = PEER_ID_ERR_ENCODING;
		}
	}

	if (status == PEER_ID_OK)
	{
		*out_buf = buf;
		*out_size = total_size;
		buf = NULL;
	}

	if (buf != NULL)
	{
		free(buf);
	}

	return status;
}

/* Back-compat wrappers retained during migration. */
peer_id_error_t peer_id_build_public_key_protobuf(uint64_t key_type, const uint8_t *raw_key_data, size_t raw_key_len,
						  uint8_t **out_buf, size_t *out_size)
{
	if (key_type > (uint64_t)PEER_ID_KEY_ECDSA)
	{
		return PEER_ID_ERR_INVALID_INPUT;
	}
	return peer_id_internal_build_public_key_pb((peer_id_key_type_t)key_type, raw_key_data, raw_key_len, out_buf,
						    out_size);
}

int parse_public_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data,
			   size_t *out_key_data_len)
{
	peer_id_proto_view_t view;
	peer_id_error_t status;

	if ((out_key_type == NULL) || (out_key_data == NULL) || (out_key_data_len == NULL))
	{
		return -1;
	}

	*out_key_type = (uint64_t)0U;
	*out_key_data = NULL;
	*out_key_data_len = (size_t)0U;

	status = peer_id_internal_parse_public_key_pb(buf, len, &view);
	if (status != PEER_ID_OK)
	{
		return -1;
	}

	*out_key_type = (uint64_t)view.key_type;
	*out_key_data = view.key_data;
	*out_key_data_len = view.key_data_len;
	return 0;
}

int parse_private_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data,
			    size_t *out_key_data_len)
{
	peer_id_proto_view_t view;
	peer_id_error_t status;

	if ((out_key_type == NULL) || (out_key_data == NULL) || (out_key_data_len == NULL))
	{
		return -1;
	}

	*out_key_type = (uint64_t)0U;
	*out_key_data = NULL;
	*out_key_data_len = (size_t)0U;

	status = peer_id_internal_parse_private_key_pb(buf, len, &view);
	if (status != PEER_ID_OK)
	{
		return -1;
	}

	*out_key_type = (uint64_t)view.key_type;
	*out_key_data = view.key_data;
	*out_key_data_len = view.key_data_len;
	return 0;
}
