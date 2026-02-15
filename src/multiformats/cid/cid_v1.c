#include "multiformats/cid/cid_v1.h"

#include <stddef.h>
#include <stdint.h>
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
#include "multiformats/unsigned_varint/unsigned_varint.h"

static void cid_v1_zero_memory(uint8_t *bytes, size_t len)
{
	size_t index;

	if (bytes != NULL)
	{
		for (index = 0U; index < len; ++index)
		{
			bytes[index] = (uint8_t)0U;
		}
	}
}

static void cid_v1_copy_bytes(uint8_t *dst, const uint8_t *src, size_t len)
{
	size_t index;

	for (index = 0U; index < len; ++index)
	{
		dst[index] = src[index];
	}
}

static void cid_v1_reset_internal(cid_v1_t *cid)
{
	if (cid != NULL)
	{
		cid->version = (uint64_t)0U;
		cid->codec = (uint64_t)0U;
		cid_v1_zero_memory(cid->multihash_storage, sizeof(cid->multihash_storage));
		cid->multihash = NULL;
		cid->multihash_size = (size_t)0U;
	}
}

static int cid_v1_read_string_length(const char *str, size_t max_len, size_t *len_out)
{
	int status;
	size_t index;

	status = (int)CIDV1_SUCCESS;
	index = (size_t)0U;
	if ((str == NULL) || (len_out == NULL))
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		while ((index < max_len) && (str[index] != '\0'))
		{
			++index;
		}
		if (index == max_len)
		{
			status = (int)CIDV1_ERROR_INVALID_ARG;
		}
		else
		{
			*len_out = index;
		}
	}

	return status;
}

static int cid_v1_add_overflow(size_t a, size_t b, size_t *out)
{
	int overflow;

	overflow = 0;
	if (out == NULL)
	{
		overflow = 1;
	}
	else if (a > (SIZE_MAX - b))
	{
		overflow = 1;
	}
	else
	{
		*out = a + b;
	}

	return overflow;
}

static int cid_v1_map_varint_decode_error(unsigned_varint_err_t error)
{
	int status;

	status = (int)CIDV1_ERROR_DECODE_FAILURE;
	if (error == UNSIGNED_VARINT_ERR_NULL_PTR)
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else if (error == UNSIGNED_VARINT_ERR_EMPTY_INPUT)
	{
		status = (int)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		/* keep decode failure */
	}

	return status;
}

static int cid_v1_map_varint_encode_error(unsigned_varint_err_t error)
{
	int status;

	status = (int)CIDV1_ERROR_ENCODE_FAILURE;
	if (error == UNSIGNED_VARINT_ERR_NULL_PTR)
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else if (error == UNSIGNED_VARINT_ERR_BUFFER_OVER)
	{
		status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
	}
	else if (error == UNSIGNED_VARINT_ERR_VALUE_OVERFLOW)
	{
		status = (int)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		/* keep encode failure */
	}

	return status;
}

static int cid_v1_map_multibase_encode_error(multibase_error_t mb_error)
{
	int status;

	status = (int)CIDV1_ERROR_ENCODE_FAILURE;
	if (mb_error == MULTIBASE_ERR_NULL_POINTER)
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else if (mb_error == MULTIBASE_ERR_BUFFER_TOO_SMALL)
	{
		status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
	}
	else if (mb_error == MULTIBASE_ERR_UNSUPPORTED_BASE)
	{
		status = (int)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		/* keep encode failure */
	}

	return status;
}

static int cid_v1_map_multibase_decode_error(multibase_error_t mb_error)
{
	int status;

	status = (int)CIDV1_ERROR_DECODE_FAILURE;
	if (mb_error == MULTIBASE_ERR_NULL_POINTER)
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else if ((mb_error == MULTIBASE_ERR_BUFFER_TOO_SMALL) || (mb_error == MULTIBASE_ERR_INVALID_INPUT_LEN))
	{
		status = (int)CIDV1_ERROR_INVALID_ARG;
	}
	else if (mb_error == MULTIBASE_ERR_UNSUPPORTED_BASE)
	{
		status = (int)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		/* keep decode failure */
	}

	return status;
}

static int cid_v1_detect_multibase(const char *str, multibase_t *base_out)
{
	int status;

	status = (int)CIDV1_SUCCESS;
	if ((str == NULL) || (base_out == NULL) || (str[0] == '\0'))
	{
		status = (int)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		switch (str[0])
		{
		case BASE58_BTC_CHARACTER:
			*base_out = MULTIBASE_BASE58_BTC;
			break;
		case BASE16_CHARACTER:
			*base_out = MULTIBASE_BASE16;
			break;
		case BASE16_UPPER_CHARACTER:
			*base_out = MULTIBASE_BASE16_UPPER;
			break;
		case BASE32_CHARACTER:
			*base_out = MULTIBASE_BASE32;
			break;
		case BASE32_UPPER_CHARACTER:
			*base_out = MULTIBASE_BASE32_UPPER;
			break;
		case BASE64_CHARACTER:
			*base_out = MULTIBASE_BASE64;
			break;
		case BASE64_URL_CHARACTER:
			*base_out = MULTIBASE_BASE64_URL;
			break;
		case BASE64_URL_PAD_CHARACTER:
			*base_out = MULTIBASE_BASE64_URL_PAD;
			break;
		default:
			status = (int)CIDV1_ERROR_DECODE_FAILURE;
			break;
		}
	}

	return status;
}

static const char *cid_v1_get_multibase_name(multibase_t base)
{
	const char *name;

	name = "unknown";
	switch (base)
	{
	case MULTIBASE_BASE16:
		name = "base16";
		break;
	case MULTIBASE_BASE16_UPPER:
		name = "base16upper";
		break;
	case MULTIBASE_BASE32:
		name = "base32";
		break;
	case MULTIBASE_BASE32_UPPER:
		name = "base32upper";
		break;
	case MULTIBASE_BASE58_BTC:
		name = "base58btc";
		break;
	case MULTIBASE_BASE64:
		name = "base64";
		break;
	case MULTIBASE_BASE64_URL:
		name = "base64url";
		break;
	case MULTIBASE_BASE64_URL_PAD:
		name = "base64urlpad";
		break;
	default:
		break;
	}

	return name;
}

static const char *cid_v1_get_codec_name(uint64_t codec)
{
	const char *name;

	name = "unknown";
	if (codec == CIDV1_CODEC_RAW)
	{
		name = "raw";
	}
	else if (codec == CIDV1_CODEC_DAG_PB)
	{
		name = "dag_pb";
	}
	else
	{
		/* keep unknown */
	}

	return name;
}

static const char *cid_v1_get_multihash_name(uint64_t hash_code)
{
	const char *name;

	name = "unknown";
	switch (hash_code)
	{
	case CIDV1_MH_CODE_IDENTITY:
		name = "identity";
		break;
	case CIDV1_MH_CODE_SHA2_256:
		name = "sha2_256";
		break;
	case CIDV1_MH_CODE_SHA2_512:
		name = "sha2_512";
		break;
	case CIDV1_MH_CODE_SHA3_512:
		name = "sha3_512";
		break;
	case CIDV1_MH_CODE_SHA3_384:
		name = "sha3_384";
		break;
	case CIDV1_MH_CODE_SHA3_256:
		name = "sha3_256";
		break;
	case CIDV1_MH_CODE_SHA3_224:
		name = "sha3_224";
		break;
	default:
		break;
	}

	return name;
}

static int cid_v1_parse_multihash(const uint8_t *mh, size_t mh_size, uint64_t *hash_code, size_t *digest_offset,
				  size_t *digest_len)
{
	int status;
	uint64_t local_hash_code;
	uint64_t local_digest_len;
	size_t hash_read;
	size_t digest_len_read;
	size_t header_size;

	status = (int)CIDV1_SUCCESS;
	local_hash_code = (uint64_t)0U;
	local_digest_len = (uint64_t)0U;
	hash_read = (size_t)0U;
	digest_len_read = (size_t)0U;
	header_size = (size_t)0U;
	if ((mh == NULL) || (hash_code == NULL) || (digest_offset == NULL) || (digest_len == NULL))
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		*hash_code = (uint64_t)0U;
		*digest_offset = (size_t)0U;
		*digest_len = (size_t)0U;
		if ((mh_size == 0U) || (mh_size > CIDV1_MAX_MULTIHASH_SIZE))
		{
			status = (int)CIDV1_ERROR_INVALID_ARG;
		}
		else
		{
			unsigned_varint_err_t varint_error;

			varint_error = unsigned_varint_decode(mh, mh_size, &local_hash_code, &hash_read);
			if (varint_error != UNSIGNED_VARINT_OK)
			{
				status = cid_v1_map_varint_decode_error(varint_error);
			}
			else if (hash_read > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
			{
				status = (int)CIDV1_ERROR_DECODE_FAILURE;
			}
			else if (hash_read >= mh_size)
			{
				status = (int)CIDV1_ERROR_DECODE_FAILURE;
			}
			else
			{
				varint_error = unsigned_varint_decode(&mh[hash_read], mh_size - hash_read,
								      &local_digest_len, &digest_len_read);
				if (varint_error != UNSIGNED_VARINT_OK)
				{
					status = cid_v1_map_varint_decode_error(varint_error);
				}
				else if (digest_len_read > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else if (cid_v1_add_overflow(hash_read, digest_len_read, &header_size) != 0)
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else if (header_size > mh_size)
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else if (local_digest_len > (uint64_t)(mh_size - header_size))
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else if (local_digest_len != (uint64_t)(mh_size - header_size))
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else
				{
					*hash_code = local_hash_code;
					*digest_offset = header_size;
					*digest_len = (size_t)local_digest_len;
				}
			}
		}
	}

	return status;
}

static int cid_v1_reserve_text(size_t out_len, size_t offset, size_t needed)
{
	int status;

	status = (int)CIDV1_SUCCESS;
	if ((out_len == 0U) || (offset >= out_len))
	{
		status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
	}
	else if (needed > ((out_len - offset) - 1U))
	{
		status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
	}
	else
	{
		/* keep success */
	}

	return status;
}

static int cid_v1_append_text(char *out, size_t out_len, size_t *offset, const char *text)
{
	int status;
	size_t text_len;
	size_t index;

	status = (int)CIDV1_SUCCESS;
	text_len = 0U;
	if ((out == NULL) || (offset == NULL) || (text == NULL))
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		text_len = strlen(text);
		status = cid_v1_reserve_text(out_len, *offset, text_len);
		if (status == (int)CIDV1_SUCCESS)
		{
			for (index = 0U; index < text_len; ++index)
			{
				out[*offset + index] = text[index];
			}
			*offset += text_len;
		}
	}

	return status;
}

static int cid_v1_append_hex(char *out, size_t out_len, size_t *offset, const uint8_t *bytes, size_t bytes_len)
{
	int status;
	size_t needed;
	size_t index;
	static const char hex_table[] = "0123456789abcdef";

	status = (int)CIDV1_SUCCESS;
	needed = (size_t)0U;
	if ((out == NULL) || (offset == NULL) || (bytes == NULL))
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else if (cid_v1_add_overflow(bytes_len, bytes_len, &needed) != 0)
	{
		status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
	}
	else
	{
		status = cid_v1_reserve_text(out_len, *offset, needed);
		if (status == (int)CIDV1_SUCCESS)
		{
			for (index = 0U; index < bytes_len; ++index)
			{
				uint8_t value;

				value = bytes[index];
				out[*offset + (index * 2U)] = hex_table[(value >> 4U) & 0x0FU];
				out[*offset + (index * 2U) + 1U] = hex_table[value & 0x0FU];
			}
			*offset += needed;
		}
	}

	return status;
}

int cid_v1_init(cid_v1_t *cid, uint64_t content_codec, const uint8_t *mh_data, size_t mh_size)
{
	int status;
	uint64_t hash_code;
	size_t digest_offset;
	size_t digest_len;

	status = (int)CIDV1_SUCCESS;
	hash_code = (uint64_t)0U;
	digest_offset = (size_t)0U;
	digest_len = (size_t)0U;
	if ((cid == NULL) || (mh_data == NULL))
	{
		status = (int)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		cid_v1_reset_internal(cid);
		if (content_codec > UNSIGNED_VARINT_MAX_VALUE)
		{
			status = (int)CIDV1_ERROR_INVALID_ARG;
		}
		else if ((mh_size == 0U) || (mh_size > CIDV1_MAX_MULTIHASH_SIZE))
		{
			status = (int)CIDV1_ERROR_INVALID_ARG;
		}
		else
		{
			status = cid_v1_parse_multihash(mh_data, mh_size, &hash_code, &digest_offset, &digest_len);
			if (status == (int)CIDV1_SUCCESS)
			{
				(void)hash_code;
				(void)digest_offset;
				(void)digest_len;
				cid->version = CIDV1_VERSION;
				cid->codec = content_codec;
				cid_v1_copy_bytes(cid->multihash_storage, mh_data, mh_size);
				cid->multihash = cid->multihash_storage;
				cid->multihash_size = mh_size;
			}
		}
	}

	return status;
}

void cid_v1_free(cid_v1_t *cid)
{
	cid_v1_reset_internal(cid);
}

ptrdiff_t cid_v1_from_bytes(cid_v1_t *cid, const uint8_t *data, size_t data_len)
{
	ptrdiff_t result;
	int status;
	uint64_t version;
	uint64_t codec;
	size_t version_read;
	size_t codec_read;
	size_t mh_offset;
	size_t mh_size;
	uint64_t hash_code;
	size_t digest_offset;
	size_t digest_len;

	result = (ptrdiff_t)CIDV1_ERROR_DECODE_FAILURE;
	status = (int)CIDV1_SUCCESS;
	version = (uint64_t)0U;
	codec = (uint64_t)0U;
	version_read = (size_t)0U;
	codec_read = (size_t)0U;
	mh_offset = (size_t)0U;
	mh_size = (size_t)0U;
	hash_code = (uint64_t)0U;
	digest_offset = (size_t)0U;
	digest_len = (size_t)0U;
	if ((cid == NULL) || (data == NULL))
	{
		result = (ptrdiff_t)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		unsigned_varint_err_t varint_error;

		cid_v1_reset_internal(cid);
		if (data_len == 0U)
		{
			status = (int)CIDV1_ERROR_INVALID_ARG;
		}
		else
		{
			varint_error = unsigned_varint_decode(data, data_len, &version, &version_read);
			if (varint_error != UNSIGNED_VARINT_OK)
			{
				status = cid_v1_map_varint_decode_error(varint_error);
			}
			else if (version_read > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
			{
				status = (int)CIDV1_ERROR_DECODE_FAILURE;
			}
			else if (version != CIDV1_VERSION)
			{
				status = (int)CIDV1_ERROR_DECODE_FAILURE;
			}
			else if (version_read >= data_len)
			{
				status = (int)CIDV1_ERROR_INVALID_ARG;
			}
			else
			{
				varint_error = unsigned_varint_decode(&data[version_read], data_len - version_read,
								      &codec, &codec_read);
				if (varint_error != UNSIGNED_VARINT_OK)
				{
					status = cid_v1_map_varint_decode_error(varint_error);
				}
				else if (codec_read > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else if (cid_v1_add_overflow(version_read, codec_read, &mh_offset) != 0)
				{
					status = (int)CIDV1_ERROR_DECODE_FAILURE;
				}
				else if (mh_offset >= data_len)
				{
					status = (int)CIDV1_ERROR_INVALID_ARG;
				}
				else
				{
					mh_size = data_len - mh_offset;
					status = cid_v1_parse_multihash(&data[mh_offset], mh_size, &hash_code,
									&digest_offset, &digest_len);
					if (status == (int)CIDV1_SUCCESS)
					{
						(void)hash_code;
						(void)digest_offset;
						(void)digest_len;
						cid->version = version;
						cid->codec = codec;
						cid_v1_copy_bytes(cid->multihash_storage, &data[mh_offset], mh_size);
						cid->multihash = cid->multihash_storage;
						cid->multihash_size = mh_size;
					}
				}
			}
		}

		if (status == (int)CIDV1_SUCCESS)
		{
			result = (ptrdiff_t)data_len;
		}
		else
		{
			result = (ptrdiff_t)status;
		}
	}

	return result;
}

ptrdiff_t cid_v1_to_bytes(const cid_v1_t *cid, uint8_t *out, size_t out_len)
{
	ptrdiff_t result;
	int status;
	size_t offset;
	size_t written;
	size_t total_size;
	uint64_t hash_code;
	size_t digest_offset;
	size_t digest_len;

	result = (ptrdiff_t)CIDV1_ERROR_ENCODE_FAILURE;
	status = (int)CIDV1_SUCCESS;
	offset = (size_t)0U;
	written = (size_t)0U;
	total_size = (size_t)0U;
	hash_code = (uint64_t)0U;
	digest_offset = (size_t)0U;
	digest_len = (size_t)0U;
	if ((cid == NULL) || (out == NULL))
	{
		result = (ptrdiff_t)CIDV1_ERROR_NULL_POINTER;
	}
	else if (cid->version != CIDV1_VERSION)
	{
		result = (ptrdiff_t)CIDV1_ERROR_INVALID_ARG;
	}
	else if ((cid->multihash == NULL) || (cid->multihash_size == 0U) ||
		 (cid->multihash_size > CIDV1_MAX_MULTIHASH_SIZE))
	{
		result = (ptrdiff_t)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		status = cid_v1_parse_multihash(cid->multihash, cid->multihash_size, &hash_code, &digest_offset,
						&digest_len);
		if (status == (int)CIDV1_SUCCESS)
		{
			(void)hash_code;
			(void)digest_offset;
			(void)digest_len;
			{
				unsigned_varint_err_t varint_error;

				varint_error = unsigned_varint_encode(cid->version, out, out_len, &written);
				if (varint_error != UNSIGNED_VARINT_OK)
				{
					status = cid_v1_map_varint_encode_error(varint_error);
				}
				else if (written > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
				{
					status = (int)CIDV1_ERROR_ENCODE_FAILURE;
				}
				else
				{
					offset = written;
					varint_error = unsigned_varint_encode(cid->codec, &out[offset],
									      out_len - offset, &written);
					if (varint_error != UNSIGNED_VARINT_OK)
					{
						status = cid_v1_map_varint_encode_error(varint_error);
					}
					else if (written > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
					{
						status = (int)CIDV1_ERROR_ENCODE_FAILURE;
					}
					else
					{
						offset += written;
					}
				}
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				if (offset > out_len)
				{
					status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
				}
				else if (cid->multihash_size > (out_len - offset))
				{
					status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
				}
				else if (cid_v1_add_overflow(offset, cid->multihash_size, &total_size) != 0)
				{
					status = (int)CIDV1_ERROR_BUFFER_TOO_SMALL;
				}
				else
				{
					cid_v1_copy_bytes(&out[offset], cid->multihash, cid->multihash_size);
				}
			}
		}

		if (status == (int)CIDV1_SUCCESS)
		{
			result = (ptrdiff_t)total_size;
		}
		else
		{
			result = (ptrdiff_t)status;
		}
	}

	return result;
}

ptrdiff_t cid_v1_to_string(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len)
{
	ptrdiff_t result;
	ptrdiff_t binary_len;
	uint8_t binary[CIDV1_MAX_BINARY_SIZE];

	result = (ptrdiff_t)CIDV1_ERROR_ENCODE_FAILURE;
	if (out != NULL)
	{
		if (out_len > 0U)
		{
			out[0] = '\0';
		}
	}
	if ((cid == NULL) || (out == NULL))
	{
		result = (ptrdiff_t)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		binary_len = cid_v1_to_bytes(cid, binary, sizeof(binary));
		if (binary_len < 0)
		{
			result = binary_len;
		}
		else
		{
			ptrdiff_t mb_written;

			mb_written = multibase_encode(base, binary, (size_t)binary_len, out, out_len);
			if (mb_written < 0)
			{
				result = (ptrdiff_t)cid_v1_map_multibase_encode_error((multibase_error_t)mb_written);
			}
			else
			{
				result = mb_written;
			}
		}
	}

	return result;
}

ptrdiff_t cid_v1_from_string(cid_v1_t *cid, const char *str)
{
	ptrdiff_t result;
	int status;
	multibase_t base;
	size_t str_len;
	uint8_t binary[CIDV1_MAX_BINARY_SIZE];
	ptrdiff_t decoded_len;
	ptrdiff_t parsed_len;

	result = (ptrdiff_t)CIDV1_ERROR_DECODE_FAILURE;
	status = (int)CIDV1_SUCCESS;
	base = MULTIBASE_BASE58_BTC;
	str_len = (size_t)0U;
	decoded_len = (ptrdiff_t)0;
	parsed_len = (ptrdiff_t)0;
	if ((cid == NULL) || (str == NULL))
	{
		result = (ptrdiff_t)CIDV1_ERROR_NULL_POINTER;
	}
	else
	{
		cid_v1_reset_internal(cid);
		status = cid_v1_read_string_length(str, CIDV1_MAX_STRING_LENGTH + 1U, &str_len);
		if (status != (int)CIDV1_SUCCESS)
		{
			/* invalid argument state already set by bounded length check */
		}
		else if (str_len == 0U)
		{
			status = (int)CIDV1_ERROR_INVALID_ARG;
		}
		else
		{
			status = cid_v1_detect_multibase(str, &base);
			if (status == (int)CIDV1_SUCCESS)
			{
				decoded_len = multibase_decode(base, str, binary, sizeof(binary));
				if (decoded_len < 0)
				{
					status = cid_v1_map_multibase_decode_error((multibase_error_t)decoded_len);
				}
				else
				{
					parsed_len = cid_v1_from_bytes(cid, binary, (size_t)decoded_len);
					if (parsed_len < 0)
					{
						status = (int)parsed_len;
					}
				}
			}
		}

		if (status == (int)CIDV1_SUCCESS)
		{
			if (str_len > (size_t)PTRDIFF_MAX)
			{
				result = (ptrdiff_t)CIDV1_ERROR_INVALID_ARG;
			}
			else
			{
				result = (ptrdiff_t)str_len;
			}
		}
		else
		{
			result = (ptrdiff_t)status;
		}
	}

	return result;
}

ptrdiff_t cid_v1_to_human(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len)
{
	ptrdiff_t result;
	int status;
	size_t offset;
	uint64_t hash_code;
	size_t digest_offset;
	size_t digest_len;
	const char *base_name;
	const char *codec_name;
	const char *hash_name;

	result = (ptrdiff_t)CIDV1_ERROR_ENCODE_FAILURE;
	status = (int)CIDV1_SUCCESS;
	offset = (size_t)0U;
	hash_code = (uint64_t)0U;
	digest_offset = (size_t)0U;
	digest_len = (size_t)0U;
	base_name = "unknown";
	codec_name = "unknown";
	hash_name = "unknown";
	if (out != NULL)
	{
		if (out_len > 0U)
		{
			out[0] = '\0';
		}
	}
	if ((cid == NULL) || (out == NULL))
	{
		result = (ptrdiff_t)CIDV1_ERROR_NULL_POINTER;
	}
	else if (cid->version != CIDV1_VERSION)
	{
		result = (ptrdiff_t)CIDV1_ERROR_INVALID_ARG;
	}
	else if ((cid->multihash == NULL) || (cid->multihash_size == 0U))
	{
		result = (ptrdiff_t)CIDV1_ERROR_INVALID_ARG;
	}
	else
	{
		status = cid_v1_parse_multihash(cid->multihash, cid->multihash_size, &hash_code, &digest_offset,
						&digest_len);
		if (status == (int)CIDV1_SUCCESS)
		{
			base_name = cid_v1_get_multibase_name(base);
			codec_name = cid_v1_get_codec_name(cid->codec);
			hash_name = cid_v1_get_multihash_name(hash_code);

			status = cid_v1_append_text(out, out_len, &offset, base_name);
			if (status == (int)CIDV1_SUCCESS)
			{
				status = cid_v1_append_text(out, out_len, &offset, " - cidv1 - ");
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				status = cid_v1_append_text(out, out_len, &offset, codec_name);
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				status = cid_v1_append_text(out, out_len, &offset, " - ");
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				status = cid_v1_append_text(out, out_len, &offset, hash_name);
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				status = cid_v1_append_text(out, out_len, &offset, "-");
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				status = cid_v1_append_hex(out, out_len, &offset, &cid->multihash[digest_offset],
							   digest_len);
			}
			if (status == (int)CIDV1_SUCCESS)
			{
				out[offset] = '\0';
			}
		}

		if (status == (int)CIDV1_SUCCESS)
		{
			result = (ptrdiff_t)offset;
		}
		else
		{
			result = (ptrdiff_t)status;
		}
	}

	return result;
}
