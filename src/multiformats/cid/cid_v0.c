#include "multiformats/cid/cid_v0.h"

#include <string.h>

#include "multiformats/multibase/encoding/base58_btc.h"

static void cid_v0_reset(cid_v0_t *cid)
{
	size_t index;

	if (cid != NULL)
	{
		for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
		{
			cid->hash[index] = (uint8_t)0U;
		}
	}
}

static void cid_v0_copy_hash(uint8_t *out, const uint8_t *in)
{
	size_t index;

	for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
	{
		out[index] = in[index];
	}
}

int cid_v0_init(cid_v0_t *cid, const uint8_t *digest, size_t digest_len)
{
	int result;

	result = (int)CIDV0_SUCCESS;
	if ((cid == NULL) || (digest == NULL))
	{
		result = (int)CIDV0_ERROR_NULL_POINTER;
	}
	else if (digest_len != CIDV0_HASH_SIZE)
	{
		cid_v0_reset(cid);
		result = (int)CIDV0_ERROR_INVALID_DIGEST_LENGTH;
	}
	else
	{
		cid_v0_copy_hash(cid->hash, digest);
	}

	return result;
}

int cid_v0_to_bytes(const cid_v0_t *cid, uint8_t *out, size_t out_len)
{
	int result;
	size_t index;

	result = (int)CIDV0_BINARY_SIZE;
	if ((cid == NULL) || (out == NULL))
	{
		result = (int)CIDV0_ERROR_NULL_POINTER;
	}
	else if (out_len < CIDV0_BINARY_SIZE)
	{
		result = (int)CIDV0_ERROR_BUFFER_TOO_SMALL;
	}
	else
	{
		out[0] = CIDV0_MULTIHASH_CODE;
		out[1] = CIDV0_MULTIHASH_LENGTH;
		for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
		{
			out[index + 2U] = cid->hash[index];
		}
	}

	return result;
}

int cid_v0_from_bytes(cid_v0_t *cid, const uint8_t *bytes, size_t bytes_len)
{
	int result;
	size_t index;

	result = (int)CIDV0_BINARY_SIZE;
	if ((cid == NULL) || (bytes == NULL))
	{
		result = (int)CIDV0_ERROR_NULL_POINTER;
	}
	else
	{
		cid_v0_reset(cid);
		if (bytes_len != CIDV0_BINARY_SIZE)
		{
			result = (int)CIDV0_ERROR_INVALID_DIGEST_LENGTH;
		}
		else if ((bytes[0] != CIDV0_MULTIHASH_CODE) || (bytes[1] != CIDV0_MULTIHASH_LENGTH))
		{
			result = (int)CIDV0_ERROR_INVALID_DIGEST_LENGTH;
		}
		else
		{
			for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
			{
				cid->hash[index] = bytes[index + 2U];
			}
		}
	}

	return result;
}

int cid_v0_to_string(const cid_v0_t *cid, char *out, size_t out_len)
{
	int result;
	uint8_t binary[CIDV0_BINARY_SIZE];
	int written;

	result = (int)CIDV0_STRING_LENGTH;
	if (out != NULL)
	{
		if (out_len > 0U)
		{
			out[0] = '\0';
		}
	}
	if ((cid == NULL) || (out == NULL))
	{
		result = (int)CIDV0_ERROR_NULL_POINTER;
	}
	else if (out_len <= CIDV0_STRING_LENGTH)
	{
		result = (int)CIDV0_ERROR_BUFFER_TOO_SMALL;
	}
	else
	{
		written = cid_v0_to_bytes(cid, binary, sizeof(binary));
		if (written != (int)CIDV0_BINARY_SIZE)
		{
			result = (written < 0) ? written : (int)CIDV0_ERROR_ENCODE_FAILURE;
		}
		else
		{
			written = multibase_base58_btc_encode(binary, CIDV0_BINARY_SIZE, out, out_len);
			if (written != (int)CIDV0_STRING_LENGTH)
			{
				result = (int)CIDV0_ERROR_ENCODE_FAILURE;
			}
			else
			{
				out[CIDV0_STRING_LENGTH] = '\0';
			}
		}
	}

	return result;
}

int cid_v0_from_string(cid_v0_t *cid, const char *str)
{
	int result;
	size_t str_len;
	uint8_t binary[CIDV0_BINARY_SIZE];
	int decoded;
	int consumed;

	result = (int)CIDV0_STRING_LENGTH;
	str_len = 0U;
	if ((cid == NULL) || (str == NULL))
	{
		result = (int)CIDV0_ERROR_NULL_POINTER;
	}
	else
	{
		cid_v0_reset(cid);
		str_len = strlen(str);
		if ((str_len != CIDV0_STRING_LENGTH) || (str[0] != 'Q') || (str[1] != 'm'))
		{
			result = (int)CIDV0_ERROR_DECODE_FAILURE;
		}
		else
		{
			decoded = multibase_base58_btc_decode(str, str_len, binary, sizeof(binary));
			if (decoded != (int)CIDV0_BINARY_SIZE)
			{
				result = (int)CIDV0_ERROR_DECODE_FAILURE;
			}
			else
			{
				consumed = cid_v0_from_bytes(cid, binary, CIDV0_BINARY_SIZE);
				if (consumed != (int)CIDV0_BINARY_SIZE)
				{
					result = (int)CIDV0_ERROR_DECODE_FAILURE;
				}
			}
		}
	}

	return result;
}
