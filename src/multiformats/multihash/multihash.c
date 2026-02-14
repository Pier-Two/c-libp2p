#include "multiformats/multihash/multihash.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "sha3_compat.h"

#define MULTIHASH_SHA2_256_HASH_SIZE ((size_t)32U)
#define MULTIHASH_SHA2_512_HASH_SIZE ((size_t)64U)
#define MULTIHASH_SHA3_224_HASH_SIZE ((size_t)28U)
#define MULTIHASH_SHA3_256_HASH_SIZE ((size_t)32U)
#define MULTIHASH_SHA3_384_HASH_SIZE ((size_t)48U)
#define MULTIHASH_SHA3_512_HASH_SIZE ((size_t)64U)
#define MULTIHASH_SHA2_INPUT_LIMIT ((size_t)UINT32_MAX)
#define MULTIHASH_SHA512_CONTEXT_BUFFER_SIZE ((size_t)256U)

extern void Sha256Calculate(void const *buffer, uint32_t buffer_size, void *digest);
extern void Sha512Initialise(void *context);
extern void Sha512Update(void *context, void const *buffer, uint32_t buffer_size);
extern void Sha512Finalise(void *context, void *digest);

static int multihash_is_supported_code(uint64_t code)
{
	int supported;

	supported = 0;
	switch (code)
	{
	case MULTIHASH_CODE_SHA2_256:
	case MULTIHASH_CODE_SHA2_512:
	case MULTIHASH_CODE_SHA3_224:
	case MULTIHASH_CODE_SHA3_256:
	case MULTIHASH_CODE_SHA3_384:
	case MULTIHASH_CODE_SHA3_512:
	case MULTIHASH_CODE_IDENTITY:
		supported = 1;
		break;
	default:
		break;
	}

	return supported;
}

static multihash_error_t multihash_map_varint_error(unsigned_varint_err_t varint_error)
{
	multihash_error_t status;

	status = MULTIHASH_ERR_INVALID_INPUT;
	if (varint_error == UNSIGNED_VARINT_ERR_NULL_PTR)
	{
		status = MULTIHASH_ERR_NULL_POINTER;
	}

	return status;
}

static multihash_error_t multihash_compute_digest(uint64_t code, const uint8_t *data, size_t data_len,
						  uint8_t *digest_out, size_t *digest_len)
{
	multihash_error_t status;

	status = MULTIHASH_SUCCESS;
	if ((data == NULL) || (digest_out == NULL) || (digest_len == NULL))
	{
		status = MULTIHASH_ERR_NULL_POINTER;
	}
	else
	{
		*digest_len = (size_t)0U;
		switch (code)
		{
		case MULTIHASH_CODE_SHA2_256: {
			if (data_len > MULTIHASH_SHA2_INPUT_LIMIT)
			{
				status = MULTIHASH_ERR_INVALID_INPUT;
			}
			else
			{
				uint8_t hash[MULTIHASH_SHA2_256_HASH_SIZE];

				Sha256Calculate(data, (uint32_t)data_len, &hash);
				*digest_len = MULTIHASH_SHA2_256_HASH_SIZE;
				(void)memcpy(digest_out, hash, *digest_len);
			}
			break;
		}
		case MULTIHASH_CODE_SHA2_512: {
			if (data_len > MULTIHASH_SHA2_INPUT_LIMIT)
			{
				status = MULTIHASH_ERR_INVALID_INPUT;
			}
			else
			{
				struct
				{
					uint64_t alignment;
					uint8_t bytes[MULTIHASH_SHA512_CONTEXT_BUFFER_SIZE];
				} context;
				uint8_t hash[MULTIHASH_SHA2_512_HASH_SIZE];

				Sha512Initialise(context.bytes);
				Sha512Update(context.bytes, data, (uint32_t)data_len);
				Sha512Finalise(context.bytes, hash);
				*digest_len = MULTIHASH_SHA2_512_HASH_SIZE;
				(void)memcpy(digest_out, hash, *digest_len);
			}
			break;
		}
		case MULTIHASH_CODE_SHA3_224:
			*digest_len = MULTIHASH_SHA3_224_HASH_SIZE;
			sha3_224(data, data_len, digest_out);
			break;
		case MULTIHASH_CODE_SHA3_256:
			*digest_len = MULTIHASH_SHA3_256_HASH_SIZE;
			sha3_256(data, data_len, digest_out);
			break;
		case MULTIHASH_CODE_SHA3_384:
			*digest_len = MULTIHASH_SHA3_384_HASH_SIZE;
			sha3_384(data, data_len, digest_out);
			break;
		case MULTIHASH_CODE_SHA3_512:
			*digest_len = MULTIHASH_SHA3_512_HASH_SIZE;
			sha3_512(data, data_len, digest_out);
			break;
		default:
			status = MULTIHASH_ERR_UNSUPPORTED_FUN;
			break;
		}
	}

	return status;
}

int multihash_encode(uint64_t code, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
{
	multihash_error_t status;
	int result;
	size_t digest_len;
	size_t code_written;
	size_t length_written;
	size_t prefix_len;
	size_t total_len;
	const uint8_t *digest_source;
	uint8_t digest_buffer[MULTIHASH_MAX_DIGEST_SIZE];

	status = MULTIHASH_ERR_ALLOC_FAILURE;
	result = (int)MULTIHASH_ERR_INVALID_INPUT;
	digest_len = (size_t)0U;
	code_written = (size_t)0U;
	length_written = (size_t)0U;
	total_len = (size_t)0U;
	digest_source = NULL;
	if ((data == NULL) || (out == NULL))
	{
		status = MULTIHASH_ERR_NULL_POINTER;
	}
	else if (!multihash_is_supported_code(code))
	{
		status = MULTIHASH_ERR_UNSUPPORTED_FUN;
	}
	else
	{
		status = MULTIHASH_SUCCESS;
		if (code == MULTIHASH_CODE_IDENTITY)
		{
			digest_source = data;
			digest_len = data_len;
		}
		else
		{
			status = multihash_compute_digest(code, data, data_len, digest_buffer, &digest_len);
			if (status == MULTIHASH_SUCCESS)
			{
				digest_source = digest_buffer;
			}
		}

		if (status == MULTIHASH_SUCCESS)
		{
			if ((uint64_t)digest_len > UNSIGNED_VARINT_MAX_VALUE)
			{
				status = MULTIHASH_ERR_INVALID_INPUT;
			}
		}

		if (status == MULTIHASH_SUCCESS)
		{
			unsigned_varint_err_t varint_error;

			varint_error = unsigned_varint_encode(code, out, out_len, &code_written);
			if (varint_error != UNSIGNED_VARINT_OK)
			{
				status = multihash_map_varint_error(varint_error);
			}
			else
			{
				varint_error = unsigned_varint_encode((uint64_t)digest_len, &out[code_written],
								      out_len - code_written, &length_written);
				if (varint_error != UNSIGNED_VARINT_OK)
				{
					status = multihash_map_varint_error(varint_error);
				}
				else if ((code_written > UNSIGNED_VARINT_MAX_ENCODED_SIZE) ||
					 (length_written > UNSIGNED_VARINT_MAX_ENCODED_SIZE))
				{
					status = MULTIHASH_ERR_INVALID_INPUT;
				}
				else
				{
					/* status remains success */
				}
			}
		}

		if (status == MULTIHASH_SUCCESS)
		{
			prefix_len = code_written + length_written;
			if (prefix_len > out_len)
			{
				status = MULTIHASH_ERR_INVALID_INPUT;
			}
			else if (digest_len > (out_len - prefix_len))
			{
				status = MULTIHASH_ERR_INVALID_INPUT;
			}
			else
			{
				if (digest_len > (size_t)0U)
				{
					(void)memcpy(&out[prefix_len], digest_source, digest_len);
				}

				total_len = prefix_len + digest_len;
				if (total_len > (size_t)INT_MAX)
				{
					status = MULTIHASH_ERR_INVALID_INPUT;
				}
			}
		}
	}

	if (status == MULTIHASH_SUCCESS)
	{
		result = (int)total_len;
	}
	else
	{
		result = (int)status;
	}

	return result;
}

int multihash_decode(const uint8_t *in, size_t in_len, uint64_t *code, uint8_t *digest, size_t *digest_len)
{
	multihash_error_t status;
	int result;
	uint64_t decoded_code;
	uint64_t decoded_digest_len;
	size_t output_capacity;
	size_t code_read;
	size_t digest_len_read;
	size_t payload_offset;
	size_t payload_size;
	size_t consumed;

	status = MULTIHASH_SUCCESS;
	result = (int)MULTIHASH_ERR_INVALID_INPUT;
	decoded_code = (uint64_t)0U;
	decoded_digest_len = (uint64_t)0U;
	code_read = (size_t)0U;
	digest_len_read = (size_t)0U;
	consumed = (size_t)0U;
	if ((in == NULL) || (code == NULL) || (digest == NULL) || (digest_len == NULL))
	{
		status = MULTIHASH_ERR_NULL_POINTER;
	}
	else
	{
		output_capacity = *digest_len;
		*code = (uint64_t)0U;
		*digest_len = (size_t)0U;

		{
			unsigned_varint_err_t varint_error;

			varint_error = unsigned_varint_decode(in, in_len, &decoded_code, &code_read);
			if (varint_error != UNSIGNED_VARINT_OK)
			{
				status = multihash_map_varint_error(varint_error);
			}
		}
		if (status != MULTIHASH_SUCCESS)
		{
			/* status already set by varint decoding */
		}
		else if (!multihash_is_supported_code(decoded_code))
		{
			status = MULTIHASH_ERR_UNSUPPORTED_FUN;
		}
		else if (code_read > in_len)
		{
			status = MULTIHASH_ERR_INVALID_INPUT;
		}
		else
		{
			{
				unsigned_varint_err_t varint_error;

				varint_error = unsigned_varint_decode(&in[code_read], in_len - code_read,
								      &decoded_digest_len, &digest_len_read);
				if (varint_error != UNSIGNED_VARINT_OK)
				{
					status = multihash_map_varint_error(varint_error);
				}
			}

			if (status != MULTIHASH_SUCCESS)
			{
				/* status already set by varint decoding */
			}
			else if (digest_len_read > (in_len - code_read))
			{
				status = MULTIHASH_ERR_INVALID_INPUT;
			}
			else
			{
				payload_offset = code_read + digest_len_read;
				if (decoded_digest_len > (uint64_t)(in_len - payload_offset))
				{
					status = MULTIHASH_ERR_INVALID_INPUT;
				}
				else if (decoded_digest_len > (uint64_t)output_capacity)
				{
					status = MULTIHASH_ERR_DIGEST_TOO_LARGE;
				}
				else
				{
					payload_size = (size_t)decoded_digest_len;
					if (payload_size > (size_t)0U)
					{
						(void)memcpy(digest, &in[payload_offset], payload_size);
					}

					consumed = payload_offset + payload_size;
					if (consumed > (size_t)INT_MAX)
					{
						status = MULTIHASH_ERR_INVALID_INPUT;
					}
					else
					{
						*code = decoded_code;
						*digest_len = payload_size;
					}
				}
			}
		}
	}

	if (status == MULTIHASH_SUCCESS)
	{
		result = (int)consumed;
	}
	else
	{
		result = (int)status;
	}

	return result;
}
