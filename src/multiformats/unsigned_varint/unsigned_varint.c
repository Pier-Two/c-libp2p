#include "multiformats/unsigned_varint/unsigned_varint.h"

#include <stddef.h>
#include <stdint.h>

static size_t unsigned_varint_size_internal(uint64_t value)
{
	uint64_t remaining_value;
	size_t encoded_size;

	encoded_size = (size_t)0U;
	if (value <= UNSIGNED_VARINT_MAX_VALUE)
	{
		remaining_value = value;
		encoded_size = (size_t)1U;
		while (remaining_value >= UINT64_C(0x80))
		{
			remaining_value >>= 7U;
			++encoded_size;
		}
	}

	return encoded_size;
}

unsigned_varint_err_t unsigned_varint_encode(uint64_t value, uint8_t *out, size_t out_size, size_t *written)
{
	unsigned_varint_err_t status;
	uint64_t remaining_value;
	size_t required_size;
	size_t index;

	status = UNSIGNED_VARINT_OK;
	if ((out == NULL) || (written == NULL))
	{
		status = UNSIGNED_VARINT_ERR_NULL_PTR;
	}
	else
	{
		*written = (size_t)0U;
		if (value > UNSIGNED_VARINT_MAX_VALUE)
		{
			status = UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
		}
		else
		{
			required_size = unsigned_varint_size_internal(value);
			if (required_size == (size_t)0U)
			{
				status = UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
			}
			else if (out_size < required_size)
			{
				status = UNSIGNED_VARINT_ERR_BUFFER_OVER;
			}
			else
			{
				remaining_value = value;
				for (index = 0; index < required_size; ++index)
				{
					uint8_t byte;

					byte = (uint8_t)(remaining_value & UINT64_C(0x7F));
					remaining_value >>= 7U;
					if (remaining_value != UINT64_C(0))
					{
						byte = (uint8_t)(byte | UINT8_C(0x80));
					}

					out[index] = byte;
				}

				*written = required_size;
			}
		}
	}

	return status;
}

unsigned_varint_err_t unsigned_varint_decode(const uint8_t *in, size_t in_size, uint64_t *value, size_t *read)
{
	unsigned_varint_err_t status;
	uint64_t decoded_value;
	unsigned int shift;
	size_t index;

	status = UNSIGNED_VARINT_ERR_TOO_LONG;
	if ((in == NULL) || (value == NULL) || (read == NULL))
	{
		status = UNSIGNED_VARINT_ERR_NULL_PTR;
	}
	else
	{
		*value = UINT64_C(0);
		*read = (size_t)0U;
		if (in_size == (size_t)0U)
		{
			status = UNSIGNED_VARINT_ERR_EMPTY_INPUT;
		}
		else
		{
			decoded_value = UINT64_C(0);
			shift = 0U;
			for (index = 0; index < in_size; ++index)
			{
				uint8_t byte;
				uint8_t terminate_loop;

				terminate_loop = UINT8_C(0);
				byte = in[index];
				if (index < UNSIGNED_VARINT_MAX_ENCODED_SIZE)
				{
					decoded_value |= ((uint64_t)(byte & UINT8_C(0x7F))) << shift;
					if ((byte & UINT8_C(0x80)) == UINT8_C(0))
					{
						size_t encoded_size;

						encoded_size = index + (size_t)1U;
						if (decoded_value > UNSIGNED_VARINT_MAX_VALUE)
						{
							status = UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
						}
						else if (unsigned_varint_size_internal(decoded_value) != encoded_size)
						{
							status = UNSIGNED_VARINT_ERR_NOT_MINIMAL;
						}
						else
						{
							*value = decoded_value;
							*read = encoded_size;
							status = UNSIGNED_VARINT_OK;
						}
						terminate_loop = UINT8_C(1);
					}
					else
					{
						shift += 7U;
					}
				}
				else
				{
					/*
					 * Tenth byte handling: permit explicit
					 * overflow detection for 2^63, reject
					 * overlong/minimal-invalid 10-byte
					 * forms, and reject any continuation
					 * beyond this point.
					 */
					if (index > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
					{
						status = UNSIGNED_VARINT_ERR_TOO_LONG;
					}
					else if ((byte & UINT8_C(0x80)) != UINT8_C(0))
					{
						status = UNSIGNED_VARINT_ERR_TOO_LONG;
					}
					else if ((byte & UINT8_C(0x7F)) == UINT8_C(0))
					{
						status = UNSIGNED_VARINT_ERR_TOO_LONG;
					}
					else if ((byte & UINT8_C(0x7F)) == UINT8_C(1))
					{
						status = UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
					}
					else
					{
						status = UNSIGNED_VARINT_ERR_TOO_LONG;
					}
					terminate_loop = UINT8_C(1);
				}

				if (terminate_loop != UINT8_C(0))
				{
					break;
				}
			}
		}
	}

	return status;
}

size_t unsigned_varint_size(uint64_t value)
{
	return unsigned_varint_size_internal(value);
}
