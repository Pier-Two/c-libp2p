#include "multiformats/multibase/encoding/base32.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int base32_compute_encoded_len(size_t data_len, size_t *encoded_len)
{
	int status;
	size_t local_len;

	status = (int)MULTIBASE_SUCCESS;
	local_len = 0U;
	if (encoded_len == NULL)
	{
		status = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (data_len == 0U)
	{
		local_len = 0U;
	}
	else if (data_len > ((SIZE_MAX - 4U) / 8U))
	{
		status = (int)MULTIBASE_ERR_OVERFLOW;
	}
	else
	{
		local_len = ((data_len * 8U) + 4U) / 5U;
	}

	if (status == (int)MULTIBASE_SUCCESS)
	{
		*encoded_len = local_len;
	}

	return status;
}

static int base32_lower_value(uint8_t ch, uint8_t *value)
{
	int valid;
	uint8_t local;

	valid = 1;
	local = 0U;
	if ((ch >= (uint8_t)'a') && (ch <= (uint8_t)'z'))
	{
		local = (uint8_t)(ch - (uint8_t)'a');
	}
	else if ((ch >= (uint8_t)'2') && (ch <= (uint8_t)'7'))
	{
		local = (uint8_t)((ch - (uint8_t)'2') + 26U);
	}
	else
	{
		valid = 0;
	}

	if (valid != 0)
	{
		*value = local;
	}

	return valid;
}

int multibase_base32_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
	int result;
	size_t encoded_len;
	size_t in_index;
	size_t out_index;
	uint32_t bit_buffer;
	size_t bits_in_buffer;
	static const char base32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	encoded_len = 0U;
	in_index = 0U;
	out_index = 0U;
	bit_buffer = 0U;
	bits_in_buffer = 0U;
	if ((data == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		result = base32_compute_encoded_len(data_len, &encoded_len);
		if (result != (int)MULTIBASE_SUCCESS)
		{
			/* result already set */
		}
		else if (out_len < (encoded_len + 1U))
		{
			result = (int)MULTIBASE_ERR_BUFFER_TOO_SMALL;
		}
		else if (encoded_len > (size_t)INT_MAX)
		{
			result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
		}
		else
		{
			while (in_index < data_len)
			{
				uint8_t byte;

				byte = data[in_index];
				bit_buffer = (bit_buffer << 8U) | (uint32_t)byte;
				bits_in_buffer += 8U;
				in_index++;

				while (bits_in_buffer >= 5U)
				{
					uint32_t shift;
					uint8_t value;

					bits_in_buffer -= 5U;
					shift = (uint32_t)bits_in_buffer;
					value = (uint8_t)((bit_buffer >> shift) & 0x1FU);
					out[out_index] = base32_alphabet[value];
					out_index++;
				}
			}

			if (bits_in_buffer > 0U)
			{
				uint32_t shift;
				uint8_t value;

				shift = (uint32_t)(5U - bits_in_buffer);
				value = (uint8_t)((bit_buffer << shift) & 0x1FU);
				out[out_index] = base32_alphabet[value];
				out_index++;
			}

			out[out_index] = '\0';
			result = (int)encoded_len;
		}
	}

	return result;
}

int multibase_base32_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
	int result;
	size_t decoded_len;
	size_t in_index;
	size_t out_index;
	size_t remainder;
	uint32_t bit_buffer;
	size_t bits_in_buffer;

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	decoded_len = 0U;
	in_index = 0U;
	out_index = 0U;
	remainder = 0U;
	bit_buffer = 0U;
	bits_in_buffer = 0U;
	if ((in == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		remainder = data_len % 8U;
		if (!((remainder == 0U) || (remainder == 2U) || (remainder == 4U) || (remainder == 5U) ||
		      (remainder == 7U)))
		{
			result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
		}
		else if (data_len > (SIZE_MAX / 5U))
		{
			result = (int)MULTIBASE_ERR_OVERFLOW;
		}
		else
		{
			decoded_len = (data_len * 5U) / 8U;
			if (out_len < decoded_len)
			{
				result = (int)MULTIBASE_ERR_BUFFER_TOO_SMALL;
			}
			else if (decoded_len > (size_t)INT_MAX)
			{
				result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
			}
			else
			{
				result = (int)MULTIBASE_SUCCESS;
				while ((in_index < data_len) && (result == (int)MULTIBASE_SUCCESS))
				{
					uint8_t value;
					int valid;

					value = 0U;
					valid = base32_lower_value((uint8_t)in[in_index], &value);
					if (valid == 0)
					{
						result = (int)MULTIBASE_ERR_INVALID_CHARACTER;
					}
					else
					{
						bit_buffer = (bit_buffer << 5U) | (uint32_t)value;
						bits_in_buffer += 5U;
						if (bits_in_buffer >= 8U)
						{
							uint32_t shift;

							bits_in_buffer -= 8U;
							shift = (uint32_t)bits_in_buffer;
							out[out_index] = (uint8_t)((bit_buffer >> shift) & 0xFFU);
							out_index++;
						}
					}
					in_index++;
				}

				if (result == (int)MULTIBASE_SUCCESS)
				{
					if (bits_in_buffer > 0U)
					{
						uint32_t mask;

						mask = (uint32_t)((1U << bits_in_buffer) - 1U);
						if ((bit_buffer & mask) != 0U)
						{
							result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
						}
					}
				}

				if (result == (int)MULTIBASE_SUCCESS)
				{
					result = (int)decoded_len;
				}
			}
		}
	}

	return result;
}
