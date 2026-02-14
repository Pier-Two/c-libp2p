#include "multiformats/multibase/encoding/base16_upper.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int base16_upper_decode_nibble(uint8_t ch, uint8_t *value)
{
	int valid;
	uint8_t nibble;

	valid = 1;
	nibble = 0U;
	if ((ch >= (uint8_t)'0') && (ch <= (uint8_t)'9'))
	{
		nibble = (uint8_t)(ch - (uint8_t)'0');
	}
	else if ((ch >= (uint8_t)'A') && (ch <= (uint8_t)'F'))
	{
		nibble = (uint8_t)((ch - (uint8_t)'A') + 10U);
	}
	else
	{
		valid = 0;
	}

	if (valid != 0)
	{
		*value = nibble;
	}

	return valid;
}

int multibase_base16_upper_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
	int result;
	size_t encoded_len;
	size_t required_len;
	size_t index;
	static const char hex_digits_upper[] = "0123456789ABCDEF";

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	encoded_len = 0U;
	required_len = 0U;
	index = 0U;
	if ((data == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (data_len > ((SIZE_MAX - 1U) / 2U))
	{
		result = (int)MULTIBASE_ERR_OVERFLOW;
	}
	else
	{
		encoded_len = data_len * 2U;
		required_len = encoded_len + 1U;
		if (out_len < required_len)
		{
			result = (int)MULTIBASE_ERR_BUFFER_TOO_SMALL;
		}
		else if (encoded_len > (size_t)INT_MAX)
		{
			result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
		}
		else
		{
			while (index < data_len)
			{
				uint8_t byte;
				uint8_t high;
				uint8_t low;

				byte = data[index];
				high = (uint8_t)(byte >> 4U);
				low = (uint8_t)(byte & 0x0FU);
				out[index * 2U] = hex_digits_upper[high];
				out[(index * 2U) + 1U] = hex_digits_upper[low];
				index++;
			}

			out[encoded_len] = '\0';
			result = (int)encoded_len;
		}
	}

	return result;
}

int multibase_base16_upper_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
	int result;
	size_t decoded_len;
	size_t index;

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	decoded_len = 0U;
	index = 0U;
	if ((in == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if ((data_len % 2U) != 0U)
	{
		result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
	}
	else
	{
		decoded_len = data_len / 2U;
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
			while ((index < decoded_len) && (result == (int)MULTIBASE_SUCCESS))
			{
				uint8_t high;
				uint8_t low;
				int high_valid;
				int low_valid;

				high = 0U;
				low = 0U;
				high_valid = base16_upper_decode_nibble((uint8_t)in[index * 2U], &high);
				low_valid = base16_upper_decode_nibble((uint8_t)in[(index * 2U) + 1U], &low);
				if ((high_valid == 0) || (low_valid == 0))
				{
					result = (int)MULTIBASE_ERR_INVALID_CHARACTER;
				}
				else
				{
					out[index] = (uint8_t)(((uint32_t)high << 4U) | (uint32_t)low);
				}
				index++;
			}

			if (result == (int)MULTIBASE_SUCCESS)
			{
				result = (int)decoded_len;
			}
		}
	}

	return result;
}
