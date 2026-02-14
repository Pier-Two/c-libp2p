#include "multiformats/multibase/encoding/base58_btc.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define BASE58_MAX_DATA_BYTES ((size_t)4096U)
#define BASE58_ENCODE_SCRATCH_MAX ((((BASE58_MAX_DATA_BYTES * 138U) + 99U) / 100U) + 1U)
#define BASE58_DECODE_SCRATCH_MAX (((BASE58_MAX_DATA_BYTES * 733U) / 1000U) + 2U)

static const char base58_btc_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int base58_encode_scratch_len(size_t data_len, size_t *scratch_len)
{
	int status;
	size_t local_len;

	status = (int)MULTIBASE_SUCCESS;
	local_len = 0U;
	if (scratch_len == NULL)
	{
		status = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (data_len == 0U)
	{
		local_len = 1U;
	}
	else if (data_len > ((SIZE_MAX - 99U) / 138U))
	{
		status = (int)MULTIBASE_ERR_OVERFLOW;
	}
	else
	{
		local_len = ((data_len * 138U) + 99U) / 100U;
		if (local_len == 0U)
		{
			local_len = 1U;
		}
	}

	if (status == (int)MULTIBASE_SUCCESS)
	{
		*scratch_len = local_len;
	}

	return status;
}

static int base58_decode_scratch_len(size_t data_len, size_t *scratch_len)
{
	int status;
	size_t local_len;

	status = (int)MULTIBASE_SUCCESS;
	local_len = 0U;
	if (scratch_len == NULL)
	{
		status = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (data_len == 0U)
	{
		local_len = 1U;
	}
	else if (data_len > ((SIZE_MAX - 1000U) / 733U))
	{
		status = (int)MULTIBASE_ERR_OVERFLOW;
	}
	else
	{
		local_len = ((data_len * 733U) / 1000U) + 1U;
	}

	if (status == (int)MULTIBASE_SUCCESS)
	{
		*scratch_len = local_len;
	}

	return status;
}

static int base58_char_value(uint8_t ch, uint8_t *value)
{
	int valid;
	size_t index;

	valid = 0;
	index = 0U;
	while ((index < 58U) && (valid == 0))
	{
		if ((uint8_t)base58_btc_alphabet[index] == ch)
		{
			*value = (uint8_t)index;
			valid = 1;
		}
		index++;
	}

	return valid;
}

int multibase_base58_btc_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
	int result;
	size_t leading_zeros;
	size_t scratch_len;
	size_t scratch_index;
	size_t out_index;
	size_t encoded_len;
	uint8_t scratch[BASE58_ENCODE_SCRATCH_MAX];

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	leading_zeros = 0U;
	scratch_len = 0U;
	scratch_index = 0U;
	out_index = 0U;
	encoded_len = 0U;
	if ((data == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (data_len > BASE58_MAX_DATA_BYTES)
	{
		result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
	}
	else if (data_len == 0U)
	{
		if (out_len < 1U)
		{
			result = (int)MULTIBASE_ERR_BUFFER_TOO_SMALL;
		}
		else
		{
			out[0] = '\0';
			result = 0;
		}
	}
	else
	{
		while ((leading_zeros < data_len) && (data[leading_zeros] == 0U))
		{
			leading_zeros++;
		}

		result = base58_encode_scratch_len(data_len - leading_zeros, &scratch_len);
		if ((result == (int)MULTIBASE_SUCCESS) && (scratch_len > BASE58_ENCODE_SCRATCH_MAX))
		{
			result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
			size_t init_index;

			init_index = 0U;
			while (init_index < scratch_len)
			{
				scratch[init_index] = 0U;
				init_index++;
			}
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
			size_t data_index;

			data_index = leading_zeros;
			while ((data_index < data_len) && (result == (int)MULTIBASE_SUCCESS))
			{
				uint32_t carry;
				size_t work_index;

				carry = (uint32_t)data[data_index];
				work_index = scratch_len;
				while (work_index > 0U)
				{
					size_t idx;

					idx = work_index - 1U;
					carry += 256U * (uint32_t)scratch[idx];
					scratch[idx] = (uint8_t)(carry % 58U);
					carry /= 58U;
					work_index--;
				}

				if (carry != 0U)
				{
					result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
				}

				data_index++;
			}
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
			while ((scratch_index < scratch_len) && (scratch[scratch_index] == 0U))
			{
				scratch_index++;
			}

			encoded_len = leading_zeros + (scratch_len - scratch_index);
			if (out_len < (encoded_len + 1U))
			{
				result = (int)MULTIBASE_ERR_BUFFER_TOO_SMALL;
			}
			else if (encoded_len > (size_t)INT_MAX)
			{
				result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
			}
			else
			{
				size_t zero_index;

				zero_index = 0U;
				while (zero_index < leading_zeros)
				{
					out[out_index] = '1';
					out_index++;
					zero_index++;
				}

				while (scratch_index < scratch_len)
				{
					out[out_index] = base58_btc_alphabet[scratch[scratch_index]];
					out_index++;
					scratch_index++;
				}

				out[out_index] = '\0';
				result = (int)encoded_len;
			}
		}
	}

	return result;
}

int multibase_base58_btc_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
	int result;
	size_t leading_ones;
	size_t scratch_len;
	size_t scratch_index;
	size_t out_index;
	size_t decoded_len;
	uint8_t scratch[BASE58_DECODE_SCRATCH_MAX];

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	leading_ones = 0U;
	scratch_len = 0U;
	scratch_index = 0U;
	out_index = 0U;
	decoded_len = 0U;
	if ((in == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (data_len > BASE58_MAX_DATA_BYTES)
	{
		result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
	}
	else if (data_len == 0U)
	{
		result = 0;
	}
	else
	{
		while ((leading_ones < data_len) && (in[leading_ones] == '1'))
		{
			leading_ones++;
		}

		result = base58_decode_scratch_len(data_len - leading_ones, &scratch_len);
		if ((result == (int)MULTIBASE_SUCCESS) && (scratch_len > BASE58_DECODE_SCRATCH_MAX))
		{
			result = (int)MULTIBASE_ERR_INPUT_TOO_LARGE;
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
			size_t init_index;

			init_index = 0U;
			while (init_index < scratch_len)
			{
				scratch[init_index] = 0U;
				init_index++;
			}
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
			size_t in_pos;

			in_pos = leading_ones;
			while ((in_pos < data_len) && (result == (int)MULTIBASE_SUCCESS))
			{
				uint8_t digit;
				int valid;
				uint32_t carry;
				size_t work_index;

				digit = 0U;
				valid = base58_char_value((uint8_t)in[in_pos], &digit);
				if (valid == 0)
				{
					result = (int)MULTIBASE_ERR_INVALID_CHARACTER;
				}
				else
				{
					carry = (uint32_t)digit;
					work_index = scratch_len;
					while (work_index > 0U)
					{
						size_t idx;

						idx = work_index - 1U;
						carry += 58U * (uint32_t)scratch[idx];
						scratch[idx] = (uint8_t)(carry & 0xFFU);
						carry >>= 8U;
						work_index--;
					}

					if (carry != 0U)
					{
						result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
					}
				}

				in_pos++;
			}
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
			while ((scratch_index < scratch_len) && (scratch[scratch_index] == 0U))
			{
				scratch_index++;
			}

			decoded_len = leading_ones + (scratch_len - scratch_index);
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
				size_t zero_index;

				zero_index = 0U;
				while (zero_index < leading_ones)
				{
					out[out_index] = 0U;
					out_index++;
					zero_index++;
				}

				while (scratch_index < scratch_len)
				{
					out[out_index] = scratch[scratch_index];
					out_index++;
					scratch_index++;
				}

				result = (int)decoded_len;
			}
		}
	}

	return result;
}
