#include "multiformats/multibase/encoding/base64_url.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int base64_url_char_value(uint8_t ch, uint8_t *value)
{
	int valid;
	uint8_t local;

	valid = 1;
	local = 0U;
	if ((ch >= (uint8_t)'A') && (ch <= (uint8_t)'Z'))
	{
		local = (uint8_t)(ch - (uint8_t)'A');
	}
	else if ((ch >= (uint8_t)'a') && (ch <= (uint8_t)'z'))
	{
		local = (uint8_t)((ch - (uint8_t)'a') + 26U);
	}
	else if ((ch >= (uint8_t)'0') && (ch <= (uint8_t)'9'))
	{
		local = (uint8_t)((ch - (uint8_t)'0') + 52U);
	}
	else if (ch == (uint8_t)'-')
	{
		local = 62U;
	}
	else if (ch == (uint8_t)'_')
	{
		local = 63U;
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

static int base64_url_unpadded_encoded_len(size_t data_len, size_t *encoded_len)
{
	int status;
	size_t groups;
	size_t remainder;
	size_t local_len;

	status = (int)MULTIBASE_SUCCESS;
	groups = 0U;
	remainder = 0U;
	local_len = 0U;
	if (encoded_len == NULL)
	{
		status = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		groups = data_len / 3U;
		remainder = data_len % 3U;
		if (groups > (SIZE_MAX / 4U))
		{
			status = (int)MULTIBASE_ERR_OVERFLOW;
		}
		else
		{
			local_len = groups * 4U;
			if (remainder == 1U)
			{
				if (local_len > (SIZE_MAX - 2U))
				{
					status = (int)MULTIBASE_ERR_OVERFLOW;
				}
				else
				{
					local_len += 2U;
				}
			}
			else if (remainder == 2U)
			{
				if (local_len > (SIZE_MAX - 3U))
				{
					status = (int)MULTIBASE_ERR_OVERFLOW;
				}
				else
				{
					local_len += 3U;
				}
			}
			else
			{
				/* no tail bytes */
			}
		}
	}

	if (status == (int)MULTIBASE_SUCCESS)
	{
		*encoded_len = local_len;
	}

	return status;
}

int multibase_base64_url_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
	int result;
	size_t encoded_len;
	size_t data_index;
	size_t out_index;
	size_t remainder;
	static const char base64_url_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	encoded_len = 0U;
	data_index = 0U;
	out_index = 0U;
	remainder = 0U;
	if ((data == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		result = base64_url_unpadded_encoded_len(data_len, &encoded_len);
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
			remainder = data_len % 3U;
			while ((data_index + 3U) <= data_len)
			{
				uint32_t triple;
				uint8_t b0;
				uint8_t b1;
				uint8_t b2;

				b0 = data[data_index];
				b1 = data[data_index + 1U];
				b2 = data[data_index + 2U];
				triple = ((uint32_t)b0 << 16U) | ((uint32_t)b1 << 8U) | (uint32_t)b2;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 18U) & 0x3FU)];
				out_index++;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 12U) & 0x3FU)];
				out_index++;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 6U) & 0x3FU)];
				out_index++;
				out[out_index] = base64_url_alphabet[(uint8_t)(triple & 0x3FU)];
				out_index++;
				data_index += 3U;
			}

			if (remainder == 1U)
			{
				uint32_t triple;
				uint8_t b0;

				b0 = data[data_index];
				triple = (uint32_t)b0 << 16U;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 18U) & 0x3FU)];
				out_index++;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 12U) & 0x3FU)];
				out_index++;
			}
			else if (remainder == 2U)
			{
				uint32_t triple;
				uint8_t b0;
				uint8_t b1;

				b0 = data[data_index];
				b1 = data[data_index + 1U];
				triple = ((uint32_t)b0 << 16U) | ((uint32_t)b1 << 8U);
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 18U) & 0x3FU)];
				out_index++;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 12U) & 0x3FU)];
				out_index++;
				out[out_index] = base64_url_alphabet[(uint8_t)((triple >> 6U) & 0x3FU)];
				out_index++;
			}
			else
			{
				/* no remainder */
			}

			out[out_index] = '\0';
			result = (int)encoded_len;
		}
	}

	return result;
}

int multibase_base64_url_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
	int result;
	size_t full_groups;
	size_t remainder;
	size_t decoded_len;
	size_t group_index;
	size_t in_index;
	size_t out_index;

	result = (int)MULTIBASE_ERR_NULL_POINTER;
	full_groups = 0U;
	remainder = 0U;
	decoded_len = 0U;
	group_index = 0U;
	in_index = 0U;
	out_index = 0U;
	if ((in == NULL) || (out == NULL))
	{
		result = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		full_groups = data_len / 4U;
		remainder = data_len % 4U;
		if (remainder == 1U)
		{
			result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
		}
		else if (full_groups > (SIZE_MAX / 3U))
		{
			result = (int)MULTIBASE_ERR_OVERFLOW;
		}
		else
		{
			decoded_len = full_groups * 3U;
			if (remainder == 2U)
			{
				if (decoded_len > (SIZE_MAX - 1U))
				{
					result = (int)MULTIBASE_ERR_OVERFLOW;
				}
				else
				{
					decoded_len += 1U;
				}
			}
			else if (remainder == 3U)
			{
				if (decoded_len > (SIZE_MAX - 2U))
				{
					result = (int)MULTIBASE_ERR_OVERFLOW;
				}
				else
				{
					decoded_len += 2U;
				}
			}
			else
			{
				/* no remainder */
			}
		}

		if (result == (int)MULTIBASE_ERR_NULL_POINTER)
		{
			result = (int)MULTIBASE_SUCCESS;
		}

		if (result == (int)MULTIBASE_SUCCESS)
		{
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
				while ((group_index < full_groups) && (result == (int)MULTIBASE_SUCCESS))
				{
					uint8_t v0;
					uint8_t v1;
					uint8_t v2;
					uint8_t v3;
					int ok0;
					int ok1;
					int ok2;
					int ok3;
					uint32_t triple;

					v0 = 0U;
					v1 = 0U;
					v2 = 0U;
					v3 = 0U;
					ok0 = base64_url_char_value((uint8_t)in[in_index], &v0);
					in_index++;
					ok1 = base64_url_char_value((uint8_t)in[in_index], &v1);
					in_index++;
					ok2 = base64_url_char_value((uint8_t)in[in_index], &v2);
					in_index++;
					ok3 = base64_url_char_value((uint8_t)in[in_index], &v3);
					in_index++;
					if ((ok0 == 0) || (ok1 == 0) || (ok2 == 0) || (ok3 == 0))
					{
						result = (int)MULTIBASE_ERR_INVALID_CHARACTER;
					}
					else
					{
						triple = ((uint32_t)v0 << 18U) | ((uint32_t)v1 << 12U) |
							 ((uint32_t)v2 << 6U) | (uint32_t)v3;
						out[out_index] = (uint8_t)((triple >> 16U) & 0xFFU);
						out_index++;
						out[out_index] = (uint8_t)((triple >> 8U) & 0xFFU);
						out_index++;
						out[out_index] = (uint8_t)(triple & 0xFFU);
						out_index++;
					}

					group_index++;
				}

				if ((result == (int)MULTIBASE_SUCCESS) && (remainder == 2U))
				{
					uint8_t v0;
					uint8_t v1;
					int ok0;
					int ok1;
					uint32_t triple;

					v0 = 0U;
					v1 = 0U;
					ok0 = base64_url_char_value((uint8_t)in[in_index], &v0);
					in_index++;
					ok1 = base64_url_char_value((uint8_t)in[in_index], &v1);
					in_index++;
					if ((ok0 == 0) || (ok1 == 0))
					{
						result = (int)MULTIBASE_ERR_INVALID_CHARACTER;
					}
					else if ((v1 & 0x0FU) != 0U)
					{
						result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
					}
					else
					{
						triple = ((uint32_t)v0 << 18U) | ((uint32_t)v1 << 12U);
						out[out_index] = (uint8_t)((triple >> 16U) & 0xFFU);
						out_index++;
					}
				}
				else if ((result == (int)MULTIBASE_SUCCESS) && (remainder == 3U))
				{
					uint8_t v0;
					uint8_t v1;
					uint8_t v2;
					int ok0;
					int ok1;
					int ok2;
					uint32_t triple;

					v0 = 0U;
					v1 = 0U;
					v2 = 0U;
					ok0 = base64_url_char_value((uint8_t)in[in_index], &v0);
					in_index++;
					ok1 = base64_url_char_value((uint8_t)in[in_index], &v1);
					in_index++;
					ok2 = base64_url_char_value((uint8_t)in[in_index], &v2);
					in_index++;
					if ((ok0 == 0) || (ok1 == 0) || (ok2 == 0))
					{
						result = (int)MULTIBASE_ERR_INVALID_CHARACTER;
					}
					else if ((v2 & 0x03U) != 0U)
					{
						result = (int)MULTIBASE_ERR_INVALID_INPUT_LEN;
					}
					else
					{
						triple = ((uint32_t)v0 << 18U) | ((uint32_t)v1 << 12U) |
							 ((uint32_t)v2 << 6U);
						out[out_index] = (uint8_t)((triple >> 16U) & 0xFFU);
						out_index++;
						out[out_index] = (uint8_t)((triple >> 8U) & 0xFFU);
						out_index++;
					}
				}
				else
				{
					/* no remainder bytes */
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
