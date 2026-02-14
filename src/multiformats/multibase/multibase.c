#include "multiformats/multibase/multibase.h"

#include <limits.h>
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

static int multibase_get_prefix(multibase_t base, char *prefix)
{
	multibase_error_t status;

	status = MULTIBASE_SUCCESS;
	if (prefix == NULL)
	{
		status = MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		switch (base)
		{
		case MULTIBASE_BASE16:
			*prefix = BASE16_CHARACTER;
			break;
		case MULTIBASE_BASE16_UPPER:
			*prefix = BASE16_UPPER_CHARACTER;
			break;
		case MULTIBASE_BASE32:
			*prefix = BASE32_CHARACTER;
			break;
		case MULTIBASE_BASE32_UPPER:
			*prefix = BASE32_UPPER_CHARACTER;
			break;
		case MULTIBASE_BASE58_BTC:
			*prefix = BASE58_BTC_CHARACTER;
			break;
		case MULTIBASE_BASE64:
			*prefix = BASE64_CHARACTER;
			break;
		case MULTIBASE_BASE64_URL:
			*prefix = BASE64_URL_CHARACTER;
			break;
		case MULTIBASE_BASE64_URL_PAD:
			*prefix = BASE64_URL_PAD_CHARACTER;
			break;
		default:
			status = MULTIBASE_ERR_UNSUPPORTED_BASE;
			break;
		}
	}

	return (int)status;
}

static int multibase_unpadded_base64_len(size_t data_len, size_t *encoded_len)
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

static int multibase_encoded_len_bound(multibase_t base, size_t data_len, size_t *encoded_len)
{
	int status;
	size_t local_len;

	status = (int)MULTIBASE_SUCCESS;
	local_len = 0U;
	if (encoded_len == NULL)
	{
		status = (int)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		switch (base)
		{
		case MULTIBASE_BASE16:
		case MULTIBASE_BASE16_UPPER:
			if (data_len > (SIZE_MAX / 2U))
			{
				status = (int)MULTIBASE_ERR_OVERFLOW;
			}
			else
			{
				local_len = data_len * 2U;
			}
			break;
		case MULTIBASE_BASE32:
		case MULTIBASE_BASE32_UPPER:
			if (data_len == 0U)
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
			break;
		case MULTIBASE_BASE58_BTC:
			if (data_len == 0U)
			{
				local_len = 0U;
			}
			else if (data_len > ((SIZE_MAX - 99U) / 138U))
			{
				status = (int)MULTIBASE_ERR_OVERFLOW;
			}
			else
			{
				local_len = ((data_len * 138U) + 99U) / 100U;
			}
			break;
		case MULTIBASE_BASE64:
		case MULTIBASE_BASE64_URL:
			status = multibase_unpadded_base64_len(data_len, &local_len);
			break;
		case MULTIBASE_BASE64_URL_PAD:
			if (data_len > (SIZE_MAX - 2U))
			{
				status = (int)MULTIBASE_ERR_OVERFLOW;
			}
			else
			{
				size_t groups;

				groups = (data_len + 2U) / 3U;
				if (groups > (SIZE_MAX / 4U))
				{
					status = (int)MULTIBASE_ERR_OVERFLOW;
				}
				else
				{
					local_len = groups * 4U;
				}
			}
			break;
		default:
			status = (int)MULTIBASE_ERR_UNSUPPORTED_BASE;
			break;
		}
	}

	if (status == (int)MULTIBASE_SUCCESS)
	{
		*encoded_len = local_len;
	}

	return status;
}

static int multibase_encode_payload(multibase_t base, const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
	int result;

	result = (int)MULTIBASE_ERR_UNSUPPORTED_BASE;
	switch (base)
	{
	case MULTIBASE_BASE16:
		result = multibase_base16_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE16_UPPER:
		result = multibase_base16_upper_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE32:
		result = multibase_base32_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE32_UPPER:
		result = multibase_base32_upper_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE58_BTC:
		result = multibase_base58_btc_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE64:
		result = multibase_base64_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE64_URL:
		result = multibase_base64_url_encode(data, data_len, out, out_len);
		break;
	case MULTIBASE_BASE64_URL_PAD:
		result = multibase_base64_url_pad_encode(data, data_len, out, out_len);
		break;
	default:
		result = (int)MULTIBASE_ERR_UNSUPPORTED_BASE;
		break;
	}

	return result;
}

static int multibase_decode_payload(multibase_t base, const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
	int result;

	result = (int)MULTIBASE_ERR_UNSUPPORTED_BASE;
	switch (base)
	{
	case MULTIBASE_BASE16:
		result = multibase_base16_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE16_UPPER:
		result = multibase_base16_upper_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE32:
		result = multibase_base32_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE32_UPPER:
		result = multibase_base32_upper_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE58_BTC:
		result = multibase_base58_btc_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE64:
		result = multibase_base64_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE64_URL:
		result = multibase_base64_url_decode(in, data_len, out, out_len);
		break;
	case MULTIBASE_BASE64_URL_PAD:
		result = multibase_base64_url_pad_decode(in, data_len, out, out_len);
		break;
	default:
		result = (int)MULTIBASE_ERR_UNSUPPORTED_BASE;
		break;
	}

	return result;
}

ptrdiff_t multibase_encode(multibase_t base, const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
	ptrdiff_t result;
	int status;
	char prefix;
	size_t payload_len;
	size_t required_len;

	result = (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER;
	status = (int)MULTIBASE_SUCCESS;
	prefix = '\0';
	payload_len = 0U;
	required_len = 0U;
	if ((out != NULL) && (out_len > 0U))
	{
		out[0] = '\0';
	}

	if ((data == NULL) || (out == NULL))
	{
		result = (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER;
	}
	else
	{
		status = multibase_get_prefix(base, &prefix);
		if (status != (int)MULTIBASE_SUCCESS)
		{
			result = (ptrdiff_t)status;
		}
		else
		{
			status = multibase_encoded_len_bound(base, data_len, &payload_len);
			if (status != (int)MULTIBASE_SUCCESS)
			{
				result = (ptrdiff_t)status;
			}
			else if (payload_len > (SIZE_MAX - 2U))
			{
				result = (ptrdiff_t)MULTIBASE_ERR_OVERFLOW;
			}
			else
			{
				required_len = payload_len + 2U;
				if (out_len < required_len)
				{
					result = (ptrdiff_t)MULTIBASE_ERR_BUFFER_TOO_SMALL;
				}
				else if ((payload_len + 1U) > (size_t)PTRDIFF_MAX)
				{
					result = (ptrdiff_t)MULTIBASE_ERR_INPUT_TOO_LARGE;
				}
				else
				{
					int payload_result;

					out[0] = prefix;
					payload_result =
						multibase_encode_payload(base, data, data_len, &out[1], out_len - 1U);
					if (payload_result < 0)
					{
						out[0] = '\0';
						result = (ptrdiff_t)payload_result;
					}
					else
					{
						size_t payload_written;
						ptrdiff_t total_written;

						payload_written = (size_t)payload_result;
						if (payload_written > payload_len)
						{
							out[0] = '\0';
							result = (ptrdiff_t)MULTIBASE_ERR_OVERFLOW;
						}
						else
						{
							out[payload_written + 1U] = '\0';
							total_written = (ptrdiff_t)payload_written;
							total_written += (ptrdiff_t)1;
							result = total_written;
						}
					}
				}
			}
		}
	}

	return result;
}

ptrdiff_t multibase_decode(multibase_t base, const char *in, uint8_t *out, size_t out_len)
{
	ptrdiff_t result;
	int status;
	char expected_prefix;
	size_t payload_len;

	result = (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER;
	status = (int)MULTIBASE_SUCCESS;
	expected_prefix = '\0';
	payload_len = 0U;
	if ((in == NULL) || (out == NULL))
	{
		result = (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER;
	}
	else if (in[0] == '\0')
	{
		if (out_len > 0U)
		{
			out[0] = 0U;
		}
		result = (ptrdiff_t)MULTIBASE_ERR_INVALID_CHARACTER;
	}
	else
	{
		status = multibase_get_prefix(base, &expected_prefix);
		if (status != (int)MULTIBASE_SUCCESS)
		{
			if (out_len > 0U)
			{
				out[0] = 0U;
			}
			result = (ptrdiff_t)status;
		}
		else if (in[0] != expected_prefix)
		{
			if (out_len > 0U)
			{
				out[0] = 0U;
			}
			result = (ptrdiff_t)MULTIBASE_ERR_INVALID_CHARACTER;
		}
		else
		{
			payload_len = strlen(&in[1]);
			if (payload_len > (size_t)PTRDIFF_MAX)
			{
				if (out_len > 0U)
				{
					out[0] = 0U;
				}
				result = (ptrdiff_t)MULTIBASE_ERR_INPUT_TOO_LARGE;
			}
			else
			{
				int payload_result;

				payload_result = multibase_decode_payload(base, &in[1], payload_len, out, out_len);
				if (payload_result < 0)
				{
					if (out_len > 0U)
					{
						out[0] = 0U;
					}
					result = (ptrdiff_t)payload_result;
				}
				else
				{
					result = (ptrdiff_t)payload_result;
				}
			}
		}
	}

	return result;
}
