#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "util/memory.h"
#include "util/net_addr.h"

#define MA_IPV4_TEXT_CAPACITY ((size_t)16U)
#define MA_IPV6_TEXT_CAPACITY ((size_t)46U)

#define MA_CODE_IP4 ((uint64_t)0x04U)
#define MA_CODE_TCP ((uint64_t)0x06U)
#define MA_CODE_IP6 ((uint64_t)0x29U)
#define MA_CODE_IP6ZONE ((uint64_t)0x2AU)
#define MA_CODE_IPCIDR ((uint64_t)0x2BU)
#define MA_CODE_PATH ((uint64_t)0x2FU)
#define MA_CODE_DNS ((uint64_t)0x35U)
#define MA_CODE_DNS4 ((uint64_t)0x36U)
#define MA_CODE_DNS6 ((uint64_t)0x37U)
#define MA_CODE_DNSADDR ((uint64_t)0x38U)
#define MA_CODE_IPFS ((uint64_t)0xE3U)
#define MA_CODE_UDP ((uint64_t)0x111U)
#define MA_CODE_UNIX ((uint64_t)0x190U)
#define MA_CODE_P2P ((uint64_t)0x1A5U)
#define MA_CODE_HTTPS ((uint64_t)0x1BBU)
#define MA_CODE_P2P_CIRCUIT ((uint64_t)0x122U)
#define MA_CODE_TLS ((uint64_t)0x1C0U)
#define MA_CODE_SNI ((uint64_t)0x1C1U)
#define MA_CODE_NOISE ((uint64_t)0x1C6U)
#define MA_CODE_QUIC ((uint64_t)0x1CCU)
#define MA_CODE_QUIC_V1 ((uint64_t)0x1CDU)
#define MA_CODE_WEBTRANSPORT ((uint64_t)0x1D1U)
#define MA_CODE_CERTHASH ((uint64_t)0x1D2U)
#define MA_CODE_WS ((uint64_t)0x1DDU)
#define MA_CODE_WSS ((uint64_t)0x1DEU)
#define MA_CODE_HTTP ((uint64_t)0x1E0U)
#define MA_CODE_HTTP_PATH ((uint64_t)0x1E1U)

#define MA_UNSIGNED_VARINT_OK 0
#define MA_UNSIGNED_VARINT_MAX_ENCODED_SIZE ((size_t)9U)

#define MA_ADDR_LEN_UNKNOWN (-1)
#define MA_ADDR_LEN_VARIABLE (-2)

int multibase_base58_btc_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len);
int multibase_base58_btc_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len);

uint64_t multicodec_code_from_name(const char *name);
const char *multicodec_name_from_code(uint64_t code);

int unsigned_varint_encode(uint64_t value, uint8_t *out, size_t out_size, size_t *written);
int unsigned_varint_decode(const uint8_t *in, size_t in_size, uint64_t *value, size_t *read);

struct multiaddr_s
{
	size_t size;
	uint8_t *bytes;
};

typedef struct
{
	uint8_t *data;
	size_t size;
	size_t capacity;
} ma_buf_t;

typedef struct
{
	uint64_t code;
	const uint8_t *addr;
	size_t addr_len;
} ma_component_t;

typedef struct
{
	const uint8_t *bytes;
	size_t length;
	size_t offset;
} ma_iter_t;

static void ma_set_error(int *err, int value)
{
	if (err != NULL)
	{
		*err = value;
	}
}

static int ma_size_add(size_t a, size_t b, size_t *out)
{
	int rc = 0;

	if (out == NULL)
	{
		rc = -1;
	}
	else if (a > (SIZE_MAX - b))
	{
		rc = -1;
	}
	else
	{
		*out = a + b;
	}

	return rc;
}

static int ma_size_mul(size_t a, size_t b, size_t *out)
{
	int rc = 0;

	if (out == NULL)
	{
		rc = -1;
	}
	else if ((a != 0U) && (b > (SIZE_MAX / a)))
	{
		rc = -1;
	}
	else
	{
		*out = a * b;
	}

	return rc;
}

static void ma_buf_init(ma_buf_t *buffer)
{
	if (buffer != NULL)
	{
		buffer->data = NULL;
		buffer->size = 0U;
		buffer->capacity = 0U;
	}
}

static void ma_buf_free(ma_buf_t *buffer)
{
	if (buffer != NULL)
	{
		if (buffer->data != NULL)
		{
			libp2p_memory_free(buffer->data);
		}
		buffer->data = NULL;
		buffer->size = 0U;
		buffer->capacity = 0U;
	}
}

static int ma_buf_ensure(ma_buf_t *buffer, size_t additional)
{
	int rc = 0;
	size_t required = 0U;

	if (buffer == NULL)
	{
		rc = -1;
	}
	else if (ma_size_add(buffer->size, additional, &required) != 0)
	{
		rc = -1;
	}
	else if (required > buffer->capacity)
	{
		size_t new_capacity = (buffer->capacity == 0U) ? 32U : buffer->capacity;
		uint8_t *new_data = NULL;
		void *raw_realloc = NULL;

		while (new_capacity < required)
		{
			if (new_capacity > (SIZE_MAX / 2U))
			{
				new_capacity = required;
			}
			else
			{
				new_capacity *= 2U;
			}
		}

		raw_realloc = libp2p_memory_realloc(buffer->data, new_capacity);
		(void)memcpy(&new_data, &raw_realloc, sizeof(new_data));
		if (new_data == NULL)
		{
			rc = -1;
		}
		else
		{
			buffer->data = new_data;
			buffer->capacity = new_capacity;
		}
	}
	else
	{
		/* already enough capacity */
	}

	return rc;
}

static int ma_buf_append(ma_buf_t *buffer, const uint8_t *src, size_t length)
{
	int rc = 0;
	size_t new_size = 0U;

	if (buffer == NULL)
	{
		rc = -1;
	}
	else if ((length > 0U) && (src == NULL))
	{
		rc = -1;
	}
	else if (ma_buf_ensure(buffer, length) != 0)
	{
		rc = -1;
	}
	else
	{
		if (length > 0U)
		{
			(void)memcpy(&buffer->data[buffer->size], src, length);
		}
		if (ma_size_add(buffer->size, length, &new_size) != 0)
		{
			rc = -1;
		}
		else
		{
			buffer->size = new_size;
		}
	}

	return rc;
}

static int ma_buf_append_byte(ma_buf_t *buffer, uint8_t value)
{
	return ma_buf_append(buffer, &value, 1U);
}

static int ma_buf_append_varint(ma_buf_t *buffer, uint64_t value)
{
	int rc = 0;
	uint8_t tmp[MA_UNSIGNED_VARINT_MAX_ENCODED_SIZE];
	size_t written = 0U;
	int varint_rc;

	varint_rc = unsigned_varint_encode(value, tmp, sizeof(tmp), &written);
	if (varint_rc != MA_UNSIGNED_VARINT_OK)
	{
		rc = -1;
	}
	else if (ma_buf_append(buffer, tmp, written) != 0)
	{
		rc = -1;
	}
	else
	{
		/* success */
	}

	return rc;
}

static int ma_protocol_addr_len(uint64_t code)
{
	int addr_len = MA_ADDR_LEN_UNKNOWN;

	switch (code)
	{
	case MA_CODE_IP4: {
		addr_len = 4;
		break;
	}
	case MA_CODE_IP6: {
		addr_len = 16;
		break;
	}
	case MA_CODE_TCP:
	case MA_CODE_UDP: {
		addr_len = 2;
		break;
	}
	case MA_CODE_IPCIDR: {
		addr_len = 1;
		break;
	}
	case MA_CODE_QUIC:
	case MA_CODE_QUIC_V1:
	case MA_CODE_WS:
	case MA_CODE_WSS:
	case MA_CODE_P2P_CIRCUIT:
	case MA_CODE_TLS:
	case MA_CODE_NOISE:
	case MA_CODE_HTTP:
	case MA_CODE_HTTPS:
	case MA_CODE_WEBTRANSPORT: {
		addr_len = 0;
		break;
	}
	case MA_CODE_DNS:
	case MA_CODE_DNS4:
	case MA_CODE_DNS6:
	case MA_CODE_DNSADDR:
	case MA_CODE_P2P:
	case MA_CODE_IPFS:
	case MA_CODE_IP6ZONE:
	case MA_CODE_SNI:
	case MA_CODE_HTTP_PATH:
	case MA_CODE_PATH:
	case MA_CODE_UNIX:
	case MA_CODE_CERTHASH: {
		addr_len = MA_ADDR_LEN_VARIABLE;
		break;
	}
	default: {
		addr_len = MA_ADDR_LEN_UNKNOWN;
		break;
	}
	}

	return addr_len;
}

static int ma_protocol_is_peer_id(uint64_t code)
{
	int rc = 0;

	if ((code == MA_CODE_P2P) || (code == MA_CODE_IPFS))
	{
		rc = 1;
	}

	return rc;
}

static int ma_protocol_has_text_address(uint64_t code)
{
	int rc = 0;

	switch (code)
	{
	case MA_CODE_DNS:
	case MA_CODE_DNS4:
	case MA_CODE_DNS6:
	case MA_CODE_DNSADDR:
	case MA_CODE_IP6ZONE:
	case MA_CODE_SNI:
	case MA_CODE_HTTP_PATH:
	case MA_CODE_PATH:
	case MA_CODE_UNIX:
	case MA_CODE_CERTHASH: {
		rc = 1;
		break;
	}
	default: {
		rc = 0;
		break;
	}
	}

	return rc;
}

static int ma_lookup_protocol_code(const char *name, size_t name_len, uint64_t *code_out)
{
	int rc = 0;
	char token[64];
	uint64_t code = 0U;
	const char *canonical = NULL;

	if ((name == NULL) || (code_out == NULL))
	{
		rc = -1;
	}
	else if ((name_len == 0U) || (name_len >= sizeof(token)))
	{
		rc = -1;
	}
	else
	{
		(void)memcpy(token, name, name_len);
		token[name_len] = '\0';

		code = multicodec_code_from_name(token);
		canonical = multicodec_name_from_code(code);
		if ((canonical == NULL) || (strcmp(canonical, token) != 0))
		{
			rc = -1;
		}
		else
		{
			*code_out = code;
		}
	}

	return rc;
}

static int ma_read_next_token(const char *input, size_t input_len, size_t *position, const char **token,
			      size_t *token_len)
{
	int rc = 0;
	size_t start = 0U;
	size_t cursor = 0U;

	if ((input == NULL) || (position == NULL) || (token == NULL) || (token_len == NULL))
	{
		rc = -1;
	}
	else if (*position >= input_len)
	{
		rc = 0;
	}
	else
	{
		start = *position;
		cursor = start;
		while ((cursor < input_len) && (input[cursor] != '/'))
		{
			cursor += 1U;
		}

		if (cursor == start)
		{
			rc = -1;
		}
		else
		{
			*token = &input[start];
			*token_len = cursor - start;
			if (cursor < input_len)
			{
				cursor += 1U;
				if (cursor == input_len)
				{
					rc = -1;
				}
				else
				{
					*position = cursor;
					rc = 1;
				}
			}
			else
			{
				*position = cursor;
				rc = 1;
			}
		}
	}

	return rc;
}

static int ma_parse_ipv4_token(const char *token, size_t token_len, uint8_t out[4])
{
	int rc = 0;
	char text[MA_IPV4_TEXT_CAPACITY];

	if ((token == NULL) || (out == NULL))
	{
		rc = -1;
	}
	else if ((token_len == 0U) || (token_len >= sizeof(text)))
	{
		rc = -1;
	}
	else
	{
		(void)memcpy(text, token, token_len);
		text[token_len] = '\0';

		if (libp2p_net_parse_ipv4(text, out) != 0)
		{
			rc = -1;
		}
		else
		{
			/* success */
		}
	}

	return rc;
}

static int ma_parse_ipv6_token(const char *token, size_t token_len, uint8_t out[16])
{
	int rc = 0;
	char text[MA_IPV6_TEXT_CAPACITY];

	if ((token == NULL) || (out == NULL))
	{
		rc = -1;
	}
	else if ((token_len == 0U) || (token_len >= sizeof(text)))
	{
		rc = -1;
	}
	else
	{
		(void)memcpy(text, token, token_len);
		text[token_len] = '\0';

		if (libp2p_net_parse_ipv6(text, out) != 0)
		{
			rc = -1;
		}
		else
		{
			/* success */
		}
	}

	return rc;
}

static int ma_parse_port_token(const char *token, size_t token_len, uint8_t out[2])
{
	int rc = 0;
	size_t idx = 0U;
	uint32_t value = 0U;

	if ((token == NULL) || (out == NULL) || (token_len == 0U) || (token_len > 5U))
	{
		rc = -1;
	}
	else
	{
		for (idx = 0U; (idx < token_len) && (rc == 0); idx += 1U)
		{
			uint32_t digit = 0U;
			if ((token[idx] < '0') || (token[idx] > '9'))
			{
				rc = -1;
			}
			else
			{
				digit = (uint32_t)(uint8_t)token[idx];
				digit = digit - (uint32_t)'0';
				value = (value * 10U) + digit;
				if (value > 65535U)
				{
					rc = -1;
				}
			}
		}

		if (rc == 0)
		{
			out[0] = (uint8_t)((value >> 8U) & 0xFFU);
			out[1] = (uint8_t)(value & 0xFFU);
		}
	}

	return rc;
}

static int ma_parse_prefix_len_token(const char *token, size_t token_len, uint8_t out[1])
{
	int rc = 0;
	size_t idx = 0U;
	uint32_t value = 0U;

	if ((token == NULL) || (out == NULL) || (token_len == 0U) || (token_len > 3U))
	{
		rc = -1;
	}
	else
	{
		for (idx = 0U; (idx < token_len) && (rc == 0); idx += 1U)
		{
			uint32_t digit = 0U;
			if ((token[idx] < '0') || (token[idx] > '9'))
			{
				rc = -1;
			}
			else
			{
				digit = (uint32_t)(uint8_t)token[idx];
				digit = digit - (uint32_t)'0';
				value = (value * 10U) + digit;
				if (value > 255U)
				{
					rc = -1;
				}
			}
		}

		if (rc == 0)
		{
			out[0] = (uint8_t)value;
		}
	}

	return rc;
}

static int ma_base58_capacity(size_t input_len, size_t *capacity_out)
{
	int rc = 0;
	size_t product = 0U;
	size_t capacity = 0U;

	if (capacity_out == NULL)
	{
		rc = -1;
	}
	else if (ma_size_mul(input_len, 138U, &product) != 0)
	{
		rc = -1;
	}
	else
	{
		capacity = (product / 100U) + 3U;
		if (capacity < 2U)
		{
			capacity = 2U;
		}
		*capacity_out = capacity;
	}

	return rc;
}

static int ma_append_decimal_u32(ma_buf_t *buffer, uint32_t value)
{
	int rc = 0;
	char digits[10];
	size_t count = 0U;
	uint32_t current = value;

	if (buffer == NULL)
	{
		rc = -1;
	}
	else
	{
		do
		{
			uint32_t remainder = current % 10U;
			digits[count] = (char)('0' + remainder);
			count += 1U;
			current /= 10U;
		}
		while (current > 0U);

		while (count > 0U)
		{
			count -= 1U;
			if (ma_buf_append(buffer, (const uint8_t *)&digits[count], 1U) != 0)
			{
				rc = -1;
				break;
			}
		}
	}

	return rc;
}

static int ma_append_fixed_address_text(ma_buf_t *buffer, uint64_t code, const uint8_t *addr, size_t addr_len)
{
	int rc = 0;

	if ((buffer == NULL) || (addr == NULL))
	{
		rc = -1;
	}
	else if ((code == MA_CODE_IP4) && (addr_len == 4U))
	{
		char text[MA_IPV4_TEXT_CAPACITY];
		if (libp2p_net_ipv4_to_text(addr, text, sizeof(text)) != 0)
		{
			rc = -1;
		}
		else if (ma_buf_append(buffer, (const uint8_t *)text, strlen(text)) != 0)
		{
			rc = -1;
		}
		else
		{
			/* success */
		}
	}
	else if ((code == MA_CODE_IP6) && (addr_len == 16U))
	{
		char text[MA_IPV6_TEXT_CAPACITY];
		if (libp2p_net_ipv6_to_text(addr, text, sizeof(text)) != 0)
		{
			rc = -1;
		}
		else if (ma_buf_append(buffer, (const uint8_t *)text, strlen(text)) != 0)
		{
			rc = -1;
		}
		else
		{
			/* success */
		}
	}
	else if ((code == MA_CODE_TCP) || (code == MA_CODE_UDP))
	{
		uint32_t port = ((uint32_t)addr[0] << 8U) | (uint32_t)addr[1];
		if ((addr_len != 2U) || (ma_append_decimal_u32(buffer, port) != 0))
		{
			rc = -1;
		}
	}
	else if ((code == MA_CODE_IPCIDR) && (addr_len == 1U))
	{
		if (ma_append_decimal_u32(buffer, (uint32_t)addr[0]) != 0)
		{
			rc = -1;
		}
	}
	else
	{
		rc = -1;
	}

	return rc;
}

static int ma_append_variable_address_text(ma_buf_t *buffer, uint64_t code, const uint8_t *addr, size_t addr_len)
{
	int rc = 0;

	if ((buffer == NULL) || ((addr_len > 0U) && (addr == NULL)))
	{
		rc = -1;
	}
	else if (ma_protocol_is_peer_id(code) != 0)
	{
		size_t out_cap = 0U;
		char *tmp = NULL;
		int written = 0;

		if (ma_base58_capacity(addr_len, &out_cap) != 0)
		{
			rc = -1;
		}
		else
		{
			void *raw_alloc = libp2p_memory_alloc(out_cap);
			(void)memcpy(&tmp, &raw_alloc, sizeof(tmp));
			if (tmp == NULL)
			{
				rc = -1;
			}
			else
			{
				written = multibase_base58_btc_encode(addr, addr_len, tmp, out_cap);
				if ((written < 0) || ((size_t)written >= out_cap))
				{
					rc = -1;
				}
				else if (ma_buf_append(buffer, (const uint8_t *)tmp, (size_t)written) != 0)
				{
					rc = -1;
				}
				else
				{
					/* success */
				}
			}
		}

		if (tmp != NULL)
		{
			libp2p_memory_free(tmp);
		}
	}
	else if (ma_protocol_has_text_address(code) != 0)
	{
		size_t idx = 0U;

		for (idx = 0U; idx < addr_len; idx += 1U)
		{
			if ((addr[idx] == (uint8_t)'/') || (addr[idx] == (uint8_t)'\0'))
			{
				rc = -1;
				break;
			}
		}

		if ((rc == 0) && (ma_buf_append(buffer, addr, addr_len) != 0))
		{
			rc = -1;
		}
	}
	else
	{
		rc = -1;
	}

	return rc;
}

static int ma_append_address_from_token(uint64_t code, const char *token, size_t token_len, ma_buf_t *buffer)
{
	int rc = MULTIADDR_SUCCESS;
	int addr_len = ma_protocol_addr_len(code);

	if ((token == NULL) || (buffer == NULL) || (token_len == 0U))
	{
		rc = MULTIADDR_ERR_INVALID_STRING;
	}
	else if (addr_len > 0)
	{
		uint8_t fixed[16];
		int parse_rc = -1;

		(void)memset(fixed, 0, sizeof(fixed));
		if (code == MA_CODE_IP4)
		{
			parse_rc = ma_parse_ipv4_token(token, token_len, fixed);
		}
		else if (code == MA_CODE_IP6)
		{
			parse_rc = ma_parse_ipv6_token(token, token_len, fixed);
		}
		else if ((code == MA_CODE_TCP) || (code == MA_CODE_UDP))
		{
			parse_rc = ma_parse_port_token(token, token_len, fixed);
		}
		else if (code == MA_CODE_IPCIDR)
		{
			parse_rc = ma_parse_prefix_len_token(token, token_len, fixed);
		}
		else
		{
			parse_rc = -1;
		}

		if (parse_rc != 0)
		{
			rc = MULTIADDR_ERR_INVALID_STRING;
		}
		else if (ma_buf_append(buffer, fixed, (size_t)addr_len) != 0)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			/* success */
		}
	}
	else if (addr_len == MA_ADDR_LEN_VARIABLE)
	{
		if (ma_protocol_is_peer_id(code) != 0)
		{
			uint8_t *decoded = NULL;
			int decoded_len = 0;
			void *raw_alloc = NULL;

			raw_alloc = libp2p_memory_alloc(token_len);
			(void)memcpy(&decoded, &raw_alloc, sizeof(decoded));
			if (decoded == NULL)
			{
				rc = MULTIADDR_ERR_ALLOC_FAILURE;
			}
			else
			{
				decoded_len = multibase_base58_btc_decode(token, token_len, decoded, token_len);
				if (decoded_len <= 0)
				{
					rc = MULTIADDR_ERR_INVALID_STRING;
				}
				else if (ma_buf_append_varint(buffer, (uint64_t)decoded_len) != 0)
				{
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else if (ma_buf_append(buffer, decoded, (size_t)decoded_len) != 0)
				{
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else
				{
					/* success */
				}
			}

			if (decoded != NULL)
			{
				libp2p_memory_free(decoded);
			}
		}
		else if (ma_protocol_has_text_address(code) != 0)
		{
			if (ma_buf_append_varint(buffer, (uint64_t)token_len) != 0)
			{
				rc = MULTIADDR_ERR_ALLOC_FAILURE;
			}
			else if (ma_buf_append(buffer, (const uint8_t *)token, token_len) != 0)
			{
				rc = MULTIADDR_ERR_ALLOC_FAILURE;
			}
			else
			{
				/* success */
			}
		}
		else
		{
			rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
		}
	}
	else
	{
		rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
	}

	return rc;
}

static int ma_iter_next(ma_iter_t *iter, ma_component_t *component)
{
	int rc = 0;
	int varint_rc;
	uint64_t code = 0U;
	size_t code_len = 0U;
	size_t cursor = 0U;
	int addr_len = MA_ADDR_LEN_UNKNOWN;

	if ((iter == NULL) || (component == NULL))
	{
		rc = MULTIADDR_ERR_INVALID_DATA;
	}
	else if ((iter->bytes == NULL) && (iter->length != 0U))
	{
		rc = MULTIADDR_ERR_INVALID_DATA;
	}
	else if (iter->offset > iter->length)
	{
		rc = MULTIADDR_ERR_INVALID_DATA;
	}
	else if (iter->offset == iter->length)
	{
		rc = 0;
	}
	else
	{
		varint_rc = unsigned_varint_decode(&iter->bytes[iter->offset], iter->length - iter->offset, &code,
						   &code_len);
		if (varint_rc != MA_UNSIGNED_VARINT_OK)
		{
			rc = MULTIADDR_ERR_INVALID_DATA;
		}
		else if (ma_size_add(iter->offset, code_len, &cursor) != 0)
		{
			rc = MULTIADDR_ERR_INVALID_DATA;
		}
		else if (multicodec_name_from_code(code) == NULL)
		{
			rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
		}
		else
		{
			addr_len = ma_protocol_addr_len(code);
			if (addr_len == MA_ADDR_LEN_UNKNOWN)
			{
				rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
			}
			else if (addr_len >= 0)
			{
				size_t component_end = 0U;
				if (ma_size_add(cursor, (size_t)addr_len, &component_end) != 0)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else if (component_end > iter->length)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else
				{
					component->code = code;
					component->addr = &iter->bytes[cursor];
					component->addr_len = (size_t)addr_len;
					iter->offset = component_end;
					rc = 1;
				}
			}
			else
			{
				uint64_t payload_len_u64 = 0U;
				size_t payload_len_len = 0U;
				size_t payload_len_offset = cursor;
				size_t payload_offset = 0U;
				size_t payload_end = 0U;

				varint_rc = unsigned_varint_decode(&iter->bytes[payload_len_offset],
								   iter->length - payload_len_offset, &payload_len_u64,
								   &payload_len_len);
				if (varint_rc != MA_UNSIGNED_VARINT_OK)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else if (payload_len_u64 > (uint64_t)SIZE_MAX)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else if (ma_size_add(payload_len_offset, payload_len_len, &payload_offset) != 0)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else if (ma_size_add(payload_offset, (size_t)payload_len_u64, &payload_end) != 0)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else if (payload_end > iter->length)
				{
					rc = MULTIADDR_ERR_INVALID_DATA;
				}
				else
				{
					component->code = code;
					component->addr = &iter->bytes[payload_offset];
					component->addr_len = (size_t)payload_len_u64;
					iter->offset = payload_end;
					rc = 1;
				}
			}
		}
	}

	return rc;
}

static int ma_validate_bytes(const uint8_t *bytes, size_t length)
{
	int rc = MULTIADDR_SUCCESS;
	ma_iter_t iter;
	ma_component_t component;

	iter.bytes = bytes;
	iter.length = length;
	iter.offset = 0U;

	do
	{
		rc = ma_iter_next(&iter, &component);
	}
	while (rc > 0);

	if (rc == 0)
	{
		rc = MULTIADDR_SUCCESS;
	}

	return rc;
}

static int ma_parse_components(const multiaddr_t *addr, ma_component_t **out_list, size_t *out_count)
{
	int rc = MULTIADDR_SUCCESS;
	ma_iter_t iter;
	ma_component_t component;
	ma_component_t *list = NULL;
	size_t count = 0U;
	size_t capacity = 0U;

	if ((addr == NULL) || (out_list == NULL) || (out_count == NULL))
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		iter.bytes = addr->bytes;
		iter.length = addr->size;
		iter.offset = 0U;

		do
		{
			rc = ma_iter_next(&iter, &component);
			if (rc > 0)
			{
				if (count == capacity)
				{
					size_t new_capacity = (capacity == 0U) ? 4U : (capacity * 2U);
					size_t new_bytes = 0U;
					ma_component_t *tmp = NULL;

					if (ma_size_mul(new_capacity, sizeof(ma_component_t), &new_bytes) != 0)
					{
						rc = MULTIADDR_ERR_ALLOC_FAILURE;
					}
					else
					{
						void *raw_realloc = libp2p_memory_realloc(list, new_bytes);
						(void)memcpy(&tmp, &raw_realloc, sizeof(tmp));
						if (tmp == NULL)
						{
							rc = MULTIADDR_ERR_ALLOC_FAILURE;
						}
						else
						{
							list = tmp;
							capacity = new_capacity;
						}
					}
				}

				if (rc > 0)
				{
					list[count] = component;
					count += 1U;
				}
			}
		}
		while (rc > 0);

		if (rc == 0)
		{
			*out_list = list;
			*out_count = count;
			rc = MULTIADDR_SUCCESS;
		}
		else
		{
			if (list != NULL)
			{
				libp2p_memory_free(list);
			}
			rc = MULTIADDR_ERR_INVALID_DATA;
		}
	}

	return rc;
}

static multiaddr_t *ma_build_from_components(const ma_component_t *list, size_t count, int *err)
{
	multiaddr_t *result = NULL;
	ma_buf_t buffer;
	int rc = MULTIADDR_SUCCESS;
	size_t idx = 0U;

	ma_buf_init(&buffer);

	for (idx = 0U; (idx < count) && (rc == MULTIADDR_SUCCESS); idx += 1U)
	{
		int addr_len = ma_protocol_addr_len(list[idx].code);

		if (ma_buf_append_varint(&buffer, list[idx].code) != 0)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}

		if (addr_len >= 0)
		{
			if (list[idx].addr_len != (size_t)addr_len)
			{
				rc = MULTIADDR_ERR_INVALID_DATA;
			}
			if ((list[idx].addr_len > 0U) &&
			    (ma_buf_append(&buffer, list[idx].addr, list[idx].addr_len) != 0))
			{
				rc = MULTIADDR_ERR_ALLOC_FAILURE;
			}
		}
		else if (addr_len == MA_ADDR_LEN_VARIABLE)
		{
			if (ma_buf_append_varint(&buffer, (uint64_t)list[idx].addr_len) != 0)
			{
				rc = MULTIADDR_ERR_ALLOC_FAILURE;
			}
			if ((list[idx].addr_len > 0U) &&
			    (ma_buf_append(&buffer, list[idx].addr, list[idx].addr_len) != 0))
			{
				rc = MULTIADDR_ERR_ALLOC_FAILURE;
			}
		}
		else
		{
			rc = MULTIADDR_ERR_INVALID_DATA;
		}
	}

	if (rc == MULTIADDR_SUCCESS)
	{
		void *raw_alloc = libp2p_memory_alloc(sizeof(multiaddr_t));
		(void)memcpy(&result, &raw_alloc, sizeof(result));
		if (result == NULL)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			result->size = buffer.size;
			result->bytes = buffer.data;
			ma_set_error(err, MULTIADDR_SUCCESS);
		}
	}

	if (rc != MULTIADDR_SUCCESS)
	{
		ma_buf_free(&buffer);
		ma_set_error(err, rc);
	}

	return result;
}

multiaddr_t *multiaddr_new_from_str(const char *str, int *err)
{
	multiaddr_t *result = NULL;
	ma_buf_t buffer;
	int rc = MULTIADDR_SUCCESS;
	size_t input_len = 0U;
	size_t position = 0U;

	ma_set_error(err, MULTIADDR_SUCCESS);
	ma_buf_init(&buffer);

	if (str == NULL)
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		input_len = strlen(str);
		if ((input_len == 0U) || (str[0] != '/'))
		{
			rc = MULTIADDR_ERR_INVALID_STRING;
		}
		else
		{
			position = 1U;
			while ((position < input_len) && (rc == MULTIADDR_SUCCESS))
			{
				const char *proto_token = NULL;
				size_t proto_len = 0U;
				const char *addr_token = NULL;
				size_t addr_len = 0U;
				uint64_t code = 0U;
				int tok_rc;
				int proto_addr_len;

				tok_rc = ma_read_next_token(str, input_len, &position, &proto_token, &proto_len);
				if (tok_rc <= 0)
				{
					rc = MULTIADDR_ERR_INVALID_STRING;
				}
				else if (ma_lookup_protocol_code(proto_token, proto_len, &code) != 0)
				{
					rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
				}
				else if (ma_buf_append_varint(&buffer, code) != 0)
				{
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else
				{
					proto_addr_len = ma_protocol_addr_len(code);
					if (proto_addr_len == MA_ADDR_LEN_UNKNOWN)
					{
						rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
					}
					else if (proto_addr_len == 0)
					{
						/* no address token */
					}
					else
					{
						tok_rc = ma_read_next_token(str, input_len, &position, &addr_token,
									    &addr_len);
						if (tok_rc <= 0)
						{
							rc = MULTIADDR_ERR_INVALID_STRING;
						}
						else
						{
							rc = ma_append_address_from_token(code, addr_token, addr_len,
											  &buffer);
						}
					}
				}
			}
		}
	}

	if (rc == MULTIADDR_SUCCESS)
	{
		int validate_rc = ma_validate_bytes(buffer.data, buffer.size);
		if (validate_rc != MULTIADDR_SUCCESS)
		{
			rc = validate_rc;
		}
	}

	if (rc == MULTIADDR_SUCCESS)
	{
		void *raw_alloc = libp2p_memory_alloc(sizeof(multiaddr_t));
		(void)memcpy(&result, &raw_alloc, sizeof(result));
		if (result == NULL)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			result->size = buffer.size;
			result->bytes = buffer.data;
		}
	}

	if (rc != MULTIADDR_SUCCESS)
	{
		ma_buf_free(&buffer);
		ma_set_error(err, rc);
	}

	return result;
}

multiaddr_t *multiaddr_new_from_bytes(const uint8_t *bytes, size_t length, int *err)
{
	multiaddr_t *result = NULL;
	int rc = MULTIADDR_SUCCESS;

	ma_set_error(err, MULTIADDR_SUCCESS);

	if (bytes == NULL)
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else if (ma_validate_bytes(bytes, length) != MULTIADDR_SUCCESS)
	{
		rc = MULTIADDR_ERR_INVALID_DATA;
	}
	else
	{
		void *raw_alloc = libp2p_memory_alloc(sizeof(multiaddr_t));
		(void)memcpy(&result, &raw_alloc, sizeof(result));
		if (result == NULL)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			result->size = length;
			result->bytes = NULL;
			if (length > 0U)
			{
				raw_alloc = libp2p_memory_alloc(length);
				(void)memcpy(&result->bytes, &raw_alloc, sizeof(result->bytes));
				if (result->bytes == NULL)
				{
					libp2p_memory_free(result);
					result = NULL;
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else
				{
					(void)memcpy(result->bytes, bytes, length);
				}
			}
		}
	}

	if (rc != MULTIADDR_SUCCESS)
	{
		ma_set_error(err, rc);
	}

	return result;
}

multiaddr_t *multiaddr_copy(const multiaddr_t *addr, int *err)
{
	multiaddr_t *result = NULL;
	int rc = MULTIADDR_SUCCESS;

	ma_set_error(err, MULTIADDR_SUCCESS);

	if (addr == NULL)
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		void *raw_alloc = libp2p_memory_alloc(sizeof(multiaddr_t));
		(void)memcpy(&result, &raw_alloc, sizeof(result));
		if (result == NULL)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			result->size = addr->size;
			result->bytes = NULL;
			if (addr->size > 0U)
			{
				raw_alloc = libp2p_memory_alloc(addr->size);
				(void)memcpy(&result->bytes, &raw_alloc, sizeof(result->bytes));
				if (result->bytes == NULL)
				{
					libp2p_memory_free(result);
					result = NULL;
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else
				{
					(void)memcpy(result->bytes, addr->bytes, addr->size);
				}
			}
		}
	}

	if (rc != MULTIADDR_SUCCESS)
	{
		ma_set_error(err, rc);
	}

	return result;
}

void multiaddr_free(multiaddr_t *addr)
{
	if (addr != NULL)
	{
		if (addr->bytes != NULL)
		{
			libp2p_memory_free(addr->bytes);
		}
		libp2p_memory_free(addr);
	}
}

int multiaddr_get_bytes(const multiaddr_t *addr, uint8_t *buffer, size_t buffer_len)
{
	int rc = MULTIADDR_SUCCESS;

	if ((addr == NULL) || (buffer == NULL))
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else if (addr->size > buffer_len)
	{
		rc = MULTIADDR_ERR_BUFFER_TOO_SMALL;
	}
	else if (addr->size > (size_t)INT_MAX)
	{
		rc = MULTIADDR_ERR_INVALID_DATA;
	}
	else
	{
		if (addr->size > 0U)
		{
			(void)memcpy(buffer, addr->bytes, addr->size);
		}
		rc = (int)addr->size;
	}

	return rc;
}

char *multiaddr_to_str(const multiaddr_t *addr, int *err)
{
	char *result = NULL;
	int rc = MULTIADDR_SUCCESS;
	ma_buf_t buffer;
	ma_iter_t iter;

	ma_set_error(err, MULTIADDR_SUCCESS);
	ma_buf_init(&buffer);

	if (addr == NULL)
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		iter.bytes = addr->bytes;
		iter.length = addr->size;
		iter.offset = 0U;

		{
			int done = 0;
			while ((rc == MULTIADDR_SUCCESS) && (done == 0))
			{
				ma_component_t component;
				int next_rc = ma_iter_next(&iter, &component);

				if (next_rc == 0)
				{
					done = 1;
				}
				else if (next_rc < 0)
				{
					rc = (next_rc == MULTIADDR_ERR_UNKNOWN_PROTOCOL)
						     ? MULTIADDR_ERR_UNKNOWN_PROTOCOL
						     : MULTIADDR_ERR_INVALID_DATA;
				}
				else if (ma_buf_append_byte(&buffer, (uint8_t)'/') != 0)
				{
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else
				{
					const char *name = multicodec_name_from_code(component.code);
					if (name == NULL)
					{
						rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
					}
					else if (ma_buf_append(&buffer, (const uint8_t *)name, strlen(name)) != 0)
					{
						rc = MULTIADDR_ERR_ALLOC_FAILURE;
					}
					else if (component.addr_len > 0U)
					{
						int addr_len_type = ma_protocol_addr_len(component.code);
						if (ma_buf_append_byte(&buffer, (uint8_t)'/') != 0)
						{
							rc = MULTIADDR_ERR_ALLOC_FAILURE;
						}
						else if (addr_len_type > 0)
						{
							if (ma_append_fixed_address_text(&buffer, component.code,
											 component.addr,
											 component.addr_len) != 0)
							{
								rc = MULTIADDR_ERR_INVALID_DATA;
							}
						}
						else if (addr_len_type == MA_ADDR_LEN_VARIABLE)
						{
							if (ma_append_variable_address_text(&buffer, component.code,
											    component.addr,
											    component.addr_len) != 0)
							{
								rc = MULTIADDR_ERR_INVALID_DATA;
							}
						}
						else
						{
							rc = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
						}
					}
					else
					{
						/* protocol has no address bytes */
					}
				}
			}
		}
	}

	if (rc == MULTIADDR_SUCCESS)
	{
		if (ma_buf_append_byte(&buffer, (uint8_t)'\0') != 0)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			result = (char *)buffer.data;
		}
	}

	if (rc != MULTIADDR_SUCCESS)
	{
		ma_buf_free(&buffer);
		ma_set_error(err, rc);
	}

	return result;
}

size_t multiaddr_nprotocols(const multiaddr_t *addr)
{
	size_t count = 0U;

	if (addr != NULL)
	{
		ma_iter_t iter;
		ma_component_t component;
		int rc;

		iter.bytes = addr->bytes;
		iter.length = addr->size;
		iter.offset = 0U;

		do
		{
			rc = ma_iter_next(&iter, &component);
			if (rc > 0)
			{
				count += 1U;
			}
			else if (rc < 0)
			{
				count = 0U;
			}
			else
			{
				/* done */
			}
		}
		while (rc > 0);
	}

	return count;
}

int multiaddr_get_protocol_code(const multiaddr_t *addr, size_t index, uint64_t *proto_out)
{
	int rc = MULTIADDR_SUCCESS;
	size_t current = 0U;

	if ((addr == NULL) || (proto_out == NULL))
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		ma_iter_t iter;
		ma_component_t component;

		iter.bytes = addr->bytes;
		iter.length = addr->size;
		iter.offset = 0U;

		do
		{
			rc = ma_iter_next(&iter, &component);
			if (rc > 0)
			{
				if (current == index)
				{
					*proto_out = component.code;
					rc = MULTIADDR_SUCCESS;
					break;
				}
				current += 1U;
			}
			else if (rc < 0)
			{
				rc = MULTIADDR_ERR_INVALID_DATA;
			}
			else
			{
				rc = MULTIADDR_ERR_INVALID_DATA;
			}
		}
		while (rc > 0);
	}

	return rc;
}

int multiaddr_get_address_bytes(const multiaddr_t *addr, size_t index, uint8_t *buf, size_t *buf_len)
{
	int rc = MULTIADDR_SUCCESS;
	size_t current = 0U;

	if ((addr == NULL) || (buf == NULL) || (buf_len == NULL))
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		ma_iter_t iter;
		ma_component_t component;

		iter.bytes = addr->bytes;
		iter.length = addr->size;
		iter.offset = 0U;

		do
		{
			rc = ma_iter_next(&iter, &component);
			if (rc > 0)
			{
				if (current == index)
				{
					if (*buf_len < component.addr_len)
					{
						*buf_len = component.addr_len;
						rc = MULTIADDR_ERR_BUFFER_TOO_SMALL;
					}
					else
					{
						if (component.addr_len > 0U)
						{
							(void)memcpy(buf, component.addr, component.addr_len);
						}
						*buf_len = component.addr_len;
						rc = MULTIADDR_SUCCESS;
					}
					break;
				}
				current += 1U;
			}
			else if (rc < 0)
			{
				rc = MULTIADDR_ERR_INVALID_DATA;
			}
			else
			{
				rc = MULTIADDR_ERR_INVALID_DATA;
			}
		}
		while (rc > 0);
	}

	return rc;
}

multiaddr_t *multiaddr_encapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err)
{
	multiaddr_t *result = NULL;
	int rc = MULTIADDR_SUCCESS;
	size_t combined_size = 0U;

	ma_set_error(err, MULTIADDR_SUCCESS);

	if ((addr == NULL) || (sub == NULL))
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else if ((ma_validate_bytes(addr->bytes, addr->size) != MULTIADDR_SUCCESS) ||
		 (ma_validate_bytes(sub->bytes, sub->size) != MULTIADDR_SUCCESS))
	{
		rc = MULTIADDR_ERR_INVALID_DATA;
	}
	else if (ma_size_add(addr->size, sub->size, &combined_size) != 0)
	{
		rc = MULTIADDR_ERR_ALLOC_FAILURE;
	}
	else
	{
		void *raw_alloc = libp2p_memory_alloc(sizeof(multiaddr_t));
		(void)memcpy(&result, &raw_alloc, sizeof(result));
		if (result == NULL)
		{
			rc = MULTIADDR_ERR_ALLOC_FAILURE;
		}
		else
		{
			result->size = combined_size;
			result->bytes = NULL;
			if (combined_size > 0U)
			{
				raw_alloc = libp2p_memory_alloc(combined_size);
				(void)memcpy(&result->bytes, &raw_alloc, sizeof(result->bytes));
				if (result->bytes == NULL)
				{
					libp2p_memory_free(result);
					result = NULL;
					rc = MULTIADDR_ERR_ALLOC_FAILURE;
				}
				else
				{
					if (addr->size > 0U)
					{
						(void)memcpy(result->bytes, addr->bytes, addr->size);
					}
					if (sub->size > 0U)
					{
						(void)memcpy(&result->bytes[addr->size], sub->bytes, sub->size);
					}
				}
			}
		}
	}

	if (rc != MULTIADDR_SUCCESS)
	{
		ma_set_error(err, rc);
	}

	return result;
}

multiaddr_t *multiaddr_decapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err)
{
	multiaddr_t *result = NULL;
	int rc = MULTIADDR_SUCCESS;
	ma_component_t *addr_components = NULL;
	ma_component_t *sub_components = NULL;
	size_t addr_count = 0U;
	size_t sub_count = 0U;
	size_t best_match = 0U;
	int found = 0;
	size_t i = 0U;

	ma_set_error(err, MULTIADDR_SUCCESS);

	if ((addr == NULL) || (sub == NULL))
	{
		rc = MULTIADDR_ERR_NULL_POINTER;
	}
	else
	{
		rc = ma_parse_components(addr, &addr_components, &addr_count);
		if (rc == MULTIADDR_SUCCESS)
		{
			rc = ma_parse_components(sub, &sub_components, &sub_count);
		}
		if (rc != MULTIADDR_SUCCESS)
		{
			rc = MULTIADDR_ERR_INVALID_DATA;
		}
		else if ((sub_count == 0U) || (sub_count > addr_count))
		{
			rc = MULTIADDR_ERR_NO_MATCH;
		}
		else
		{
			for (i = 0U; i <= (addr_count - sub_count); i += 1U)
			{
				size_t j = 0U;
				int match = 1;

				for (j = 0U; (j < sub_count) && (match != 0); j += 1U)
				{
					const ma_component_t *a = &addr_components[i + j];
					const ma_component_t *b = &sub_components[j];

					if ((a->code != b->code) || (a->addr_len != b->addr_len))
					{
						match = 0;
					}
					else if ((a->addr_len > 0U) && (memcmp(a->addr, b->addr, a->addr_len) != 0))
					{
						match = 0;
					}
					else
					{
						/* matched this component */
					}
				}

				if (match != 0)
				{
					best_match = i;
					found = 1;
				}
			}

			if (found == 0)
			{
				rc = MULTIADDR_ERR_NO_MATCH;
			}
			else
			{
				result = ma_build_from_components(addr_components, best_match, err);
				if (result == NULL)
				{
					if ((err != NULL) && (*err == MULTIADDR_SUCCESS))
					{
						ma_set_error(err, MULTIADDR_ERR_ALLOC_FAILURE);
					}
				}
			}
		}
	}

	if (addr_components != NULL)
	{
		libp2p_memory_free(addr_components);
	}
	if (sub_components != NULL)
	{
		libp2p_memory_free(sub_components);
	}

	if ((rc != MULTIADDR_SUCCESS) && (result == NULL))
	{
		ma_set_error(err, rc);
	}

	return result;
}
