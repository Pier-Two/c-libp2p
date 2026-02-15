#include "multiformats/multiaddr/multiaddr.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_CODE_IP4 ((uint64_t)0x04U)
#define TEST_CODE_TCP ((uint64_t)0x06U)
#define TEST_CODE_WS ((uint64_t)0x01DDU)

static void print_result(const char *name, int passed, const char *detail)
{
	if (passed != 0)
	{
		printf("TEST: %-60s | PASS\n", name);
	}
	else
	{
		printf("TEST: %-60s | FAIL: %s\n", name, detail);
	}
}

static int expect_true(int condition, const char *name, const char *detail)
{
	print_result(name, condition, detail);
	return (condition != 0) ? 0 : 1;
}

static int expect_roundtrip(const char *input, const char *expected, const char *name)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *addr = multiaddr_new_from_str(input, &err);

	failures += expect_true((addr != NULL) && (err == MULTIADDR_SUCCESS), name, "multiaddr_new_from_str failed");

	if (addr != NULL)
	{
		char *text = multiaddr_to_str(addr, &err);
		failures += expect_true((text != NULL) && (err == MULTIADDR_SUCCESS), "multiaddr_to_str after parse",
					"multiaddr_to_str failed");
		if (text != NULL)
		{
			failures += expect_true(strcmp(text, expected) == 0, "multiaddr roundtrip text",
						"roundtrip text mismatch");
			free(text);
		}
		multiaddr_free(addr);
	}

	return failures;
}

static int test_new_from_str_valid(void)
{
	int failures = 0;

	failures += expect_roundtrip("/ip4/127.0.0.1/tcp/80", "/ip4/127.0.0.1/tcp/80", "parse ip4/tcp");
	failures += expect_roundtrip("/ip6/::1/udp/4001/quic-v1", "/ip6/::1/udp/4001/quic-v1", "parse ip6/udp/quic-v1");
	failures += expect_roundtrip("/dns4/example.com/tcp/443", "/dns4/example.com/tcp/443", "parse dns4/tcp");
	failures += expect_roundtrip("/ip4/127.0.0.1/tcp/80/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
				     "/ip4/127.0.0.1/tcp/80/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
				     "parse p2p peer id");
	failures += expect_roundtrip("/ip6/fe80::1/ip6zone/en0/udp/4001/quic-v1",
				     "/ip6/fe80::1/ip6zone/en0/udp/4001/quic-v1", "parse ip6zone address");

	return failures;
}

static int test_new_from_str_invalid(void)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *addr = NULL;

	addr = multiaddr_new_from_str(NULL, &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_NULL_POINTER), "new_from_str NULL input",
				"expected NULL_POINTER error");

	addr = multiaddr_new_from_str("ip4/127.0.0.1/tcp/80", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_INVALID_STRING),
				"new_from_str missing leading slash", "expected INVALID_STRING error");

	addr = multiaddr_new_from_str("/ip4", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_INVALID_STRING),
				"new_from_str missing protocol address", "expected INVALID_STRING error");

	addr = multiaddr_new_from_str("/ip4/127.0.0.1/", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_INVALID_STRING), "new_from_str trailing slash",
				"expected INVALID_STRING error");

	addr = multiaddr_new_from_str("/ip4/999.0.0.1/tcp/80", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_INVALID_STRING), "new_from_str invalid ipv4",
				"expected INVALID_STRING error");

	addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/70000", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_INVALID_STRING), "new_from_str invalid port",
				"expected INVALID_STRING error");

	addr = multiaddr_new_from_str("/unknownproto/value", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_UNKNOWN_PROTOCOL),
				"new_from_str unknown protocol", "expected UNKNOWN_PROTOCOL error");

	addr = multiaddr_new_from_str("/p2p/not_base58###", &err);
	failures += expect_true((addr == NULL) && (err == MULTIADDR_ERR_INVALID_STRING), "new_from_str invalid p2p id",
				"expected INVALID_STRING error");

	return failures;
}

static int test_new_from_bytes(void)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *from_str = NULL;
	multiaddr_t *from_bytes = NULL;
	uint8_t bytes[256];
	int wrote = 0;

	from_str = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
	failures += expect_true((from_str != NULL) && (err == MULTIADDR_SUCCESS), "new_from_bytes setup source",
				"failed to create source multiaddr");

	if (from_str != NULL)
	{
		wrote = multiaddr_get_bytes(from_str, bytes, sizeof(bytes));
		failures +=
			expect_true(wrote > 0, "new_from_bytes setup get bytes", "failed to serialize source bytes");

		if (wrote > 0)
		{
			from_bytes = multiaddr_new_from_bytes(bytes, (size_t)wrote, &err);
			failures += expect_true((from_bytes != NULL) && (err == MULTIADDR_SUCCESS),
						"new_from_bytes valid", "failed to parse serialized bytes");

			if (from_bytes != NULL)
			{
				char *text = multiaddr_to_str(from_bytes, &err);
				failures += expect_true((text != NULL) && (strcmp(text, "/ip4/127.0.0.1/tcp/80") == 0),
							"new_from_bytes roundtrip text", "roundtrip text mismatch");
				free(text);
				multiaddr_free(from_bytes);
			}
		}
		multiaddr_free(from_str);
	}

	from_bytes = multiaddr_new_from_bytes(NULL, 8U, &err);
	failures += expect_true((from_bytes == NULL) && (err == MULTIADDR_ERR_NULL_POINTER),
				"new_from_bytes NULL bytes", "expected NULL_POINTER error");

	{
		const uint8_t invalid_truncated[] = {0x04U};
		from_bytes = multiaddr_new_from_bytes(invalid_truncated, sizeof(invalid_truncated), &err);
		failures += expect_true((from_bytes == NULL) && (err == MULTIADDR_ERR_INVALID_DATA),
					"new_from_bytes truncated ip4", "expected INVALID_DATA error");
	}

	{
		const uint8_t invalid_unknown[] = {0x50U};
		from_bytes = multiaddr_new_from_bytes(invalid_unknown, sizeof(invalid_unknown), &err);
		failures += expect_true((from_bytes == NULL) && (err == MULTIADDR_ERR_INVALID_DATA),
					"new_from_bytes unknown protocol", "expected INVALID_DATA error");
	}

	return failures;
}

static int test_copy_and_get_bytes(void)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);

	failures += expect_true((addr != NULL) && (err == MULTIADDR_SUCCESS), "copy/get_bytes setup",
				"failed to create multiaddr");

	if (addr != NULL)
	{
		multiaddr_t *copy = multiaddr_copy(addr, &err);
		failures += expect_true((copy != NULL) && (err == MULTIADDR_SUCCESS), "multiaddr_copy valid",
					"copy failed");

		if (copy != NULL)
		{
			char *s1 = multiaddr_to_str(addr, &err);
			char *s2 = multiaddr_to_str(copy, &err);
			failures += expect_true((s1 != NULL) && (s2 != NULL) && (strcmp(s1, s2) == 0),
						"multiaddr_copy equivalent", "copy text mismatch");
			free(s1);
			free(s2);
			multiaddr_free(copy);
		}

		{
			uint8_t tiny[2];
			int rc = multiaddr_get_bytes(addr, tiny, sizeof(tiny));
			failures += expect_true(rc == MULTIADDR_ERR_BUFFER_TOO_SMALL,
						"multiaddr_get_bytes small buffer", "expected BUFFER_TOO_SMALL");
		}

		{
			uint8_t out[128];
			int rc = multiaddr_get_bytes(addr, out, sizeof(out));
			failures += expect_true(rc > 0, "multiaddr_get_bytes valid", "expected positive byte count");
		}

		{
			uint8_t out[128];
			int rc = multiaddr_get_bytes(NULL, out, sizeof(out));
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "multiaddr_get_bytes NULL addr",
						"expected NULL_POINTER error");

			rc = multiaddr_get_bytes(addr, NULL, sizeof(out));
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "multiaddr_get_bytes NULL buffer",
						"expected NULL_POINTER error");
		}

		multiaddr_free(addr);
	}

	{
		multiaddr_t *copy = multiaddr_copy(NULL, &err);
		failures += expect_true((copy == NULL) && (err == MULTIADDR_ERR_NULL_POINTER),
					"multiaddr_copy NULL input", "expected NULL_POINTER error");
	}

	return failures;
}

static int test_accessors(void)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80/ws", &err);

	failures += expect_true((addr != NULL) && (err == MULTIADDR_SUCCESS), "accessors setup",
				"failed to create multiaddr");

	if (addr != NULL)
	{
		size_t n = multiaddr_nprotocols(addr);
		failures += expect_true(n == 3U, "multiaddr_nprotocols", "expected 3 protocols");

		{
			uint64_t code = 0U;
			int rc = multiaddr_get_protocol_code(addr, 0U, &code);
			failures += expect_true((rc == MULTIADDR_SUCCESS) && (code == TEST_CODE_IP4),
						"protocol code index 0", "expected ip4 code");

			rc = multiaddr_get_protocol_code(addr, 1U, &code);
			failures += expect_true((rc == MULTIADDR_SUCCESS) && (code == TEST_CODE_TCP),
						"protocol code index 1", "expected tcp code");

			rc = multiaddr_get_protocol_code(addr, 2U, &code);
			failures += expect_true((rc == MULTIADDR_SUCCESS) && (code == TEST_CODE_WS),
						"protocol code index 2", "expected ws code");

			rc = multiaddr_get_protocol_code(addr, 3U, &code);
			failures += expect_true(rc == MULTIADDR_ERR_INVALID_DATA, "protocol code invalid index",
						"expected INVALID_DATA");
		}

		{
			uint8_t out[16];
			size_t out_len = 2U;
			int rc = multiaddr_get_address_bytes(addr, 0U, out, &out_len);
			failures += expect_true((rc == MULTIADDR_ERR_BUFFER_TOO_SMALL) && (out_len == 4U),
						"address bytes short buffer index 0", "expected required length 4");

			out_len = 4U;
			rc = multiaddr_get_address_bytes(addr, 0U, out, &out_len);
			failures += expect_true((rc == MULTIADDR_SUCCESS) && (out_len == 4U) && (out[0] == 127U) &&
							(out[1] == 0U) && (out[2] == 0U) && (out[3] == 1U),
						"address bytes index 0", "unexpected ip4 bytes");

			out_len = 1U;
			rc = multiaddr_get_address_bytes(addr, 1U, out, &out_len);
			failures += expect_true((rc == MULTIADDR_ERR_BUFFER_TOO_SMALL) && (out_len == 2U),
						"address bytes short buffer index 1", "expected required length 2");

			out_len = 2U;
			rc = multiaddr_get_address_bytes(addr, 1U, out, &out_len);
			failures += expect_true((rc == MULTIADDR_SUCCESS) && (out_len == 2U) && (out[0] == 0U) &&
							(out[1] == 80U),
						"address bytes index 1", "unexpected tcp port bytes");

			out_len = sizeof(out);
			rc = multiaddr_get_address_bytes(addr, 2U, out, &out_len);
			failures += expect_true((rc == MULTIADDR_SUCCESS) && (out_len == 0U),
						"address bytes index 2 zero-length",
						"expected zero-length address for /ws");

			out_len = sizeof(out);
			rc = multiaddr_get_address_bytes(addr, 3U, out, &out_len);
			failures += expect_true(rc == MULTIADDR_ERR_INVALID_DATA, "address bytes invalid index",
						"expected INVALID_DATA");
		}

		{
			uint64_t code = 0U;
			uint8_t out[4];
			size_t out_len = sizeof(out);
			int rc = multiaddr_get_protocol_code(NULL, 0U, &code);
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "get_protocol_code NULL addr",
						"expected NULL_POINTER error");

			rc = multiaddr_get_protocol_code(addr, 0U, NULL);
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "get_protocol_code NULL output",
						"expected NULL_POINTER error");

			rc = multiaddr_get_address_bytes(NULL, 0U, out, &out_len);
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "get_address_bytes NULL addr",
						"expected NULL_POINTER error");

			rc = multiaddr_get_address_bytes(addr, 0U, NULL, &out_len);
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "get_address_bytes NULL buffer",
						"expected NULL_POINTER error");

			rc = multiaddr_get_address_bytes(addr, 0U, out, NULL);
			failures += expect_true(rc == MULTIADDR_ERR_NULL_POINTER, "get_address_bytes NULL length",
						"expected NULL_POINTER error");
		}

		multiaddr_free(addr);
	}

	return failures;
}

static int test_encapsulate_and_decapsulate(void)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *base = multiaddr_new_from_str("/ip4/127.0.0.1", &err);
	multiaddr_t *sub = multiaddr_new_from_str("/tcp/80", &err);

	failures +=
		expect_true((base != NULL) && (sub != NULL), "encapsulate setup", "failed to create input multiaddrs");

	if ((base != NULL) && (sub != NULL))
	{
		multiaddr_t *enc = multiaddr_encapsulate(base, sub, &err);
		failures += expect_true((enc != NULL) && (err == MULTIADDR_SUCCESS), "multiaddr_encapsulate valid",
					"encapsulation failed");

		if (enc != NULL)
		{
			char *text = multiaddr_to_str(enc, &err);
			failures += expect_true((text != NULL) && (strcmp(text, "/ip4/127.0.0.1/tcp/80") == 0),
						"multiaddr_encapsulate text", "unexpected encapsulated text");
			free(text);
			multiaddr_free(enc);
		}
	}

	{
		multiaddr_t *enc = multiaddr_encapsulate(NULL, sub, &err);
		failures += expect_true((enc == NULL) && (err == MULTIADDR_ERR_NULL_POINTER),
					"multiaddr_encapsulate NULL", "expected NULL_POINTER error");
	}

	if (base != NULL)
	{
		multiaddr_free(base);
	}
	if (sub != NULL)
	{
		multiaddr_free(sub);
	}

	{
		multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80/ws/tcp/443/ws", &err);
		multiaddr_t *suffix = multiaddr_new_from_str("/ws", &err);
		failures += expect_true((addr != NULL) && (suffix != NULL), "decapsulate setup",
					"failed to create decapsulation inputs");

		if ((addr != NULL) && (suffix != NULL))
		{
			multiaddr_t *dec = multiaddr_decapsulate(addr, suffix, &err);
			failures += expect_true((dec != NULL) && (err == MULTIADDR_SUCCESS),
						"multiaddr_decapsulate last occurrence", "decapsulation failed");
			if (dec != NULL)
			{
				char *text = multiaddr_to_str(dec, &err);
				failures += expect_true(
					(text != NULL) && (strcmp(text, "/ip4/127.0.0.1/tcp/80/ws/tcp/443") == 0),
					"multiaddr_decapsulate removes last match", "unexpected decapsulation result");
				free(text);
				multiaddr_free(dec);
			}

			multiaddr_free(suffix);
			suffix = multiaddr_new_from_str("/tcp/443/ws", &err);
			if (suffix != NULL)
			{
				multiaddr_t *dec2 = multiaddr_decapsulate(addr, suffix, &err);
				failures +=
					expect_true((dec2 != NULL) && (err == MULTIADDR_SUCCESS),
						    "multiaddr_decapsulate compound suffix", "decapsulation failed");
				if (dec2 != NULL)
				{
					char *text2 = multiaddr_to_str(dec2, &err);
					failures += expect_true(
						(text2 != NULL) && (strcmp(text2, "/ip4/127.0.0.1/tcp/80/ws") == 0),
						"multiaddr_decapsulate compound suffix text",
						"unexpected compound decapsulation result");
					free(text2);
					multiaddr_free(dec2);
				}
				multiaddr_free(suffix);
			}
			multiaddr_free(addr);
		}
	}

	{
		multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
		multiaddr_t *suffix = multiaddr_new_from_str("/udp/80", &err);
		if ((addr != NULL) && (suffix != NULL))
		{
			multiaddr_t *dec = multiaddr_decapsulate(addr, suffix, &err);
			failures += expect_true((dec == NULL) && (err == MULTIADDR_ERR_NO_MATCH),
						"multiaddr_decapsulate no match", "expected NO_MATCH error");
		}
		multiaddr_free(addr);
		multiaddr_free(suffix);
	}

	{
		multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
		multiaddr_t *dec = multiaddr_decapsulate(NULL, addr, &err);
		failures += expect_true((dec == NULL) && (err == MULTIADDR_ERR_NULL_POINTER),
					"multiaddr_decapsulate NULL input", "expected NULL_POINTER error");
		multiaddr_free(addr);
	}

	return failures;
}

static int test_empty_result_and_zero_length_bytes(void)
{
	int failures = 0;
	int err = 0;
	multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
	multiaddr_t *sub = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);

	if ((addr != NULL) && (sub != NULL))
	{
		multiaddr_t *dec = multiaddr_decapsulate(addr, sub, &err);
		failures += expect_true((dec != NULL) && (err == MULTIADDR_SUCCESS),
					"full decapsulation returns empty multiaddr", "decapsulation failed");

		if (dec != NULL)
		{
			char *text = multiaddr_to_str(dec, &err);
			failures += expect_true((text != NULL) && (strcmp(text, "") == 0), "empty multiaddr to_str",
						"expected empty string");
			free(text);

			{
				uint8_t out[1] = {0U};
				int rc = multiaddr_get_bytes(dec, out, sizeof(out));
				failures += expect_true(rc == 0, "empty multiaddr get_bytes",
							"expected 0-byte serialization");
			}

			{
				multiaddr_t *copy = multiaddr_copy(dec, &err);
				failures += expect_true((copy != NULL) && (err == MULTIADDR_SUCCESS),
							"copy empty multiaddr", "copy failed for empty multiaddr");
				if (copy != NULL)
				{
					char *copy_text = multiaddr_to_str(copy, &err);
					failures += expect_true((copy_text != NULL) && (strcmp(copy_text, "") == 0),
								"copy empty multiaddr text",
								"expected empty text from copied empty multiaddr");
					free(copy_text);
					multiaddr_free(copy);
				}
			}

			multiaddr_free(dec);
		}
	}
	else
	{
		failures += expect_true(0, "empty decapsulation setup", "failed to create setup multiaddrs");
	}

	multiaddr_free(addr);
	multiaddr_free(sub);

	return failures;
}

int main(void)
{
	int failures = 0;

	failures += test_new_from_str_valid();
	failures += test_new_from_str_invalid();
	failures += test_new_from_bytes();
	failures += test_copy_and_get_bytes();
	failures += test_accessors();
	failures += test_encapsulate_and_decapsulate();
	failures += test_empty_result_and_zero_length_bytes();

	if (failures == 0)
	{
		printf("\nAll tests passed!\n");
		return EXIT_SUCCESS;
	}

	printf("\nSome tests failed. Total failures: %d\n", failures);
	return EXIT_FAILURE;
}
