#include "multiformats/multibase/multibase.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_standard(const char *test_name, const char *details, int passed)
{
	if (passed != 0)
	{
		printf("TEST: %-56s | PASS\n", test_name);
	}
	else
	{
		printf("TEST: %-56s | FAIL: %s\n", test_name, details);
	}
}

typedef struct
{
	const char *input;
	const char *expected_base16;
	const char *expected_base16_upper;
	const char *expected_base32_lower;
	const char *expected_base32_upper;
	const char *expected_base58_btc;
	const char *expected_base64;
	const char *expected_base64_url;
	const char *expected_base64_url_pad;
} multibase_vector_t;

typedef struct
{
	multibase_t base;
	const char *name;
} multibase_entry_t;

static const char *expected_for_base(const multibase_vector_t *vector, multibase_t base)
{
	const char *expected;

	expected = NULL;
	switch (base)
	{
	case MULTIBASE_BASE16:
		expected = vector->expected_base16;
		break;
	case MULTIBASE_BASE16_UPPER:
		expected = vector->expected_base16_upper;
		break;
	case MULTIBASE_BASE32:
		expected = vector->expected_base32_lower;
		break;
	case MULTIBASE_BASE32_UPPER:
		expected = vector->expected_base32_upper;
		break;
	case MULTIBASE_BASE58_BTC:
		expected = vector->expected_base58_btc;
		break;
	case MULTIBASE_BASE64:
		expected = vector->expected_base64;
		break;
	case MULTIBASE_BASE64_URL:
		expected = vector->expected_base64_url;
		break;
	case MULTIBASE_BASE64_URL_PAD:
		expected = vector->expected_base64_url_pad;
		break;
	default:
		expected = NULL;
		break;
	}

	return expected;
}

static int run_round_trip_vectors(void)
{
	int failures;
	size_t i;
	size_t j;
	multibase_vector_t vectors[] = {
		{"", "f", "F", "b", "B", "z", "m", "u", "U"},
		{"f", "f66", "F66", "bmy", "BMY", "z2m", "mZg", "uZg", "UZg=="},
		{"fo", "f666f", "F666F", "bmzxq", "BMZXQ", "z8o8", "mZm8", "uZm8", "UZm8="},
		{"foo", "f666f6f", "F666F6F", "bmzxw6", "BMZXW6", "zbQbp", "mZm9v", "uZm9v", "UZm9v"},
		{"foob", "f666f6f62", "F666F6F62", "bmzxw6yq", "BMZXW6YQ", "z3csAg9", "mZm9vYg", "uZm9vYg",
		 "UZm9vYg=="},
		{"fooba", "f666f6f6261", "F666F6F6261", "bmzxw6ytb", "BMZXW6YTB", "zCZJRhmz", "mZm9vYmE", "uZm9vYmE",
		 "UZm9vYmE="},
		{"foobar", "f666f6f626172", "F666F6F626172", "bmzxw6ytboi", "BMZXW6YTBOI", "zt1Zv2yaZ", "mZm9vYmFy",
		 "uZm9vYmFy", "UZm9vYmFy"}};
	multibase_entry_t bases[] = {
		{MULTIBASE_BASE16, "MULTIBASE_BASE16"},		{MULTIBASE_BASE16_UPPER, "MULTIBASE_BASE16_UPPER"},
		{MULTIBASE_BASE32, "MULTIBASE_BASE32"},		{MULTIBASE_BASE32_UPPER, "MULTIBASE_BASE32_UPPER"},
		{MULTIBASE_BASE58_BTC, "MULTIBASE_BASE58_BTC"}, {MULTIBASE_BASE64, "MULTIBASE_BASE64"},
		{MULTIBASE_BASE64_URL, "MULTIBASE_BASE64_URL"}, {MULTIBASE_BASE64_URL_PAD, "MULTIBASE_BASE64_URL_PAD"}};
	const size_t vector_count = sizeof(vectors) / sizeof(vectors[0]);
	const size_t base_count = sizeof(bases) / sizeof(bases[0]);

	failures = 0;
	for (i = 0U; i < vector_count; i++)
	{
		for (j = 0U; j < base_count; j++)
		{
			const multibase_vector_t *vector;
			const multibase_entry_t *entry;
			const char *expected;
			char encoded[256];
			uint8_t decoded[128];
			ptrdiff_t encoded_len;
			ptrdiff_t decoded_len;
			size_t input_len;
			char test_name[160];

			vector = &vectors[i];
			entry = &bases[j];
			expected = expected_for_base(vector, entry->base);
			input_len = strlen(vector->input);
			encoded_len = multibase_encode(entry->base, (const uint8_t *)vector->input, input_len, encoded,
						       sizeof(encoded));
			(void)snprintf(test_name, sizeof(test_name), "%s encode \"%s\"", entry->name, vector->input);
			if (encoded_len < 0)
			{
				char details[128];

				(void)snprintf(details, sizeof(details), "encode error %td", encoded_len);
				print_standard(test_name, details, 0);
				failures++;
			}
			else if (strcmp(encoded, expected) != 0)
			{
				char details[192];

				(void)snprintf(details, sizeof(details), "got \"%s\", expected \"%s\"", encoded,
					       expected);
				print_standard(test_name, details, 0);
				failures++;
			}
			else
			{
				print_standard(test_name, "", 1);
			}

			decoded_len = multibase_decode(entry->base, encoded, decoded, sizeof(decoded));
			(void)snprintf(test_name, sizeof(test_name), "%s decode \"%s\"", entry->name, expected);
			if (decoded_len < 0)
			{
				char details[128];

				(void)snprintf(details, sizeof(details), "decode error %td", decoded_len);
				print_standard(test_name, details, 0);
				failures++;
			}
			else if (((size_t)decoded_len != input_len) || (memcmp(decoded, vector->input, input_len) != 0))
			{
				char details[128];

				(void)snprintf(details, sizeof(details), "decoded bytes mismatch for \"%s\"",
					       vector->input);
				print_standard(test_name, details, 0);
				failures++;
			}
			else
			{
				print_standard(test_name, "", 1);
			}
		}
	}

	return failures;
}

static int run_negative_tests(void)
{
	int failures;
	char encoded[64];
	uint8_t decoded[64];
	ptrdiff_t result;

	failures = 0;
	encoded[0] = 'x';
	result = multibase_encode(MULTIBASE_BASE16, NULL, 1U, encoded, sizeof(encoded));
	if (result != (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER)
	{
		print_standard("null data encode", "expected MULTIBASE_ERR_NULL_POINTER", 0);
		failures++;
	}
	else
	{
		print_standard("null data encode", "", 1);
	}

	result = multibase_encode(MULTIBASE_BASE16, (const uint8_t *)"f", 1U, NULL, 0U);
	if (result != (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER)
	{
		print_standard("null out encode", "expected MULTIBASE_ERR_NULL_POINTER", 0);
		failures++;
	}
	else
	{
		print_standard("null out encode", "", 1);
	}

	result = multibase_decode(MULTIBASE_BASE16, NULL, decoded, sizeof(decoded));
	if (result != (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER)
	{
		print_standard("null in decode", "expected MULTIBASE_ERR_NULL_POINTER", 0);
		failures++;
	}
	else
	{
		print_standard("null in decode", "", 1);
	}

	result = multibase_decode(MULTIBASE_BASE16, "f66", NULL, 0U);
	if (result != (ptrdiff_t)MULTIBASE_ERR_NULL_POINTER)
	{
		print_standard("null out decode", "expected MULTIBASE_ERR_NULL_POINTER", 0);
		failures++;
	}
	else
	{
		print_standard("null out decode", "", 1);
	}

	encoded[0] = 'x';
	encoded[1] = '\0';
	result = multibase_encode(MULTIBASE_BASE16, (const uint8_t *)"f", 1U, encoded, 2U);
	if ((result != (ptrdiff_t)MULTIBASE_ERR_BUFFER_TOO_SMALL) || (encoded[0] != '\0'))
	{
		print_standard("encode short buffer reset", "expected buffer-too-small and empty output", 0);
		failures++;
	}
	else
	{
		print_standard("encode short buffer reset", "", 1);
	}

	result = multibase_encode((multibase_t)7777, (const uint8_t *)"f", 1U, encoded, sizeof(encoded));
	if (result != (ptrdiff_t)MULTIBASE_ERR_UNSUPPORTED_BASE)
	{
		print_standard("encode unsupported base", "expected MULTIBASE_ERR_UNSUPPORTED_BASE", 0);
		failures++;
	}
	else
	{
		print_standard("encode unsupported base", "", 1);
	}

	decoded[0] = 0xAAU;
	result = multibase_decode(MULTIBASE_BASE16, "x66", decoded, sizeof(decoded));
	if ((result != (ptrdiff_t)MULTIBASE_ERR_INVALID_CHARACTER) || (decoded[0] != 0U))
	{
		print_standard("decode wrong prefix", "expected invalid-character and output reset", 0);
		failures++;
	}
	else
	{
		print_standard("decode wrong prefix", "", 1);
	}

	decoded[0] = 0xAAU;
	result = multibase_decode(MULTIBASE_BASE16, "f0g", decoded, sizeof(decoded));
	if ((result != (ptrdiff_t)MULTIBASE_ERR_INVALID_CHARACTER) || (decoded[0] != 0U))
	{
		print_standard("decode invalid payload", "expected invalid-character and output reset", 0);
		failures++;
	}
	else
	{
		print_standard("decode invalid payload", "", 1);
	}

	result = multibase_decode(MULTIBASE_BASE16, "f00", decoded, 0U);
	if (result != (ptrdiff_t)MULTIBASE_ERR_BUFFER_TOO_SMALL)
	{
		print_standard("decode short output buffer", "expected MULTIBASE_ERR_BUFFER_TOO_SMALL", 0);
		failures++;
	}
	else
	{
		print_standard("decode short output buffer", "", 1);
	}

	decoded[0] = 0xAAU;
	result = multibase_decode((multibase_t)7777, "f66", decoded, sizeof(decoded));
	if ((result != (ptrdiff_t)MULTIBASE_ERR_UNSUPPORTED_BASE) || (decoded[0] != 0U))
	{
		print_standard("decode unsupported base", "expected unsupported-base and output reset", 0);
		failures++;
	}
	else
	{
		print_standard("decode unsupported base", "", 1);
	}

	decoded[0] = 0xAAU;
	result = multibase_decode(MULTIBASE_BASE64_URL_PAD, "Uab=", decoded, sizeof(decoded));
	if ((result != (ptrdiff_t)MULTIBASE_ERR_INVALID_INPUT_LEN) || (decoded[0] != 0U))
	{
		print_standard("decode invalid padding", "expected invalid-input-len and output reset", 0);
		failures++;
	}
	else
	{
		print_standard("decode invalid padding", "", 1);
	}

	return failures;
}

int main(void)
{
	int failures;

	failures = 0;
	failures += run_round_trip_vectors();
	failures += run_negative_tests();

	if (failures != 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", failures);
		return EXIT_FAILURE;
	}

	printf("\nAll tests passed!\n");
	return EXIT_SUCCESS;
}
