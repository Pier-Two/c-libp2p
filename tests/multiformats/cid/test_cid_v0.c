#include "multiformats/cid/cid_v0.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

static void report_result(const char *test_name, int passed, const char *details)
{
	if (passed != 0)
	{
		printf("TEST: %-50s | PASS\n", test_name);
	}
	else
	{
		++g_failures;
		printf("TEST: %-50s | FAIL: %s\n", test_name, details);
	}
}

static int hash_is_zero(const uint8_t *hash)
{
	int is_zero;
	size_t index;

	is_zero = 1;
	for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
	{
		if (hash[index] != (uint8_t)0U)
		{
			is_zero = 0;
			break;
		}
	}

	return is_zero;
}

static void run_round_trip_case(const char *name, const uint8_t *digest)
{
	char test_name[128];
	cid_v0_t cid;
	cid_v0_t decoded_from_bytes;
	cid_v0_t decoded_from_string;
	uint8_t binary[CIDV0_BINARY_SIZE];
	char encoded[CIDV0_STRING_LENGTH + 1U];
	int result;

	snprintf(test_name, sizeof(test_name), "init %s", name);
	result = cid_v0_init(&cid, digest, CIDV0_HASH_SIZE);
	report_result(test_name, result == CIDV0_SUCCESS, "cid_v0_init failed");
	if (result != CIDV0_SUCCESS)
	{
		return;
	}

	snprintf(test_name, sizeof(test_name), "to_bytes %s", name);
	result = cid_v0_to_bytes(&cid, binary, sizeof(binary));
	report_result(test_name, result == (int)CIDV0_BINARY_SIZE, "cid_v0_to_bytes unexpected length/error");
	if (result != (int)CIDV0_BINARY_SIZE)
	{
		return;
	}

	snprintf(test_name, sizeof(test_name), "from_bytes %s", name);
	result = cid_v0_from_bytes(&decoded_from_bytes, binary, sizeof(binary));
	report_result(test_name,
		      (result == (int)CIDV0_BINARY_SIZE) &&
			      (memcmp(decoded_from_bytes.hash, digest, CIDV0_HASH_SIZE) == 0),
		      "cid_v0_from_bytes mismatch");

	snprintf(test_name, sizeof(test_name), "to_string %s", name);
	result = cid_v0_to_string(&cid, encoded, sizeof(encoded));
	report_result(test_name,
		      (result == (int)CIDV0_STRING_LENGTH) && (strlen(encoded) == CIDV0_STRING_LENGTH) &&
			      (encoded[0] == 'Q') && (encoded[1] == 'm'),
		      "cid_v0_to_string mismatch");
	if (result != (int)CIDV0_STRING_LENGTH)
	{
		return;
	}

	snprintf(test_name, sizeof(test_name), "from_string %s", name);
	result = cid_v0_from_string(&decoded_from_string, encoded);
	report_result(test_name,
		      (result == (int)CIDV0_STRING_LENGTH) &&
			      (memcmp(decoded_from_string.hash, digest, CIDV0_HASH_SIZE) == 0),
		      "cid_v0_from_string mismatch");
}

static void test_known_vector(void)
{
	const char *known_string;
	const uint8_t known_digest[CIDV0_HASH_SIZE] = {
		0xc3U, 0xc4U, 0x73U, 0x3eU, 0xc8U, 0xafU, 0xfdU, 0x06U, 0xcfU, 0x9eU, 0x9fU,
		0xf5U, 0x0fU, 0xfcU, 0x6bU, 0xcdU, 0x2eU, 0xc8U, 0x5aU, 0x61U, 0x70U, 0x00U,
		0x4bU, 0xb7U, 0x09U, 0x66U, 0x9cU, 0x31U, 0xdeU, 0x94U, 0x39U, 0x1aU,
	};
	cid_v0_t cid;
	char encoded[CIDV0_STRING_LENGTH + 1U];
	int result;

	known_string = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
	result = cid_v0_from_string(&cid, known_string);
	report_result("known vector decode",
		      (result == (int)CIDV0_STRING_LENGTH) && (memcmp(cid.hash, known_digest, CIDV0_HASH_SIZE) == 0),
		      "known CIDv0 decode mismatch");

	result = cid_v0_to_string(&cid, encoded, sizeof(encoded));
	report_result("known vector encode",
		      (result == (int)CIDV0_STRING_LENGTH) && (strcmp(encoded, known_string) == 0),
		      "known CIDv0 encode mismatch");
}

static void test_error_paths(void)
{
	cid_v0_t cid;
	uint8_t digest[CIDV0_HASH_SIZE];
	uint8_t binary[CIDV0_BINARY_SIZE];
	char output[CIDV0_STRING_LENGTH + 1U];
	int result;
	size_t index;

	for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
	{
		digest[index] = (uint8_t)index;
	}

	result = cid_v0_init(NULL, digest, CIDV0_HASH_SIZE);
	report_result("init NULL cid", result == CIDV0_ERROR_NULL_POINTER, "expected null-pointer error");

	result = cid_v0_init(&cid, digest, CIDV0_HASH_SIZE - 1U);
	report_result("init wrong digest length",
		      (result == CIDV0_ERROR_INVALID_DIGEST_LENGTH) && (hash_is_zero(cid.hash) != 0),
		      "expected invalid-digest-length and reset");

	result = cid_v0_init(&cid, digest, CIDV0_HASH_SIZE);
	report_result("init for error-path setup", result == CIDV0_SUCCESS, "setup failed");
	if (result != CIDV0_SUCCESS)
	{
		return;
	}

	result = cid_v0_to_bytes(&cid, binary, CIDV0_BINARY_SIZE - 1U);
	report_result("to_bytes buffer too small", result == CIDV0_ERROR_BUFFER_TOO_SMALL, "expected buffer-too-small");

	binary[0] = CIDV0_MULTIHASH_CODE;
	binary[1] = CIDV0_MULTIHASH_LENGTH;
	for (index = 0U; index < CIDV0_HASH_SIZE; ++index)
	{
		binary[index + 2U] = digest[index];
	}
	binary[0] = (uint8_t)0x13U;
	result = cid_v0_from_bytes(&cid, binary, sizeof(binary));
	report_result("from_bytes invalid prefix",
		      (result == CIDV0_ERROR_INVALID_DIGEST_LENGTH) && (hash_is_zero(cid.hash) != 0),
		      "expected invalid prefix with reset");

	output[0] = 'X';
	result = cid_v0_to_string(&cid, output, 4U);
	report_result("to_string small buffer", (result == CIDV0_ERROR_BUFFER_TOO_SMALL) && (output[0] == '\0'),
		      "expected buffer-too-small and output reset");

	result = cid_v0_from_string(&cid, "Qm123");
	report_result("from_string short input",
		      (result == CIDV0_ERROR_DECODE_FAILURE) && (hash_is_zero(cid.hash) != 0),
		      "expected decode failure and reset");

	result = cid_v0_from_string(&cid, "Xm01234567890123456789012345678901234567890123");
	report_result("from_string bad prefix", (result == CIDV0_ERROR_DECODE_FAILURE) && (hash_is_zero(cid.hash) != 0),
		      "expected decode failure and reset");
}

int main(void)
{
	static const uint8_t digest_incremental[CIDV0_HASH_SIZE] = {
		0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU,
		0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
		0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU,
	};
	static const uint8_t digest_zero[CIDV0_HASH_SIZE] = {
		0U,
	};
	static const uint8_t digest_ff[CIDV0_HASH_SIZE] = {
		0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
		0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
		0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
	};

	run_round_trip_case("incremental", digest_incremental);
	run_round_trip_case("all-zero", digest_zero);
	run_round_trip_case("all-ff", digest_ff);
	test_known_vector();
	test_error_paths();

	if (g_failures != 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", g_failures);
		return EXIT_FAILURE;
	}

	printf("\nAll tests passed!\n");
	return EXIT_SUCCESS;
}
