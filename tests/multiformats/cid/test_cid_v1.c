#include "multiformats/cid/cid_v1.h"

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

static void build_sha2_256_multihash(const uint8_t *digest, uint8_t *out, size_t *out_len)
{
	size_t index;

	out[0] = (uint8_t)CIDV1_MH_CODE_SHA2_256;
	out[1] = (uint8_t)32U;
	for (index = 0U; index < 32U; ++index)
	{
		out[index + 2U] = digest[index];
	}
	*out_len = (size_t)34U;
}

static int cid_is_reset(const cid_v1_t *cid)
{
	int reset;

	reset = 0;
	if (cid != NULL)
	{
		if ((cid->version == (uint64_t)0U) && (cid->codec == (uint64_t)0U) && (cid->multihash == NULL) &&
		    (cid->multihash_size == (size_t)0U))
		{
			reset = 1;
		}
	}

	return reset;
}

static void run_round_trip_case(const char *name, const uint8_t *digest)
{
	char test_name[160];
	cid_v1_t cid;
	cid_v1_t decoded_from_bytes;
	cid_v1_t decoded_from_string;
	uint8_t mh[40];
	size_t mh_len;
	uint8_t binary[CIDV1_MAX_BINARY_SIZE];
	ptrdiff_t result;
	char encoded[CIDV1_MAX_STRING_LENGTH + 1U];
	char encoded_upper[CIDV1_MAX_STRING_LENGTH + 1U];

	cid_v1_free(&cid);
	cid_v1_free(&decoded_from_bytes);
	cid_v1_free(&decoded_from_string);
	build_sha2_256_multihash(digest, mh, &mh_len);

	snprintf(test_name, sizeof(test_name), "init %s", name);
	result = cid_v1_init(&cid, CIDV1_CODEC_RAW, mh, mh_len);
	report_result(test_name, result == CIDV1_SUCCESS, "cid_v1_init failed");
	if (result != CIDV1_SUCCESS)
	{
		return;
	}

	snprintf(test_name, sizeof(test_name), "to_bytes %s", name);
	result = cid_v1_to_bytes(&cid, binary, sizeof(binary));
	report_result(test_name,
		      (result > 0) && (binary[0] == (uint8_t)CIDV1_VERSION) && (binary[1] == (uint8_t)CIDV1_CODEC_RAW),
		      "cid_v1_to_bytes mismatch");
	if (result <= 0)
	{
		cid_v1_free(&cid);
		return;
	}

	snprintf(test_name, sizeof(test_name), "from_bytes %s", name);
	result = cid_v1_from_bytes(&decoded_from_bytes, binary, (size_t)result);
	report_result(test_name,
		      (result > 0) && (decoded_from_bytes.version == CIDV1_VERSION) &&
			      (decoded_from_bytes.codec == CIDV1_CODEC_RAW) &&
			      (decoded_from_bytes.multihash_size == mh_len) &&
			      (memcmp(decoded_from_bytes.multihash, mh, mh_len) == 0),
		      "cid_v1_from_bytes mismatch");

	snprintf(test_name, sizeof(test_name), "to_string base58 %s", name);
	result = cid_v1_to_string(&cid, MULTIBASE_BASE58_BTC, encoded, sizeof(encoded));
	report_result(test_name, (result > 0) && (encoded[0] == 'z'), "cid_v1_to_string base58 failed");
	if (result > 0)
	{
		snprintf(test_name, sizeof(test_name), "from_string base58 %s", name);
		result = cid_v1_from_string(&decoded_from_string, encoded);
		report_result(test_name,
			      (result == (ptrdiff_t)strlen(encoded)) &&
				      (decoded_from_string.version == CIDV1_VERSION) &&
				      (decoded_from_string.codec == CIDV1_CODEC_RAW) &&
				      (decoded_from_string.multihash_size == mh_len) &&
				      (memcmp(decoded_from_string.multihash, mh, mh_len) == 0),
			      "cid_v1_from_string base58 mismatch");
	}

	snprintf(test_name, sizeof(test_name), "to_string base16upper %s", name);
	result = cid_v1_to_string(&cid, MULTIBASE_BASE16_UPPER, encoded_upper, sizeof(encoded_upper));
	report_result(test_name, (result > 0) && (encoded_upper[0] == 'F'), "cid_v1_to_string base16upper failed");
	if (result > 0)
	{
		snprintf(test_name, sizeof(test_name), "from_string base16upper %s", name);
		result = cid_v1_from_string(&decoded_from_string, encoded_upper);
		report_result(test_name,
			      (result == (ptrdiff_t)strlen(encoded_upper)) &&
				      (decoded_from_string.version == CIDV1_VERSION) &&
				      (decoded_from_string.codec == CIDV1_CODEC_RAW) &&
				      (decoded_from_string.multihash_size == mh_len) &&
				      (memcmp(decoded_from_string.multihash, mh, mh_len) == 0),
			      "cid_v1_from_string base16upper mismatch");
	}

	cid_v1_free(&decoded_from_string);
	cid_v1_free(&decoded_from_bytes);
	cid_v1_free(&cid);
}

static void test_known_vectors(void)
{
	const char *known_base32;
	const char *known_base58;
	const char *expected_human_base32;
	const char *expected_human_base58;
	cid_v1_t cid;
	char human[256];
	char encoded[CIDV1_MAX_STRING_LENGTH + 1U];
	ptrdiff_t result;

	known_base32 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
	known_base58 = "zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA";
	expected_human_base32 = "base32 - cidv1 - dag_pb - "
				"sha2_256-c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a";
	expected_human_base58 = "base58btc - cidv1 - raw - "
				"sha2_256-6e6ff7950a36187a801613426e858dce686cd7d7e3c0fc42ee0330072d245c95";

	cid_v1_free(&cid);
	result = cid_v1_from_string(&cid, known_base32);
	report_result("known base32 decode", result == (ptrdiff_t)strlen(known_base32), "known base32 decode failed");
	if (result == (ptrdiff_t)strlen(known_base32))
	{
		result = cid_v1_to_human(&cid, MULTIBASE_BASE32, human, sizeof(human));
		report_result("known base32 human", (result > 0) && (strcmp(human, expected_human_base32) == 0),
			      "known base32 human mismatch");

		result = cid_v1_to_string(&cid, MULTIBASE_BASE32, encoded, sizeof(encoded));
		report_result("known base32 re-encode",
			      (result == (ptrdiff_t)strlen(known_base32)) && (strcmp(encoded, known_base32) == 0),
			      "known base32 re-encode mismatch");
	}
	cid_v1_free(&cid);

	result = cid_v1_from_string(&cid, known_base58);
	report_result("known base58 decode", result == (ptrdiff_t)strlen(known_base58), "known base58 decode failed");
	if (result == (ptrdiff_t)strlen(known_base58))
	{
		result = cid_v1_to_human(&cid, MULTIBASE_BASE58_BTC, human, sizeof(human));
		report_result("known base58 human", (result > 0) && (strcmp(human, expected_human_base58) == 0),
			      "known base58 human mismatch");
	}
	cid_v1_free(&cid);
}

static void test_error_paths(void)
{
	cid_v1_t cid;
	uint8_t digest[32];
	uint8_t mh[40];
	size_t mh_len;
	uint8_t binary[CIDV1_MAX_BINARY_SIZE];
	char oversized_input[CIDV1_MAX_STRING_LENGTH + 2U];
	char unterminated_input[CIDV1_MAX_STRING_LENGTH + 1U];
	char text[8];
	ptrdiff_t result;
	size_t index;

	cid_v1_free(&cid);
	for (index = 0U; index < 32U; ++index)
	{
		digest[index] = (uint8_t)index;
	}
	build_sha2_256_multihash(digest, mh, &mh_len);

	result = cid_v1_init(NULL, CIDV1_CODEC_RAW, mh, mh_len);
	report_result("init NULL cid", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");

	result = cid_v1_init(&cid, CIDV1_CODEC_RAW, NULL, mh_len);
	report_result("init NULL multihash", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");

	result = cid_v1_init(&cid, CIDV1_CODEC_RAW, mh, 0U);
	report_result("init empty multihash", result == CIDV1_ERROR_INVALID_ARG, "expected invalid-arg error");

	mh[1] = (uint8_t)33U;
	result = cid_v1_init(&cid, CIDV1_CODEC_RAW, mh, mh_len);
	report_result("init malformed multihash", result == CIDV1_ERROR_DECODE_FAILURE,
		      "expected malformed multihash failure");
	build_sha2_256_multihash(digest, mh, &mh_len);

	result = cid_v1_init(&cid, CIDV1_CODEC_RAW, mh, mh_len);
	report_result("init for error setup", result == CIDV1_SUCCESS, "setup failed");
	if (result != CIDV1_SUCCESS)
	{
		return;
	}

	cid.version = (uint64_t)2U;
	result = cid_v1_to_bytes(&cid, binary, sizeof(binary));
	report_result("to_bytes invalid version", result == CIDV1_ERROR_INVALID_ARG, "expected invalid-version error");
	cid.version = CIDV1_VERSION;

	result = cid_v1_to_bytes(NULL, binary, sizeof(binary));
	report_result("to_bytes NULL cid", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");

	result = cid_v1_to_bytes(&cid, NULL, sizeof(binary));
	report_result("to_bytes NULL out", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");

	text[0] = 'X';
	result = cid_v1_to_string(&cid, MULTIBASE_BASE58_BTC, text, sizeof(text));
	report_result("to_string small buffer", (result == CIDV1_ERROR_BUFFER_TOO_SMALL) && (text[0] == '\0'),
		      "expected buffer-too-small and output reset");

	result = cid_v1_from_bytes(NULL, binary, sizeof(binary));
	report_result("from_bytes NULL cid", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");

	result = cid_v1_to_bytes(&cid, binary, sizeof(binary));
	report_result("to_bytes for decode errors", result > 0, "setup encode failed");
	if (result > 0)
	{
		size_t encoded_len;

		encoded_len = (size_t)result;
		binary[0] = (uint8_t)2U;
		result = cid_v1_from_bytes(&cid, binary, encoded_len);
		report_result("from_bytes invalid version",
			      (result == CIDV1_ERROR_DECODE_FAILURE) && (cid_is_reset(&cid) != 0),
			      "expected decode failure and reset");

		binary[0] = (uint8_t)CIDV1_VERSION;
		result = cid_v1_from_bytes(&cid, binary, 1U);
		report_result("from_bytes truncated input",
			      (result == CIDV1_ERROR_INVALID_ARG) && (cid_is_reset(&cid) != 0),
			      "expected invalid-arg and reset");
	}

	result = cid_v1_from_string(&cid, "xabc");
	report_result("from_string invalid prefix", (result == CIDV1_ERROR_DECODE_FAILURE) && (cid_is_reset(&cid) != 0),
		      "expected decode failure and reset");

	result = cid_v1_from_string(&cid, "z@@@");
	report_result("from_string invalid payload", (result < 0) && (cid_is_reset(&cid) != 0),
		      "expected failure and reset");

	for (index = 0U; index < (CIDV1_MAX_STRING_LENGTH + 1U); ++index)
	{
		oversized_input[index] = '1';
	}
	oversized_input[0] = 'z';
	oversized_input[CIDV1_MAX_STRING_LENGTH + 1U] = '\0';
	result = cid_v1_from_string(&cid, oversized_input);
	report_result("from_string oversized input", (result == CIDV1_ERROR_INVALID_ARG) && (cid_is_reset(&cid) != 0),
		      "expected invalid-arg and reset");

	for (index = 0U; index < (CIDV1_MAX_STRING_LENGTH + 1U); ++index)
	{
		unterminated_input[index] = '1';
	}
	unterminated_input[0] = 'z';
	result = cid_v1_from_string(&cid, unterminated_input);
	report_result("from_string unterminated input",
		      (result == CIDV1_ERROR_INVALID_ARG) && (cid_is_reset(&cid) != 0),
		      "expected invalid-arg and reset");

	result = cid_v1_to_human(NULL, MULTIBASE_BASE58_BTC, text, sizeof(text));
	report_result("to_human NULL cid", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");

	result = cid_v1_to_human(&cid, MULTIBASE_BASE58_BTC, NULL, sizeof(text));
	report_result("to_human NULL out", result == CIDV1_ERROR_NULL_POINTER, "expected null-pointer error");
}

int main(void)
{
	static const uint8_t digest_incremental[32] = {
		0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU,
		0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
		0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU,
	};
	static const uint8_t digest_zero[32] = {
		0U,
	};
	static const uint8_t digest_ff[32] = {
		0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
		0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
		0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
	};

	run_round_trip_case("incremental", digest_incremental);
	run_round_trip_case("all-zero", digest_zero);
	run_round_trip_case("all-ff", digest_ff);
	test_known_vectors();
	test_error_paths();

	if (g_failures != 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", g_failures);
		return EXIT_FAILURE;
	}

	printf("\nAll tests passed!\n");
	return EXIT_SUCCESS;
}
