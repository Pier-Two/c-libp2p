#include "multiformats/multihash/multihash.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ENCODE_BUFFER_SIZE ((size_t)512U)
#define TEST_DECODE_BUFFER_SIZE ((size_t)512U)

typedef struct
{
	const char *input;
	const char *expected_sha256;
	const char *expected_sha512;
	const char *expected_sha3_224;
	const char *expected_sha3_256;
	const char *expected_sha3_384;
	const char *expected_sha3_512;
} multihash_vector_t;

typedef struct
{
	const char *name;
	uint64_t code;
	size_t digest_len;
} hash_algorithm_t;

static int g_failures = 0;

static void report_result(const char *test_name, int passed, const char *details)
{
	if (passed)
	{
		printf("TEST: %-50s | PASS\n", test_name);
		return;
	}

	++g_failures;
	printf("TEST: %-50s | FAIL: %s\n", test_name, details);
}

static int hex_char_to_int(char c)
{
	int value;

	value = -1;
	if ((c >= '0') && (c <= '9'))
	{
		value = c - '0';
	}
	else if ((c >= 'a') && (c <= 'f'))
	{
		value = (c - 'a') + 10;
	}
	else if ((c >= 'A') && (c <= 'F'))
	{
		value = (c - 'A') + 10;
	}

	return value;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_size)
{
	size_t hex_len;
	size_t needed;
	size_t index;
	int status;

	status = 0;
	hex_len = strlen(hex);
	if ((hex_len % 2U) != 0U)
	{
		status = -1;
	}
	else
	{
		needed = hex_len / 2U;
		if (needed > out_size)
		{
			status = -1;
		}
		else
		{
			for (index = 0; index < needed; ++index)
			{
				int high;
				int low;

				high = hex_char_to_int(hex[index * 2U]);
				low = hex_char_to_int(hex[(index * 2U) + 1U]);
				if ((high < 0) || (low < 0))
				{
					status = -1;
					break;
				}

				out[index] = (uint8_t)((high << 4) | low);
			}

			if (status == 0)
			{
				status = (int)needed;
			}
		}
	}

	return status;
}

static void bytes_to_hex(const uint8_t *input, size_t input_len, char *hex_out)
{
	static const char hex_digits[] = "0123456789abcdef";
	size_t index;

	for (index = 0; index < input_len; ++index)
	{
		hex_out[index * 2U] = hex_digits[(input[index] >> 4U) & 0x0FU];
		hex_out[(index * 2U) + 1U] = hex_digits[input[index] & 0x0FU];
	}
	hex_out[input_len * 2U] = '\0';
}

static int decode_varint_local(const uint8_t *input, size_t input_len, uint64_t *value, size_t *read)
{
	uint64_t decoded;
	unsigned int shift;
	size_t index;
	int status;

	status = -1;
	if ((input != NULL) && (value != NULL) && (read != NULL) && (input_len > (size_t)0U))
	{
		decoded = (uint64_t)0U;
		shift = 0U;
		for (index = 0; index < input_len; ++index)
		{
			uint8_t byte;

			byte = input[index];
			decoded |= (((uint64_t)byte) & UINT64_C(0x7f)) << shift;
			if ((byte & (uint8_t)0x80U) == (uint8_t)0U)
			{
				*value = decoded;
				*read = index + (size_t)1U;
				status = 0;
				break;
			}

			if (shift >= 63U)
			{
				break;
			}
			shift += 7U;
		}
	}

	return status;
}

static const char *expected_hex_for_code(const multihash_vector_t *vector, uint64_t code)
{
	const char *expected;

	expected = NULL;
	switch (code)
	{
	case MULTIHASH_CODE_SHA2_256:
		expected = vector->expected_sha256;
		break;
	case MULTIHASH_CODE_SHA2_512:
		expected = vector->expected_sha512;
		break;
	case MULTIHASH_CODE_SHA3_224:
		expected = vector->expected_sha3_224;
		break;
	case MULTIHASH_CODE_SHA3_256:
		expected = vector->expected_sha3_256;
		break;
	case MULTIHASH_CODE_SHA3_384:
		expected = vector->expected_sha3_384;
		break;
	case MULTIHASH_CODE_SHA3_512:
		expected = vector->expected_sha3_512;
		break;
	default:
		break;
	}

	return expected;
}

static void run_hash_vector_case(const multihash_vector_t *vector, const hash_algorithm_t *algorithm)
{
	uint8_t encoded[TEST_ENCODE_BUFFER_SIZE];
	uint8_t decoded[TEST_DECODE_BUFFER_SIZE];
	uint8_t expected_digest[TEST_DECODE_BUFFER_SIZE];
	char encoded_hex[(TEST_ENCODE_BUFFER_SIZE * 2U) + 1U];
	char test_name[192];
	const char *expected_hex;
	const char *digest_hex;
	size_t input_len;
	size_t decoded_len;
	uint64_t decoded_code;
	int encode_result;
	int decode_result;
	int expected_digest_len;

	expected_hex = expected_hex_for_code(vector, algorithm->code);
	snprintf(test_name, sizeof(test_name), "vector setup %s '%s'", algorithm->name, vector->input);
	report_result(test_name, expected_hex != NULL, "missing expected vector for algorithm");
	if (expected_hex == NULL)
	{
		return;
	}

	input_len = strlen(vector->input);
	encode_result =
		multihash_encode(algorithm->code, (const uint8_t *)vector->input, input_len, encoded, sizeof(encoded));
	snprintf(test_name, sizeof(test_name), "encode %s '%s'", algorithm->name, vector->input);
	if (encode_result < 0)
	{
		char details[96];

		snprintf(details, sizeof(details), "unexpected encode error %d", encode_result);
		report_result(test_name, 0, details);
		return;
	}

	report_result(test_name, 1, "");

	bytes_to_hex(encoded, (size_t)encode_result, encoded_hex);
	snprintf(test_name, sizeof(test_name), "encoded bytes %s '%s'", algorithm->name, vector->input);
	report_result(test_name, strcmp(encoded_hex, expected_hex) == 0, "encoded bytes mismatch");

	decoded_len = sizeof(decoded);
	decoded_code = UINT64_MAX;
	decode_result = multihash_decode(encoded, (size_t)encode_result, &decoded_code, decoded, &decoded_len);
	snprintf(test_name, sizeof(test_name), "decode %s '%s'", algorithm->name, vector->input);
	if (decode_result < 0)
	{
		char details[96];

		snprintf(details, sizeof(details), "unexpected decode error %d", decode_result);
		report_result(test_name, 0, details);
		return;
	}

	if ((decode_result != encode_result) || (decoded_code != algorithm->code) ||
	    (decoded_len != algorithm->digest_len))
	{
		report_result(test_name, 0, "decode length/code/digest length mismatch");
		return;
	}
	report_result(test_name, 1, "");

	digest_hex = expected_hex + 4;
	expected_digest_len = hex_to_bytes(digest_hex, expected_digest, sizeof(expected_digest));
	snprintf(test_name, sizeof(test_name), "decoded digest %s '%s'", algorithm->name, vector->input);
	if ((expected_digest_len != (int)algorithm->digest_len) ||
	    (memcmp(decoded, expected_digest, algorithm->digest_len) != 0))
	{
		report_result(test_name, 0, "decoded digest mismatch");
		return;
	}
	report_result(test_name, 1, "");
}

static void test_known_hash_vectors(void)
{
	static const multihash_vector_t vectors[] = {
		{"", "1220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		 "1340cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f6"
		 "3b931bd47417a81a538327af927da3e",
		 "171c6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		 "1620a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		 "15300c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
		 "1440a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f"
		 "500199d95b6d3e301758586281dcd26"},
		{"foo", "12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		 "1340f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5"
		 "a8c0c7f7eda19594a7eb539453e1ed7",
		 "171cf4f6779e153c391bbd29c95e72b0708e39d9166c7cea51d1f10ef58a",
		 "162076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01",
		 "1530665551928d13b7d84ee02734502b018d896a0fb87eed5adb4c87ba91bbd6489410e11b0fbcc06ed7d0ebad559e5d3bb5",
		 "14404bca2b137edc580fe50a88983ef860ebaca36c857b1f492839d6d7392452a63c82cbebc68e3b70a2a1480b4bb5d437a7c"
		 "ba6ecf9d89f9ff3ccd14cd6146ea7e7"},
		{"foobar", "1220c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
		 "13400a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360"
		 "230c19b273500ee013e030601bf2425",
		 "171c1ad852ba147a715fe5a3df39a741fad08186c303c7d21cefb7be763b",
		 "162009234807e4af85f17c66b48ee3bca89dffd1f1233659f9f940a2b17b0b8c6bc5",
		 "15300fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8",
		 "1440ff32a30c3af5012ea395827a3e99a13073c3a8d8410a708568ff7e6eb85968fccfebaea039bc21411e9d43fdb9a851b52"
		 "9b9960ffea8679199781b8f45ca85e2"},
	};
	static const hash_algorithm_t algorithms[] = {
		{"sha2-256", MULTIHASH_CODE_SHA2_256, (size_t)32U}, {"sha2-512", MULTIHASH_CODE_SHA2_512, (size_t)64U},
		{"sha3-224", MULTIHASH_CODE_SHA3_224, (size_t)28U}, {"sha3-256", MULTIHASH_CODE_SHA3_256, (size_t)32U},
		{"sha3-384", MULTIHASH_CODE_SHA3_384, (size_t)48U}, {"sha3-512", MULTIHASH_CODE_SHA3_512, (size_t)64U},
	};
	size_t vector_index;
	size_t algorithm_index;

	for (vector_index = 0; vector_index < (sizeof(vectors) / sizeof(vectors[0])); ++vector_index)
	{
		for (algorithm_index = 0; algorithm_index < (sizeof(algorithms) / sizeof(algorithms[0]));
		     ++algorithm_index)
		{
			run_hash_vector_case(&vectors[vector_index], &algorithms[algorithm_index]);
		}
	}
}

static void run_identity_round_trip_case(const char *name, const uint8_t *input, size_t input_len)
{
	uint8_t encoded[TEST_ENCODE_BUFFER_SIZE];
	uint8_t decoded[TEST_DECODE_BUFFER_SIZE];
	uint64_t decoded_code;
	size_t decoded_len;
	size_t expected_len;
	size_t code_len;
	size_t length_varint_len;
	uint64_t parsed_code;
	uint64_t parsed_digest_len;
	int encode_result;
	int decode_result;
	int varint_status;
	char test_name[192];

	if (input_len < (size_t)128U)
	{
		expected_len = (size_t)2U + input_len;
	}
	else
	{
		expected_len = (size_t)3U + input_len;
	}
	snprintf(test_name, sizeof(test_name), "identity encode %s", name);
	if (expected_len > sizeof(encoded))
	{
		report_result(test_name, 0, "test input exceeds fixed encode buffer");
		return;
	}

	encode_result = multihash_encode(MULTIHASH_CODE_IDENTITY, input, input_len, encoded, sizeof(encoded));
	if (encode_result < 0)
	{
		char details[96];

		snprintf(details, sizeof(details), "unexpected encode error %d", encode_result);
		report_result(test_name, 0, details);
		return;
	}

	report_result(test_name, (size_t)encode_result == expected_len, "unexpected identity encoded length");

	parsed_code = UINT64_MAX;
	code_len = 0U;
	varint_status = decode_varint_local(encoded, (size_t)encode_result, &parsed_code, &code_len);
	snprintf(test_name, sizeof(test_name), "identity code varint %s", name);
	if ((varint_status != 0) || (parsed_code != MULTIHASH_CODE_IDENTITY))
	{
		report_result(test_name, 0, "identity code varint mismatch");
		return;
	}
	report_result(test_name, 1, "");

	parsed_digest_len = UINT64_MAX;
	length_varint_len = 0U;
	varint_status = decode_varint_local(encoded + code_len, ((size_t)encode_result) - code_len, &parsed_digest_len,
					    &length_varint_len);
	snprintf(test_name, sizeof(test_name), "identity length varint %s", name);
	if ((varint_status != 0) || (parsed_digest_len != (uint64_t)input_len))
	{
		report_result(test_name, 0, "identity digest length varint mismatch");
		return;
	}
	report_result(test_name, 1, "");

	decoded_code = UINT64_MAX;
	decoded_len = sizeof(decoded);
	decode_result = multihash_decode(encoded, (size_t)encode_result, &decoded_code, decoded, &decoded_len);
	snprintf(test_name, sizeof(test_name), "identity decode %s", name);
	if (decode_result < 0)
	{
		char details[96];

		snprintf(details, sizeof(details), "unexpected decode error %d", decode_result);
		report_result(test_name, 0, details);
		return;
	}

	if ((decode_result != encode_result) || (decoded_code != MULTIHASH_CODE_IDENTITY) ||
	    (decoded_len != input_len) || (memcmp(decoded, input, input_len) != 0))
	{
		report_result(test_name, 0, "decoded identity payload mismatch");
		return;
	}
	report_result(test_name, 1, "");
}

static void test_identity_round_trip(void)
{
	static const uint8_t foo_input[] = {'f', 'o', 'o'};
	static const uint8_t foobar_input[] = {'f', 'o', 'o', 'b', 'a', 'r'};
	uint8_t long_input[130];
	size_t index;

	for (index = 0; index < sizeof(long_input); ++index)
	{
		long_input[index] = (uint8_t)(index & 0xFFU);
	}

	run_identity_round_trip_case("empty", (const uint8_t *)"", (size_t)0U);
	run_identity_round_trip_case("foo", foo_input, sizeof(foo_input));
	run_identity_round_trip_case("foobar", foobar_input, sizeof(foobar_input));
	run_identity_round_trip_case("130-bytes", long_input, sizeof(long_input));
}

static void test_encode_errors(void)
{
	static const uint8_t sample_data[] = {'a', 'b', 'c'};
	uint8_t out[80];
	int result;

	result = multihash_encode(MULTIHASH_CODE_SHA2_256, NULL, sizeof(sample_data), out, sizeof(out));
	report_result("encode NULL data", result == MULTIHASH_ERR_NULL_POINTER, "expected NULL_POINTER");

	result = multihash_encode(MULTIHASH_CODE_SHA2_256, sample_data, sizeof(sample_data), NULL, sizeof(out));
	report_result("encode NULL out", result == MULTIHASH_ERR_NULL_POINTER, "expected NULL_POINTER");

	result = multihash_encode(UINT64_C(0x7fffffffffffffff), sample_data, sizeof(sample_data), out, sizeof(out));
	report_result("encode unsupported function", result == MULTIHASH_ERR_UNSUPPORTED_FUN,
		      "expected UNSUPPORTED_FUN");

	result = multihash_encode(MULTIHASH_CODE_SHA2_256, sample_data, sizeof(sample_data), out, (size_t)33U);
	report_result("encode output too small", result == MULTIHASH_ERR_INVALID_INPUT, "expected INVALID_INPUT");

	result = multihash_encode(MULTIHASH_CODE_IDENTITY, sample_data, sizeof(sample_data), out, (size_t)2U);
	report_result("encode identity output too small", result == MULTIHASH_ERR_INVALID_INPUT,
		      "expected INVALID_INPUT");

	result = multihash_encode(MULTIHASH_CODE_SHA2_256, sample_data, (size_t)UINT32_MAX + (size_t)1U, out,
				  sizeof(out));
	report_result("encode sha2 length overflow", result == MULTIHASH_ERR_INVALID_INPUT, "expected INVALID_INPUT");
}

static void test_decode_errors(void)
{
	static const uint8_t non_minimal_code[] = {0x80U, 0x00U, 0x00U};
	static const uint8_t non_minimal_length[] = {0x12U, 0x80U, 0x00U};
	static const uint8_t truncated_digest[] = {0x12U, 0x20U, 0xAAU};
	static const uint8_t non_hash_code[] = {0x01U, 0x00U};
	uint8_t digest[64];
	uint64_t code;
	size_t digest_len;
	int result;
	uint8_t encoded[64];
	int encoded_len;

	result =
		multihash_encode(MULTIHASH_CODE_SHA2_256, (const uint8_t *)"foo", (size_t)3U, encoded, sizeof(encoded));
	report_result("decode setup encode", result > 0, "setup encode failed");
	if (result <= 0)
	{
		return;
	}
	encoded_len = result;

	code = UINT64_MAX;
	digest_len = sizeof(digest);
	result = multihash_decode(NULL, 1U, &code, digest, &digest_len);
	report_result("decode NULL input", result == MULTIHASH_ERR_NULL_POINTER, "expected NULL_POINTER");

	result = multihash_decode(encoded, (size_t)encoded_len, NULL, digest, &digest_len);
	report_result("decode NULL code", result == MULTIHASH_ERR_NULL_POINTER, "expected NULL_POINTER");

	result = multihash_decode(encoded, (size_t)encoded_len, &code, NULL, &digest_len);
	report_result("decode NULL digest", result == MULTIHASH_ERR_NULL_POINTER, "expected NULL_POINTER");

	result = multihash_decode(encoded, (size_t)encoded_len, &code, digest, NULL);
	report_result("decode NULL digest_len", result == MULTIHASH_ERR_NULL_POINTER, "expected NULL_POINTER");

	code = UINT64_MAX;
	digest_len = sizeof(digest);
	result = multihash_decode(non_minimal_code, sizeof(non_minimal_code), &code, digest, &digest_len);
	report_result("decode non-minimal code varint", result == MULTIHASH_ERR_INVALID_INPUT,
		      "expected INVALID_INPUT");
	report_result("decode non-minimal code resets outputs", (code == 0U) && (digest_len == 0U),
		      "expected output reset");

	code = UINT64_MAX;
	digest_len = sizeof(digest);
	result = multihash_decode(non_minimal_length, sizeof(non_minimal_length), &code, digest, &digest_len);
	report_result("decode non-minimal digest length", result == MULTIHASH_ERR_INVALID_INPUT,
		      "expected INVALID_INPUT");
	report_result("decode non-minimal length resets outputs", (code == 0U) && (digest_len == 0U),
		      "expected output reset");

	code = UINT64_MAX;
	digest_len = sizeof(digest);
	result = multihash_decode(truncated_digest, sizeof(truncated_digest), &code, digest, &digest_len);
	report_result("decode truncated digest", result == MULTIHASH_ERR_INVALID_INPUT, "expected INVALID_INPUT");
	report_result("decode truncated digest resets outputs", (code == 0U) && (digest_len == 0U),
		      "expected output reset");

	code = UINT64_MAX;
	digest_len = sizeof(digest);
	result = multihash_decode(non_hash_code, sizeof(non_hash_code), &code, digest, &digest_len);
	report_result("decode non-hash multicodec", result == MULTIHASH_ERR_UNSUPPORTED_FUN,
		      "expected UNSUPPORTED_FUN");
	report_result("decode non-hash code resets outputs", (code == 0U) && (digest_len == 0U),
		      "expected output reset");

	code = UINT64_MAX;
	digest_len = (size_t)31U;
	result = multihash_decode(encoded, (size_t)encoded_len, &code, digest, &digest_len);
	report_result("decode digest too large", result == MULTIHASH_ERR_DIGEST_TOO_LARGE, "expected DIGEST_TOO_LARGE");
	report_result("decode digest too large resets outputs", (code == 0U) && (digest_len == 0U),
		      "expected output reset");
}

static void test_decode_trailing_bytes(void)
{
	uint8_t encoded[64];
	uint8_t with_trailing[66];
	uint8_t digest[64];
	uint64_t code;
	size_t digest_len;
	int encoded_len;
	int decode_result;

	encoded_len =
		multihash_encode(MULTIHASH_CODE_SHA2_256, (const uint8_t *)"foo", (size_t)3U, encoded, sizeof(encoded));
	report_result("decode trailing setup", encoded_len > 0, "setup encode failed");
	if (encoded_len <= 0)
	{
		return;
	}

	memcpy(with_trailing, encoded, (size_t)encoded_len);
	with_trailing[encoded_len] = 0xAAU;
	with_trailing[encoded_len + 1] = 0xBBU;

	code = UINT64_MAX;
	digest_len = sizeof(digest);
	decode_result = multihash_decode(with_trailing, ((size_t)encoded_len) + 2U, &code, digest, &digest_len);
	report_result("decode trailing bytes consumed",
		      (decode_result == encoded_len) && (code == MULTIHASH_CODE_SHA2_256) &&
			      (digest_len == (size_t)32U),
		      "expected decode to consume only one multihash");
}

int main(void)
{
	test_known_hash_vectors();
	test_identity_round_trip();
	test_encode_errors();
	test_decode_errors();
	test_decode_trailing_bytes();

	if (g_failures != 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", g_failures);
		return EXIT_FAILURE;
	}

	printf("\nAll multihash tests passed!\n");
	return EXIT_SUCCESS;
}
