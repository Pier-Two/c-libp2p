#include "multiformats/unsigned_varint/unsigned_varint.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *name;
	uint64_t value;
	uint8_t encoding[UNSIGNED_VARINT_MAX_ENCODED_SIZE];
	size_t encoding_len;
} varint_vector_t;

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

static void run_round_trip_vector(const varint_vector_t *vector)
{
	uint8_t out[16];
	size_t written;
	uint64_t decoded;
	size_t read;
	unsigned_varint_err_t err;
	size_t expected_size;
	char test_name[160];

	written = 0;
	decoded = 0;
	read = 0;
	memset(out, 0, sizeof(out));

	snprintf(test_name, sizeof(test_name), "encode %s", vector->name);
	err = unsigned_varint_encode(vector->value, out, sizeof(out), &written);
	if (err != UNSIGNED_VARINT_OK)
	{
		report_result(test_name, 0, "unexpected encode error");
		return;
	}

	report_result(test_name, 1, "");

	snprintf(test_name, sizeof(test_name), "encoding bytes %s", vector->name);
	if ((written != vector->encoding_len) || (memcmp(out, vector->encoding, vector->encoding_len) != 0))
	{
		report_result(test_name, 0, "encoded bytes mismatch");
		return;
	}

	report_result(test_name, 1, "");

	snprintf(test_name, sizeof(test_name), "decode %s", vector->name);
	err = unsigned_varint_decode(out, written, &decoded, &read);
	if (err != UNSIGNED_VARINT_OK)
	{
		report_result(test_name, 0, "unexpected decode error");
		return;
	}

	if ((decoded != vector->value) || (read != written))
	{
		report_result(test_name, 0, "decoded value or length mismatch");
		return;
	}

	report_result(test_name, 1, "");

	snprintf(test_name, sizeof(test_name), "size %s", vector->name);
	expected_size = unsigned_varint_size(vector->value);
	report_result(test_name, expected_size == vector->encoding_len, "unsigned_varint_size mismatch");
}

static void test_round_trip_vectors(void)
{
	static const varint_vector_t vectors[] = {
		{"value 0", UINT64_C(0), {0x00}, 1},
		{"value 1", UINT64_C(1), {0x01}, 1},
		{"value 127", UINT64_C(127), {0x7F}, 1},
		{"value 128", UINT64_C(128), {0x80, 0x01}, 2},
		{"value 255", UINT64_C(255), {0xFF, 0x01}, 2},
		{"value 300", UINT64_C(300), {0xAC, 0x02}, 2},
		{"value 16383", UINT64_C(16383), {0xFF, 0x7F}, 2},
		{"value 16384", UINT64_C(16384), {0x80, 0x80, 0x01}, 3},
		{"value 2097151", UINT64_C(2097151), {0xFF, 0xFF, 0x7F}, 3},
		{"value 2097152", UINT64_C(2097152), {0x80, 0x80, 0x80, 0x01}, 4},
		{"value 2^48", UINT64_C(281474976710656), {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40}, 7},
		{"value max", UINT64_C(0x7FFFFFFFFFFFFFFF), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}, 9},
	};
	size_t i;

	for (i = 0; i < (sizeof(vectors) / sizeof(vectors[0])); ++i)
	{
		run_round_trip_vector(&vectors[i]);
	}
}

static void test_encode_errors(void)
{
	uint8_t out[16];
	size_t written;
	unsigned_varint_err_t err;

	written = 0;
	err = unsigned_varint_encode(UINT64_C(0x8000000000000000), out, sizeof(out), &written);
	report_result("encode overflow value", err == UNSIGNED_VARINT_ERR_VALUE_OVERFLOW, "expected VALUE_OVERFLOW");

	written = SIZE_MAX;
	err = unsigned_varint_encode(UINT64_C(300), out, 1, &written);
	report_result("encode buffer over", (err == UNSIGNED_VARINT_ERR_BUFFER_OVER) && (written == 0),
		      "expected BUFFER_OVER with written reset");

	written = 0;
	err = unsigned_varint_encode(UINT64_C(1), NULL, sizeof(out), &written);
	report_result("encode NULL out", err == UNSIGNED_VARINT_ERR_NULL_PTR, "expected NULL_PTR");

	err = unsigned_varint_encode(UINT64_C(1), out, sizeof(out), NULL);
	report_result("encode NULL written", err == UNSIGNED_VARINT_ERR_NULL_PTR, "expected NULL_PTR");
}

static void run_decode_error_case(const char *name, const uint8_t *input, size_t input_len,
				  unsigned_varint_err_t expected)
{
	uint64_t value;
	size_t read;
	unsigned_varint_err_t err;

	value = 0;
	read = 0;
	err = unsigned_varint_decode(input, input_len, &value, &read);
	report_result(name, err == expected, "unexpected decode error code");
}

static void test_decode_errors(void)
{
	static const uint8_t non_minimal_zero[] = {0x80, 0x00};
	static const uint8_t non_minimal_one[] = {0x81, 0x00};
	static const uint8_t non_minimal_127[] = {0xFF, 0x00};
	static const uint8_t truncated_1[] = {0x80};
	static const uint8_t truncated_2[] = {0x80, 0x80};
	static const uint8_t ten_byte_overlong[] = {
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
	};
	static const uint8_t value_2_63[] = {
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
	};
	uint64_t decoded;
	size_t read;
	unsigned_varint_err_t err;

	run_decode_error_case("decode non-minimal zero", non_minimal_zero, sizeof(non_minimal_zero),
			      UNSIGNED_VARINT_ERR_NOT_MINIMAL);
	run_decode_error_case("decode non-minimal one", non_minimal_one, sizeof(non_minimal_one),
			      UNSIGNED_VARINT_ERR_NOT_MINIMAL);
	run_decode_error_case("decode non-minimal 127", non_minimal_127, sizeof(non_minimal_127),
			      UNSIGNED_VARINT_ERR_NOT_MINIMAL);
	run_decode_error_case("decode truncated 1", truncated_1, sizeof(truncated_1), UNSIGNED_VARINT_ERR_TOO_LONG);
	run_decode_error_case("decode truncated 2", truncated_2, sizeof(truncated_2), UNSIGNED_VARINT_ERR_TOO_LONG);
	run_decode_error_case("decode overlong 10 bytes", ten_byte_overlong, sizeof(ten_byte_overlong),
			      UNSIGNED_VARINT_ERR_TOO_LONG);
	run_decode_error_case("decode 2^63 overflow", value_2_63, sizeof(value_2_63),
			      UNSIGNED_VARINT_ERR_VALUE_OVERFLOW);

	decoded = UINT64_MAX;
	read = SIZE_MAX;
	err = unsigned_varint_decode(truncated_1, sizeof(truncated_1), &decoded, &read);
	report_result("decode error resets outputs",
		      (err == UNSIGNED_VARINT_ERR_TOO_LONG) && (decoded == 0) && (read == 0),
		      "expected TOO_LONG with cleared outputs");

	decoded = 0;
	read = 0;
	err = unsigned_varint_decode(NULL, 1, &decoded, &read);
	report_result("decode NULL input", err == UNSIGNED_VARINT_ERR_NULL_PTR, "expected NULL_PTR");

	err = unsigned_varint_decode(non_minimal_zero, 2, NULL, &read);
	report_result("decode NULL value", err == UNSIGNED_VARINT_ERR_NULL_PTR, "expected NULL_PTR");

	err = unsigned_varint_decode(non_minimal_zero, 2, &decoded, NULL);
	report_result("decode NULL read", err == UNSIGNED_VARINT_ERR_NULL_PTR, "expected NULL_PTR");

	decoded = UINT64_MAX;
	read = SIZE_MAX;
	err = unsigned_varint_decode(non_minimal_zero, 0, &decoded, &read);
	report_result("decode empty input", (err == UNSIGNED_VARINT_ERR_EMPTY_INPUT) && (decoded == 0) && (read == 0),
		      "expected EMPTY_INPUT with cleared outputs");
}

static void test_decode_with_trailing_bytes(void)
{
	static const uint8_t input[] = {0x01, 0x80, 0x80, 0x80};
	uint64_t decoded;
	size_t read;
	unsigned_varint_err_t err;

	decoded = 0;
	read = 0;
	err = unsigned_varint_decode(input, sizeof(input), &decoded, &read);
	report_result("decode with trailing bytes",
		      (err == UNSIGNED_VARINT_OK) && (decoded == UINT64_C(1)) && (read == 1),
		      "expected decode to stop at first varint");
}

static void test_size_boundaries(void)
{
	report_result("size(0) == 1", unsigned_varint_size(UINT64_C(0)) == 1, "unexpected size for 0");
	report_result("size(127) == 1", unsigned_varint_size(UINT64_C(127)) == 1, "unexpected size for 127");
	report_result("size(128) == 2", unsigned_varint_size(UINT64_C(128)) == 2, "unexpected size for 128");
	report_result("size(16383) == 2", unsigned_varint_size(UINT64_C(16383)) == 2, "unexpected size for 16383");
	report_result("size(16384) == 3", unsigned_varint_size(UINT64_C(16384)) == 3, "unexpected size for 16384");
	report_result("size(max) == 9", unsigned_varint_size(UNSIGNED_VARINT_MAX_VALUE) == 9,
		      "unexpected size for max");
	report_result("size(2^63) == 0", unsigned_varint_size(UINT64_C(0x8000000000000000)) == 0,
		      "expected overflow size to be 0");
	report_result("size(UINT64_MAX) == 0", unsigned_varint_size(UINT64_MAX) == 0, "expected overflow size to be 0");
}

int main(void)
{
	test_round_trip_vectors();
	test_encode_errors();
	test_decode_errors();
	test_decode_with_trailing_bytes();
	test_size_boundaries();

	if (g_failures != 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", g_failures);
		return EXIT_FAILURE;
	}

	printf("\nAll unsigned_varint tests passed!\n");
	return EXIT_SUCCESS;
}
