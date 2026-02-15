#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "peer_id/peer_id.h"
#include "peer_id/peer_id_secp256k1.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_ecdsa.h"
#include "peer_id/peer_id_rsa.h"

/* Helper function to print test results. */
static void print_standard(const char *test_name, const char *details, int passed)
{
	if (passed)
	{
		printf("TEST: %-50s | PASS\n", test_name);
	}
	else
	{
		printf("TEST: %-50s | FAIL: %s\n", test_name, details);
	}
}

/* Helper function: convert a hex string to a byte array.
   The caller must free the returned array.
*/
static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
	size_t hex_len = strlen(hex);
	if (hex_len % 2 != 0)
	{
		return NULL;
	}
	size_t bytes_len = hex_len / 2;
	uint8_t *bytes = malloc(bytes_len);
	if (!bytes)
	{
		return NULL;
	}
	for (size_t i = 0; i < bytes_len; i++)
	{
		char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
		bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
	}
	*out_len = bytes_len;
	return bytes;
}

/* Test vectors (hex-encoded) for secp256k1 keys from the spec */
#define SECP256K1_PUBLIC_HEX "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
#define SECP256K1_PRIVATE_HEX "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"

/* Test vectors (hex-encoded) for RSA keys from the spec */
#define RSA_PRIVATE_HEX                                                                                                \
	"080012ae123082092a0201000282020100e1beab071d08200bde24eef00d049449b07770ff9910257b2d7d5dda242ce8f0e2f12e1af4" \
	"b32d9efd2c090f66b0f29986dbb645dae9880089704a94e5066d594162ae6ee8892e6ec70701db0a6c445c04778eb3de1293aa1a23c3" \
	"825b85c6620a2bc3f82f9b0c309bc0ab3aeb1873282bebd3da03c33e76c21e9beb172fd44c9e43be32e2c99827033cf8d0f0c606f457" \
	"9326c930eb4e854395ad941256542c793902185153c474bed109d6ff5141ebf9cd256cf58893a37f83729f97e7cb435ec679d2e33901" \
	"d27bb35aa0d7e20561da08885ef0abbf8e2fb48d6a5487047a9ecb1ad41fa7ed84f6e3e8ecd5d98b3982d2a901b4454991766da295ab" \
	"78822add5612a2df83bcee814cf50973e80d7ef38111b1bd87da2ae92438a2c8cbcc70b31ee319939a3b9c761dbc13b5c086d6b64bf7" \
	"ae7dacc14622375d92a8ff9af7eb962162bbddebf90acb32adb5e4e4029f1c96019949ecfbfeffd7ac1e3fbcc6b6168c34be3d5a2e59" \
	"99fcbb39bba7adbca78eab09b9bc39f7fa4b93411f4cc175e70c0a083e96bfaefb04a9580b4753c1738a6a760ae1afd851a1a4bdad23" \
	"1cf56e9284d832483df215a46c1c21bdf0c6cfe951c18f1ee4078c79c13d63edb6e14feaeffabc90ad317e4875fe648101b0864097e9" \
	"98f0ca3025ef9638cd2b0caecd3770ab54a1d9c6ca959b0f5dcbc90caeefc4135baca6fd475224269bbe1b02030100010282020100a4" \
	"72ffa858efd8588ce59ee264b957452f3673acdf5631d7bfd5ba0ef59779c231b0bc838a8b14cae367b6d9ef572c03c7883b0a3c652f" \
	"5c24c316b1ccfd979f13d0cd7da20c7d34d9ec32dfdc81ee7292167e706d705efde5b8f3edfcba41409e642f8897357df5d320d21c43" \
	"b33600a7ae4e505db957c1afbc189d73f0b5d972d9aaaeeb232ca20eebd5de6fe7f29d01470354413cc9a0af1154b7af7c1029adcd67" \
	"c74b4798afeb69e09f2cb387305e73a1b5f450202d54f0ef096fe1bde340219a1194d1ac9026e90b366cce0c59b239d10e4888f52ca1" \
	"780824d39ae01a6b9f4dd6059191a7f12b2a3d8db3c2868cd4e5a5862b8b625a4197d52c6ac77710116ebd3ced81c4d91ad5fdfbed68" \
	"312ebce7eea45c1833ca3acf7da2052820eacf5c6b07d086dabeb893391c71417fd8a4b1829ae2cf60d1749d0e25da19530d889461c2" \
	"1da3492a8dc6ccac7de83ac1c2185262c7473c8cc42f547cc9864b02a8073b6aa54a037d8c0de3914784e6205e83d97918b944f11b87" \
	"7b12084c0dd1d36592f8a4f8b8da5bb404c3d2c079b22b6ceabfbcb637c0dbe0201f0909d533f8bf308ada47aee641a012a494d31b54" \
	"c974e58b87f140258258bb82f31692659db7aa07e17a5b2a0832c24e122d3a8babcc9ee74cbb07d3058bb85b15f6f6b2674aba9fd343" \
	"67be9782d444335fbed31e3c4086c652597c27104938b47fa10282010100e9fdf843c1550070ca711cb8ff28411466198f0e212511c3" \
	"186623890c0071bf6561219682fe7dbdfd81176eba7c4faba21614a20721e0fcd63768e6d925688ecc90992059ac89256e0524de90bf" \
	"3d8a052ce6a9f6adafa712f3107a016e20c80255c9e37d8206d1bc327e06e66eb24288da866b55904fd8b59e6b2ab31bc5eab47e5970" \
	"93c63fab7872102d57b4c589c66077f534a61f5f65127459a33c91f6db61fc431b1ae90be92b4149a3255291baf94304e3efb77b1107" \
	"b5a3bda911359c40a53c347ff9100baf8f36dc5cd991066b5bdc28b39ed644f404afe9213f4d31c9d4e40f3a5f5e3c39bebeb244e841" \
	"37544e1a1839c1c8aaebf0c78a7fad590282010100f6fa1f1e6b803742d5490b7441152f500970f46feb0b73a6e4baba2aaf3c0e245e" \
	"d852fc31d86a8e46eb48e90fac409989dfee45238f97e8f1f8e83a136488c1b04b8a7fb695f37b8616307ff8a8d63e8cfa0b4fb9b916" \
	"7ffaebabf111aa5a4344afbabd002ae8961c38c02da76a9149abdde93eb389eb32595c29ba30d8283a7885218a5a9d33f7f01dbdf85f" \
	"3aad016c071395491338ec318d39220e1c7bd69d3d6b520a13a30d745c102b827ad9984b0dd6aed73916ffa82a06c1c111e7047dcd26" \
	"68f988a0570a71474992eecf416e068f029ec323d5d635fd24694fc9bf96973c255d26c772a95bf8b7f876547a5beabf86f06cd21b67" \
	"994f944e7a5493028201010095b02fd30069e547426a8bea58e8a2816f33688dac6c6f6974415af8402244a22133baedf34ce499d703" \
	"6f3f19b38eb00897c18949b0c5a25953c71aeeccfc8f6594173157cc854bd98f16dffe8f28ca13b77eb43a2730585c49fc3f608cd811" \
	"bb54b03b84bddaa8ef910988567f783012266199667a546a18fd88271fbf63a45ae4fd4884706da8befb9117c0a4d73de5172f8640b1" \
	"091ed8a4aea3ed4641463f5ff6a5e3401ad7d0c92811f87956d1fd5f9a1d15c7f3839a08698d9f35f9d966e5000f7cb2655d7b6c4adc" \
	"d8a9d950ea5f61bb7c9a33c17508f9baa313eecfee4ae493249ebe05a5d7770bbd3551b2eeb752e3649e0636de08e3d672e66cb90282" \
	"010100ad93e4c31072b063fc5ab5fe22afacece775c795d0efdf7c704cfc027bde0d626a7646fc905bb5a80117e3ca49059af14e0160" \
	"089f9190065be9bfecf12c3b2145b211c8e89e42dd91c38e9aa23ca73697063564f6f6aa6590088a738722df056004d18d7bccac62b3" \
	"bafef6172fc2a4b071ea37f31eff7a076bcab7dd144e51a9da8754219352aef2c73478971539fa41de4759285ea626fa3c72e7085be4" \
	"7d554d915bbb5149cb6ef835351f231043049cd941506a034bf2f8767f3e1e42ead92f91cb3d75549b57ef7d56ac39c2d80d67f6a2b4" \
	"ca192974bfc5060e2dd171217971002193dba12e7e4133ab201f07500a90495a38610279b13a48d54f0c99028201003e3a1ac0c2b67d" \
	"54ed5c4bbe04a7db99103659d33a4f9d35809e1f60c282e5988dddc964527f3b05e6cc890eab3dcb571d66debf3a5527704c87264b39" \
	"54d7265f4e8d2c637dd89b491b9cf23f264801f804b90454d65af0c4c830d1aef76f597ef61b26ca857ecce9cb78d4f6c2218c00d297" \
	"5d46c2b013fbf59b750c3b92d8d3ed9e6d1fd0ef1ec091a5c286a3fe2dead292f40f380065731e2079ebb9f2a7ef2c415ecbb488da98" \
	"f3a12609ca1b6ec8c734032c8bd513292ff842c375d4acd1b02dfb206b24cd815f8e2f9d4af8e7dea0370b19c1b23cc531d78b40e06e" \
	"1119ee2e08f6f31c6e2e8444c568d13c5d451a291ae0c9f1d4f27d23b3a00d60ad"
#define RSA_PUBLIC_HEX                                                                                                 \
	"080012a60430820222300d06092a864886f70d01010105000382020f003082020a0282020100e1beab071d08200bde24eef00d049449" \
	"b07770ff9910257b2d7d5dda242ce8f0e2f12e1af4b32d9efd2c090f66b0f29986dbb645dae9880089704a94e5066d594162ae6ee889" \
	"2e6ec70701db0a6c445c04778eb3de1293aa1a23c3825b85c6620a2bc3f82f9b0c309bc0ab3aeb1873282bebd3da03c33e76c21e9beb" \
	"172fd44c9e43be32e2c99827033cf8d0f0c606f4579326c930eb4e854395ad941256542c793902185153c474bed109d6ff5141ebf9cd" \
	"256cf58893a37f83729f97e7cb435ec679d2e33901d27bb35aa0d7e20561da08885ef0abbf8e2fb48d6a5487047a9ecb1ad41fa7ed84" \
	"f6e3e8ecd5d98b3982d2a901b4454991766da295ab78822add5612a2df83bcee814cf50973e80d7ef38111b1bd87da2ae92438a2c8cb" \
	"cc70b31ee319939a3b9c761dbc13b5c086d6b64bf7ae7dacc14622375d92a8ff9af7eb962162bbddebf90acb32adb5e4e4029f1c9601" \
	"9949ecfbfeffd7ac1e3fbcc6b6168c34be3d5a2e5999fcbb39bba7adbca78eab09b9bc39f7fa4b93411f4cc175e70c0a083e96bfaefb" \
	"04a9580b4753c1738a6a760ae1afd851a1a4bdad231cf56e9284d832483df215a46c1c21bdf0c6cfe951c18f1ee4078c79c13d63edb6" \
	"e14feaeffabc90ad317e4875fe648101b0864097e998f0ca3025ef9638cd2b0caecd3770ab54a1d9c6ca959b0f5dcbc90caeefc4135b" \
	"aca6fd475224269bbe1b0203010001"

/* Test vectors (hex-encoded) for ED25519 keys from the spec */
#define ED25519_PRIVATE_HEX                                                                                            \
	"080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b" \
	"871c3cacf6010f0e42d474fce27e"
#define ED25519_PUBLIC_HEX "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

/* New test vectors (hex-encoded) for ECDSA keys from the spec */
#define ECDSA_PRIVATE_HEX                                                                                              \
	"08031279307702010104203E5B1FE9712E6C314942A750BD67485DE3C1EFE85B1BFB520AE8F9AE3DFA4A4CA00A06082A8648CE3D0301" \
	"07A14403420004DE3D300FA36AE0E8F5D530899D83ABAB44ABF3161F162A4BC901D8E6ECDA020E8B6D5F8DA30525E71D6851510C098E" \
	"5C47C646A597FB4DCEC034E9F77C409E62"
#define ECDSA_PUBLIC_HEX                                                                                               \
	"0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004de3d300fa36ae0e8f5d530899d83abab44abf3161f162a" \
	"4bc901d8e6ecda020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9f77c409e62"

typedef struct
{
	const char *name;
	const char *public_hex;
	const char *private_hex;
} peer_key_vector_t;

static int g_failures = 0;

static void report_result(const char *test_name, int passed, const char *details)
{
	if (passed != 0)
	{
		print_standard(test_name, "", 1);
	}
	else
	{
		++g_failures;
		print_standard(test_name, details, 0);
	}
}

static peer_id_error_t peer_id_from_public_hex(const char *hex, peer_id_t *out)
{
	peer_id_error_t status;
	size_t key_len;
	uint8_t *key_bytes;

	status = PEER_ID_E_ALLOC_FAILED;
	key_len = 0U;
	key_bytes = hex_to_bytes(hex, &key_len);
	if (key_bytes != NULL)
	{
		status = peer_id_create_from_public_key(key_bytes, key_len, out);
		free(key_bytes);
	}

	return status;
}

static peer_id_error_t peer_id_from_private_hex(const char *hex, peer_id_t *out)
{
	peer_id_error_t status;
	size_t key_len;
	uint8_t *key_bytes;

	status = PEER_ID_E_ALLOC_FAILED;
	key_len = 0U;
	key_bytes = hex_to_bytes(hex, &key_len);
	if (key_bytes != NULL)
	{
		status = peer_id_create_from_private_key(key_bytes, key_len, out);
		free(key_bytes);
	}

	return status;
}

static void run_round_trip_vector(const peer_key_vector_t *vector)
{
	char legacy[512];
	char cid[512];
	char test_name[128];
	peer_id_t from_public;
	peer_id_t from_private;
	peer_id_t from_legacy;
	peer_id_t from_cid;
	peer_id_error_t status;
	int rc;

	from_public.bytes = NULL;
	from_public.size = 0U;
	from_private.bytes = NULL;
	from_private.size = 0U;
	from_legacy.bytes = NULL;
	from_legacy.size = 0U;
	from_cid.bytes = NULL;
	from_cid.size = 0U;

	snprintf(test_name, sizeof(test_name), "%s create from public", vector->name);
	status = peer_id_from_public_hex(vector->public_hex, &from_public);
	report_result(test_name, status == PEER_ID_SUCCESS, "peer_id_create_from_public_key failed");
	if (status != PEER_ID_SUCCESS)
	{
		goto cleanup;
	}

	snprintf(test_name, sizeof(test_name), "%s create from private", vector->name);
	status = peer_id_from_private_hex(vector->private_hex, &from_private);
	report_result(test_name, status == PEER_ID_SUCCESS, "peer_id_create_from_private_key failed");
	if (status != PEER_ID_SUCCESS)
	{
		goto cleanup;
	}

	snprintf(test_name, sizeof(test_name), "%s private/public equality", vector->name);
	report_result(test_name, peer_id_equals(&from_public, &from_private) == 1, "derived peer IDs differ");

	snprintf(test_name, sizeof(test_name), "%s to legacy string", vector->name);
	rc = peer_id_to_string(&from_public, PEER_ID_FMT_BASE58_LEGACY, legacy, sizeof(legacy));
	report_result(test_name, rc > 0, "peer_id_to_string legacy failed");
	if (rc <= 0)
	{
		goto cleanup;
	}

	snprintf(test_name, sizeof(test_name), "%s parse legacy string", vector->name);
	status = peer_id_create_from_string(legacy, &from_legacy);
	report_result(test_name, status == PEER_ID_SUCCESS, "peer_id_create_from_string legacy failed");
	if (status == PEER_ID_SUCCESS)
	{
		snprintf(test_name, sizeof(test_name), "%s legacy round trip equals", vector->name);
		report_result(test_name, peer_id_equals(&from_public, &from_legacy) == 1,
			      "legacy parse differs from original");
	}

	snprintf(test_name, sizeof(test_name), "%s to cid string", vector->name);
	rc = peer_id_to_string(&from_public, PEER_ID_FMT_MULTIBASE_CIDv1, cid, sizeof(cid));
	report_result(test_name, rc > 0, "peer_id_to_string cid failed");
	if (rc <= 0)
	{
		goto cleanup;
	}

	snprintf(test_name, sizeof(test_name), "%s parse cid string", vector->name);
	status = peer_id_create_from_string(cid, &from_cid);
	report_result(test_name, status == PEER_ID_SUCCESS, "peer_id_create_from_string cid failed");
	if (status == PEER_ID_SUCCESS)
	{
		snprintf(test_name, sizeof(test_name), "%s cid round trip equals", vector->name);
		report_result(test_name, peer_id_equals(&from_public, &from_cid) == 1,
			      "cid parse differs from original");
	}

cleanup:
	peer_id_destroy(&from_public);
	peer_id_destroy(&from_private);
	peer_id_destroy(&from_legacy);
	peer_id_destroy(&from_cid);
}

static void run_basic_behavior_tests(void)
{
	peer_id_t left;
	peer_id_t right;
	peer_id_t invalid;
	peer_id_error_t status;
	char out[8];
	int rc;

	left.bytes = NULL;
	left.size = 0U;
	right.bytes = NULL;
	right.size = 0U;
	invalid.bytes = NULL;
	invalid.size = 7U;

	status = peer_id_from_public_hex(SECP256K1_PUBLIC_HEX, &left);
	report_result("create secp256k1 for behavior tests", status == PEER_ID_SUCCESS, "setup failed");
	if (status != PEER_ID_SUCCESS)
	{
		goto cleanup;
	}

	status = peer_id_from_public_hex(SECP256K1_PUBLIC_HEX, &right);
	report_result("create second secp256k1 for equals", status == PEER_ID_SUCCESS, "setup failed");
	if (status != PEER_ID_SUCCESS)
	{
		goto cleanup;
	}

	report_result("peer_id_equals same value", peer_id_equals(&left, &right) == 1, "expected equal peer IDs");

	if (right.size > 0U)
	{
		right.bytes[0] = (uint8_t)(right.bytes[0] ^ 0xFFU);
	}
	report_result("peer_id_equals different value", peer_id_equals(&left, &right) == 0,
		      "expected different peer IDs");

	report_result("peer_id_equals null input", peer_id_equals(&left, NULL) == -1, "expected invalid-input result");

	out[0] = 'X';
	rc = peer_id_to_string(&left, PEER_ID_FMT_BASE58_LEGACY, out, sizeof(out));
	report_result("peer_id_to_string short buffer", (rc < 0) && (out[0] == '\0'),
		      "expected short-buffer failure with output reset");

	rc = peer_id_to_string(NULL, PEER_ID_FMT_BASE58_LEGACY, out, sizeof(out));
	report_result("peer_id_to_string null pid", rc == -PEER_ID_E_NULL_PTR, "expected null pointer error");

	rc = peer_id_to_string(&left, PEER_ID_FMT_BASE58_LEGACY, NULL, sizeof(out));
	report_result("peer_id_to_string null output", rc == -PEER_ID_E_NULL_PTR, "expected null pointer error");

	rc = peer_id_to_string(&left, PEER_ID_FMT_BASE58_LEGACY, out, 0U);
	report_result("peer_id_to_string zero output size", rc == -PEER_ID_E_BUFFER_TOO_SMALL,
		      "expected buffer-too-small error");

	rc = peer_id_to_string(&left, (peer_id_format_t)99, out, sizeof(out));
	report_result("peer_id_to_string unsupported format", rc == -PEER_ID_E_ENCODING_FAILED,
		      "expected unsupported-format failure");

	peer_id_destroy(&invalid);
	report_result("peer_id_destroy resets size when bytes are null", invalid.size == 0U,
		      "expected size reset for null bytes");

cleanup:
	peer_id_destroy(&left);
	peer_id_destroy(&right);
}

static void run_invalid_input_tests(void)
{
	const uint8_t dummy = 0x00U;
	const uint8_t malformed_public[] = {0x08U, 0x01U, 0x12U, 0x05U, 0xAAU};
	const uint8_t malformed_private[] = {0x08U, 0x01U, 0x12U, 0x40U, 0xAAU};
	const uint8_t unsupported_private[] = {0x08U, 0x04U, 0x12U, 0x01U, 0x00U};
	peer_id_t pid;
	peer_id_error_t status;
	char legacy[256];
	int rc;

	pid.bytes = NULL;
	pid.size = 0U;

	status = peer_id_create_from_public_key(NULL, 1U, &pid);
	report_result("public key null input", status == PEER_ID_E_NULL_PTR, "expected null pointer error");

	status = peer_id_create_from_public_key(&dummy, 1U, NULL);
	report_result("public key null output", status == PEER_ID_E_NULL_PTR, "expected null pointer error");

	status = peer_id_create_from_public_key(&dummy, (size_t)((64U * 1024U) + 1U), &pid);
	report_result("public key oversize", status == PEER_ID_E_INVALID_RANGE, "expected invalid-range error");

	status = peer_id_create_from_public_key(malformed_public, sizeof(malformed_public), &pid);
	report_result("public key malformed protobuf", status == PEER_ID_E_INVALID_PROTOBUF,
		      "expected invalid-protobuf error");

	status = peer_id_create_from_private_key(NULL, 1U, &pid);
	report_result("private key null input", status == PEER_ID_E_NULL_PTR, "expected null pointer error");

	status = peer_id_create_from_private_key(malformed_private, sizeof(malformed_private), &pid);
	report_result("private key malformed protobuf", status == PEER_ID_E_INVALID_PROTOBUF,
		      "expected invalid-protobuf error");

	status = peer_id_create_from_private_key(unsupported_private, sizeof(unsupported_private), &pid);
	report_result("private key unsupported type", status == PEER_ID_E_INVALID_PROTOBUF,
		      "expected invalid-protobuf error");

	status = peer_id_create_from_string(NULL, &pid);
	report_result("string null input", status == PEER_ID_E_NULL_PTR, "expected null pointer error");

	status = peer_id_create_from_string("", &pid);
	report_result("string empty input", status == PEER_ID_E_INVALID_STRING, "expected invalid-string error");

	status = peer_id_create_from_string("@@@", &pid);
	report_result("string non-base input", status == PEER_ID_E_INVALID_STRING, "expected invalid-string error");

	status = peer_id_create_from_string("bafyinvalid", &pid);
	report_result("string malformed cid", status == PEER_ID_E_INVALID_STRING, "expected invalid-string error");

	status = peer_id_create_from_string("QmInvalidPeerId%", &pid);
	report_result("string malformed legacy", status == PEER_ID_E_INVALID_STRING, "expected invalid-string error");

	status = peer_id_create_from_string("12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E", &pid);
	report_result("string known peer id", status == PEER_ID_SUCCESS, "expected known peer ID to parse");
	if (status == PEER_ID_SUCCESS)
	{
		rc = peer_id_to_string(&pid, PEER_ID_FMT_BASE58_LEGACY, legacy, sizeof(legacy));
		report_result("known peer id legacy encode", rc > 0, "expected known peer ID to encode");
	}
	peer_id_destroy(&pid);
}

int main(void)
{
	const peer_key_vector_t vectors[] = {
		{"secp256k1", SECP256K1_PUBLIC_HEX, SECP256K1_PRIVATE_HEX},
		{"rsa", RSA_PUBLIC_HEX, RSA_PRIVATE_HEX},
		{"ed25519", ED25519_PUBLIC_HEX, ED25519_PRIVATE_HEX},
		{"ecdsa", ECDSA_PUBLIC_HEX, ECDSA_PRIVATE_HEX},
	};
	size_t index;

	for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
	{
		run_round_trip_vector(&vectors[index]);
	}

	run_basic_behavior_tests();
	run_invalid_input_tests();

	if (g_failures > 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", g_failures);
		return EXIT_FAILURE;
	}

	printf("\nAll tests passed!\n");
	return EXIT_SUCCESS;
}
