#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multihash/multihash.h"
#include "peer_id/peer_id.h"

static int g_failures = 0;

static void print_standard(const char *name, const char *details, int passed)
{
	if (passed != 0)
	{
		printf("TEST: %-56s | PASS\n", name);
	}
	else
	{
		printf("TEST: %-56s | FAIL: %s\n", name, details);
		++g_failures;
	}
}

static void test_ok(const char *name, int cond, const char *details)
{
	print_standard(name, details, cond);
}

static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
	size_t hex_len;
	size_t bytes_len;
	size_t i;
	uint8_t *bytes;

	if ((hex == NULL) || (out_len == NULL))
	{
		return NULL;
	}

	hex_len = strlen(hex);
	if ((hex_len % (size_t)2U) != (size_t)0U)
	{
		return NULL;
	}

	bytes_len = hex_len / (size_t)2U;
	bytes = (uint8_t *)malloc(bytes_len);
	if (bytes == NULL)
	{
		return NULL;
	}

	for (i = (size_t)0U; i < bytes_len; ++i)
	{
		char byte_str[3];

		byte_str[0] = hex[i * 2U];
		byte_str[1] = hex[i * 2U + 1U];
		byte_str[2] = '\0';
		bytes[i] = (uint8_t)strtoul(byte_str, NULL, 16);
	}

	*out_len = bytes_len;
	return bytes;
}

#define SECP256K1_PUBLIC_HEX "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
#define SECP256K1_PRIVATE_HEX "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"

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

#define ED25519_PRIVATE_HEX                                                                                            \
	"080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b" \
	"871c3cacf6010f0e42d474fce27e"
#define ED25519_PUBLIC_HEX "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

#define ECDSA_PRIVATE_HEX                                                                                              \
	"08031279307702010104203E5B1FE9712E6C314942A750BD67485DE3C1EFE85B1BFB520AE8F9AE3DFA4A4CA00A06082A8648CE3D0301" \
	"07A14403420004DE3D300FA36AE0E8F5D530899D83ABAB44ABF3161F162A4BC901D8E6ECDA020E8B6D5F8DA30525E71D6851510C098E" \
	"5C47C646A597FB4DCEC034E9F77C409E62"
#define ECDSA_PUBLIC_HEX                                                                                               \
	"0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004de3d300fa36ae0e8f5d530899d83abab44abf3161f162a" \
	"4bc901d8e6ecda020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9f77c409e62"

typedef struct peer_key_vector
{
	const char *name;
	const char *public_hex;
	const char *private_hex;
} peer_key_vector_t;

static peer_id_error_t pid_from_public_hex(const char *hex, peer_id_t **out)
{
	size_t len;
	uint8_t *bytes;
	peer_id_error_t rc;

	len = (size_t)0U;
	bytes = hex_to_bytes(hex, &len);
	if (bytes == NULL)
	{
		return PEER_ID_ERR_ALLOC;
	}

	rc = peer_id_new_from_public_key_pb(bytes, len, out);
	free(bytes);
	return rc;
}

static peer_id_error_t pid_from_private_hex(const char *hex, peer_id_t **out)
{
	size_t len;
	uint8_t *bytes;
	peer_id_error_t rc;

	len = (size_t)0U;
	bytes = hex_to_bytes(hex, &len);
	if (bytes == NULL)
	{
		return PEER_ID_ERR_ALLOC;
	}

	rc = peer_id_new_from_private_key_pb(bytes, len, out);
	free(bytes);
	return rc;
}

static void run_vector_roundtrip(const peer_key_vector_t *v)
{
	char name[128];
	char legacy[512];
	char cid[512];
	size_t out_len;
	peer_id_t *from_pub;
	peer_id_t *from_priv;
	peer_id_t *from_legacy;
	peer_id_t *from_cid;
	peer_id_error_t rc;

	out_len = (size_t)0U;
	from_pub = NULL;
	from_priv = NULL;
	from_legacy = NULL;
	from_cid = NULL;

	snprintf(name, sizeof(name), "%s: from public", v->name);
	rc = pid_from_public_hex(v->public_hex, &from_pub);
	test_ok(name, rc == PEER_ID_OK, "peer_id_new_from_public_key_pb failed");
	if (rc != PEER_ID_OK)
	{
		goto cleanup;
	}

	snprintf(name, sizeof(name), "%s: from private", v->name);
	rc = pid_from_private_hex(v->private_hex, &from_priv);
	test_ok(name, rc == PEER_ID_OK, "peer_id_new_from_private_key_pb failed");
	if (rc != PEER_ID_OK)
	{
		goto cleanup;
	}

	snprintf(name, sizeof(name), "%s: pub/private equal", v->name);
	test_ok(name, peer_id_equal(from_pub, from_priv) == 1, "derived peer ids differ");

	snprintf(name, sizeof(name), "%s: legacy write", v->name);
	rc = peer_id_text_write(from_pub, PEER_ID_TEXT_LEGACY_BASE58, legacy, sizeof(legacy), &out_len);
	test_ok(name, (rc == PEER_ID_OK) && (out_len > 0U), "legacy write failed");
	if (rc != PEER_ID_OK)
	{
		goto cleanup;
	}

	snprintf(name, sizeof(name), "%s: parse legacy", v->name);
	rc = peer_id_new_from_text(legacy, &from_legacy);
	test_ok(name, rc == PEER_ID_OK, "legacy parse failed");
	if (rc == PEER_ID_OK)
	{
		snprintf(name, sizeof(name), "%s: legacy roundtrip equal", v->name);
		test_ok(name, peer_id_equal(from_pub, from_legacy) == 1, "legacy roundtrip mismatch");
	}

	snprintf(name, sizeof(name), "%s: cid write", v->name);
	rc = peer_id_text_write(from_pub, PEER_ID_TEXT_CIDV1_BASE32, cid, sizeof(cid), &out_len);
	test_ok(name, (rc == PEER_ID_OK) && (out_len > 0U), "cid write failed");
	if (rc != PEER_ID_OK)
	{
		goto cleanup;
	}

	snprintf(name, sizeof(name), "%s: parse cid", v->name);
	rc = peer_id_new_from_text(cid, &from_cid);
	test_ok(name, rc == PEER_ID_OK, "cid parse failed");
	if (rc == PEER_ID_OK)
	{
		snprintf(name, sizeof(name), "%s: cid roundtrip equal", v->name);
		test_ok(name, peer_id_equal(from_pub, from_cid) == 1, "cid roundtrip mismatch");
	}

	snprintf(name, sizeof(name), "%s: default write legacy", v->name);
	rc = peer_id_text_write_default(from_pub, legacy, sizeof(legacy), &out_len);
	test_ok(name, (rc == PEER_ID_OK) && (legacy[0] == 'Q' || legacy[0] == '1'), "default writer not legacy");

cleanup:
	peer_id_free(from_pub);
	peer_id_free(from_priv);
	peer_id_free(from_legacy);
	peer_id_free(from_cid);
}

static void run_parse_strict_tests(void)
{
	peer_id_t *pid;
	peer_id_error_t rc;

	pid = NULL;

	rc = peer_id_new_from_text("", &pid);
	test_ok("strict parse: empty rejected", rc == PEER_ID_ERR_INVALID_STRING, "empty should fail");

	rc = peer_id_new_from_text("@@@", &pid);
	test_ok("strict parse: invalid prefix rejected", rc == PEER_ID_ERR_INVALID_STRING, "bad prefix should fail");

	rc = peer_id_new_from_text("QmInvalidPeerId%", &pid);
	test_ok("strict parse: malformed legacy rejected", rc == PEER_ID_ERR_INVALID_STRING, "bad legacy should fail");

	rc = peer_id_new_from_text("bafyinvalid", &pid);
	test_ok("strict parse: malformed cid rejected", rc == PEER_ID_ERR_INVALID_STRING, "bad cid should fail");

	rc = peer_id_new_from_text("12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E", &pid);
	test_ok("strict parse: known id accepted", rc == PEER_ID_OK, "known id should parse");
	peer_id_free(pid);
}

static void run_multihash_integrity_tests(void)
{
	const uint8_t bad1[] = {0x12U};
	const uint8_t bad2[] = {0x12U, 0x20U, 0xAAU};
	const uint8_t bad3[] = {0x00U, 0x02U, 0xAAU};
	peer_id_t *pid;
	peer_id_error_t rc;

	pid = NULL;

	rc = peer_id_new_from_multihash(bad1, sizeof(bad1), &pid);
	test_ok("multihash integrity: truncated varint", rc == PEER_ID_ERR_INVALID_STRING, "should reject");

	rc = peer_id_new_from_multihash(bad2, sizeof(bad2), &pid);
	test_ok("multihash integrity: truncated digest", rc == PEER_ID_ERR_INVALID_STRING, "should reject");

	rc = peer_id_new_from_multihash(bad3, sizeof(bad3), &pid);
	test_ok("multihash integrity: identity length mismatch", rc == PEER_ID_ERR_INVALID_STRING, "should reject");
}

static void run_pb_strictness_tests(void)
{
	const uint8_t reordered[] = {0x12U, 0x01U, 0x01U, 0x08U, 0x01U};
	const uint8_t missing_data[] = {0x08U, 0x01U};
	const uint8_t extra_field[] = {0x08U, 0x01U, 0x12U, 0x01U, 0xAAU, 0x18U, 0x01U};
	const uint8_t non_minimal_type[] = {0x08U, 0x81U, 0x00U, 0x12U, 0x01U, 0xAAU};
	peer_id_t *pid;
	peer_id_error_t rc;

	pid = NULL;

	rc = peer_id_new_from_public_key_pb(reordered, sizeof(reordered), &pid);
	test_ok("pb strict: field order", rc == PEER_ID_ERR_INVALID_PROTOBUF, "reordered fields must fail");

	rc = peer_id_new_from_public_key_pb(missing_data, sizeof(missing_data), &pid);
	test_ok("pb strict: missing field", rc == PEER_ID_ERR_INVALID_PROTOBUF, "missing data must fail");

	rc = peer_id_new_from_public_key_pb(extra_field, sizeof(extra_field), &pid);
	test_ok("pb strict: extra field", rc == PEER_ID_ERR_INVALID_PROTOBUF, "extra field must fail");

	rc = peer_id_new_from_public_key_pb(non_minimal_type, sizeof(non_minimal_type), &pid);
	test_ok("pb strict: non-minimal varint", rc == PEER_ID_ERR_INVALID_PROTOBUF, "non-minimal varint must fail");
}

static void run_identity_threshold_tests(void)
{
	uint8_t pb42[42];
	uint8_t pb43[43];
	size_t pb42_len;
	size_t pb43_len;
	peer_id_t *pid42;
	peer_id_t *pid43;
	const uint8_t *mh;
	size_t mh_len;

	(void)memset(pb42, 0, sizeof(pb42));
	(void)memset(pb43, 0, sizeof(pb43));
	pb42[0] = 0x08U;
	pb42[1] = 0x01U;
	pb42[2] = 0x12U;
	pb42[3] = 0x26U; /* 38-byte payload => total protobuf length 42 */
	(void)memset(pb42 + 4, 0xA5, 38U);
	pb43[0] = 0x08U;
	pb43[1] = 0x01U;
	pb43[2] = 0x12U;
	pb43[3] = 0x27U; /* 39-byte payload => total protobuf length 43 */
	(void)memset(pb43 + 4, 0x5A, 39U);
	pb42_len = sizeof(pb42);
	pb43_len = sizeof(pb43);
	pid42 = NULL;
	pid43 = NULL;
	mh = NULL;
	mh_len = (size_t)0U;
	test_ok("threshold pb length 42", pb42_len == 42U, "expected 42-byte pb");
	test_ok("threshold pb length 43", pb43_len == 43U, "expected 43-byte pb");

	test_ok("threshold pid42", peer_id_new_from_public_key_pb(pb42, pb42_len, &pid42) == PEER_ID_OK,
		"pid42 failed");
	test_ok("threshold pid43", peer_id_new_from_public_key_pb(pb43, pb43_len, &pid43) == PEER_ID_OK,
		"pid43 failed");

	if (pid42 != NULL)
	{
		test_ok("threshold pid42 view", peer_id_multihash_view(pid42, &mh, &mh_len) == PEER_ID_OK,
			"view failed");
		test_ok("threshold <=42 uses identity", (mh_len > 0U) && (mh[0] == (uint8_t)MULTIHASH_CODE_IDENTITY),
			"expected identity");
	}

	if (pid43 != NULL)
	{
		test_ok("threshold pid43 view", peer_id_multihash_view(pid43, &mh, &mh_len) == PEER_ID_OK,
			"view failed");
		test_ok("threshold >42 uses sha2-256", (mh_len > 0U) && (mh[0] == (uint8_t)MULTIHASH_CODE_SHA2_256),
			"expected sha2-256");
	}

	peer_id_free(pid42);
	peer_id_free(pid43);
}

static void run_clone_and_buffer_tests(void)
{
	peer_id_t *pid;
	peer_id_t *clone;
	peer_id_error_t rc;
	const uint8_t *a;
	const uint8_t *b;
	size_t a_len;
	size_t b_len;
	uint8_t small[2];
	size_t out_len;
	char text[8];

	pid = NULL;
	clone = NULL;
	a = NULL;
	b = NULL;
	a_len = (size_t)0U;
	b_len = (size_t)0U;
	out_len = (size_t)0U;
	text[0] = 'X';

	rc = pid_from_public_hex(SECP256K1_PUBLIC_HEX, &pid);
	test_ok("clone setup", rc == PEER_ID_OK, "setup failed");
	if (rc != PEER_ID_OK)
	{
		return;
	}

	rc = peer_id_clone(pid, &clone);
	test_ok("clone success", rc == PEER_ID_OK, "clone failed");
	test_ok("clone equality", peer_id_equal(pid, clone) == 1, "clone not equal");

	if ((peer_id_multihash_view(pid, &a, &a_len) == PEER_ID_OK) &&
	    (peer_id_multihash_view(clone, &b, &b_len) == PEER_ID_OK))
	{
		test_ok("clone independence", (a != b) && (a_len == b_len), "clone shares storage");
	}

	rc = peer_id_multihash_copy(pid, small, sizeof(small), &out_len);
	test_ok("copy short buffer", rc == PEER_ID_ERR_BUFFER_TOO_SMALL, "expected short buffer error");

	rc = peer_id_text_write(pid, PEER_ID_TEXT_LEGACY_BASE58, text, sizeof(text), &out_len);
	test_ok("write short buffer resets output", (rc != PEER_ID_OK) && (text[0] == '\0'), "expected reset");

	peer_id_free(pid);
	peer_id_free(clone);
}

int main(void)
{
	const peer_key_vector_t vectors[] = {
		{"secp256k1", SECP256K1_PUBLIC_HEX, SECP256K1_PRIVATE_HEX},
		{"rsa", RSA_PUBLIC_HEX, RSA_PRIVATE_HEX},
		{"ed25519", ED25519_PUBLIC_HEX, ED25519_PRIVATE_HEX},
		{"ecdsa", ECDSA_PUBLIC_HEX, ECDSA_PRIVATE_HEX},
	};
	size_t i;

	for (i = (size_t)0U; i < (sizeof(vectors) / sizeof(vectors[0])); ++i)
	{
		run_vector_roundtrip(&vectors[i]);
	}

	run_parse_strict_tests();
	run_multihash_integrity_tests();
	run_pb_strictness_tests();
	run_identity_threshold_tests();
	run_clone_and_buffer_tests();

	if (g_failures != 0)
	{
		printf("\nSome tests failed. Total failures: %d\n", g_failures);
		return EXIT_FAILURE;
	}

	printf("\nAll tests passed!\n");
	return EXIT_SUCCESS;
}
