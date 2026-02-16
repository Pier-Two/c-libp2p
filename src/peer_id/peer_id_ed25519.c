#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../external/libeddsa/lib/eddsa.h"
#include "peer_id_internal.h"

#ifdef _WIN32
#include <windows.h>
#define secure_zero(ptr, len) SecureZeroMemory((PVOID)(ptr), (SIZE_T)(len))
#else
static void secure_zero(void *ptr, size_t len)
{
	volatile unsigned char *p;

	p = (volatile unsigned char *)ptr;
	while (len > (size_t)0U)
	{
		*p = (unsigned char)0U;
		++p;
		--len;
	}
}
#endif

peer_id_error_t peer_id_internal_pub_from_private_ed25519(const uint8_t *key_data, size_t key_data_len,
							  uint8_t **pubkey_buf, size_t *pubkey_len)
{
	peer_id_error_t status;
	const uint8_t *seed;
	uint8_t raw_pub[32];

	status = PEER_ID_OK;
	seed = NULL;
	(void)memset(raw_pub, 0, sizeof(raw_pub));

	if ((key_data == NULL) || (pubkey_buf == NULL) || (pubkey_len == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*pubkey_buf = NULL;
	*pubkey_len = (size_t)0U;

	/* Ed25519 private key payloads are either 32-byte seeds or 64-byte
	   concatenations (seed || public key). */
	if ((key_data_len != (size_t)32U) && (key_data_len != (size_t)64U))
	{
		return PEER_ID_ERR_INVALID_PROTOBUF;
	}

	seed = key_data;
	ed25519_genpub(raw_pub, seed);
	status = peer_id_internal_build_public_key_pb(PEER_ID_KEY_ED25519, raw_pub, sizeof(raw_pub), pubkey_buf,
						      pubkey_len);
	secure_zero(raw_pub, sizeof(raw_pub));
	return status;
}

peer_id_error_t peer_id_new_from_private_key_pb_ed25519(const uint8_t *key_data, size_t key_data_len,
							uint8_t **pubkey_buf, size_t *pubkey_len)
{
	return peer_id_internal_pub_from_private_ed25519(key_data, key_data_len, pubkey_buf, pubkey_len);
}
