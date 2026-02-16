#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../external/secp256k1/include/secp256k1.h"
#include "peer_id_internal.h"

#ifndef HAVE_EXPLICIT_BZERO
static void explicit_bzero_local(void *s, size_t n)
{
	volatile unsigned char *p;

	p = (volatile unsigned char *)s;
	while (n > (size_t)0U)
	{
		*p = (unsigned char)0U;
		++p;
		--n;
	}
}
#else
#define explicit_bzero_local explicit_bzero
#endif

static int get_random_bytes(void *buf, size_t len)
{
#if defined(__linux__)
	ssize_t r;
	int fd;
	size_t total;

	r = getrandom(buf, len, 0);
	if (r == (ssize_t)len)
	{
		return 0;
	}

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
	{
		return -1;
	}

	total = (size_t)0U;
	while (total < len)
	{
		ssize_t n;

		n = read(fd, (char *)buf + total, len - total);
		if (n <= 0)
		{
			close(fd);
			return -1;
		}
		total += (size_t)n;
	}
	close(fd);
	return 0;
#elif defined(_WIN32)
	HCRYPTPROV h_prov;

	h_prov = (HCRYPTPROV)0;
	if (CryptAcquireContextA(&h_prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		return -1;
	}
	if (CryptGenRandom(h_prov, (DWORD)len, (BYTE *)buf) == FALSE)
	{
		CryptReleaseContext(h_prov, 0);
		return -1;
	}
	CryptReleaseContext(h_prov, 0);
	return 0;
#else
	arc4random_buf(buf, len);
	return 0;
#endif
}

peer_id_error_t peer_id_internal_pub_from_private_secp256k1(const uint8_t *key_data, size_t key_data_len,
							    uint8_t **pubkey_buf, size_t *pubkey_len)
{
	peer_id_error_t status;
	secp256k1_context *ctx;
	unsigned char seed32[32];
	uint8_t seckey[32];
	secp256k1_pubkey pubkey;
	uint8_t raw_pubkey[33];
	size_t len;

	status = PEER_ID_OK;
	ctx = NULL;
	len = sizeof(raw_pubkey);

	if ((key_data == NULL) || (pubkey_buf == NULL) || (pubkey_len == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*pubkey_buf = NULL;
	*pubkey_len = (size_t)0U;

	if (key_data_len != (size_t)32U)
	{
		return PEER_ID_ERR_INVALID_PROTOBUF;
	}

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	if (ctx == NULL)
	{
		return PEER_ID_ERR_CRYPTO;
	}

	if ((get_random_bytes(seed32, sizeof(seed32)) != 0) || (secp256k1_context_randomize(ctx, seed32) == 0))
	{
		explicit_bzero_local(seed32, sizeof(seed32));
		secp256k1_context_destroy(ctx);
		return PEER_ID_ERR_CRYPTO;
	}
	explicit_bzero_local(seed32, sizeof(seed32));

	if (secp256k1_ec_seckey_verify(ctx, key_data) == 0)
	{
		secp256k1_context_destroy(ctx);
		return PEER_ID_ERR_INVALID_PROTOBUF;
	}

	(void)memcpy(seckey, key_data, sizeof(seckey));

	if (secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 0)
	{
		explicit_bzero_local(seckey, sizeof(seckey));
		secp256k1_context_destroy(ctx);
		return PEER_ID_ERR_CRYPTO;
	}

	if ((secp256k1_ec_pubkey_serialize(ctx, raw_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 0) ||
	    (len != sizeof(raw_pubkey)))
	{
		explicit_bzero_local(seckey, sizeof(seckey));
		explicit_bzero_local(&pubkey, sizeof(pubkey));
		secp256k1_context_destroy(ctx);
		return PEER_ID_ERR_CRYPTO;
	}

	secp256k1_context_destroy(ctx);

	status = peer_id_internal_build_public_key_pb(PEER_ID_KEY_SECP256K1, raw_pubkey, len, pubkey_buf, pubkey_len);

	explicit_bzero_local(&pubkey, sizeof(pubkey));
	explicit_bzero_local(seckey, sizeof(seckey));

	return status;
}

peer_id_error_t peer_id_new_from_private_key_pb_secp256k1(const uint8_t *key_data, size_t key_data_len,
							  uint8_t **pubkey_buf, size_t *pubkey_len)
{
	return peer_id_internal_pub_from_private_secp256k1(key_data, key_data_len, pubkey_buf, pubkey_len);
}
