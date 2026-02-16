#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/ltc_compat.h"
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

#if !defined(_WIN32) && defined(__has_include)
#if __has_include(<threads.h>)
#include <threads.h>
#define HAVE_C11_THREADS 1
#endif
#endif

static void init_ltc_mp_shared(void)
{
#if defined(LTM_DESC)
	ltc_mp = ltm_desc;
#elif defined(TFM_DESC)
	ltc_mp = tfm_desc;
#elif defined(GMP_DESC)
	ltc_mp = gmp_desc;
#else
	ltc_mp.name = NULL;
#endif
}

#if defined(HAVE_C11_THREADS)
static once_flag ltc_mp_once = ONCE_FLAG_INIT;
#define CALL_LTC_MP_INIT() call_once(&ltc_mp_once, init_ltc_mp_shared)
#elif defined(_WIN32)
static INIT_ONCE ltc_mp_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK init_ltc_mp_windows(PINIT_ONCE once, PVOID param, PVOID *context)
{
	(void)once;
	(void)param;
	(void)context;
	init_ltc_mp_shared();
	return TRUE;
}
#define CALL_LTC_MP_INIT() InitOnceExecuteOnce(&ltc_mp_once, init_ltc_mp_windows, NULL, NULL)
#else
#include <pthread.h>
static pthread_once_t ltc_mp_once = PTHREAD_ONCE_INIT;
#define CALL_LTC_MP_INIT() pthread_once(&ltc_mp_once, init_ltc_mp_shared)
#endif

peer_id_error_t peer_id_internal_pub_from_private_rsa(const uint8_t *key_data, size_t key_data_len,
						      uint8_t **pubkey_buf, size_t *pubkey_len)
{
	peer_id_error_t status;
	rsa_key rsa;
	int ltc_err;
	unsigned long der_len;
	unsigned long old_len;
	uint8_t *der_buf;
	uint8_t *tmp;

	status = PEER_ID_OK;
	der_len = 1UL;
	old_len = 0UL;
	der_buf = NULL;
	tmp = NULL;

	if ((key_data == NULL) || (pubkey_buf == NULL) || (pubkey_len == NULL))
	{
		return PEER_ID_ERR_NULL_PTR;
	}

	*pubkey_buf = NULL;
	*pubkey_len = (size_t)0U;

	CALL_LTC_MP_INIT();
	if (ltc_mp.name == NULL)
	{
		return PEER_ID_ERR_CRYPTO;
	}

	ltc_err = rsa_import(key_data, (unsigned long)key_data_len, &rsa);
	if (ltc_err != CRYPT_OK)
	{
		return PEER_ID_ERR_INVALID_PROTOBUF;
	}

	der_buf = (uint8_t *)malloc((size_t)der_len);
	if (der_buf == NULL)
	{
		rsa_free(&rsa);
		secure_zero(&rsa, sizeof(rsa));
		return PEER_ID_ERR_ALLOC;
	}

	ltc_err = rsa_export(der_buf, &der_len, PK_PUBLIC | PK_STD, &rsa);
	while (ltc_err == CRYPT_BUFFER_OVERFLOW)
	{
		old_len = der_len;
		tmp = (uint8_t *)realloc(der_buf, (size_t)der_len);
		if (tmp == NULL)
		{
			secure_zero(der_buf, (size_t)old_len);
			free(der_buf);
			rsa_free(&rsa);
			secure_zero(&rsa, sizeof(rsa));
			return PEER_ID_ERR_ALLOC;
		}
		der_buf = tmp;
		ltc_err = rsa_export(der_buf, &der_len, PK_PUBLIC | PK_STD, &rsa);
	}

	rsa_free(&rsa);
	secure_zero(&rsa, sizeof(rsa));

	if (ltc_err != CRYPT_OK)
	{
		secure_zero(der_buf, (size_t)der_len);
		free(der_buf);
		return PEER_ID_ERR_CRYPTO;
	}

	status =
		peer_id_internal_build_public_key_pb(PEER_ID_KEY_RSA, der_buf, (size_t)der_len, pubkey_buf, pubkey_len);

	secure_zero(der_buf, (size_t)der_len);
	free(der_buf);

	return status;
}

peer_id_error_t peer_id_new_from_private_key_pb_rsa(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf,
						    size_t *pubkey_len)
{
	return peer_id_internal_pub_from_private_rsa(key_data, key_data_len, pubkey_buf, pubkey_len);
}
