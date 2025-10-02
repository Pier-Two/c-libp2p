#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/ltc_compat.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_rsa.h"

#ifdef _WIN32
#include <windows.h>
#define secure_zero(ptr, len) SecureZeroMemory((PVOID)(ptr), (SIZE_T)(len))
#else
/**
 * @brief Securely zero out a memory region.
 *
 * This function ensures that the memory region pointed to by `ptr` is securely
 * zeroed out, preventing sensitive data from lingering in memory.
 *
 * @param ptr Pointer to the memory region to zero out.
 * @param len Length of the memory region in bytes.
 */
static void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
}
#endif

/* Detect C11 threads support */
#if defined(__has_include)
#if __has_include(<threads.h>)
#include <threads.h>
#define HAVE_C11_THREADS 1
#endif
#endif

/**
 * @brief Initialize the LibTomCrypt multi-precision descriptor.
 *
 * This function sets the global `ltc_mp` descriptor to the appropriate
 * multi-precision library descriptor based on the available configuration.
 */
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

/* C11 threads: use call_once */
static once_flag ltc_mp_once = ONCE_FLAG_INIT;
#define CALL_LTC_MP_INIT() call_once(&ltc_mp_once, init_ltc_mp_shared)

#elif defined(_WIN32)

/* Windows InitOnce */
static INIT_ONCE ltc_mp_once = INIT_ONCE_STATIC_INIT;
/**
 * @brief Windows-specific initialization callback for LibTomCrypt.
 *
 * This function is used with `InitOnceExecuteOnce` to ensure that the
 * `init_ltc_mp_shared` function is called only once in a thread-safe manner.
 *
 * @return TRUE on successful initialization.
 */
static BOOL CALLBACK init_ltc_mp_windows(PINIT_ONCE, PVOID, PVOID *)
{
    init_ltc_mp_shared();
    return TRUE;
}
#define CALL_LTC_MP_INIT() InitOnceExecuteOnce(&ltc_mp_once, init_ltc_mp_windows, NULL, NULL)

#else

/* POSIX pthreads */
#include <pthread.h>
static pthread_once_t ltc_mp_once = PTHREAD_ONCE_INIT;
#define CALL_LTC_MP_INIT() pthread_once(&ltc_mp_once, init_ltc_mp_shared)

#endif

/**
 * @brief Create a public key from an RSA private key.
 *
 * This function takes an RSA private key, imports it, and then exports the
 * corresponding public key in a protobuf format.
 *
 * @param key_data Pointer to the RSA private key data.
 * @param key_data_len Length of the private key data in bytes.
 * @param pubkey_buf [out] Pointer to the buffer where the public key will be stored.
 * @param pubkey_len [out] Pointer to the length of the public key buffer.
 *
 * @return A `peer_id_error_t` error code indicating success or failure.
 */
peer_id_error_t peer_id_create_from_private_key_rsa(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len)
{
    if (!key_data || !pubkey_buf || !pubkey_len)
    {
        return PEER_ID_E_NULL_PTR;
    }

    CALL_LTC_MP_INIT();
    if (ltc_mp.name == NULL)
    {
        return PEER_ID_E_CRYPTO_FAILED;
    }

    rsa_key rsa;
    int err = rsa_import(key_data, (unsigned long)key_data_len, &rsa);
    if (err != CRYPT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    secure_zero((void *)key_data, key_data_len);

    size_t der_len = 1, old_len = 0;
    uint8_t *der_buf = malloc(der_len);
    if (!der_buf)
    {
        rsa_free(&rsa);
        secure_zero(&rsa, sizeof(rsa));
        return PEER_ID_E_ALLOC_FAILED;
    }

    err = rsa_export(der_buf, (unsigned long *)&der_len, PK_PUBLIC | PK_STD, &rsa);
    while (err == CRYPT_BUFFER_OVERFLOW)
    {
        old_len = der_len;
        uint8_t *tmp = realloc(der_buf, der_len);
        if (!tmp)
        {
            secure_zero(der_buf, old_len);
            free(der_buf);
            rsa_free(&rsa);
            secure_zero(&rsa, sizeof(rsa));
            return PEER_ID_E_ALLOC_FAILED;
        }
        der_buf = tmp;
        err = rsa_export(der_buf, (unsigned long *)&der_len, PK_PUBLIC | PK_STD, &rsa);
    }

    rsa_free(&rsa);
    secure_zero(&rsa, sizeof(rsa));

    if (err != CRYPT_OK)
    {
        secure_zero(der_buf, der_len);
        free(der_buf);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    peer_id_error_t ret = peer_id_build_public_key_protobuf(PEER_ID_RSA_KEY_TYPE, der_buf, der_len, pubkey_buf, pubkey_len);

    secure_zero(der_buf, der_len);
    free(der_buf);

    return ret;
}
