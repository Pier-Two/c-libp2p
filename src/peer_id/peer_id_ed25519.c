#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/ltc_compat.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_proto.h"

#ifdef _WIN32
#include <windows.h>
#define secure_zero(ptr, len) SecureZeroMemory((PVOID)(ptr), (SIZE_T)(len))
#else

/**
 * @brief Securely zero out a memory region.
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

/* Shared initializer for the LibTomCrypt multi‑precision descriptor */
/**
 * @brief Initialize the multi-precision descriptor for LibTomCrypt.
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
 * @brief Create a peer ID from an Ed25519 private key.
 *
 * @param key_data Pointer to the private key data.
 * @param key_data_len Length of the private key data.
 * @param pubkey_buf Pointer to store the generated public key buffer.
 * @param pubkey_len Pointer to store the length of the generated public key buffer.
 * @return peer_id_error_t Error code indicating success or type of failure.
 */
peer_id_error_t peer_id_create_from_private_key_ed25519(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len)
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

#ifdef LTC_CURVE25519
    curve25519_key ed_key;
    int err = ed25519_import_raw(key_data, (unsigned long)key_data_len, PK_PRIVATE, &ed_key);
    if (err != CRYPT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    secure_zero((void *)key_data, key_data_len);

    const int export_flags = PK_PUBLIC;
    size_t der_len = 1, old_len = 0;
    uint8_t *der_buf = malloc(der_len);
    if (!der_buf)
    {
        secure_zero(&ed_key, sizeof(ed_key));
        return PEER_ID_E_ALLOC_FAILED;
    }

    err = ed25519_export(der_buf, (unsigned long *)&der_len, export_flags, &ed_key);
    while (err == CRYPT_BUFFER_OVERFLOW)
    {
        old_len = der_len;
        uint8_t *tmp = realloc(der_buf, der_len);
        if (!tmp)
        {
            secure_zero(der_buf, old_len);
            free(der_buf);
            secure_zero(&ed_key, sizeof(ed_key));
            return PEER_ID_E_ALLOC_FAILED;
        }
        der_buf = tmp;
        err = ed25519_export(der_buf, (unsigned long *)&der_len, export_flags, &ed_key);
    }

    if (err != CRYPT_OK)
    {
        secure_zero(der_buf, der_len);
        free(der_buf);
        secure_zero(&ed_key, sizeof(ed_key));
        return PEER_ID_E_CRYPTO_FAILED;
    }

    peer_id_error_t ret = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE, der_buf, der_len, pubkey_buf, pubkey_len);

    secure_zero(der_buf, der_len);
    free(der_buf);
    secure_zero(&ed_key, sizeof(ed_key));

    return ret;
#else
    return PEER_ID_E_CRYPTO_FAILED;
#endif
}

#undef ed25519_export
#undef ed25519_import_raw
