#ifdef _WIN32
// avoid pulling in the world
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// core Windows types, plus LONG, DWORD, etc.
#include <windows.h>
// Win32 CryptoAPI (CryptGenRandom, CryptAcquireContext, …)
#include <wincrypt.h>
#else
// POSIX / BSD side
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#endif

#include "../../lib/secp256k1/include/secp256k1.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_secp256k1.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_EXPLICIT_BZERO
static void explicit_bzero(void *s, size_t n)
{
    volatile unsigned char *p = s;
    while (n--)
        *p++ = 0;
}
#endif

static int get_random_bytes(void *buf, size_t len)
{
#if defined(__linux__)
    ssize_t r = getrandom(buf, len, 0);
    if (r == (ssize_t)len)
    {
        return 0;
    }
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return -1;
    }
    size_t total = 0;
    while (total < len)
    {
        ssize_t n = read(fd, (char *)buf + total, len - total);
        if (n <= 0)
        {
            close(fd);
            return -1;
        }
        total += n;
    }
    close(fd);
    return 0;

#elif defined(_WIN32)
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        return -1;
    }
    if (!CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf))
    {
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    CryptReleaseContext(hProv, 0);
    return 0;

#else
    arc4random_buf(buf, len);
    return 0;
#endif
}

peer_id_error_t peer_id_create_from_private_key_secp256k1(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len)
{
    if (!key_data || !pubkey_buf || !pubkey_len)
    {
        return PEER_ID_E_NULL_PTR;
    }
    if (key_data_len != 32)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
    {
        return PEER_ID_E_CRYPTO_FAILED;
    }

    unsigned char seed32[32];
    if (get_random_bytes(seed32, sizeof(seed32)) != 0 || !secp256k1_context_randomize(ctx, seed32))
    {
        explicit_bzero(seed32, sizeof(seed32));
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }
    explicit_bzero(seed32, sizeof(seed32));

    if (!secp256k1_ec_seckey_verify(ctx, key_data))
    {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    uint8_t seckey[32];
    memcpy(seckey, key_data, 32);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey))
    {
        explicit_bzero(seckey, sizeof(seckey));
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    uint8_t raw_pubkey[33];
    size_t len = sizeof(raw_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, raw_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED) || len != 33)
    {
        explicit_bzero(seckey, sizeof(seckey));
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    secp256k1_context_destroy(ctx);

    peer_id_error_t err = peer_id_build_public_key_protobuf(PEER_ID_SECP256K1_KEY_TYPE, raw_pubkey, len, pubkey_buf, pubkey_len);

    explicit_bzero(&pubkey, sizeof(pubkey));
    explicit_bzero(seckey, sizeof(seckey));

    return err;
}