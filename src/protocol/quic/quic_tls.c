#include "protocol/quic/protocol_quic.h"

#include "libp2p/errors.h"
#include "libp2p/log.h"
#include "peer_id/peer_id_proto.h"

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif
#include <time.h>
#if !defined(_WIN32)
#include <pthread.h>
#endif

#define DH libeddsa_DH
#include "../../../external/libeddsa/lib/eddsa.h"
#undef DH

#include "../../../external/secp256k1/include/secp256k1.h"
#include "../../../external/wjcryptlib/lib/WjCryptLib_Sha256.h"

#include "libp2p/crypto/ltc_compat.h"

#define PEER_ID_RSA_KEY_TYPE 0
#define PEER_ID_ED25519_KEY_TYPE 1
#define PEER_ID_SECP256K1_KEY_TYPE 2
#define PEER_ID_ECDSA_KEY_TYPE 3

static const uint8_t TLS_SIGN_PREFIX[] = "libp2p-tls-handshake:";

typedef struct libp2p_tls_signed_key
{
    ASN1_OCTET_STRING *public_key;
    ASN1_OCTET_STRING *signature;
} LIBP2P_TLS_SIGNED_KEY;

ASN1_SEQUENCE(LIBP2P_TLS_SIGNED_KEY) = {
    ASN1_SIMPLE(LIBP2P_TLS_SIGNED_KEY, public_key, ASN1_OCTET_STRING),
    ASN1_SIMPLE(LIBP2P_TLS_SIGNED_KEY, signature, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(LIBP2P_TLS_SIGNED_KEY)

IMPLEMENT_ASN1_FUNCTIONS(LIBP2P_TLS_SIGNED_KEY)

/* --- LibTomCrypt bignum initialisation helpers (mirrors Noise implementation) --- */

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

#if defined(__has_include)
#if __has_include(<threads.h>)
#include <threads.h>
#define HAVE_C11_THREADS 1
#endif
#endif

#if defined(HAVE_C11_THREADS)
static once_flag ltc_mp_once = ONCE_FLAG_INIT;
#define CALL_LTC_MP_INIT() call_once(&ltc_mp_once, init_ltc_mp_shared)
#elif defined(_WIN32)
#include <windows.h>
static INIT_ONCE ltc_mp_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK init_ltc_mp_windows(PINIT_ONCE, PVOID, PVOID *)
{
    init_ltc_mp_shared();
    return TRUE;
}
#define CALL_LTC_MP_INIT() InitOnceExecuteOnce(&ltc_mp_once, init_ltc_mp_windows, NULL, NULL)
#else
#include <pthread.h>
static pthread_once_t ltc_mp_once = PTHREAD_ONCE_INIT;
#define CALL_LTC_MP_INIT() pthread_once(&ltc_mp_once, init_ltc_mp_shared)
#endif

static int ensure_ltc_ready(void)
{
    CALL_LTC_MP_INIT();
    if (ltc_mp.name == NULL)
    {
        LP_LOGE("quic-tls", "libtomcrypt mp descriptor not initialised");
        return LIBP2P_ERR_INTERNAL;
    }
    return LIBP2P_ERR_OK;
}

static bool is_strong_signature_nid(int nid)
{
    switch (nid)
    {
        case NID_sha256WithRSAEncryption:
        case NID_sha384WithRSAEncryption:
        case NID_sha512WithRSAEncryption:
        case NID_ecdsa_with_SHA256:
        case NID_ecdsa_with_SHA384:
        case NID_ecdsa_with_SHA512:
        case NID_ED25519:
        case NID_ED448:
            return true;
        default:
            return false;
    }
}

static int sha256_hash(const uint8_t *data, size_t len, SHA256_HASH *out)
{
    if (!data || !out)
        return LIBP2P_ERR_NULL_PTR;
    Sha256Calculate(data, len, out);
    return LIBP2P_ERR_OK;
}

static int verify_signed_key(uint64_t key_type,
                             const uint8_t *key_data,
                             size_t key_len,
                             const uint8_t *sig,
                             size_t sig_len,
                             const uint8_t *msg,
                             size_t msg_len)
{
    if (!key_data || !sig || !msg)
        return LIBP2P_ERR_NULL_PTR;

    if (ensure_ltc_ready() != LIBP2P_ERR_OK)
        return LIBP2P_ERR_INTERNAL;

    if (key_type == PEER_ID_ED25519_KEY_TYPE)
    {
        if (sig_len != 64)
            return LIBP2P_ERR_INTERNAL;
        if (!eddsa_verify(sig, key_data, msg, msg_len))
            return LIBP2P_ERR_INTERNAL;
        return LIBP2P_ERR_OK;
    }

    if (key_type == PEER_ID_SECP256K1_KEY_TYPE)
    {
        SHA256_HASH hash;
        sha256_hash(msg, msg_len, &hash);

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        if (!ctx)
            return LIBP2P_ERR_INTERNAL;

        secp256k1_pubkey pk;
        int pk_ok = secp256k1_ec_pubkey_parse(ctx, &pk, key_data, key_len);
        if (!pk_ok)
        {
            secp256k1_context_destroy(ctx);
            return LIBP2P_ERR_INTERNAL;
        }

        secp256k1_ecdsa_signature sig_obj;
        int sig_ok = secp256k1_ecdsa_signature_parse_der(ctx, &sig_obj, sig, sig_len);
        if (!sig_ok && sig_len == 64)
            sig_ok = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_obj, sig);

        if (!sig_ok)
        {
            secp256k1_context_destroy(ctx);
            return LIBP2P_ERR_INTERNAL;
        }

        int ver_ok = secp256k1_ecdsa_verify(ctx, &sig_obj, hash.bytes, &pk);
        secp256k1_context_destroy(ctx);
        return ver_ok ? LIBP2P_ERR_OK : LIBP2P_ERR_INTERNAL;
    }

    if (key_type == PEER_ID_RSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        sha256_hash(msg, msg_len, &hash);

        rsa_key rsa;
        if (rsa_import(key_data, (unsigned long)key_len, &rsa) != CRYPT_OK)
            return LIBP2P_ERR_INTERNAL;
        int sha_idx = find_hash("sha256");
        int stat = 0;
        int rc = rsa_verify_hash_ex(sig, (unsigned long)sig_len, hash.bytes, sizeof(hash.bytes), LTC_PKCS_1_V1_5, sha_idx, 0, &stat, &rsa);
        rsa_free(&rsa);
        if (rc != CRYPT_OK || stat == 0)
            return LIBP2P_ERR_INTERNAL;
        return LIBP2P_ERR_OK;
    }

    if (key_type == PEER_ID_ECDSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        sha256_hash(msg, msg_len, &hash);

        ecc_key ecdsa;
        if (ecc_import_openssl(key_data, (unsigned long)key_len, &ecdsa) != CRYPT_OK)
            return LIBP2P_ERR_INTERNAL;
        int stat = 0;
        int rc = ecc_verify_hash(sig, (unsigned long)sig_len, hash.bytes, sizeof(hash.bytes), &stat, &ecdsa);
        ecc_free(&ecdsa);
        if (rc != CRYPT_OK || stat == 0)
            return LIBP2P_ERR_INTERNAL;
        return LIBP2P_ERR_OK;
    }

    return LIBP2P_ERR_UNSUPPORTED;
}

static int parse_signed_key(const ASN1_OCTET_STRING *raw, LIBP2P_TLS_SIGNED_KEY **out)
{
    if (!raw || !out)
        return LIBP2P_ERR_NULL_PTR;
    const unsigned char *ptr = ASN1_STRING_get0_data(raw);
    long len = ASN1_STRING_length(raw);
    if (ptr == NULL || len <= 0)
        return LIBP2P_ERR_INTERNAL;
    const unsigned char *tmp = ptr;
    LIBP2P_TLS_SIGNED_KEY *sk = d2i_LIBP2P_TLS_SIGNED_KEY(NULL, &tmp, len);
    if (!sk)
        return LIBP2P_ERR_INTERNAL;
    if (tmp != ptr + len)
    {
        LIBP2P_TLS_SIGNED_KEY_free(sk);
        return LIBP2P_ERR_INTERNAL;
    }
    *out = sk;
    return LIBP2P_ERR_OK;
}

static void secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
        *p++ = 0;
}

static int build_public_key_protobuf(uint64_t key_type,
                                     const uint8_t *identity_key,
                                     size_t identity_key_len,
                                     uint8_t **out_pb,
                                     size_t *out_pb_len)
{
    if (!identity_key || identity_key_len == 0 || !out_pb || !out_pb_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_pb = NULL;
    *out_pb_len = 0;

    if (ensure_ltc_ready() != LIBP2P_ERR_OK)
        return LIBP2P_ERR_INTERNAL;

    if (key_type == PEER_ID_ED25519_KEY_TYPE)
    {
        uint8_t pub[32];
        ed25519_genpub(pub, identity_key);
        peer_id_error_t perr = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE, pub, sizeof(pub), out_pb, out_pb_len);
        secure_zero(pub, sizeof(pub));
        return (perr == PEER_ID_SUCCESS) ? LIBP2P_ERR_OK : LIBP2P_ERR_INTERNAL;
    }

    if (key_type == PEER_ID_SECP256K1_KEY_TYPE)
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!ctx)
            return LIBP2P_ERR_INTERNAL;
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, identity_key))
        {
            secp256k1_context_destroy(ctx);
            return LIBP2P_ERR_INTERNAL;
        }
        uint8_t comp[33];
        size_t comp_len = sizeof(comp);
        if (!secp256k1_ec_pubkey_serialize(ctx, comp, &comp_len, &pk, SECP256K1_EC_COMPRESSED))
        {
            secp256k1_context_destroy(ctx);
            return LIBP2P_ERR_INTERNAL;
        }
        peer_id_error_t perr = peer_id_build_public_key_protobuf(PEER_ID_SECP256K1_KEY_TYPE, comp, comp_len, out_pb, out_pb_len);
        secp256k1_context_destroy(ctx);
        return (perr == PEER_ID_SUCCESS) ? LIBP2P_ERR_OK : LIBP2P_ERR_INTERNAL;
    }

    if (key_type == PEER_ID_RSA_KEY_TYPE)
    {
        rsa_key rsa;
        if (rsa_import(identity_key, (unsigned long)identity_key_len, &rsa) != CRYPT_OK)
            return LIBP2P_ERR_INTERNAL;
        unsigned long der_len = 1, old_len = 0;
        uint8_t *der_buf = (uint8_t *)malloc((size_t)der_len);
        if (!der_buf)
        {
            rsa_free(&rsa);
            return LIBP2P_ERR_INTERNAL;
        }
        int err = rsa_export(der_buf, &der_len, PK_PUBLIC | PK_STD, &rsa);
        while (err == CRYPT_BUFFER_OVERFLOW)
        {
            old_len = der_len;
            uint8_t *tmp = (uint8_t *)realloc(der_buf, (size_t)der_len);
            if (!tmp)
            {
                secure_zero(der_buf, (size_t)old_len);
                free(der_buf);
                rsa_free(&rsa);
                return LIBP2P_ERR_INTERNAL;
            }
            der_buf = tmp;
            err = rsa_export(der_buf, &der_len, PK_PUBLIC | PK_STD, &rsa);
        }
        rsa_free(&rsa);
        if (err != CRYPT_OK)
        {
            secure_zero(der_buf, (size_t)der_len);
            free(der_buf);
            return LIBP2P_ERR_INTERNAL;
        }
        peer_id_error_t perr = peer_id_build_public_key_protobuf(PEER_ID_RSA_KEY_TYPE, der_buf, (size_t)der_len, out_pb, out_pb_len);
        secure_zero(der_buf, (size_t)der_len);
        free(der_buf);
        return (perr == PEER_ID_SUCCESS) ? LIBP2P_ERR_OK : LIBP2P_ERR_INTERNAL;
    }

    if (key_type == PEER_ID_ECDSA_KEY_TYPE)
    {
        ecc_key ecdsa;
        if (ecc_import_openssl(identity_key, (unsigned long)identity_key_len, &ecdsa) != CRYPT_OK)
            return LIBP2P_ERR_INTERNAL;
        unsigned long der_len = 1, old_len = 0;
        uint8_t *der_buf = (uint8_t *)malloc((size_t)der_len);
        if (!der_buf)
        {
            ecc_free(&ecdsa);
            return LIBP2P_ERR_INTERNAL;
        }
        int err = ecc_export_openssl(der_buf, &der_len, PK_PUBLIC | PK_CURVEOID, &ecdsa);
        while (err == CRYPT_BUFFER_OVERFLOW)
        {
            old_len = der_len;
            uint8_t *tmp = (uint8_t *)realloc(der_buf, (size_t)der_len);
            if (!tmp)
            {
                secure_zero(der_buf, (size_t)old_len);
                free(der_buf);
                ecc_free(&ecdsa);
                return LIBP2P_ERR_INTERNAL;
            }
            der_buf = tmp;
            err = ecc_export_openssl(der_buf, &der_len, PK_PUBLIC | PK_CURVEOID, &ecdsa);
        }
        ecc_free(&ecdsa);
        if (err != CRYPT_OK)
        {
            secure_zero(der_buf, (size_t)der_len);
            free(der_buf);
            return LIBP2P_ERR_INTERNAL;
        }
        peer_id_error_t perr = peer_id_build_public_key_protobuf(PEER_ID_ECDSA_KEY_TYPE, der_buf, (size_t)der_len, out_pb, out_pb_len);
        secure_zero(der_buf, (size_t)der_len);
        free(der_buf);
        return (perr == PEER_ID_SUCCESS) ? LIBP2P_ERR_OK : LIBP2P_ERR_INTERNAL;
    }

    return LIBP2P_ERR_UNSUPPORTED;
}

static int sign_identity_key(uint64_t key_type,
                             const uint8_t *identity_key,
                             size_t identity_key_len,
                             const uint8_t *msg,
                             size_t msg_len,
                             uint8_t **out_sig,
                             size_t *out_sig_len)
{
    if (!identity_key || identity_key_len == 0 || !msg || msg_len == 0 || !out_sig || !out_sig_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_sig = NULL;
    *out_sig_len = 0;

    if (ensure_ltc_ready() != LIBP2P_ERR_OK)
        return LIBP2P_ERR_INTERNAL;

    if (key_type == PEER_ID_ED25519_KEY_TYPE)
    {
#if defined(_WIN32)
        static CRITICAL_SECTION ed_mutex;
        static int init;
        if (!init)
        {
            InitializeCriticalSection(&ed_mutex);
            init = 1;
        }
        EnterCriticalSection(&ed_mutex);
#else
        static pthread_mutex_t ed_mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&ed_mutex);
#endif
        uint8_t *sig = (uint8_t *)malloc(64);
        if (!sig)
        {
#if defined(_WIN32)
            LeaveCriticalSection(&ed_mutex);
#else
            pthread_mutex_unlock(&ed_mutex);
#endif
            return LIBP2P_ERR_INTERNAL;
        }
        uint8_t pub[32];
        ed25519_genpub(pub, identity_key);
        eddsa_sign(sig, identity_key, pub, msg, msg_len);
        secure_zero(pub, sizeof(pub));
#if defined(_WIN32)
        LeaveCriticalSection(&ed_mutex);
#else
        pthread_mutex_unlock(&ed_mutex);
#endif
        *out_sig = sig;
        *out_sig_len = 64;
        return LIBP2P_ERR_OK;
    }

    if (key_type == PEER_ID_SECP256K1_KEY_TYPE)
    {
        SHA256_HASH hash;
        sha256_hash(msg, msg_len, &hash);
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!ctx)
            return LIBP2P_ERR_INTERNAL;
        secp256k1_ecdsa_signature sig_obj;
        if (!secp256k1_ecdsa_sign(ctx, &sig_obj, hash.bytes, identity_key, NULL, NULL))
        {
            secp256k1_context_destroy(ctx);
            return LIBP2P_ERR_INTERNAL;
        }
        uint8_t *sig = (uint8_t *)malloc(64);
        if (!sig)
        {
            secp256k1_context_destroy(ctx);
            return LIBP2P_ERR_INTERNAL;
        }
        secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &sig_obj);
        secp256k1_context_destroy(ctx);
        *out_sig = sig;
        *out_sig_len = 64;
        return LIBP2P_ERR_OK;
    }

    if (key_type == PEER_ID_RSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        sha256_hash(msg, msg_len, &hash);
        rsa_key rsa;
        if (rsa_import(identity_key, (unsigned long)identity_key_len, &rsa) != CRYPT_OK)
        {
            LP_LOGE("quic-tls", "rsa_import failed during sign_identity_key");
            return LIBP2P_ERR_INTERNAL;
        }
        unsigned long sig_len = rsa_get_size(&rsa);
        uint8_t *sig = (uint8_t *)malloc(sig_len);
        if (!sig)
        {
            rsa_free(&rsa);
            return LIBP2P_ERR_INTERNAL;
        }
        int sha_idx = find_hash("sha256");
        if (sha_idx < 0)
        {
            if (register_hash(&sha256_desc) == CRYPT_OK)
                sha_idx = find_hash("sha256");
        }
        if (sha_idx < 0)
        {
            rsa_free(&rsa);
            free(sig);
            LP_LOGE("quic-tls", "find_hash(sha256) failed during sign_identity_key");
            return LIBP2P_ERR_INTERNAL;
        }
        if (rsa_sign_hash_ex(hash.bytes, sizeof(hash.bytes), sig, &sig_len, LTC_PKCS_1_V1_5, NULL, 0, sha_idx, 0, &rsa) != CRYPT_OK)
        {
            rsa_free(&rsa);
            free(sig);
            LP_LOGE("quic-tls", "rsa_sign_hash_ex failed during sign_identity_key");
            return LIBP2P_ERR_INTERNAL;
        }
        rsa_free(&rsa);
        *out_sig = sig;
        *out_sig_len = sig_len;
        return LIBP2P_ERR_OK;
    }

    if (key_type == PEER_ID_ECDSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        sha256_hash(msg, msg_len, &hash);
        ecc_key ecdsa;
        if (ecc_import_openssl(identity_key, (unsigned long)identity_key_len, &ecdsa) != CRYPT_OK)
        {
            LP_LOGE("quic-tls", "ecc_import_openssl failed during sign_identity_key");
            return LIBP2P_ERR_INTERNAL;
        }
        unsigned long sig_len = 2 * ecc_get_size(&ecdsa) + 16;
        uint8_t *sig = (uint8_t *)malloc(sig_len);
        if (!sig)
        {
            ecc_free(&ecdsa);
            return LIBP2P_ERR_INTERNAL;
        }
        prng_state prng;
        int prng_idx = find_prng("sprng");
        if (prng_idx == -1)
        {
            if (register_prng(&sprng_desc) == CRYPT_OK)
                prng_idx = find_prng("sprng");
        }
        if (prng_idx == -1 || rng_make_prng(128, prng_idx, &prng, NULL) != CRYPT_OK)
        {
            ecc_free(&ecdsa);
            free(sig);
            LP_LOGE("quic-tls", "rng_make_prng failed during sign_identity_key");
            return LIBP2P_ERR_INTERNAL;
        }
        if (ecc_sign_hash(hash.bytes, sizeof(hash.bytes), sig, &sig_len, &prng, prng_idx, &ecdsa) != CRYPT_OK)
        {
            ecc_free(&ecdsa);
            free(sig);
            LP_LOGE("quic-tls", "ecc_sign_hash failed during sign_identity_key");
            return LIBP2P_ERR_INTERNAL;
        }
        ecc_free(&ecdsa);
        *out_sig = sig;
        *out_sig_len = sig_len;
        return LIBP2P_ERR_OK;
    }

    return LIBP2P_ERR_UNSUPPORTED;
}

static int set_serial_number(X509 *cert)
{
    if (!cert)
        return LIBP2P_ERR_NULL_PTR;
    unsigned char serial_bytes[16];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1)
        return LIBP2P_ERR_INTERNAL;
    serial_bytes[0] &= 0x7F; /* ensure positive */
    BIGNUM *bn = BN_bin2bn(serial_bytes, (int)sizeof(serial_bytes), NULL);
    if (!bn)
        return LIBP2P_ERR_INTERNAL;
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (!serial || !BN_to_ASN1_INTEGER(bn, serial))
    {
        BN_free(bn);
        return LIBP2P_ERR_INTERNAL;
    }
    BN_free(bn);
    return LIBP2P_ERR_OK;
}

int libp2p_quic_tls_generate_certificate(const libp2p_quic_tls_cert_options_t *opts,
                                         libp2p_quic_tls_certificate_t *out)
{
    if (!opts || !out || !opts->identity_key || opts->identity_key_len == 0)
        return LIBP2P_ERR_NULL_PTR;

    memset(out, 0, sizeof(*out));

    uint32_t lifetime = opts->not_after_lifetime ? opts->not_after_lifetime : 3600;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *tls_key = NULL;
    X509 *cert = NULL;
    uint8_t *spki_der = NULL;
    uint8_t *public_key_pb = NULL;
    size_t public_key_pb_len = 0;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    unsigned char *ext_der = NULL;
    ASN1_OBJECT *libp2p_oid = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *ext_value = NULL;
    LIBP2P_TLS_SIGNED_KEY *signed_key = NULL;
    uint8_t *msg = NULL;
    int rc = LIBP2P_ERR_INTERNAL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx)
        goto cleanup;
    if (EVP_PKEY_keygen_init(pctx) != 1)
        goto cleanup;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1)
        goto cleanup;
    if (EVP_PKEY_keygen(pctx, &tls_key) != 1)
        goto cleanup;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2) != 1)
        goto cleanup;
    if (set_serial_number(cert) != LIBP2P_ERR_OK)
        goto cleanup;

    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -60))
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notAfter(cert), (long)lifetime))
        goto cleanup;

    X509_NAME *name = X509_NAME_new();
    if (!name)
        goto cleanup;
    if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)"libp2p", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"libp2p TLS", -1, -1, 0) != 1)
    {
        X509_NAME_free(name);
        goto cleanup;
    }
    if (X509_set_subject_name(cert, name) != 1 || X509_set_issuer_name(cert, name) != 1)
    {
        X509_NAME_free(name);
        goto cleanup;
    }
    X509_NAME_free(name);

    if (X509_set_pubkey(cert, tls_key) != 1)
        goto cleanup;

    signed_key = LIBP2P_TLS_SIGNED_KEY_new();
    if (!signed_key)
        goto cleanup;

    int ret = build_public_key_protobuf(opts->identity_key_type,
                                        opts->identity_key,
                                        opts->identity_key_len,
                                        &public_key_pb,
                                        &public_key_pb_len);
    if (ret != LIBP2P_ERR_OK)
    {
        LP_LOGE("quic-tls", "build_public_key_protobuf failed (type=%" PRIu64 ", rc=%d)", opts->identity_key_type, ret);
        goto cleanup;
    }

    unsigned char *spki_tmp = NULL;
    int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki_tmp);
    if (spki_len <= 0)
        goto cleanup;
    spki_der = (uint8_t *)spki_tmp;

    size_t msg_len = sizeof(TLS_SIGN_PREFIX) - 1 + (size_t)spki_len;
    msg = (uint8_t *)malloc(msg_len);
    if (!msg)
        goto cleanup;
    memcpy(msg, TLS_SIGN_PREFIX, sizeof(TLS_SIGN_PREFIX) - 1);
    memcpy(msg + sizeof(TLS_SIGN_PREFIX) - 1, spki_der, (size_t)spki_len);

    if (sign_identity_key(opts->identity_key_type,
                          opts->identity_key,
                          opts->identity_key_len,
                          msg,
                          msg_len,
                          &signature,
                          &signature_len) != LIBP2P_ERR_OK)
    {
        LP_LOGE("quic-tls", "sign_identity_key failed (type=%" PRIu64 ")", opts->identity_key_type);
        goto cleanup;
    }

    if (!ASN1_OCTET_STRING_set(signed_key->public_key, public_key_pb, (int)public_key_pb_len) ||
        !ASN1_OCTET_STRING_set(signed_key->signature, signature, (int)signature_len))
        goto cleanup;

    int ext_len = i2d_LIBP2P_TLS_SIGNED_KEY(signed_key, NULL);
    if (ext_len <= 0)
        goto cleanup;
    ext_der = (unsigned char *)OPENSSL_malloc((size_t)ext_len);
    if (!ext_der)
        goto cleanup;
    unsigned char *ext_ptr = ext_der;
    if (i2d_LIBP2P_TLS_SIGNED_KEY(signed_key, &ext_ptr) != ext_len)
        goto cleanup;

    ext_value = ASN1_OCTET_STRING_new();
    if (!ext_value || !ASN1_OCTET_STRING_set(ext_value, ext_der, ext_len))
        goto cleanup;

    libp2p_oid = OBJ_txt2obj("1.3.6.1.4.1.53594.1.1", 1);
    if (!libp2p_oid)
        goto cleanup;
    ext = X509_EXTENSION_create_by_OBJ(NULL, libp2p_oid, 1, ext_value);
    if (!ext)
        goto cleanup;
    if (X509_add_ext(cert, ext, -1) != 1)
        goto cleanup;

    const uint8_t *raw_key = NULL;
    size_t raw_key_len = 0;
    uint64_t parsed_type = 0;
    if (parse_public_key_proto(public_key_pb, public_key_pb_len, &parsed_type, &raw_key, &raw_key_len) != 0)
        goto cleanup;
    if (parsed_type != opts->identity_key_type)
        goto cleanup;
    if (verify_signed_key(parsed_type, raw_key, raw_key_len, signature, signature_len, msg, msg_len) != LIBP2P_ERR_OK)
        goto cleanup;

    if (!X509_sign(cert, tls_key, EVP_sha256()))
        goto cleanup;

    int cert_len = i2d_X509(cert, NULL);
    if (cert_len <= 0)
        goto cleanup;
    out->cert_der = (uint8_t *)malloc((size_t)cert_len);
    if (!out->cert_der)
        goto cleanup;
    unsigned char *cert_ptr = out->cert_der;
    if (i2d_X509(cert, &cert_ptr) != cert_len)
        goto cleanup;
    out->cert_len = (size_t)cert_len;

    int key_len = i2d_PrivateKey(tls_key, NULL);
    if (key_len <= 0)
        goto cleanup;
    out->key_der = (uint8_t *)malloc((size_t)key_len);
    if (!out->key_der)
        goto cleanup;
    unsigned char *key_ptr = out->key_der;
    if (i2d_PrivateKey(tls_key, &key_ptr) != key_len)
        goto cleanup;
    out->key_len = (size_t)key_len;

    rc = LIBP2P_ERR_OK;

cleanup:
    if (rc != LIBP2P_ERR_OK)
        libp2p_quic_tls_certificate_clear(out);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (tls_key)
        EVP_PKEY_free(tls_key);
    if (cert)
        X509_free(cert);
    if (spki_der)
        OPENSSL_free(spki_der);
    if (public_key_pb)
        free(public_key_pb);
    if (signature)
    {
        secure_zero(signature, signature_len);
        free(signature);
    }
    if (ext_der)
        OPENSSL_free(ext_der);
    if (ext_value)
        ASN1_OCTET_STRING_free(ext_value);
    if (ext)
        X509_EXTENSION_free(ext);
    if (libp2p_oid)
        ASN1_OBJECT_free(libp2p_oid);
    if (signed_key)
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
    if (msg)
    {
        secure_zero(msg, msg_len);
        free(msg);
    }

    return rc;
}

void libp2p_quic_tls_certificate_clear(libp2p_quic_tls_certificate_t *cert)
{
    if (!cert)
        return;
    if (cert->cert_der)
    {
        secure_zero(cert->cert_der, cert->cert_len);
        free(cert->cert_der);
        cert->cert_der = NULL;
        cert->cert_len = 0;
    }
    if (cert->key_der)
    {
        secure_zero(cert->key_der, cert->key_len);
        free(cert->key_der);
        cert->key_der = NULL;
        cert->key_len = 0;
    }
}

void libp2p_quic_tls_identity_clear(libp2p_quic_tls_identity_t *id)
{
    if (!id)
        return;
    if (id->peer)
    {
        peer_id_destroy(id->peer);
        free(id->peer);
        id->peer = NULL;
    }
    free(id->public_key_proto);
    id->public_key_proto = NULL;
    id->public_key_len = 0;
    id->key_type = 0;
}

int libp2p_quic_tls_identity_from_certificate(const uint8_t *cert_der,
                                              size_t cert_len,
                                              libp2p_quic_tls_identity_t *out)
{
    if (!cert_der || cert_len == 0 || !out)
        return LIBP2P_ERR_NULL_PTR;

    memset(out, 0, sizeof(*out));

    const unsigned char *p = cert_der;
    X509 *cert = d2i_X509(NULL, &p, (long)cert_len);
    if (!cert)
    {
        LP_LOGE("quic-tls", "failed to parse certificate DER: %s", ERR_error_string(ERR_get_error(), NULL));
        return LIBP2P_ERR_INTERNAL;
    }
    if ((size_t)(p - cert_der) != cert_len)
    {
        LP_LOGE("quic-tls", "certificate DER has trailing data");
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    const ASN1_TIME *nb = X509_get0_notBefore(cert);
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    if (X509_cmp_current_time(nb) > 0 || X509_cmp_current_time(na) < 0)
    {
        LP_LOGW("quic-tls", "certificate not valid at current time");
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    int sig_nid = X509_get_signature_nid(cert);
    if (!is_strong_signature_nid(sig_nid))
    {
        LP_LOGW("quic-tls", "certificate uses weak signature algorithm (nid=%d)", sig_nid);
        X509_free(cert);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    EVP_PKEY *pub = X509_get0_pubkey(cert);
    if (!pub)
    {
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }
    if (X509_verify(cert, pub) != 1)
    {
        LP_LOGW("quic-tls", "certificate self-signature verification failed");
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    ASN1_OBJECT *libp2p_oid = OBJ_txt2obj("1.3.6.1.4.1.53594.1.1", 1);
    if (!libp2p_oid)
    {
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    X509_EXTENSION *libp2p_ext = NULL;
    bool seen_ext = false;
    int ext_count = X509_get_ext_count(cert);
    for (int i = 0; i < ext_count; ++i)
    {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        if (OBJ_cmp(obj, libp2p_oid) == 0)
        {
            if (seen_ext)
            {
                LP_LOGW("quic-tls", "duplicate libp2p public key extension");
                ASN1_OBJECT_free(libp2p_oid);
                X509_free(cert);
                return LIBP2P_ERR_INTERNAL;
            }
            libp2p_ext = ext;
            seen_ext = true;
            continue;
        }
        if (X509_EXTENSION_get_critical(ext))
        {
            LP_LOGW("quic-tls", "unsupported critical extension present");
            ASN1_OBJECT_free(libp2p_oid);
            X509_free(cert);
            return LIBP2P_ERR_INTERNAL;
        }
    }

    ASN1_OBJECT_free(libp2p_oid);

    if (!libp2p_ext)
    {
        LP_LOGW("quic-tls", "certificate missing libp2p public key extension");
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(libp2p_ext);
    LIBP2P_TLS_SIGNED_KEY *signed_key = NULL;
    int pk_rc = parse_signed_key(ext_data, &signed_key);
    if (pk_rc != LIBP2P_ERR_OK)
    {
        X509_free(cert);
        return pk_rc;
    }

    const uint8_t *public_key_pb = ASN1_STRING_get0_data(signed_key->public_key);
    size_t public_key_len = (size_t)ASN1_STRING_length(signed_key->public_key);
    const uint8_t *signature = ASN1_STRING_get0_data(signed_key->signature);
    size_t signature_len = (size_t)ASN1_STRING_length(signed_key->signature);

    uint64_t key_type = 0;
    const uint8_t *raw_key = NULL;
    size_t raw_key_len = 0;
    if (parse_public_key_proto(public_key_pb, public_key_len, &key_type, &raw_key, &raw_key_len) != 0)
    {
        LP_LOGW("quic-tls", "unable to parse PublicKey protobuf in extension");
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    unsigned char *spki_der = NULL;
    int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki_der);
    if (spki_len <= 0)
    {
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    size_t msg_len = sizeof(TLS_SIGN_PREFIX) - 1 + (size_t)spki_len;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg)
    {
        OPENSSL_free(spki_der);
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(msg, TLS_SIGN_PREFIX, sizeof(TLS_SIGN_PREFIX) - 1);
    memcpy(msg + sizeof(TLS_SIGN_PREFIX) - 1, spki_der, (size_t)spki_len);

    int verify_rc = verify_signed_key(key_type, raw_key, raw_key_len, signature, signature_len, msg, msg_len);
    free(msg);
    OPENSSL_free(spki_der);
    if (verify_rc != LIBP2P_ERR_OK)
    {
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return verify_rc;
    }

    peer_id_t *pid = (peer_id_t *)calloc(1, sizeof(*pid));
    if (!pid)
    {
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }
    peer_id_error_t perr = peer_id_create_from_public_key(public_key_pb, public_key_len, pid);
    if (perr != PEER_ID_SUCCESS)
    {
        LP_LOGW("quic-tls", "failed to derive peer id from public key (err=%d)", perr);
        free(pid);
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }

    uint8_t *pk_copy = (uint8_t *)malloc(public_key_len);
    if (!pk_copy)
    {
        peer_id_destroy(pid);
        free(pid);
        LIBP2P_TLS_SIGNED_KEY_free(signed_key);
        X509_free(cert);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(pk_copy, public_key_pb, public_key_len);

    out->peer = pid;
    out->public_key_proto = pk_copy;
    out->public_key_len = public_key_len;
    out->key_type = key_type;

    LIBP2P_TLS_SIGNED_KEY_free(signed_key);
    X509_free(cert);
    return LIBP2P_ERR_OK;
}
