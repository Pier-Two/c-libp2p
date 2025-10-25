#include "protocol/noise/protocol_noise.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "protocol/noise/protocol_noise_conn.h"
#include "protocol/noise/protocol_noise_extensions.h"
#include <inttypes.h>
#include <noise/protocol.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define PEER_ID_ED25519_KEY_TYPE 1
#include "../../../external/libeddsa/lib/eddsa.h"
#include "../../../external/secp256k1/include/secp256k1.h"
#include "../../../external/wjcryptlib/lib/WjCryptLib_Sha256.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id_secp256k1.h"
#define PEER_ID_RSA_KEY_TYPE 0
#define PEER_ID_ECDSA_KEY_TYPE 3
#include "libp2p/crypto/ltc_compat.h"

peer_id_error_t peer_id_create_from_private_key_rsa(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len);
peer_id_error_t peer_id_create_from_private_key_ecdsa(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len);

/* If the TCP utility header isn't available in this compilation unit, fall back to
   a local definition of now_mono_ms() so we don't introduce a new link-time dep. */
#ifndef NOW_MONO_MS_DECLARED
static inline uint64_t now_mono_ms(void)
{
    struct timespec ts;
#ifdef _WIN32
    /* On Windows CLOCK_MONOTONIC is supported by mingw-w64 runtime. */
#endif
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}
#define NOW_MONO_MS_DECLARED 1
#endif

static inline int varint_is_minimal(uint64_t v, size_t len)
{
    uint8_t tmp[10];
    size_t min_len;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &min_len) != UNSIGNED_VARINT_OK)
        return 0;
    return min_len == len;
}

struct libp2p_noise_ctx
{
    unsigned char static_key[32];
    uint8_t *identity_key;
    size_t identity_key_len;
    int have_identity;
    int identity_type;
    uint8_t *early_data;
    size_t early_data_len;
    uint8_t *extensions;
    size_t extensions_len;
    size_t max_plaintext;
};

static int build_handshake_payload(struct libp2p_noise_ctx *ctx, uint8_t **out, size_t *out_len)
{
    if (!ctx || !out || !out_len || !ctx->have_identity)
        return -1;

    uint8_t static_pub[32];
    x25519_base(static_pub, ctx->static_key);

    uint8_t id_pub[33];
    size_t id_pub_len = 0;
    uint8_t *pubkey_pb = NULL;
    size_t pubkey_pb_len = 0;
    int pbret = -1;

    if (ctx->identity_type == PEER_ID_ED25519_KEY_TYPE)
    {
        ed25519_genpub(id_pub, ctx->identity_key);
        id_pub_len = 32;
        pbret = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE, id_pub, id_pub_len, &pubkey_pb, &pubkey_pb_len);
    }
    else if (ctx->identity_type == PEER_ID_SECP256K1_KEY_TYPE)
    {
        secp256k1_context *sctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(sctx, &pk, ctx->identity_key))
        {
            secp256k1_context_destroy(sctx);
            return -1;
        }
        id_pub_len = sizeof(id_pub);
        if (!secp256k1_ec_pubkey_serialize(sctx, id_pub, &id_pub_len, &pk, SECP256K1_EC_COMPRESSED))
        {
            secp256k1_context_destroy(sctx);
            return -1;
        }
        pbret = peer_id_build_public_key_protobuf(PEER_ID_SECP256K1_KEY_TYPE, id_pub, id_pub_len, &pubkey_pb, &pubkey_pb_len);
        secp256k1_context_destroy(sctx);
    }
    else if (ctx->identity_type == PEER_ID_RSA_KEY_TYPE)
    {
        uint8_t *tmp = malloc(ctx->identity_key_len);
        if (!tmp)
            return -1;
        memcpy(tmp, ctx->identity_key, ctx->identity_key_len);
        pbret = peer_id_create_from_private_key_rsa(tmp, ctx->identity_key_len, &pubkey_pb, &pubkey_pb_len);
        free(tmp);
    }
    else if (ctx->identity_type == PEER_ID_ECDSA_KEY_TYPE)
    {
        uint8_t *tmp = malloc(ctx->identity_key_len);
        if (!tmp)
            return -1;
        memcpy(tmp, ctx->identity_key, ctx->identity_key_len);
        pbret = peer_id_create_from_private_key_ecdsa(tmp, ctx->identity_key_len, &pubkey_pb, &pubkey_pb_len);
        free(tmp);
    }
    if (pbret != PEER_ID_SUCCESS)
        return -1;

    const char prefix[] = "noise-libp2p-static-key:";
    uint8_t to_sign[sizeof(prefix) - 1 + 32];
    memcpy(to_sign, prefix, sizeof(prefix) - 1);
    memcpy(to_sign + sizeof(prefix) - 1, static_pub, sizeof(static_pub));

    size_t sig_len = 0;
    uint8_t *signature = NULL;
    if (ctx->identity_type == PEER_ID_ED25519_KEY_TYPE)
    {
        static pthread_mutex_t sign_mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&sign_mutex);
        signature = malloc(64);
        if (!signature)
        {
            pthread_mutex_unlock(&sign_mutex);
            free(pubkey_pb);
            return -1;
        }
        eddsa_sign(signature, ctx->identity_key, id_pub, to_sign, sizeof(to_sign));
        sig_len = 64;
        pthread_mutex_unlock(&sign_mutex);
    }
    else if (ctx->identity_type == PEER_ID_SECP256K1_KEY_TYPE)
    {
        SHA256_HASH hash;
        Sha256Calculate(to_sign, sizeof(to_sign), &hash);
        secp256k1_context *sctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_sign(sctx, &sig, hash.bytes, ctx->identity_key, NULL, NULL))
        {
            secp256k1_context_destroy(sctx);
            free(pubkey_pb);
            return -1;
        }
        signature = malloc(64);
        if (!signature)
        {
            secp256k1_context_destroy(sctx);
            free(pubkey_pb);
            return -1;
        }
        secp256k1_ecdsa_signature_serialize_compact(sctx, signature, &sig);
        sig_len = 64;
        secp256k1_context_destroy(sctx);
    }
    else if (ctx->identity_type == PEER_ID_RSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        Sha256Calculate(to_sign, sizeof(to_sign), &hash);
        rsa_key rsa;
        if (rsa_import(ctx->identity_key, (unsigned long)ctx->identity_key_len, &rsa) != CRYPT_OK)
            return -1;
        unsigned long temp_sig_len = rsa_get_size(&rsa);
        signature = malloc(temp_sig_len);
        if (!signature)
        {
            rsa_free(&rsa);
            free(pubkey_pb);
            return -1;
        }
        int sha_idx = find_hash("sha256");
        if (rsa_sign_hash_ex(hash.bytes, sizeof(hash.bytes), signature, &temp_sig_len, LTC_PKCS_1_V1_5, NULL, 0, sha_idx, 0, &rsa) != CRYPT_OK)
        {
            rsa_free(&rsa);
            free(signature);
            free(pubkey_pb);
            return -1;
        }
        sig_len = temp_sig_len;
        rsa_free(&rsa);
    }
    else if (ctx->identity_type == PEER_ID_ECDSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        Sha256Calculate(to_sign, sizeof(to_sign), &hash);
        ecc_key ecdsa;
        if (ecc_import_openssl(ctx->identity_key, (unsigned long)ctx->identity_key_len, &ecdsa) != CRYPT_OK)
            return -1;
        unsigned long temp_sig_len = 2 * ecc_get_size(&ecdsa) + 16;
        signature = malloc(temp_sig_len);
        if (!signature)
        {
            ecc_free(&ecdsa);
            free(pubkey_pb);
            return -1;
        }
        prng_state prng;
        int prng_idx = find_prng("sprng");
        if (prng_idx == -1 || rng_make_prng(128, prng_idx, &prng, NULL) != CRYPT_OK)
        {
            ecc_free(&ecdsa);
            free(pubkey_pb);
            return -1;
        }
        if (ecc_sign_hash(hash.bytes, sizeof(hash.bytes), signature, &temp_sig_len, &prng, prng_idx, &ecdsa) != CRYPT_OK)
        {
            ecc_free(&ecdsa);
            free(signature);
            free(pubkey_pb);
            return -1;
        }
        sig_len = temp_sig_len;
        ecc_free(&ecdsa);
    }
    else
    {
        free(pubkey_pb);
        return -1;
    }

    uint8_t lenbuf[10];
    size_t len_sz;

    size_t total = 0;

    /* field 1: identity_key */
    total += 1; /* tag */
    unsigned_varint_encode(pubkey_pb_len, lenbuf, sizeof(lenbuf), &len_sz);
    total += len_sz + pubkey_pb_len;

    /* field 2: identity_sig */
    total += 1;
    unsigned_varint_encode(sig_len, lenbuf, sizeof(lenbuf), &len_sz);
    total += len_sz + sig_len;

    if (ctx->extensions && ctx->extensions_len)
    {
        total += 1;
        unsigned_varint_encode(ctx->extensions_len, lenbuf, sizeof(lenbuf), &len_sz);
        total += len_sz + ctx->extensions_len;
    }

    if (total + ctx->early_data_len > NOISE_MAX_PAYLOAD_LEN)
    {
        free(pubkey_pb);
        free(signature);
        return -1;
    }

    uint8_t *buf = malloc(total + ctx->early_data_len);
    if (!buf)
    {
        free(pubkey_pb);
        free(signature);
        return -1;
    }

    size_t offset = 0;
    buf[offset++] = 0x0A; /* field 1 tag */
    unsigned_varint_encode(pubkey_pb_len, buf + offset, total, &len_sz);
    offset += len_sz;
    memcpy(buf + offset, pubkey_pb, pubkey_pb_len);
    offset += pubkey_pb_len;

    buf[offset++] = 0x12; /* field 2 tag */
    unsigned_varint_encode(sig_len, buf + offset, total - offset, &len_sz);
    offset += len_sz;
    memcpy(buf + offset, signature, sig_len);
    offset += sig_len;

    if (ctx->extensions && ctx->extensions_len)
    {
        buf[offset++] = 0x22; /* field 4 tag */
        unsigned_varint_encode(ctx->extensions_len, buf + offset, total - offset, &len_sz);
        offset += len_sz;
        memcpy(buf + offset, ctx->extensions, ctx->extensions_len);
        offset += ctx->extensions_len;
    }

    if (ctx->early_data && ctx->early_data_len)
    {
        memcpy(buf + offset, ctx->early_data, ctx->early_data_len);
        offset += ctx->early_data_len;
    }

    *out = buf;
    *out_len = offset;

    free(pubkey_pb);
    free(signature);
    return 0;
}

static int verify_handshake_payload(NoiseHandshakeState *hs, const uint8_t *payload, size_t payload_len, peer_id_t **out_peer, uint8_t **out_ed,
                                    size_t *out_ed_len, uint8_t **out_ext, size_t *out_ext_len)
{
    if (!hs || !payload || payload_len == 0)
    {
        return -1;
    }

    size_t offset = 0, len_sz = 0;
    uint64_t hdr = 0, fld_len = 0;

    if (unsigned_varint_decode(payload + offset, payload_len - offset, &hdr, &len_sz) != UNSIGNED_VARINT_OK || hdr != 0x0A ||
        !varint_is_minimal(hdr, len_sz))
    {
        return -1;
    }
    offset += len_sz;

    if (unsigned_varint_decode(payload + offset, payload_len - offset, &fld_len, &len_sz) != UNSIGNED_VARINT_OK ||
        fld_len > payload_len - offset - len_sz || !varint_is_minimal(fld_len, len_sz))
    {
        return -1;
    }
    offset += len_sz;
    const uint8_t *id_key = payload + offset;
    size_t id_key_len = (size_t)fld_len;
    offset += id_key_len;

    if (unsigned_varint_decode(payload + offset, payload_len - offset, &hdr, &len_sz) != UNSIGNED_VARINT_OK || hdr != 0x12 ||
        !varint_is_minimal(hdr, len_sz))
    {
        return -1;
    }
    offset += len_sz;

    if (unsigned_varint_decode(payload + offset, payload_len - offset, &fld_len, &len_sz) != UNSIGNED_VARINT_OK || fld_len == 0 ||
        fld_len > payload_len - offset - len_sz || !varint_is_minimal(fld_len, len_sz))
    {
        return -1;
    }
    offset += len_sz;
    const uint8_t *sig = payload + offset;
    offset += (size_t)fld_len;

    uint64_t key_type = 0;
    const uint8_t *key_data = NULL;
    size_t key_data_len = 0;
    if (parse_public_key_proto(id_key, id_key_len, &key_type, &key_data, &key_data_len) != 0)
    {
        return -1;
    }

    uint8_t static_pub[32];
    NoiseDHState *dh = noise_handshakestate_get_remote_public_key_dh(hs);
    if (!dh || noise_dhstate_get_public_key(dh, static_pub, sizeof(static_pub)) != NOISE_ERROR_NONE)
    {
        return -1;
    }

    const char prefix[] = "noise-libp2p-static-key:";
    uint8_t to_sign[sizeof(prefix) - 1 + 32];
    memcpy(to_sign, prefix, sizeof(prefix) - 1);
    memcpy(to_sign + sizeof(prefix) - 1, static_pub, sizeof(static_pub));

    if (key_type == PEER_ID_ED25519_KEY_TYPE)
    {
        if (fld_len != 64 || !eddsa_verify(sig, key_data, to_sign, sizeof(to_sign)))
        {
            return -1;
        }
    }
    else if (key_type == PEER_ID_SECP256K1_KEY_TYPE)
    {
        SHA256_HASH hash;
        Sha256Calculate(to_sign, sizeof(to_sign), &hash);
        secp256k1_context *sctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        if (!sctx)
        {
            return -1;
        }

        secp256k1_pubkey pk;
        secp256k1_ecdsa_signature s;
        int pk_parse_ok = secp256k1_ec_pubkey_parse(sctx, &pk, key_data, key_data_len);
        if (!pk_parse_ok)
        {
            secp256k1_context_destroy(sctx);
            return -1;
        }

        // Try DER format first (more common in libp2p)
        int sig_parse_ok = secp256k1_ecdsa_signature_parse_der(sctx, &s, sig, fld_len);
        if (!sig_parse_ok && fld_len == 64)
        {
            // Fallback to compact format if DER fails and length is 64
            sig_parse_ok = secp256k1_ecdsa_signature_parse_compact(sctx, &s, sig);
        }

        if (!sig_parse_ok)
        {
            secp256k1_context_destroy(sctx);
            return -1;
        }

        int verify_ok = secp256k1_ecdsa_verify(sctx, &s, hash.bytes, &pk);
        secp256k1_context_destroy(sctx);

        if (!verify_ok)
        {
            return -1;
        }
    }
    else if (key_type == PEER_ID_RSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        Sha256Calculate(to_sign, sizeof(to_sign), &hash);
        rsa_key rsa;
        if (rsa_import(key_data, (unsigned long)key_data_len, &rsa) != CRYPT_OK)
            return -1;
        int sha_idx = find_hash("sha256");
        int stat = 0;
        int rc = rsa_verify_hash_ex(sig, (unsigned long)fld_len, hash.bytes, sizeof(hash.bytes), LTC_PKCS_1_V1_5, sha_idx, 0, &stat, &rsa);
        rsa_free(&rsa);
        if (rc != CRYPT_OK || stat == 0)
            return -1;
    }
    else if (key_type == PEER_ID_ECDSA_KEY_TYPE)
    {
        SHA256_HASH hash;
        Sha256Calculate(to_sign, sizeof(to_sign), &hash);
        ecc_key ecdsa;
        if (ecc_import_openssl(key_data, (unsigned long)key_data_len, &ecdsa) != CRYPT_OK)
            return -1;
        int stat = 0;
        int rc = ecc_verify_hash(sig, (unsigned long)fld_len, hash.bytes, sizeof(hash.bytes), &stat, &ecdsa);
        ecc_free(&ecdsa);
        if (rc != CRYPT_OK || stat == 0)
            return -1;
    }
    else
    {
        return -1;
    }

    if (offset < payload_len && unsigned_varint_decode(payload + offset, payload_len - offset, &hdr, &len_sz) == UNSIGNED_VARINT_OK && hdr == 0x22 &&
        varint_is_minimal(hdr, len_sz))
    {
        offset += len_sz;
        if (unsigned_varint_decode(payload + offset, payload_len - offset, &fld_len, &len_sz) != UNSIGNED_VARINT_OK ||
            fld_len > payload_len - offset - len_sz || !varint_is_minimal(fld_len, len_sz))
            return -1;
        offset += len_sz;
        if (out_ext && out_ext_len)
        {
            *out_ext_len = (size_t)fld_len;
            *out_ext = malloc(*out_ext_len);
            if (!*out_ext)
                return -1;
            memcpy(*out_ext, payload + offset, *out_ext_len);
        }
        offset += (size_t)fld_len;
    }

    if (out_ed && out_ed_len && offset < payload_len)
    {
        *out_ed_len = payload_len - offset;
        *out_ed = malloc(*out_ed_len);
        if (!*out_ed)
            return -1;
        memcpy(*out_ed, payload + offset, *out_ed_len);
    }

    if (out_peer)
    {
        peer_id_t *pid = malloc(sizeof(*pid));
        if (!pid)
            return -1;
        if (peer_id_create_from_public_key(id_key, id_key_len, pid) != PEER_ID_SUCCESS)
        {
            free(pid);
            return -1;
        }
        *out_peer = pid;
    }

    return 0;
}

/* ───────────────────────── Helper: blocking-style read on non-blocking conn ── */
static int read_exact_deadline(libp2p_conn_t *c, uint8_t *buf, size_t len, uint64_t deadline_ms)
{
    if (len == 0)
        return 0;

    /* Fallback budget when no overall deadline is provided. */
    const uint64_t FALLBACK_MS = 3000; /* 3 seconds */
    uint64_t start = now_mono_ms();
    size_t off = 0;

    while (off < len)
    {
        uint64_t now = now_mono_ms();
        uint64_t remain;
        if (deadline_ms)
        {
            if (now >= deadline_ms)
                return -1; /* overall handshake deadline exceeded */
            remain = deadline_ms - now;
        }
        else
        {
            uint64_t elapsed = now - start;
            remain = (elapsed < FALLBACK_MS) ? (FALLBACK_MS - elapsed) : 0;
            if (remain == 0)
                return -1; /* fallback timeout */
        }
        libp2p_conn_set_deadline(c, remain);

        ssize_t r = libp2p_conn_read(c, buf + off, len - off);
        if (r > 0)
        {
            off += (size_t)r;
            continue;
        }

        if (r == LIBP2P_CONN_ERR_AGAIN)
        {
            /* continue; deadline blocks efficiently */
            continue;
        }

        /* treat EOF / CLOSED / INTERNAL as failure */
        libp2p_conn_set_deadline(c, 0);
        return -1;
    }

    /* clear deadline */
    libp2p_conn_set_deadline(c, 0);
    return 0;
}

static libp2p_security_err_t noise_secure_outbound(libp2p_security_t *self, libp2p_conn_t *raw, const peer_id_t *remote_hint, uint64_t timeout_ms,
                                                   libp2p_conn_t **out, peer_id_t **remote_peer)
{
    (void)remote_hint;
    if (!self || !raw || !out)
        return LIBP2P_SECURITY_ERR_NULL_PTR;

    /* Compute absolute monotonic handshake deadline once. */
    uint64_t deadline_ms = timeout_ms ? (now_mono_ms() + timeout_ms) : 0;

    struct libp2p_noise_ctx *ctx = self->ctx;
    NoiseHandshakeState *hs = NULL;
    uint8_t buf[65535];
    uint8_t lenbuf[2];
    NoiseBuffer mbuf;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    unsigned msg_idx = 0;
    unsigned read_idx = 0;
    int err;
    uint8_t *remote_ed = NULL, *remote_ext = NULL;
    size_t remote_ed_len = 0, remote_ext_len = 0;
    noise_extensions_t *parsed_ext = NULL;
    int hint_mismatch = 0;

    if (noise_init() != NOISE_ERROR_NONE)
    {
        return LIBP2P_SECURITY_ERR_INTERNAL;
    }

    err = noise_handshakestate_new_by_name(&hs, "Noise_XX_25519_ChaChaPoly_SHA256", NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE)
    {
        return LIBP2P_SECURITY_ERR_INTERNAL;
    }

    if (noise_handshakestate_needs_local_keypair(hs) && ctx)
    {
        NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(hs);
        noise_dhstate_set_keypair_private(dh, ctx->static_key, sizeof(ctx->static_key));
    }

    err = noise_handshakestate_start(hs);
    if (err != NOISE_ERROR_NONE)
    {
        noise_handshakestate_free(hs);
        free(payload);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    if (!ctx->have_identity)
    {
        noise_handshakestate_free(hs);
        free(payload);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    if (build_handshake_payload(ctx, &payload, &payload_len) != 0)
    {
        noise_handshakestate_free(hs);
        free(payload);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    for (;;)
    {
        int action = noise_handshakestate_get_action(hs);
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
            noise_buffer_set_output(mbuf, buf, sizeof(buf));
            NoiseBuffer pbuf;
            if (payload && msg_idx == 1) /* second write */
            {
                noise_buffer_set_input(pbuf, payload, payload_len);
                err = noise_handshakestate_write_message(hs, &mbuf, &pbuf);
            }
            else
            {
                err = noise_handshakestate_write_message(hs, &mbuf, NULL);
            }
            msg_idx++;
            if (err != NOISE_ERROR_NONE)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            uint16_t l = (uint16_t)mbuf.size;
            /* Write length prefix and message in a single atomic write to
             * simplify testing and match expectations of corruption tests. */
            size_t frame_len = 2u + (size_t)l;
            uint8_t *frame = (uint8_t *)malloc(frame_len);
            if (!frame)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_INTERNAL;
            }
            frame[0] = (uint8_t)(l >> 8);
            frame[1] = (uint8_t)l;
            memcpy(frame + 2, buf, l);
            if (deadline_ms)
            {
                uint64_t now = now_mono_ms();
                if (now >= deadline_ms)
                {
                    noise_handshakestate_free(hs);
                    free(payload);
                    free(frame);
                    return LIBP2P_SECURITY_ERR_HANDSHAKE;
                }
                libp2p_conn_set_deadline(raw, deadline_ms - now);
            }
            ssize_t w = libp2p_conn_write(raw, frame, frame_len);
            free(frame);
            if (w < 0 || (size_t)w != frame_len)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            if (deadline_ms)
                libp2p_conn_set_deadline(raw, 0);
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {
            if (read_exact_deadline(raw, lenbuf, 2, deadline_ms) != 0)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            uint16_t l = ((uint16_t)lenbuf[0] << 8) | lenbuf[1];
            if (l > sizeof(buf))
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            if (read_exact_deadline(raw, buf, l, deadline_ms) != 0)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            noise_buffer_set_input(mbuf, buf, l);
            uint8_t *pbuf_data = malloc(NOISE_MAX_PAYLOAD_LEN);
            if (!pbuf_data)
            {
                noise_handshakestate_free(hs);
                free(remote_ed);
                free(remote_ext);
                free(payload);
                return LIBP2P_SECURITY_ERR_INTERNAL;
            }
            NoiseBuffer pbuf;
            noise_buffer_set_output(pbuf, pbuf_data, NOISE_MAX_PAYLOAD_LEN);
            err = noise_handshakestate_read_message(hs, &mbuf, &pbuf);
            if (err == NOISE_ERROR_NONE && pbuf.size > 0)
            {
                err = verify_handshake_payload(hs, pbuf.data, pbuf.size, remote_peer, &remote_ed, &remote_ed_len, &remote_ext, &remote_ext_len);
                if (err == 0 && remote_ext_len > 0)
                {
                    if (parse_noise_extensions(remote_ext, remote_ext_len, &parsed_ext) != 0)
                        err = -1;
                }
                if (err == 0 && remote_hint && remote_peer && *remote_peer && peer_id_equals(remote_hint, *remote_peer) != 1)
                {
                    hint_mismatch = 1;
                }
            }
            free(pbuf_data);
            if (err != NOISE_ERROR_NONE)
            {
                noise_handshakestate_free(hs);
                free(remote_ed);
                free(remote_ext);
                if (remote_peer && *remote_peer)
                {
                    peer_id_destroy(*remote_peer);
                    free(*remote_peer);
                    *remote_peer = NULL;
                }
                noise_extensions_free(parsed_ext);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
        }
        else
        {
            break;
        }
    }

    NoiseCipherState *send_cs = NULL, *recv_cs = NULL;
    err = noise_handshakestate_split(hs, &send_cs, &recv_cs);
    if (err != NOISE_ERROR_NONE)
    {
        noise_handshakestate_free(hs);
        free(payload);
        if (remote_peer && *remote_peer)
        {
            peer_id_destroy(*remote_peer);
            free(*remote_peer);
            *remote_peer = NULL;
        }
        free(remote_ed);
        free(remote_ext);
        noise_extensions_free(parsed_ext);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }
    noise_handshakestate_free(hs);
    free(payload);
    if (hint_mismatch || (remote_hint && remote_peer && *remote_peer && peer_id_equals(remote_hint, *remote_peer) != 1))
    {
        noise_cipherstate_free(send_cs);
        noise_cipherstate_free(recv_cs);
        free(remote_ed);
        free(remote_ext);
        peer_id_destroy(*remote_peer);
        free(*remote_peer);
        *remote_peer = NULL;
        noise_extensions_free(parsed_ext);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    libp2p_conn_t *secure =
        make_noise_conn(raw, send_cs, recv_cs, ctx->max_plaintext, remote_ed, remote_ed_len, remote_ext, remote_ext_len, parsed_ext);
    if (!secure)
    {
        noise_cipherstate_free(send_cs);
        noise_cipherstate_free(recv_cs);
        free(remote_ed);
        free(remote_ext);
        if (remote_peer && *remote_peer)
        {
            peer_id_destroy(*remote_peer);
            free(*remote_peer);
            *remote_peer = NULL;
        }
        noise_extensions_free(parsed_ext);
        return LIBP2P_SECURITY_ERR_INTERNAL;
    }
    free(remote_ed);
    remote_ed = NULL;
    free(remote_ext);
    remote_ext = NULL;
    *out = secure;
    return LIBP2P_SECURITY_OK;
}

static libp2p_security_err_t noise_secure_inbound(libp2p_security_t *self, libp2p_conn_t *raw, uint64_t timeout_ms, libp2p_conn_t **out,
                                                  peer_id_t **remote_peer)
{
    if (!self || !raw || !out)
        return LIBP2P_SECURITY_ERR_NULL_PTR;

    /* Compute absolute monotonic handshake deadline once. */
    uint64_t deadline_ms = timeout_ms ? (now_mono_ms() + timeout_ms) : 0;

    struct libp2p_noise_ctx *ctx = self->ctx;
    NoiseHandshakeState *hs = NULL;
    uint8_t buf[65535];
    uint8_t lenbuf[2];
    NoiseBuffer mbuf;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    unsigned msg_idx = 0;
    unsigned read_idx = 0;
    int err;
    uint8_t *remote_ed = NULL, *remote_ext = NULL;
    size_t remote_ed_len = 0, remote_ext_len = 0;
    noise_extensions_t *parsed_ext = NULL;

    if (noise_init() != NOISE_ERROR_NONE)
    {
        return LIBP2P_SECURITY_ERR_INTERNAL;
    }

    err = noise_handshakestate_new_by_name(&hs, "Noise_XX_25519_ChaChaPoly_SHA256", NOISE_ROLE_RESPONDER);
    if (err != NOISE_ERROR_NONE)
    {
        return LIBP2P_SECURITY_ERR_INTERNAL;
    }

    if (noise_handshakestate_needs_local_keypair(hs) && ctx)
    {
        NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(hs);
        noise_dhstate_set_keypair_private(dh, ctx->static_key, sizeof(ctx->static_key));
    }

    err = noise_handshakestate_start(hs);
    if (err != NOISE_ERROR_NONE)
    {
        noise_handshakestate_free(hs);
        free(payload);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    if (!ctx->have_identity)
    {
        noise_handshakestate_free(hs);
        free(payload);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    if (build_handshake_payload(ctx, &payload, &payload_len) != 0)
    {
        noise_handshakestate_free(hs);
        free(payload);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    for (;;)
    {
        int action = noise_handshakestate_get_action(hs);
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
            noise_buffer_set_output(mbuf, buf, sizeof(buf));
            NoiseBuffer pbuf;
            if (payload && msg_idx == 0)
            {
                noise_buffer_set_input(pbuf, payload, payload_len);
                err = noise_handshakestate_write_message(hs, &mbuf, &pbuf);
            }
            else
            {
                err = noise_handshakestate_write_message(hs, &mbuf, NULL);
            }
            msg_idx++;
            if (err != NOISE_ERROR_NONE)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            uint16_t l = (uint16_t)mbuf.size;
            size_t frame_len = 2u + (size_t)l;
            uint8_t *frame = (uint8_t *)malloc(frame_len);
            if (!frame)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_INTERNAL;
            }
            frame[0] = (uint8_t)(l >> 8);
            frame[1] = (uint8_t)l;
            memcpy(frame + 2, buf, l);
            if (deadline_ms)
            {
                uint64_t now = now_mono_ms();
                if (now >= deadline_ms)
                {
                    noise_handshakestate_free(hs);
                    free(payload);
                    free(frame);
                    return LIBP2P_SECURITY_ERR_HANDSHAKE;
                }
                libp2p_conn_set_deadline(raw, deadline_ms - now);
            }
            ssize_t w = libp2p_conn_write(raw, frame, frame_len);
            free(frame);
            if (w < 0 || (size_t)w != frame_len)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            if (deadline_ms)
                libp2p_conn_set_deadline(raw, 0);
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {
            if (read_exact_deadline(raw, lenbuf, 2, deadline_ms) != 0)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            uint16_t l = ((uint16_t)lenbuf[0] << 8) | lenbuf[1];
            if (l > sizeof(buf))
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            if (read_exact_deadline(raw, buf, l, deadline_ms) != 0)
            {
                noise_handshakestate_free(hs);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            noise_buffer_set_input(mbuf, buf, l);
            uint8_t *pbuf_data = malloc(NOISE_MAX_PAYLOAD_LEN);
            if (!pbuf_data)
            {
                noise_handshakestate_free(hs);
                free(remote_ed);
                free(remote_ext);
                free(payload);
                return LIBP2P_SECURITY_ERR_INTERNAL;
            }
            NoiseBuffer pbuf;
            noise_buffer_set_output(pbuf, pbuf_data, NOISE_MAX_PAYLOAD_LEN);
            err = noise_handshakestate_read_message(hs, &mbuf, &pbuf);
            if (err == NOISE_ERROR_NONE)
            {
                if (read_idx == 0 && pbuf.size > 0)
                {
                    err = -1;
                }
                else if (pbuf.size > 0)
                {
                    err = verify_handshake_payload(hs, pbuf.data, pbuf.size, remote_peer, &remote_ed, &remote_ed_len, &remote_ext, &remote_ext_len);
                    if (err == 0 && remote_ext_len > 0)
                    {
                        if (parse_noise_extensions(remote_ext, remote_ext_len, &parsed_ext) != 0)
                            err = -1;
                    }
                }
            }
            read_idx++;
            free(pbuf_data);
            if (err != NOISE_ERROR_NONE)
            {
                noise_handshakestate_free(hs);
                free(remote_ed);
                free(remote_ext);
                if (remote_peer && *remote_peer)
                {
                    peer_id_destroy(*remote_peer);
                    free(*remote_peer);
                    *remote_peer = NULL;
                }
                noise_extensions_free(parsed_ext);
                free(payload);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
        }
        else
        {
            break;
        }
    }

    NoiseCipherState *send_cs = NULL, *recv_cs = NULL;
    err = noise_handshakestate_split(hs, &send_cs, &recv_cs);
    if (err != NOISE_ERROR_NONE)
    {
        noise_handshakestate_free(hs);
        free(payload);
        if (remote_peer && *remote_peer)
        {
            peer_id_destroy(*remote_peer);
            free(*remote_peer);
            *remote_peer = NULL;
        }
        free(remote_ed);
        free(remote_ext);
        noise_extensions_free(parsed_ext);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }
    noise_handshakestate_free(hs);
    free(payload);
    libp2p_conn_t *secure =
        make_noise_conn(raw, send_cs, recv_cs, ctx->max_plaintext, remote_ed, remote_ed_len, remote_ext, remote_ext_len, parsed_ext);

    if (!secure)
    {
        noise_cipherstate_free(send_cs);
        noise_cipherstate_free(recv_cs);
        free(remote_ed);
        free(remote_ext);
        if (remote_peer && *remote_peer)
        {
            peer_id_destroy(*remote_peer);
            free(*remote_peer);
            *remote_peer = NULL;
        }
        noise_extensions_free(parsed_ext);
        return LIBP2P_SECURITY_ERR_INTERNAL;
    }
    free(remote_ed);
    remote_ed = NULL;
    free(remote_ext);
    remote_ext = NULL;
    *out = secure;
    return LIBP2P_SECURITY_OK;
}

static libp2p_security_err_t noise_close(libp2p_security_t *self)
{
    (void)self;
    return LIBP2P_SECURITY_OK;
}

static void noise_security_free(libp2p_security_t *self)
{
    if (!self)
        return;
    if (self->ctx)
    {
        struct libp2p_noise_ctx *ctx = self->ctx;
        free(ctx->identity_key);
        free(ctx->early_data);
        free(ctx->extensions);
        free(ctx);
    }
    free(self);
}

static const libp2p_security_vtbl_t noise_vtbl = {
    .secure_outbound = noise_secure_outbound,
    .secure_inbound = noise_secure_inbound,
    .close = noise_close,
    .free = noise_security_free,
};

libp2p_security_t *libp2p_noise_security_new(const libp2p_noise_config_t *cfg)
{
    libp2p_security_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    struct libp2p_noise_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        free(s);
        return NULL;
    }

    if (cfg && cfg->static_private_key && cfg->static_private_key_len == 32)
        memcpy(ctx->static_key, cfg->static_private_key, sizeof(ctx->static_key));
    else
        noise_randstate_generate_simple(ctx->static_key, sizeof(ctx->static_key));

    ctx->have_identity = 0;
    ctx->identity_type = 0;
    ctx->identity_key = NULL;
    ctx->identity_key_len = 0;
    if (cfg && cfg->identity_private_key && cfg->identity_private_key_len > 0)
    {
        ctx->identity_key = malloc(cfg->identity_private_key_len);
        if (!ctx->identity_key)
        {
            free(ctx);
            free(s);
            return NULL;
        }
        memcpy(ctx->identity_key, cfg->identity_private_key, cfg->identity_private_key_len);
        ctx->identity_key_len = cfg->identity_private_key_len;
        ctx->identity_type = cfg->identity_key_type;
        ctx->have_identity = 1;
    }
    if (cfg && cfg->early_data && cfg->early_data_len)
    {
        ctx->early_data = malloc(cfg->early_data_len);
        if (ctx->early_data)
        {
            memcpy(ctx->early_data, cfg->early_data, cfg->early_data_len);
            ctx->early_data_len = cfg->early_data_len;
        }
    }
    if (cfg && cfg->extensions && cfg->extensions_len)
    {
        ctx->extensions = malloc(cfg->extensions_len);
        if (ctx->extensions)
        {
            memcpy(ctx->extensions, cfg->extensions, cfg->extensions_len);
            ctx->extensions_len = cfg->extensions_len;
        }
    }

    ctx->max_plaintext = cfg ? cfg->max_plaintext : 0;

    s->vt = &noise_vtbl;
    s->ctx = ctx;
    return s;
}
