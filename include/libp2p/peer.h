#ifndef LIBP2P_PEER_SPEC_COMPAT_H
#define LIBP2P_PEER_SPEC_COMPAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Spec-compat adapter header for unified libp2p API.
 *
 * Maps spec types like libp2p_peer_id_t to the existing peer_id_t and
 * provides wrapper helpers with the spec names.
 */

typedef peer_id_t libp2p_peer_id_t;

/* Minimal key wrappers to align with spec wording. These are protobuf-encoded
 * PublicKey/PrivateKey message blobs. */
typedef struct libp2p_public_key
{
    const uint8_t *bytes;
    size_t len;
} libp2p_public_key_t;

typedef struct libp2p_private_key
{
    const uint8_t *bytes;
    size_t len;
} libp2p_private_key_t;

/* Default textual representation is CIDv1 (multibase). */
static inline int libp2p_peer_id_to_string(const libp2p_peer_id_t *pid, char *buf, size_t buf_len)
{
    return peer_id_to_string(pid, PEER_ID_FMT_MULTIBASE_CIDv1, buf, buf_len);
}

static inline int libp2p_peer_id_from_string(const char *s, libp2p_peer_id_t **out)
{
    if (!s || !out)
        return PEER_ID_E_NULL_PTR;
    libp2p_peer_id_t *p = (libp2p_peer_id_t *)calloc(1, sizeof(*p));
    if (!p)
        return PEER_ID_E_ALLOC_FAILED;
    peer_id_error_t rc = peer_id_create_from_string(s, p);
    if (rc != PEER_ID_SUCCESS)
    {
        free(p);
        return rc;
    }
    *out = p;
    return 0;
}

static inline int libp2p_peer_id_equal(const libp2p_peer_id_t *a, const libp2p_peer_id_t *b) { return peer_id_equals(a, b); }

static inline int libp2p_peer_id_from_public_key(const libp2p_public_key_t *pk, libp2p_peer_id_t **out)
{
    if (!pk || !pk->bytes || pk->len == 0 || !out)
        return PEER_ID_E_NULL_PTR;
    libp2p_peer_id_t *p = (libp2p_peer_id_t *)calloc(1, sizeof(*p));
    if (!p)
        return PEER_ID_E_ALLOC_FAILED;
    peer_id_error_t rc = peer_id_create_from_public_key(pk->bytes, pk->len, p);
    if (rc != PEER_ID_SUCCESS)
    {
        free(p);
        return rc;
    }
    *out = p;
    return 0;
}

static inline int libp2p_peer_id_from_private_key(const libp2p_private_key_t *sk, libp2p_peer_id_t **out)
{
    if (!sk || !sk->bytes || sk->len == 0 || !out)
        return PEER_ID_E_NULL_PTR;
    libp2p_peer_id_t *p = (libp2p_peer_id_t *)calloc(1, sizeof(*p));
    if (!p)
        return PEER_ID_E_ALLOC_FAILED;
    peer_id_error_t rc = peer_id_create_from_private_key(sk->bytes, sk->len, p);
    if (rc != PEER_ID_SUCCESS)
    {
        free(p);
        return rc;
    }
    *out = p;
    return 0;
}

static inline void libp2p_peer_id_free(libp2p_peer_id_t *pid)
{
    if (!pid)
        return;
    peer_id_destroy(pid);
    free(pid);
}

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PEER_SPEC_COMPAT_H */
