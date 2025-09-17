#ifndef PROTOCOL_NOISE_H
#define PROTOCOL_NOISE_H

#include "security/security.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file protocol_noise.h
 * @brief Declarations for the libp2p Noise security protocol.
 */

/** Canonical protocol id for noise-libp2p (without trailing newline). */
#define LIBP2P_NOISE_PROTO_ID "/noise"

/**
 * @brief Error codes returned by the Noise protocol implementation.
 */
typedef enum
{
    LIBP2P_NOISE_OK = 0,
    LIBP2P_NOISE_ERR_NULL_PTR = -1,
    LIBP2P_NOISE_ERR_HANDSHAKE = -2,
    LIBP2P_NOISE_ERR_INTERNAL = -3
} libp2p_noise_err_t;

/**
 * @brief Configuration for creating a Noise security instance.
 */
typedef struct
{
    const uint8_t *static_private_key;   /**< Optional 32-byte X25519 private key. */
    size_t static_private_key_len;       /**< Length of key (0 or 32). */
    const uint8_t *identity_private_key; /**< Optional identity private key bytes.
                                          *  Supports RSA, Ed25519,
                                          *  secp256k1 and ECDSA. */
    size_t identity_private_key_len;     /**< Length of identity key
                                          *  (0 or key-specific). */
    int identity_key_type;               /**< 0 → none, 0=RSA, 1=Ed25519,
                                          * 2=secp256k1, 3=ECDSA. */
    const uint8_t *early_data;           /**< Optional early data bytes. */
    size_t early_data_len;               /**< Length of early data. */
    const uint8_t *extensions;           /**< Optional pre-encoded NoiseExtensions msg. */
    size_t extensions_len;               /**< Length of extensions msg. */
    size_t max_plaintext;                /**< 0 → library default. */
} libp2p_noise_config_t;

/**
 * @brief Return a zero-initialized Noise configuration.
 */
static inline libp2p_noise_config_t libp2p_noise_config_default(void)
{
    return (libp2p_noise_config_t){.static_private_key = NULL,
                                   .static_private_key_len = 0,
                                   .identity_private_key = NULL,
                                   .identity_private_key_len = 0,
                                   .identity_key_type = 0,
                                   .early_data = NULL,
                                   .early_data_len = 0,
                                   .extensions = NULL,
                                   .extensions_len = 0,
                                   .max_plaintext = 0};
}

/**
 * @brief Create a Noise security protocol instance.
 *
 * The returned object implements @ref libp2p_security_t.
 *
 * @param cfg Optional configuration (NULL → defaults).
 */
libp2p_security_t *libp2p_noise_security_new(const libp2p_noise_config_t *cfg);

/**
 * @brief Dial-side negotiation + Noise handshake.
 *
 * Performs multistream-select negotiation for @ref LIBP2P_NOISE_PROTO_ID and
 * runs the Noise handshake on success.
 *
 * @param sec          Noise security instance.
 * @param conn         Raw connection (consumed on success).
 * @param remote_hint  Optional expected remote peer id (may be NULL).
 * @param timeout_ms   Negotiation timeout in milliseconds (0 → none).
 * @param out          On success, new secured connection.
 * @param remote_peer  On success, remote peer identity (may be NULL).
 */
libp2p_security_err_t libp2p_noise_negotiate_outbound(libp2p_security_t *sec, libp2p_conn_t *conn, const peer_id_t *remote_hint, uint64_t timeout_ms,
                                                      libp2p_conn_t **out, peer_id_t **remote_peer);

/**
 * @brief Listen-side negotiation + Noise handshake.
 *
 * Performs multistream-select negotiation for @ref LIBP2P_NOISE_PROTO_ID and
 * runs the Noise handshake on success.
 *
 * @param sec          Noise security instance.
 * @param conn         Raw connection (consumed on success).
 * @param timeout_ms   Negotiation timeout in milliseconds (0 → none).
 * @param out          On success, new secured connection.
 * @param remote_peer  On success, remote peer identity (may be NULL).
 */
libp2p_security_err_t libp2p_noise_negotiate_inbound(libp2p_security_t *sec, libp2p_conn_t *conn, uint64_t timeout_ms, libp2p_conn_t **out,
                                                     peer_id_t **remote_peer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_NOISE_H */
