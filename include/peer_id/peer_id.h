#ifndef PEER_ID_H
#define PEER_ID_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @file peer_id.h
 * @brief API for creating and handling libp2p Peer IDs.
 *
 * Peer IDs are derived by hashing a deterministically serialized public key.
 * The serialization is a protobuf of the form:
 *
 *     message PublicKey {
 *       required KeyType Type = 1;
 *       required bytes Data = 2;
 *     }
 *
 * If the serialized public key is <= 42 bytes, it is placed into
 * an "identity" multihash. Otherwise, a sha2-256 multihash is used.
 *
 * This API also provides utilities to encode/decode peer IDs as:
 *   - Legacy base58btc multihash strings (e.g., "Qm...")
 *   - CIDv1 strings in a multibase encoding, typically base32 (e.g., "bafz...")
 */

/**
 * @brief Error codes for Peer ID operations.
 */
typedef enum peer_id_error
{
    PEER_ID_SUCCESS = 0,        /**< Operation completed successfully. */
    PEER_ID_E_NULL_PTR,         /**< A null pointer was passed where it is not allowed. */
    PEER_ID_E_INVALID_PROTOBUF, /**< Could not parse or handle the given protobuf data. */
    PEER_ID_E_INVALID_RANGE,    /**< Value outside allowed range / overflow risk */
    PEER_ID_E_UNSUPPORTED_KEY,  /**< Unsupported key type in the protobuf. */
    PEER_ID_E_CRYPTO_FAILED,    /**< Underlying crypto library failed. */
    PEER_ID_E_ENCODING_FAILED,  /**< Could not encode or decode. */
    PEER_ID_E_BUFFER_TOO_SMALL, /**< Caller provided a buffer too small for the output. */
    PEER_ID_E_INVALID_STRING,   /**< Input string is not a valid Peer ID. */
    PEER_ID_E_ALLOC_FAILED      /**< Memory allocation failed. */
} peer_id_error_t;

/**
 * @brief Supported textual representations of a Peer ID.
 *
 * PEER_ID_FMT_BASE58_LEGACY:   the legacy raw base58btc (multihash).
 * PEER_ID_FMT_MULTIBASE_CIDv1: a CIDv1 with multibase prefix (usually base32)
 *                              and multicodec = `libp2p-key`.
 */
typedef enum peer_id_format
{
    PEER_ID_FMT_BASE58_LEGACY,
    PEER_ID_FMT_MULTIBASE_CIDv1
} peer_id_format_t;

/**
 * @brief Opaque structure holding the canonical bytes (multihash) of a Peer ID.
 *
 * The @p bytes field contains the entire multihash, including:
 *     <varint hash_code><varint digest_size><digest_bytes>
 *
 * The size is stored in @p size.
 */
typedef struct peer_id
{
    uint8_t *bytes; /**< Pointer to the multihash bytes. */
    size_t size;    /**< Number of bytes in @p bytes.     */
} peer_id_t;

/**
 * @brief Derive a Peer ID from a deterministically serialized (protobuf) public key.
 *
 * The input must be a protobuf-encoded `PublicKey` of the form:
 *
 *     message PublicKey {
 *       required KeyType Type = 1;
 *       required bytes Data = 2;
 *     }
 *
 * If the total protobuf serialization is <= 42 bytes, an "identity" multihash
 * is used. Otherwise a SHA-256 multihash is computed.
 *
 * @param[in]  pubkey_buf   Pointer to the serialized protobuf public key bytes.
 * @param[in]  pubkey_len   Length of @p pubkey_buf in bytes.
 * @param[out] pid          Output pointer to a valid peer_id_t struct. The
 *                          function will allocate @p pid->bytes on success.
 * @return PEER_ID_SUCCESS on success, or an error code on failure.
 *
 * @note The caller is responsible for calling peer_id_destroy() on @p pid
 *       to free allocated resources.
 */
peer_id_error_t peer_id_create_from_public_key(const uint8_t *pubkey_buf, size_t pubkey_len, peer_id_t *pid);

/**
 * @brief Derive a Peer ID from a deterministically serialized (protobuf) private key.
 *
 * The input must be a protobuf-encoded `PrivateKey`, which includes:
 *
 *     message PrivateKey {
 *       required KeyType Type = 1;
 *       required bytes Data = 2;
 *     }
 *
 * Implementations will parse the private key enough to extract (or regenerate)
 * the associated public key. The same rules for <= 42 bytes apply.
 *
 * @param[in]  privkey_buf  Pointer to the serialized protobuf private key bytes.
 * @param[in]  privkey_len  Length of @p privkey_buf in bytes.
 * @param[out] pid          Output pointer to a valid peer_id_t struct.
 * @return PEER_ID_SUCCESS on success, or an error code on failure.
 *
 * @note The caller is responsible for calling peer_id_destroy() on @p pid
 *       to free allocated resources.
 */
peer_id_error_t peer_id_create_from_private_key(const uint8_t *privkey_buf, size_t privkey_len, peer_id_t *pid);

/**
 * @brief Parse a human-readable Peer ID string (either legacy base58btc multihash
 *        or a CIDv1 with multibase) into a canonical `peer_id_t`.
 *
 * This function automatically detects:
 *   - The legacy base58btc format (starts with 'Qm' or '1', etc.).
 *   - A CIDv1 format if it starts with a multibase prefix (e.g. 'bafz...')
 *
 * @param[in]  str         Null-terminated input string containing the Peer ID.
 * @param[out] pid         Output pointer to a valid peer_id_t struct.
 * @return PEER_ID_SUCCESS on success, or an error code on failure.
 *
 * @note The caller must eventually call peer_id_destroy() on @p pid.
 */
peer_id_error_t peer_id_create_from_string(const char *str, peer_id_t *pid);

/**
 * @brief Return a textual representation of the Peer ID in either:
 *        - Legacy base58btc multihash format, or
 *        - CIDv1 (multibase) format with multicodec = libp2p-key
 *
 * @param[in]  pid         Pointer to the peer_id_t to encode.
 * @param[in]  format      The desired output format (legacy base58 or CIDv1).
 * @param[out] out         Buffer for the output string.
 * @param[in]  out_size    Length of the @p out buffer in bytes.
 * @return On success, the number of characters written (excluding null terminator).
 *         On failure, a negative `peer_id_error_t` code is returned.
 */
int peer_id_to_string(const peer_id_t *pid, peer_id_format_t format, char *out, size_t out_size);

/**
 * @brief Compare two Peer IDs for equality (byte-for-byte).
 *
 * @param[in] a    Pointer to the first Peer ID.
 * @param[in] b    Pointer to the second Peer ID.
 * @return 1 if equal, 0 if not equal, or -1 if either pointer is invalid.
 */
int peer_id_equals(const peer_id_t *a, const peer_id_t *b);

/**
 * @brief Free the memory used by a peer_id_t. This does not destroy
 *        the underlying keys (since only the hashed representation
 *        is stored here).
 *
 * @param[in,out] pid   Pointer to a peer_id_t. After this call,
 *                      pid->bytes is deallocated and pid->size is set to 0.
 */
void peer_id_destroy(peer_id_t *pid);

#ifdef __cplusplus
}
#endif

#endif /* PEER_ID_H */