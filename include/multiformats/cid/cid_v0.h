#ifndef CID_V0_H
#define CID_V0_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @file cid_v0.h
 * @brief CIDv0 public API.
 *
 * CIDv0:
 *   - Implicitly uses base58btc in its string form (leading "Qm...").
 *   - Implicitly uses multicodec = dag-pb.
 *   - Implicitly uses version = 0.
 *   - Always a 32-byte sha2-256 digest in the binary form (34 bytes total: 0x12 0x20 + 32-byte
 * hash).
 */

/** The size of the CIDv0 hash (sha2-256) in bytes. */
#define CIDV0_HASH_SIZE 32

/**
 * @enum cidv0_error_t
 * @brief Error codes for CIDv0 operations.
 */
typedef enum
{
    CIDV0_SUCCESS = 0,                      /**< Operation successful. */
    CIDV0_ERROR_NULL_POINTER = -1,          /**< A required pointer parameter was NULL. */
    CIDV0_ERROR_INVALID_DIGEST_LENGTH = -2, /**< The provided digest is not 32 bytes. */
    CIDV0_ERROR_BUFFER_TOO_SMALL = -3,      /**< Provided buffer is too small for output. */
    CIDV0_ERROR_ENCODE_FAILURE = -4,        /**< Failed while encoding base58btc. */
    CIDV0_ERROR_DECODE_FAILURE = -5,        /**< Failed while decoding base58btc. */
} cidv0_error_t;

/**
 * @struct cid_v0_t
 * @brief Represents a CIDv0, storing only the 32-byte sha2-256 hash.
 */
typedef struct
{
    uint8_t hash[CIDV0_HASH_SIZE]; /**< The 32-byte (sha2-256) hash. */
} cid_v0_t;

/**
 * @brief Initialize a CIDv0 from a raw 32-byte sha2-256 digest.
 *
 * @param[out] cid        Pointer to a cid_v0_t struct to initialize.
 * @param[in]  digest     Pointer to a 32-byte sha2-256 hash.
 * @param[in]  digest_len Length of `digest` (must be 32).
 * @return ::CIDV0_SUCCESS on success, negative error code otherwise.
 */
int cid_v0_init(cid_v0_t *cid, const uint8_t *digest, size_t digest_len);

/**
 * @brief Encode a CIDv0 into its 34-byte binary form:
 *          [0x12, 0x20] + 32-byte digest
 *
 * @param[in]  cid       Pointer to the CIDv0.
 * @param[out] out       Buffer to hold the 34-byte result.
 * @param[in]  out_len   Size of `out` in bytes (must be >= 34).
 * @return Number of bytes written (34) on success, or a negative error code.
 */
int cid_v0_to_bytes(const cid_v0_t *cid, uint8_t *out, size_t out_len);

/**
 * @brief Parse a CIDv0 from its 34-byte binary form:
 *          [0x12, 0x20] + 32-byte digest
 *
 * @param[out] cid        Pointer to a cid_v0_t struct to fill.
 * @param[in]  bytes      The 34-byte buffer.
 * @param[in]  bytes_len  Size of `bytes` (must be >= 34).
 * @return Number of bytes consumed (34) on success, or a negative error code.
 */
int cid_v0_from_bytes(cid_v0_t *cid, const uint8_t *bytes, size_t bytes_len);

/**
 * @brief Encode a CIDv0 to its Base58 BTC string form (leading "Qm...").
 *
 * @param[in]  cid      Pointer to the CIDv0.
 * @param[out] out      Buffer for the resulting null-terminated string.
 * @param[in]  out_len  Size of `out` in bytes.
 * @return Number of characters written (excluding null terminator) on success,
 *         or a negative error code.
 */
int cid_v0_to_string(const cid_v0_t *cid, char *out, size_t out_len);

/**
 * @brief Decode a CIDv0 from a Base58 BTC string (must be exactly 46 characters, starting with
 * "Qm").
 *
 * @param[out] cid  Pointer to a cid_v0_t struct to fill.
 * @param[in]  str  Null-terminated string containing the base58-encoded CIDv0.
 * @return Number of bytes consumed from `str` on success (46 if it’s a valid CIDv0),
 *         or a negative error code.
 */
int cid_v0_from_string(cid_v0_t *cid, const char *str);

#ifdef __cplusplus
}
#endif

#endif /* CID_V0_H */