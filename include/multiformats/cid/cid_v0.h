#ifndef CID_V0_H
#define CID_V0_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file cid_v0.h
 * @brief CIDv0 public API.
 *
 * CIDv0 binary layout:
 *   <multihash-code=0x12><digest-len=0x20><32-byte digest>
 *
 * CIDv0 string layout:
 *   Base58BTC string with fixed length 46 characters (commonly `Qm...`).
 */

/** @brief SHA2-256 digest size used by CIDv0. */
#define CIDV0_HASH_SIZE ((size_t)32U)

/** @brief CIDv0 binary size in bytes. */
#define CIDV0_BINARY_SIZE ((size_t)34U)

/** @brief CIDv0 base58btc string length (without null terminator). */
#define CIDV0_STRING_LENGTH ((size_t)46U)

/** @brief CIDv0 multihash code byte (`sha2-256`). */
#define CIDV0_MULTIHASH_CODE ((uint8_t)0x12U)

/** @brief CIDv0 multihash digest-length byte (32 bytes). */
#define CIDV0_MULTIHASH_LENGTH ((uint8_t)0x20U)

/**
 * @brief Error-code type for CIDv0 operations.
 */
typedef int cidv0_error_t;

#define CIDV0_SUCCESS ((cidv0_error_t)0)
#define CIDV0_ERROR_NULL_POINTER ((cidv0_error_t) - 1)
#define CIDV0_ERROR_INVALID_DIGEST_LENGTH ((cidv0_error_t) - 2)
#define CIDV0_ERROR_BUFFER_TOO_SMALL ((cidv0_error_t) - 3)
#define CIDV0_ERROR_ENCODE_FAILURE ((cidv0_error_t) - 4)
#define CIDV0_ERROR_DECODE_FAILURE ((cidv0_error_t) - 5)

/**
 * @brief Represents a CIDv0 (sha2-256 digest only).
 */
typedef struct
{
	uint8_t hash[CIDV0_HASH_SIZE];
} cid_v0_t;

/**
 * @brief Initialize a CIDv0 from a raw SHA2-256 digest.
 *
 * @param[out] cid        Destination CID object.
 * @param[in]  digest     Pointer to digest bytes.
 * @param[in]  digest_len Digest length, must be @ref CIDV0_HASH_SIZE.
 *
 * @return @ref CIDV0_SUCCESS on success, or a negative @ref cidv0_error_t value.
 */
int cid_v0_init(cid_v0_t *cid, const uint8_t *digest, size_t digest_len);

/**
 * @brief Encode CIDv0 to binary form.
 *
 * Writes exactly @ref CIDV0_BINARY_SIZE bytes as:
 * `<0x12><0x20><digest[32]>`.
 *
 * @param[in]  cid      Source CID object.
 * @param[out] out      Output buffer.
 * @param[in]  out_len  Output buffer size.
 *
 * @return Bytes written on success (@ref CIDV0_BINARY_SIZE), or negative error code.
 */
int cid_v0_to_bytes(const cid_v0_t *cid, uint8_t *out, size_t out_len);

/**
 * @brief Parse CIDv0 from binary form.
 *
 * Expects exactly @ref CIDV0_BINARY_SIZE bytes with CIDv0 multihash framing.
 *
 * @param[out] cid       Destination CID object.
 * @param[in]  bytes     Input binary bytes.
 * @param[in]  bytes_len Input length.
 *
 * @return Bytes consumed on success (@ref CIDV0_BINARY_SIZE), or negative error code.
 *
 * @note On failure (except NULL-pointer failure), @p cid is reset to all-zero hash bytes.
 */
int cid_v0_from_bytes(cid_v0_t *cid, const uint8_t *bytes, size_t bytes_len);

/**
 * @brief Encode CIDv0 to base58btc string form.
 *
 * @param[in]  cid      Source CID object.
 * @param[out] out      Output buffer for null-terminated string.
 * @param[in]  out_len  Output buffer size.
 *
 * @return Characters written (excluding null terminator) on success,
 *         or negative error code.
 *
 * @note On failure (except NULL-pointer failure), and when @p out_len > 0,
 * `out[0]` is set to `\0`.
 */
int cid_v0_to_string(const cid_v0_t *cid, char *out, size_t out_len);

/**
 * @brief Decode CIDv0 from base58btc string form.
 *
 * Input must be exactly @ref CIDV0_STRING_LENGTH characters and represent a valid
 * CIDv0 multihash.
 *
 * @param[out] cid Destination CID object.
 * @param[in]  str Null-terminated input string.
 *
 * @return Characters consumed on success (@ref CIDV0_STRING_LENGTH),
 *         or negative error code.
 *
 * @note On failure (except NULL-pointer failure), @p cid is reset to all-zero hash bytes.
 */
int cid_v0_from_string(cid_v0_t *cid, const char *str);

#ifdef __cplusplus
}
#endif

#endif /* CID_V0_H */
