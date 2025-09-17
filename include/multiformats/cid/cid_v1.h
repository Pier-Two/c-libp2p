#ifndef CID_V1_H
#define CID_V1_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multibase/multibase.h" /* for multibase_t */
#include "multiformats/multicodec/multicodec_codes.h"

/**
 * @file cid_v1.h
 * @brief CIDv1 public API.
 *
 * CIDv1 layout (binary):
 *   varint(cid_version=1), varint(content_codec), multihash
 *
 * When stringified with a chosen multibase, the layout is:
 *   <multibase-prefix><encoded-binary-cidv1>.
 *
 * Example (base58btc-encoded):
 *   "zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA"
 */

/**
 * @enum cidv1_error_t
 * @brief Error codes for CIDv1 operations.
 */
typedef enum
{
    CIDV1_SUCCESS = 0,                 /**< Operation successful. */
    CIDV1_ERROR_NULL_POINTER = -1,     /**< A required pointer parameter was NULL. */
    CIDV1_ERROR_INVALID_ARG = -2,      /**< An invalid argument was passed (e.g., zero length). */
    CIDV1_ERROR_BUFFER_TOO_SMALL = -3, /**< Output buffer is too small for the required data. */
    CIDV1_ERROR_ENCODE_FAILURE = -4,   /**< Failed to encode the CIDv1 in the chosen base. */
    CIDV1_ERROR_DECODE_FAILURE = -5,   /**< Failed to decode the CIDv1 from binary or string. */
    CIDV1_ERROR_ALLOCATION_FAILED = -6 /**< Memory allocation failed. */
} cidv1_error_t;

/**
 * @struct cid_v1_t
 * @brief Represents a CIDv1.
 *
 * Fields:
 *   - version: Must be 1 for CIDv1.
 *   - codec: Numeric multicodec code for the content type (e.g., MULTICODEC_CBOR).
 *   - multihash: Dynamically allocated pointer to the raw multihash bytes.
 *   - multihash_size: Number of bytes in the multihash array.
 *
 * The library manages the memory in `multihash`. Call cid_v1_free() when done.
 */
typedef struct
{
    uint64_t version;      /**< Always 1 for CIDv1. */
    uint64_t codec;        /**< Numeric multicodec code for the content type. */
    uint8_t *multihash;    /**< Dynamically allocated array for the multihash. */
    size_t multihash_size; /**< Length of the `multihash` array in bytes. */
} cid_v1_t;

/**
 * @brief Initialize a CIDv1 with the given codec and raw multihash bytes.
 *
 * This function allocates and copies the multihash data internally. The caller
 * should eventually call cid_v1_free() to release the memory.
 *
 * @param[out] cid           Pointer to the cid_v1_t to initialize.
 * @param[in]  content_codec Numeric code for the content type (from multicodec_codes.h).
 * @param[in]  mh_data       Pointer to the multihash bytes to copy.
 * @param[in]  mh_size       Length of `mh_data` in bytes.
 *
 * @return ::CIDV1_SUCCESS on success, or a negative error code otherwise.
 */
int cid_v1_init(cid_v1_t *cid, uint64_t content_codec, const uint8_t *mh_data, size_t mh_size);

/**
 * @brief Free memory allocated by cid_v1_init().
 *
 * After this call, `cid->multihash` will be freed, and `cid->multihash` is set to NULL.
 *
 * @param[in,out] cid  Pointer to a cid_v1_t whose internal data will be freed.
 *
 * @note Does nothing if `cid == NULL`.
 */
void cid_v1_free(cid_v1_t *cid);

/**
 * @brief Parse a binary CIDv1 from the given buffer.
 *        Expects: <varint(1)><varint(content_codec)><multihash>.
 *
 * Allocates memory for `cid->multihash`. The caller must call cid_v1_free() when done.
 *
 * @param[out] cid       Pointer to the cid_v1_t structure to fill.
 * @param[in]  data      Pointer to the binary data containing the CIDv1.
 * @param[in]  data_len  Size of `data` in bytes.
 *
 * @return Number of bytes consumed on success, or a negative error code on failure.
 */
ssize_t cid_v1_from_bytes(cid_v1_t *cid, const uint8_t *data, size_t data_len);

/**
 * @brief Encode a CIDv1 structure into its binary form:
 *        <varint(1)><varint(content_codec)><multihash>.
 *
 * @param[in]  cid      Pointer to the cid_v1_t to encode.
 * @param[out] out      Buffer to hold the CIDv1 bytes.
 * @param[in]  out_len  Size of `out` in bytes.
 *
 * @return Number of bytes written on success, or a negative error code.
 */
ssize_t cid_v1_to_bytes(const cid_v1_t *cid, uint8_t *out, size_t out_len);

/**
 * @brief Encode a CIDv1 into a multibase string. The result is:
 *        <multibase-prefix><encoded-binary-cidv1>.
 *
 * @param[in]  cid     Pointer to the cid_v1_t.
 * @param[in]  base    The desired multibase (e.g., MULTIBASE_BASE58_BTC).
 * @param[out] out     Buffer for the null-terminated string.
 * @param[in]  out_len Size of `out` in bytes.
 *
 * @return Number of characters (excluding null terminator) on success, or a negative error code.
 */
ssize_t cid_v1_to_string(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len);

/**
 * @brief Decode a CIDv1 from a multibase string. Detects the multibase prefix,
 *        decodes, then parses the underlying binary as a CIDv1.
 *
 * Allocates memory for `cid->multihash`. The caller must call cid_v1_free() when done.
 *
 * @param[out] cid  Pointer to the cid_v1_t to fill.
 * @param[in]  str  Null-terminated multibase string.
 *
 * @return Number of characters consumed from `str` on success, or a negative error code.
 */
ssize_t cid_v1_from_string(cid_v1_t *cid, const char *str);

/**
 * @brief Convert a CIDv1 to a human-readable string of the form:
 *        `<hr-mbc> - cidv1 - <hr-codec> - <hr-mh>`
 *
 * Where:
 *  - `<hr-mbc>` is the multibase name (e.g., "base58btc"),
 *  - `cidv1` is always used for the version portion,
 *  - `<hr-codec>` is the content codec name (e.g. "raw", "cbor", etc.),
 *  - `<hr-mh>` is the hash function name plus "-" plus the hex digest.
 *
 * @param[in]  cid      Pointer to the cid_v1_t.
 * @param[in]  base     Which base is considered the "primary" for `<hr-mbc>`.
 * @param[out] out      Buffer for the resulting null-terminated string.
 * @param[in]  out_len  Size of `out` in bytes.
 *
 * @return Number of characters (excluding null terminator) on success, or negative error code.
 */
ssize_t cid_v1_to_human(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* CID_V1_H */