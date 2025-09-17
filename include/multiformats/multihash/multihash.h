#ifndef MULTIHASH_H
#define MULTIHASH_H

#include <stddef.h>
#include <stdint.h>

#include "multiformats/multicodec/multicodec_codes.h" /* For codes like MULTICODEC_SHA1, MULTICODEC_SHA2_256, etc. */

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Error codes for multihash operations.
 *
 */
typedef enum
{
    MULTIHASH_SUCCESS = 0,               /**< Operation completed successfully. */
    MULTIHASH_ERR_NULL_POINTER = -1,     /**< A null pointer was provided. */
    MULTIHASH_ERR_INVALID_INPUT = -2,    /**< The input provided is invalid. */
    MULTIHASH_ERR_UNSUPPORTED_FUN = -3,  /**< The requested function is unsupported. */
    MULTIHASH_ERR_DIGEST_TOO_LARGE = -4, /**< The computed digest exceeds the allowed size. */
    MULTIHASH_ERR_ALLOC_FAILURE = -5     /**< Memory allocation failed. */
} multihash_error_t;

/**
 * @brief Hash the input data using the specified hash function code,
 *        then encode it as a multihash:
 *
 *            <varint code><varint digest_len><digest>
 *
 * @param code      The multicodec hash function code (e.g., MULTICODEC_SHA2_256).
 * @param data      Pointer to the input data to be hashed.
 * @param data_len  Number of bytes in `data`.
 * @param out       Buffer where the encoded multihash is written.
 * @param out_len   Size of the `out` buffer in bytes.
 *
 * @return On success, the total number of bytes written is returned.
 *         On failure, a negative error code is returned.
 */
int multihash_encode(uint64_t code, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/**
 * @brief Decode a multihash from the given buffer, extracting the hash function code,
 *        digest length, and digest bytes.
 *
 * The multihash format is assumed to be:
 *
 *            <varint code><varint digest_len><digest>
 *
 * @param in         Pointer to the multihash bytes.
 * @param in_len     Number of bytes in `in`.
 * @param code       Output parameter: the hash function code (as defined in multicodec_codes.h).
 * @param digest     Output buffer where the digest is copied.
 * @param digest_len On input, the size of the digest buffer; on output, the actual digest length.
 *
 * @return On success, the total number of bytes consumed is returned.
 *         On failure, a negative error code is returned.
 */
int multihash_decode(const uint8_t *in, size_t in_len, uint64_t *code, uint8_t *digest, size_t *digest_len);

#ifdef __cplusplus
}
#endif

#endif /* MULTIHASH_H */