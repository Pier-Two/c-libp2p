#ifndef MULTIHASH_H
#define MULTIHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Maximum digest size produced by supported non-identity hash functions.
 */
#define MULTIHASH_MAX_DIGEST_SIZE ((size_t)64U)

/**
 * @brief Supported multihash code values.
 */
#define MULTIHASH_CODE_IDENTITY ((uint64_t)0x00U)
#define MULTIHASH_CODE_SHA2_256 ((uint64_t)0x12U)
#define MULTIHASH_CODE_SHA2_512 ((uint64_t)0x13U)
#define MULTIHASH_CODE_SHA3_512 ((uint64_t)0x14U)
#define MULTIHASH_CODE_SHA3_384 ((uint64_t)0x15U)
#define MULTIHASH_CODE_SHA3_256 ((uint64_t)0x16U)
#define MULTIHASH_CODE_SHA3_224 ((uint64_t)0x17U)

/**
 * @brief Error-code type for multihash operations.
 */
typedef int multihash_error_t;

#define MULTIHASH_SUCCESS ((multihash_error_t)0)
#define MULTIHASH_ERR_NULL_POINTER ((multihash_error_t) - 1)
#define MULTIHASH_ERR_INVALID_INPUT ((multihash_error_t) - 2)
#define MULTIHASH_ERR_UNSUPPORTED_FUN ((multihash_error_t) - 3)
#define MULTIHASH_ERR_DIGEST_TOO_LARGE ((multihash_error_t) - 4)
#define MULTIHASH_ERR_ALLOC_FAILURE ((multihash_error_t) - 5)

/**
 * @brief Hashes input data and encodes the result in multihash format:
 *
 *            <varint code><varint digest_len><digest>
 *
 * Supported codes are:
 * - `MULTIHASH_CODE_SHA2_256`
 * - `MULTIHASH_CODE_SHA2_512`
 * - `MULTIHASH_CODE_SHA3_224`
 * - `MULTIHASH_CODE_SHA3_256`
 * - `MULTIHASH_CODE_SHA3_384`
 * - `MULTIHASH_CODE_SHA3_512`
 * - `MULTIHASH_CODE_IDENTITY`
 *
 * Include `multiformats/multicodec/multicodec_codes.h` if you want to use
 * equivalent `MULTICODEC_*` constants.
 *
 * For SHA2 variants, `data_len` must fit in 32 bits because the backing hash
 * library API accepts `uint32_t` lengths.
 *
 * @param code      Multicodec hash function code.
 * @param data      Input bytes to hash.
 * @param data_len  Number of bytes in @p data.
 * @param out       Output buffer receiving encoded multihash.
 * @param out_len   Size of @p out in bytes.
 *
 * @return On success, returns the number of bytes written.
 *         On failure, returns one of @ref multihash_error_t.
 */
int multihash_encode(uint64_t code, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/**
 * @brief Decodes a multihash from an input buffer:
 *
 *            <varint code><varint digest_len><digest>
 *
 * Trailing bytes after the decoded multihash are allowed; the return value
 * reports how many bytes were consumed.
 *
 * @param in         Input bytes containing a multihash prefix and digest.
 * @param in_len     Number of bytes available in @p in.
 * @param code       Output hash function code.
 * @param digest     Output buffer receiving decoded digest bytes.
 * @param digest_len On input, capacity of @p digest. On success, digest length.
 *
 * @return On success, returns bytes consumed from @p in.
 *         On failure, returns one of @ref multihash_error_t.
 *
 * @note On failure (except NULL-parameter errors), `*code` and `*digest_len`
 * are reset to zero.
 */
int multihash_decode(const uint8_t *in, size_t in_len, uint64_t *code, uint8_t *digest, size_t *digest_len);

#ifdef __cplusplus
}
#endif

#endif /* MULTIHASH_H */
