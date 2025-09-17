#ifndef UNSIGNED_VARINT_H
#define UNSIGNED_VARINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @enum unsigned_varint_err_t
 * @brief Error codes for varint operations.
 */
typedef enum
{
    UNSIGNED_VARINT_OK = 0,                 /**< No error. */
    UNSIGNED_VARINT_ERR_NULL_PTR = -1,      /**< A required pointer argument was NULL. */
    UNSIGNED_VARINT_ERR_BUFFER_OVER = -2,   /**< The output buffer is not large enough. */
    UNSIGNED_VARINT_ERR_EMPTY_INPUT = -3,   /**< The input buffer is empty. */
    UNSIGNED_VARINT_ERR_TOO_LONG = -4,      /**< Exceeded 9-byte (63-bit) practical maximum or incomplete varint. */
    UNSIGNED_VARINT_ERR_NOT_MINIMAL = -5,   /**< The encoding was not minimal. */
    UNSIGNED_VARINT_ERR_VALUE_OVERFLOW = -6 /**< The decoded value does not fit in 63 bits. */
} unsigned_varint_err_t;

/**
 * @brief Encodes a 64-bit unsigned integer into a varint buffer.
 *
 * @param value    The 64-bit unsigned value to encode (must be ≤ 2^63-1).
 * @param out      Pointer to the output buffer (must not be NULL).
 * @param out_size Size of the @p out buffer in bytes (must be ≥ required size).
 * @param written  Pointer to receive the number of bytes written (must not be NULL).
 *
 * @return UNSIGNED_VARINT_OK on success.
 *         UNSIGNED_VARINT_ERR_NULL_PTR if @p out or @p written is NULL.
 *         UNSIGNED_VARINT_ERR_BUFFER_OVER if @p out_size is too small.
 *         UNSIGNED_VARINT_ERR_VALUE_OVERFLOW if @p value > 2^63-1.
 */
unsigned_varint_err_t unsigned_varint_encode(uint64_t value, uint8_t *out, size_t out_size, size_t *written);

/**
 * @brief Decodes a varint from the given buffer into a 64-bit unsigned integer.
 *
 * @param in      Pointer to the input buffer containing varint data (must not be NULL).
 * @param in_size Number of bytes available in @p in (must be ≥1).
 * @param value   Pointer to receive the decoded value (must not be NULL).
 * @param read    Pointer to receive the number of bytes read (must not be NULL).
 *
 * @return UNSIGNED_VARINT_OK on success.
 *         UNSIGNED_VARINT_ERR_NULL_PTR if @p in, @p value, or @p read is NULL.
 *         UNSIGNED_VARINT_ERR_EMPTY_INPUT if @p in_size is 0.
 *         UNSIGNED_VARINT_ERR_TOO_LONG if >9 bytes are required or a continuation bit remains.
 *         UNSIGNED_VARINT_ERR_NOT_MINIMAL if the varint is not minimally encoded.
 *         UNSIGNED_VARINT_ERR_VALUE_OVERFLOW if the decoded value > 2^63-1.
 */
unsigned_varint_err_t unsigned_varint_decode(const uint8_t *in, size_t in_size, uint64_t *value, size_t *read);

/**
 * @brief Returns how many bytes are needed to encode the given value as a varint.
 *
 * @param value The 64-bit unsigned integer to measure (must be ≤2^63-1).
 * @return The number of bytes required (1..9), or 0 if value > 2^63-1.
 */
size_t unsigned_varint_size(uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* UNSIGNED_VARINT_H */
