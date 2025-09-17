#include "multiformats/unsigned_varint/unsigned_varint.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Calculate the number of bytes required to encode a 64-bit unsigned integer as a varint.
 *
 * @param value The 64-bit unsigned integer to be encoded.
 * @return The number of bytes required (1–9), or 0 if the value is ≥ 2^63 (illegal to encode).
 */
static size_t varint_size_64(uint64_t value)
{
    if (value > (UINT64_C(1) << 63) - 1)
    {
        return 0;
    }

    size_t size = 1;
    while (value >>= 7)
    {
        ++size;
    }

    return size;
}

/**
 * @brief Encode a 64-bit unsigned integer into a varint format.
 *
 * @param value The 64-bit unsigned integer to encode.
 * @param out The buffer to write the encoded varint to.
 * @param out_size The size of the output buffer.
 * @param written Pointer to store the number of bytes written to the output buffer.
 * @return unsigned_varint_err_t Error code indicating success or type of failure.
 */
unsigned_varint_err_t unsigned_varint_encode(uint64_t value, uint8_t *out, size_t out_size, size_t *written)
{
    if (!out || !written)
    {
        return UNSIGNED_VARINT_ERR_NULL_PTR;
    }

    if (value > UINT64_C(0x7FFFFFFFFFFFFFFF))
    {
        return UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
    }

    if (value < 0x80ULL)
    {
        if (out_size < 1)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)value;
        *written = 1;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x4000ULL)
    {
        if (out_size < 2)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(value >> 7);
        *written = 2;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x200000ULL)
    {
        if (out_size < 3)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
        out[2] = (uint8_t)(value >> 14);
        *written = 3;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x10000000ULL)
    {
        if (out_size < 4)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
        out[2] = (uint8_t)(((value >> 14) & 0x7F) | 0x80);
        out[3] = (uint8_t)(value >> 21);
        *written = 4;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x800000000ULL)
    {
        if (out_size < 5)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
        out[2] = (uint8_t)(((value >> 14) & 0x7F) | 0x80);
        out[3] = (uint8_t)(((value >> 21) & 0x7F) | 0x80);
        out[4] = (uint8_t)(value >> 28);
        *written = 5;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x40000000000ULL)
    {
        if (out_size < 6)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
        out[2] = (uint8_t)(((value >> 14) & 0x7F) | 0x80);
        out[3] = (uint8_t)(((value >> 21) & 0x7F) | 0x80);
        out[4] = (uint8_t)(((value >> 28) & 0x7F) | 0x80);
        out[5] = (uint8_t)(value >> 35);
        *written = 6;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x2000000000000ULL)
    {
        if (out_size < 7)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
        out[2] = (uint8_t)(((value >> 14) & 0x7F) | 0x80);
        out[3] = (uint8_t)(((value >> 21) & 0x7F) | 0x80);
        out[4] = (uint8_t)(((value >> 28) & 0x7F) | 0x80);
        out[5] = (uint8_t)(((value >> 35) & 0x7F) | 0x80);
        out[6] = (uint8_t)(value >> 42);
        *written = 7;

        return UNSIGNED_VARINT_OK;
    }

    if (value < 0x100000000000000ULL)
    {
        if (out_size < 8)
        {
            return UNSIGNED_VARINT_ERR_BUFFER_OVER;
        }

        out[0] = (uint8_t)((value & 0x7F) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
        out[2] = (uint8_t)(((value >> 14) & 0x7F) | 0x80);
        out[3] = (uint8_t)(((value >> 21) & 0x7F) | 0x80);
        out[4] = (uint8_t)(((value >> 28) & 0x7F) | 0x80);
        out[5] = (uint8_t)(((value >> 35) & 0x7F) | 0x80);
        out[6] = (uint8_t)(((value >> 42) & 0x7F) | 0x80);
        out[7] = (uint8_t)(value >> 49);
        *written = 8;

        return UNSIGNED_VARINT_OK;
    }

    /* Otherwise, value fits in 9 bytes */
    if (out_size < 9)
    {
        return UNSIGNED_VARINT_ERR_BUFFER_OVER;
    }

    out[0] = (uint8_t)((value & 0x7F) | 0x80);
    out[1] = (uint8_t)(((value >> 7) & 0x7F) | 0x80);
    out[2] = (uint8_t)(((value >> 14) & 0x7F) | 0x80);
    out[3] = (uint8_t)(((value >> 21) & 0x7F) | 0x80);
    out[4] = (uint8_t)(((value >> 28) & 0x7F) | 0x80);
    out[5] = (uint8_t)(((value >> 35) & 0x7F) | 0x80);
    out[6] = (uint8_t)(((value >> 42) & 0x7F) | 0x80);
    out[7] = (uint8_t)(((value >> 49) & 0x7F) | 0x80);
    out[8] = (uint8_t)(value >> 56);
    *written = 9;

    return UNSIGNED_VARINT_OK;
}

/**
 * @brief Decode a varint-encoded 64-bit unsigned integer.
 *
 * @param in The input buffer containing the varint-encoded data.
 * @param in_size The size of the input buffer.
 * @param value Pointer to store the decoded 64-bit unsigned integer.
 * @param read Pointer to store the number of bytes read from the input buffer.
 * @return unsigned_varint_err_t Error code indicating success or type of failure.
 */
unsigned_varint_err_t unsigned_varint_decode(const uint8_t *in, size_t in_size, uint64_t *value, size_t *read)
{
    if (!in || !value || !read)
    {
        return UNSIGNED_VARINT_ERR_NULL_PTR;
    }

    if (in_size == 0)
    {
        return UNSIGNED_VARINT_ERR_EMPTY_INPUT;
    }

    if (!(in[0] & 0x80))
    {
        *value = in[0];
        *read = 1;

        return UNSIGNED_VARINT_OK;
    }

    if (in_size >= 2 && !(in[1] & 0x80))
    {
        uint64_t v = ((uint64_t)(in[1] & 0x7F) << 7) | (in[0] & 0x7F);
        if (v < (1ULL << 7))
        {
            return UNSIGNED_VARINT_ERR_NOT_MINIMAL;
        }

        *value = v;
        *read = 2;

        return UNSIGNED_VARINT_OK;
    }

    if (in_size >= 3 && !(in[2] & 0x80))
    {
        uint64_t v = ((uint64_t)(in[2] & 0x7F) << 14) | ((uint64_t)(in[1] & 0x7F) << 7) | (in[0] & 0x7F);
        if (v < (1ULL << 14))
        {
            return UNSIGNED_VARINT_ERR_NOT_MINIMAL;
        }

        *value = v;
        *read = 3;

        return UNSIGNED_VARINT_OK;
    }

    if (in_size >= 4 && !(in[3] & 0x80))
    {
        uint64_t v = ((uint64_t)(in[3] & 0x7F) << 21) | ((uint64_t)(in[2] & 0x7F) << 14) | ((uint64_t)(in[1] & 0x7F) << 7) | (in[0] & 0x7F);
        if (v < (1ULL << 21))
        {
            return UNSIGNED_VARINT_ERR_NOT_MINIMAL;
        }

        *value = v;
        *read = 4;

        return UNSIGNED_VARINT_OK;
    }

    uint64_t result = 0;
    size_t idx = 0;
    uint8_t b;

    /* Byte 0 */
    b = in[idx++];
    result = b & 0x7F;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 1 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 7;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 2 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 14;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 3 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 21;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 4 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 28;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 5 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 35;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 6 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 42;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 7 */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    result |= ((uint64_t)(b & 0x7F)) << 49;
    if (!(b & 0x80))
    {
        goto minimal_check;
    }

    /* Byte 8 (ninth byte) */
    if (idx >= in_size)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }
    b = in[idx++];
    if (b & 0x80)
    {
        /* Continuation on ninth byte → read tenth */
        if (idx >= in_size)
        {
            return UNSIGNED_VARINT_ERR_TOO_LONG;
        }
        b = in[idx++];
        if (b & 0x80)
        {
            return UNSIGNED_VARINT_ERR_TOO_LONG;
        }
        result |= ((uint64_t)(b & 0x7F)) << 63;
    }
    else
    {
        result |= ((uint64_t)(b & 0x7F)) << 56;
    }

minimal_check:
    if (result > UINT64_C(0x7FFFFFFFFFFFFFFF))
    {
        return UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
    }

    if (idx > 9)
    {
        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }

    size_t expected = unsigned_varint_size(result);
    if (expected != idx)
    {
        return UNSIGNED_VARINT_ERR_NOT_MINIMAL;
    }

    *value = result;
    *read = idx;

    return UNSIGNED_VARINT_OK;
}

/**
 * @brief Calculate the size of a 64-bit unsigned integer when encoded as a varint.
 *
 * @param value The 64-bit unsigned integer to calculate the size for.
 * @return The size of the encoded integer in bytes.
 */
size_t unsigned_varint_size(uint64_t value) { return varint_size_64(value); }