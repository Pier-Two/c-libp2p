#include "multiformats/unsigned_varint/unsigned_varint.h"

#include <stddef.h>
#include <stdint.h>

static size_t unsigned_varint_size_internal(uint64_t value)
{
    size_t encoded_size;

    if (value > UNSIGNED_VARINT_MAX_VALUE)
    {
        return 0;
    }

    encoded_size = 1;
    while (value >= UINT64_C(0x80))
    {
        value >>= 7;
        ++encoded_size;
    }

    return encoded_size;
}

unsigned_varint_err_t unsigned_varint_encode(uint64_t value, uint8_t *out, size_t out_size, size_t *written)
{
    size_t required_size;
    size_t index;

    if ((out == NULL) || (written == NULL))
    {
        return UNSIGNED_VARINT_ERR_NULL_PTR;
    }

    *written = 0;

    if (value > UNSIGNED_VARINT_MAX_VALUE)
    {
        return UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
    }

    required_size = unsigned_varint_size_internal(value);
    if (required_size == 0)
    {
        return UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
    }

    if (out_size < required_size)
    {
        return UNSIGNED_VARINT_ERR_BUFFER_OVER;
    }

    for (index = 0; index < required_size; ++index)
    {
        uint8_t byte;

        byte = (uint8_t)(value & UINT64_C(0x7F));
        value >>= 7;
        if (value != 0)
        {
            byte = (uint8_t)(byte | UINT8_C(0x80));
        }

        out[index] = byte;
    }

    *written = required_size;
    return UNSIGNED_VARINT_OK;
}

unsigned_varint_err_t unsigned_varint_decode(const uint8_t *in, size_t in_size, uint64_t *value, size_t *read)
{
    uint64_t decoded_value;
    unsigned int shift;
    size_t index;

    if ((in == NULL) || (value == NULL) || (read == NULL))
    {
        return UNSIGNED_VARINT_ERR_NULL_PTR;
    }

    if (in_size == 0)
    {
        return UNSIGNED_VARINT_ERR_EMPTY_INPUT;
    }

    decoded_value = 0;
    shift = 0;

    for (index = 0; index < in_size; ++index)
    {
        uint8_t byte;

        byte = in[index];

        if (index < UNSIGNED_VARINT_MAX_ENCODED_SIZE)
        {
            decoded_value |= ((uint64_t)(byte & UINT8_C(0x7F))) << shift;
            if ((byte & UINT8_C(0x80)) == 0)
            {
                size_t encoded_size;

                encoded_size = index + 1;
                if (decoded_value > UNSIGNED_VARINT_MAX_VALUE)
                {
                    return UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
                }

                if (unsigned_varint_size_internal(decoded_value) != encoded_size)
                {
                    return UNSIGNED_VARINT_ERR_NOT_MINIMAL;
                }

                *value = decoded_value;
                *read = encoded_size;
                return UNSIGNED_VARINT_OK;
            }

            shift += 7;
            continue;
        }

        if (index > UNSIGNED_VARINT_MAX_ENCODED_SIZE)
        {
            return UNSIGNED_VARINT_ERR_TOO_LONG;
        }

        /*
         * Tenth byte handling: permit explicit overflow detection for 2^63,
         * reject overlong/minimal-invalid 10-byte forms, and reject any
         * continuation beyond this point.
         */
        if ((byte & UINT8_C(0x80)) != 0)
        {
            return UNSIGNED_VARINT_ERR_TOO_LONG;
        }

        if ((byte & UINT8_C(0x7F)) == 0)
        {
            return UNSIGNED_VARINT_ERR_TOO_LONG;
        }

        if ((byte & UINT8_C(0x7F)) == 1)
        {
            return UNSIGNED_VARINT_ERR_VALUE_OVERFLOW;
        }

        return UNSIGNED_VARINT_ERR_TOO_LONG;
    }

    return UNSIGNED_VARINT_ERR_TOO_LONG;
}

size_t unsigned_varint_size(uint64_t value) { return unsigned_varint_size_internal(value); }
