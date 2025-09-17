#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"

/* The base32 alphabet (RFC 4648, Table 3) */
static const char base32_alphabet[32] = "abcdefghijklmnopqrstuvwxyz234567";

/**
 * @brief Encode data into a Base32 format using lowercase letters.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the Base32 encoded string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer (excluding the
 * null terminator), or an error code indicating a null pointer or insufficient
 * buffer size.
 */
int multibase_base32_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    size_t full_blocks, rem;
    size_t i;
    size_t pos = 0;

    if (!data || !out)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    if (data_len == 0)
    {
        if (out_len < 1)
        {
            return MULTIBASE_ERR_BUFFER_TOO_SMALL;
        }
        out[0] = '\0';
        return 0;
    }

    full_blocks = data_len / 5;
    rem = data_len % 5;

    if (full_blocks > SIZE_MAX / 8)
    {
        return MULTIBASE_ERR_OVERFLOW;
    }
    size_t out_chars = full_blocks * 8;

    if (rem)
    {
        size_t extra;
        if (rem == 1)
        {
            extra = 2;
        }
        else if (rem == 2)
        {
            extra = 4;
        }
        else if (rem == 3)
        {
            extra = 5;
        }
        else /* rem == 4 */
        {
            extra = 7;
        }

        if (out_chars > SIZE_MAX - extra)
        {
            return MULTIBASE_ERR_OVERFLOW;
        }
        out_chars += extra;
    }

    if (out_len < out_chars + 1)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < full_blocks; i++)
    {
        const uint8_t *chunk = data + (i * 5);
        uint8_t index0 = chunk[0] >> 3;
        uint8_t index1 = ((chunk[0] & 0x07) << 2) | (chunk[1] >> 6);
        uint8_t index2 = (chunk[1] >> 1) & 0x1F;
        uint8_t index3 = ((chunk[1] & 0x01) << 4) | (chunk[2] >> 4);
        uint8_t index4 = ((chunk[2] & 0x0F) << 1) | (chunk[3] >> 7);
        uint8_t index5 = (chunk[3] >> 2) & 0x1F;
        uint8_t index6 = ((chunk[3] & 0x03) << 3) | (chunk[4] >> 5);
        uint8_t index7 = chunk[4] & 0x1F;

        out[pos++] = base32_alphabet[index0];
        out[pos++] = base32_alphabet[index1];
        out[pos++] = base32_alphabet[index2];
        out[pos++] = base32_alphabet[index3];
        out[pos++] = base32_alphabet[index4];
        out[pos++] = base32_alphabet[index5];
        out[pos++] = base32_alphabet[index6];
        out[pos++] = base32_alphabet[index7];
    }

    if (rem)
    {
        uint8_t tail[5] = {0, 0, 0, 0, 0};
        for (size_t j = 0; j < rem; j++)
        {
            tail[j] = data[full_blocks * 5 + j];
        }
        uint8_t indices[8];
        indices[0] = tail[0] >> 3;
        if (rem == 1)
        {
            indices[1] = (tail[0] & 0x07) << 2;
        }
        else
        {
            indices[1] = ((tail[0] & 0x07) << 2) | (tail[1] >> 6);
            indices[2] = (tail[1] >> 1) & 0x1F;
            if (rem == 2)
            {
                indices[3] = (tail[1] & 0x01) << 4;
            }
            else
            {
                indices[3] = ((tail[1] & 0x01) << 4) | (tail[2] >> 4);
                indices[4] = ((tail[2] & 0x0F) << 1);
                if (rem == 4)
                {
                    indices[4] |= (tail[3] >> 7);
                    indices[5] = (tail[3] >> 2) & 0x1F;
                    indices[6] = ((tail[3] & 0x03) << 3) | (tail[4] >> 5);
                }
            }
        }
        size_t valid_chars;
        if (rem == 1)
        {
            valid_chars = 2;
        }
        else if (rem == 2)
        {
            valid_chars = 4;
        }
        else if (rem == 3)
        {
            valid_chars = 5;
        }
        else /* rem == 4 */
        {
            valid_chars = 7;
        }

        for (size_t j = 0; j < valid_chars; j++)
        {
            out[pos++] = base32_alphabet[indices[j]];
        }
    }

    out[pos] = '\0';
    return pos;
}

/**
 * @brief Decode a Base32 encoded string using lowercase letters.
 *
 * @param in The input Base32 encoded string.
 * @param data_len The length of the input encoded string.
 * @param out The buffer to store the decoded binary data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error
 *         code indicating a null pointer, insufficient buffer size, invalid
 *         input, or integer overflow.
 */
int multibase_base32_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
    size_t pos = 0;
    size_t i, j;

    if (!in || !out)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    if (data_len == 0)
    {
        return 0;
    }

    uint8_t decode_table[256];
    for (i = 0; i < 256; i++)
    {
        decode_table[i] = 0xFF;
    }
    for (i = 0; i < 26; i++)
    {
        decode_table[(unsigned char)('a' + i)] = i;
    }
    for (i = 0; i < 6; i++)
    {
        decode_table[(unsigned char)('2' + i)] = 26 + i;
    }

    size_t full_blocks = data_len / 8;
    size_t rem = data_len % 8;

    if (full_blocks > SIZE_MAX / 5)
    {
        return MULTIBASE_ERR_OVERFLOW;
    }
    size_t decoded_len = full_blocks * 5;

    if (rem)
    {
        size_t extra;
        if (rem == 2)
        {
            extra = 1;
        }
        else if (rem == 4)
        {
            extra = 2;
        }
        else if (rem == 5)
        {
            extra = 3;
        }
        else if (rem == 7)
        {
            extra = 4;
        }
        else
        {
            return MULTIBASE_ERR_INVALID_INPUT_LEN;
        }
        if (decoded_len > SIZE_MAX - extra)
        {
            return MULTIBASE_ERR_OVERFLOW;
        }
        decoded_len += extra;
    }

    if (decoded_len > out_len)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < full_blocks; i++)
    {
        const char *block = in + i * 8;
        uint8_t indices[8];
        for (j = 0; j < 8; j++)
        {
            uint8_t val = decode_table[(unsigned char)block[j]];
            if (val == 0xFF)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            indices[j] = val;
        }
        out[pos++] = (indices[0] << 3) | (indices[1] >> 2);
        out[pos++] = ((indices[1] & 0x03) << 6) | (indices[2] << 1) | (indices[3] >> 4);
        out[pos++] = ((indices[3] & 0x0F) << 4) | (indices[4] >> 1);
        out[pos++] = ((indices[4] & 0x01) << 7) | (indices[5] << 2) | (indices[6] >> 3);
        out[pos++] = ((indices[6] & 0x07) << 5) | indices[7];
    }

    if (rem)
    {
        uint8_t indices[8];
        for (j = 0; j < rem; j++)
        {
            uint8_t val = decode_table[(unsigned char)in[full_blocks * 8 + j]];
            if (val == 0xFF)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            indices[j] = val;
        }
        if (rem == 2)
        {
            out[pos++] = (indices[0] << 3) | (indices[1] >> 2);
        }
        else if (rem == 4)
        {
            out[pos++] = (indices[0] << 3) | (indices[1] >> 2);
            out[pos++] = ((indices[1] & 0x03) << 6) | (indices[2] << 1) | (indices[3] >> 4);
        }
        else if (rem == 5)
        {
            out[pos++] = (indices[0] << 3) | (indices[1] >> 2);
            out[pos++] = ((indices[1] & 0x03) << 6) | (indices[2] << 1) | (indices[3] >> 4);
            out[pos++] = ((indices[3] & 0x0F) << 4) | (indices[4] >> 1);
        }
        else if (rem == 7)
        {
            out[pos++] = (indices[0] << 3) | (indices[1] >> 2);
            out[pos++] = ((indices[1] & 0x03) << 6) | (indices[2] << 1) | (indices[3] >> 4);
            out[pos++] = ((indices[3] & 0x0F) << 4) | (indices[4] >> 1);
            out[pos++] = ((indices[4] & 0x01) << 7) | (indices[5] << 2) | (indices[6] >> 3);
        }
    }
    return pos;
}