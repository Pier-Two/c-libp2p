#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/cid/cid_v1.h"
#include "multiformats/multibase/encoding/base16.h"
#include "multiformats/multibase/encoding/base32.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multibase/encoding/base64.h"
#include "multiformats/multibase/encoding/base64_url.h"
#include "multiformats/multibase/encoding/base64_url_pad.h"
#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multicodec/multicodec_table.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

/* Maximum size of a multihash in bytes. */
#define CIDV1_MAX_DIGEST (4U * 1024U * 1024U)

static inline int add_overflow_size(size_t a, size_t b, size_t *out)
{
    if (a > SIZE_MAX - b)
    {
        return 1;
    }
    *out = a + b;
    return 0;
}

static inline int mul_overflow_size(size_t a, size_t b, size_t *out)
{
    if (a != 0 && b > SIZE_MAX / a)
    {
        return 1;
    }
    *out = a * b;
    return 0;
}

static int detect_multibase(const char *str, multibase_t *base_out)
{
    if (str == NULL || base_out == NULL || *str == '\0')
    {
        return CIDV1_ERROR_INVALID_ARG;
    }

    switch (str[0])
    {
        case BASE58_BTC_CHARACTER:
            *base_out = MULTIBASE_BASE58_BTC;
            return CIDV1_SUCCESS;
        case BASE16_CHARACTER:
            *base_out = MULTIBASE_BASE16;
            return CIDV1_SUCCESS;
        case BASE32_CHARACTER:
            *base_out = MULTIBASE_BASE32;
            return CIDV1_SUCCESS;
        case BASE64_CHARACTER:
            *base_out = MULTIBASE_BASE64;
            return CIDV1_SUCCESS;
        case BASE64_URL_CHARACTER:
            *base_out = MULTIBASE_BASE64_URL;
            return CIDV1_SUCCESS;
        case BASE64_URL_PAD_CHARACTER:
            *base_out = MULTIBASE_BASE64_URL_PAD;
            return CIDV1_SUCCESS;
        default:
            return CIDV1_ERROR_DECODE_FAILURE;
    }
}

static const char *get_multibase_name(multibase_t base)
{
    switch (base)
    {
        case MULTIBASE_BASE16:
            return "base16";
        case MULTIBASE_BASE16_UPPER:
            return "base16upper";
        case MULTIBASE_BASE32:
            return "base32";
        case MULTIBASE_BASE32_UPPER:
            return "base32upper";
        case MULTIBASE_BASE58_BTC:
            return "base58btc";
        case MULTIBASE_BASE64:
            return "base64";
        case MULTIBASE_BASE64_URL:
            return "base64url";
        case MULTIBASE_BASE64_URL_PAD:
            return "base64urlpad";
        default:
            return "unknown";
    }
}

static const char *get_multicodec_name(uint64_t code)
{
    for (size_t i = 0; i < multicodec_table_len; i++)
    {
        if (multicodec_table[i].code == code)
        {
            return multicodec_table[i].name;
        }
    }
    return "unknown";
}

static ssize_t multihash_to_human(const uint8_t *mh, size_t mh_size, char *out, size_t out_len)
{
    if (mh == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    uint64_t hash_code = 0;
    size_t read = 0;
    if (unsigned_varint_decode(mh, mh_size, &hash_code, &read) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }
    if (read >= mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    uint64_t digest_len = 0;
    size_t read2 = 0;
    if (unsigned_varint_decode(mh + read, mh_size - read, &digest_len, &read2) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    if (digest_len > CIDV1_MAX_DIGEST)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    size_t header_size = read + read2;
    if (header_size + digest_len != mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    size_t hex_len = 0;
    if (mul_overflow_size((size_t)digest_len, 2, &hex_len))
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }

    char *hex_str = (char *)malloc(hex_len + 1);
    if (!hex_str)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    for (size_t i = 0; i < digest_len; i++)
    {
        static const char lut[] = "0123456789abcdef";
        uint8_t b = mh[header_size + i];
        hex_str[i * 2] = lut[b >> 4];
        hex_str[i * 2 + 1] = lut[b & 0x0F];
    }
    hex_str[hex_len] = '\0';
    const char *hash_name = get_multicodec_name(hash_code);
    int written = snprintf(out, out_len, "%s-%s", hash_name, hex_str);
    free(hex_str);

    if (written < 0 || (size_t)written >= out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    return (ssize_t)written;
}

static int compute_mh_human_size(const uint8_t *mh, size_t mh_size, size_t *out_size)
{
    if (mh == NULL || out_size == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    uint64_t hash_code = 0;
    size_t read = 0;
    if (unsigned_varint_decode(mh, mh_size, &hash_code, &read) != UNSIGNED_VARINT_OK || read >= mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    uint64_t digest_len = 0;
    size_t read2 = 0;
    if (unsigned_varint_decode(mh + read, mh_size - read, &digest_len, &read2) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    if (digest_len > CIDV1_MAX_DIGEST)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    size_t header_size = read + read2;
    if (header_size + digest_len != mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    size_t name_len = strlen(get_multicodec_name(hash_code));
    size_t hex_len = 0;
    if (mul_overflow_size((size_t)digest_len, 2, &hex_len) || add_overflow_size(name_len + 1, hex_len, out_size) ||
        add_overflow_size(*out_size, 1, out_size))
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }

    return CIDV1_SUCCESS;
}

int cid_v1_init(cid_v1_t *cid, uint64_t content_codec, const uint8_t *mh_data, size_t mh_size)
{
    if (cid == NULL || (mh_data == NULL && mh_size > 0))
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    cid->version = 1;
    cid->codec = content_codec;
    cid->multihash = NULL;
    cid->multihash_size = 0;

    if (mh_size > 0)
    {
        cid->multihash = (uint8_t *)malloc(mh_size);
        if (!cid->multihash)
        {
            return CIDV1_ERROR_ALLOCATION_FAILED;
        }
        memcpy(cid->multihash, mh_data, mh_size);
        cid->multihash_size = mh_size;
    }

    return CIDV1_SUCCESS;
}

/**
 * @brief Free the resources associated with a CIDv1 structure.
 *
 * @param cid Pointer to the CIDv1 structure to free.
 */
void cid_v1_free(cid_v1_t *cid)
{
    if (cid != NULL)
    {
        if (cid->multihash != NULL)
        {
            free(cid->multihash);
            cid->multihash = NULL;
        }
        cid->multihash_size = 0;
    }
}

ssize_t cid_v1_from_bytes(cid_v1_t *cid, const uint8_t *data, size_t data_len)
{
    if (cid == NULL || data == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t offset = 0;
    uint64_t version = 0;
    size_t read = 0;
    if (unsigned_varint_decode(data, data_len, &version, &read) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }
    offset += read;
    if (version != 1)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    uint64_t codec = 0;
    size_t read2 = 0;
    if (unsigned_varint_decode(data + offset, data_len - offset, &codec, &read2) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }
    offset += read2;
    size_t mh_size = data_len - offset;
    if (mh_size == 0)
    {
        return CIDV1_ERROR_INVALID_ARG;
    }

    uint8_t *mh = (uint8_t *)malloc(mh_size);
    if (!mh)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }
    memcpy(mh, data + offset, mh_size);

    cid->version = version;
    cid->codec = codec;
    cid->multihash = mh;
    cid->multihash_size = mh_size;

    return (ssize_t)(offset + mh_size);
}

ssize_t cid_v1_to_bytes(const cid_v1_t *cid, uint8_t *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t idx = 0;
    size_t written = 0;
    size_t ver_size = unsigned_varint_size(cid->version);

    if (idx + ver_size > out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    if (unsigned_varint_encode(cid->version, out + idx, out_len - idx, &written) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_ENCODE_FAILURE;
    }
    idx += written;
    size_t codec_size = unsigned_varint_size(cid->codec);
    if (idx + codec_size > out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    if (unsigned_varint_encode(cid->codec, out + idx, out_len - idx, &written) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_ENCODE_FAILURE;
    }
    idx += written;
    if (idx + cid->multihash_size > out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(out + idx, cid->multihash, cid->multihash_size);
    idx += cid->multihash_size;

    if (idx > INT_MAX)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    return (ssize_t)idx;
}

ssize_t cid_v1_to_string(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t version_size = unsigned_varint_size(cid->version);
    size_t codec_size = unsigned_varint_size(cid->codec);
    size_t total_bin_size = 0;

    if (add_overflow_size(version_size, codec_size, &total_bin_size) || add_overflow_size(total_bin_size, cid->multihash_size, &total_bin_size))
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t *tmp = (uint8_t *)malloc(total_bin_size);
    if (!tmp)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    ssize_t bin_len = cid_v1_to_bytes(cid, tmp, total_bin_size);
    if (bin_len < 0)
    {
        free(tmp);
        return bin_len;
    }

    ssize_t str_len = multibase_encode(base, tmp, (size_t)bin_len, out, out_len);
    free(tmp);

    if (str_len < 0)
    {
        return CIDV1_ERROR_ENCODE_FAILURE;
    }
    return str_len;
}

ssize_t cid_v1_from_string(cid_v1_t *cid, const char *str)
{
    if (cid == NULL || str == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    multibase_t base = 0;
    int err = detect_multibase(str, &base);
    if (err != CIDV1_SUCCESS)
    {
        return err;
    }

    size_t str_len = strlen(str);
    uint8_t *bin = (uint8_t *)malloc(str_len);
    if (!bin)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    ssize_t decoded_len = multibase_decode(base, str, bin, str_len);
    if (decoded_len < 0)
    {
        free(bin);
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    ssize_t ret = cid_v1_from_bytes(cid, bin, (size_t)decoded_len);
    free(bin);
    return ret;
}

ssize_t cid_v1_to_human(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    const char *mb_name = get_multibase_name(base);
    const char *codec_name = get_multicodec_name(cid->codec);

    size_t mh_human_size = 0;
    int err = compute_mh_human_size(cid->multihash, cid->multihash_size, &mh_human_size);
    if (err < 0)
    {
        return err;
    }

    char *mh_human = (char *)malloc(mh_human_size);
    if (!mh_human)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    ssize_t hlen = multihash_to_human(cid->multihash, cid->multihash_size, mh_human, mh_human_size);
    if (hlen < 0)
    {
        free(mh_human);
        return hlen;
    }

    int written = snprintf(out, out_len, "%s - cidv1 - %s - %s", mb_name, codec_name, mh_human);
    free(mh_human);

    if (written < 0 || (size_t)written >= out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }

    return (ssize_t)written;
}