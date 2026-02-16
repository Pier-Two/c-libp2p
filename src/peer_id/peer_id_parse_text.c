#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multibase/encoding/base16.h"
#include "multiformats/multibase/encoding/base16_upper.h"
#include "multiformats/multibase/encoding/base32.h"
#include "multiformats/multibase/encoding/base32_upper.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multibase/encoding/base64.h"
#include "multiformats/multibase/encoding/base64_url.h"
#include "multiformats/multibase/encoding/base64_url_pad.h"
#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id_internal.h"

static bool peer_id_size_add(size_t left, size_t right, size_t *sum)
{
    if ((sum == NULL) || (left > (SIZE_MAX - right)))
    {
        return false;
    }
    *sum = left + right;
    return true;
}

static multibase_t peer_id_base_from_prefix(char prefix)
{
    switch (prefix)
    {
    case BASE32_CHARACTER:
        return MULTIBASE_BASE32;
    case BASE32_UPPER_CHARACTER:
        return MULTIBASE_BASE32_UPPER;
    case BASE58_BTC_CHARACTER:
        return MULTIBASE_BASE58_BTC;
    case BASE64_CHARACTER:
        return MULTIBASE_BASE64;
    case BASE64_URL_CHARACTER:
        return MULTIBASE_BASE64_URL;
    case BASE64_URL_PAD_CHARACTER:
        return MULTIBASE_BASE64_URL_PAD;
    case BASE16_CHARACTER:
        return MULTIBASE_BASE16;
    case BASE16_UPPER_CHARACTER:
        return MULTIBASE_BASE16_UPPER;
    default:
        return (multibase_t)-1;
    }
}

static peer_id_error_t peer_id_decode_multibase(multibase_t base,
                                                 const char *text,
                                                 uint8_t **out_buf,
                                                 size_t *out_len)
{
    peer_id_error_t status;
    size_t text_len;
    uint8_t *decoded;
    ptrdiff_t decode_rc;

    status = PEER_ID_OK;
    text_len = (size_t)0U;
    decoded = NULL;
    decode_rc = (ptrdiff_t)0;

    if ((text == NULL) || (out_buf == NULL) || (out_len == NULL))
    {
        return PEER_ID_ERR_NULL_PTR;
    }

    *out_buf = NULL;
    *out_len = (size_t)0U;

    text_len = strlen(text);
    if (text_len == (size_t)0U)
    {
        return PEER_ID_ERR_INVALID_STRING;
    }

    decoded = (uint8_t *)malloc(text_len);
    if (decoded == NULL)
    {
        return PEER_ID_ERR_ALLOC;
    }

    decode_rc = multibase_decode(base, text, decoded, text_len);
    if ((decode_rc <= 0) || ((size_t)decode_rc > text_len))
    {
        free(decoded);
        return PEER_ID_ERR_INVALID_STRING;
    }

    *out_buf = decoded;
    *out_len = (size_t)decode_rc;
    return status;
}

static peer_id_error_t peer_id_parse_legacy_base58(const char *text, peer_id_t **out)
{
    peer_id_error_t status;
    size_t text_len;
    size_t prefixed_len;
    char *prefixed;
    uint8_t *decoded;
    size_t decoded_len;

    status = PEER_ID_OK;
    text_len = (size_t)0U;
    prefixed_len = (size_t)0U;
    prefixed = NULL;
    decoded = NULL;
    decoded_len = (size_t)0U;

    if ((text == NULL) || (out == NULL))
    {
        return PEER_ID_ERR_NULL_PTR;
    }

    text_len = strlen(text);
    if (text_len == (size_t)0U)
    {
        return PEER_ID_ERR_INVALID_STRING;
    }

    if ((text[0] != '1') && ((text_len < (size_t)2U) || (text[0] != 'Q') || (text[1] != 'm')))
    {
        return PEER_ID_ERR_INVALID_STRING;
    }

    if (peer_id_size_add(text_len, (size_t)2U, &prefixed_len) == false)
    {
        return PEER_ID_ERR_RANGE;
    }

    prefixed = (char *)malloc(prefixed_len);
    if (prefixed == NULL)
    {
        return PEER_ID_ERR_ALLOC;
    }

    prefixed[0] = BASE58_BTC_CHARACTER;
    (void)memcpy(prefixed + 1, text, text_len + (size_t)1U);

    status = peer_id_decode_multibase(MULTIBASE_BASE58_BTC, prefixed, &decoded, &decoded_len);
    if (status == PEER_ID_OK)
    {
        status = peer_id_new_from_multihash(decoded, decoded_len, out);
    }

    if (decoded != NULL)
    {
        free(decoded);
    }
    free(prefixed);

    return status;
}

static peer_id_error_t peer_id_parse_cid(const char *text, peer_id_t **out)
{
    peer_id_error_t status;
    multibase_t base;
    uint8_t *decoded;
    size_t decoded_len;
    size_t offset;
    uint64_t cid_version;
    size_t cid_version_size;
    uint64_t codec;
    size_t codec_size;
    unsigned_varint_err_t uv_status;

    status = PEER_ID_OK;
    base = (multibase_t)-1;
    decoded = NULL;
    decoded_len = (size_t)0U;
    offset = (size_t)0U;
    cid_version = (uint64_t)0U;
    cid_version_size = (size_t)0U;
    codec = (uint64_t)0U;
    codec_size = (size_t)0U;

    if ((text == NULL) || (out == NULL))
    {
        return PEER_ID_ERR_NULL_PTR;
    }

    base = peer_id_base_from_prefix(text[0]);
    if (base == (multibase_t)-1)
    {
        return PEER_ID_ERR_INVALID_STRING;
    }

    status = peer_id_decode_multibase(base, text, &decoded, &decoded_len);
    if (status != PEER_ID_OK)
    {
        return status;
    }

    uv_status = unsigned_varint_decode(decoded, decoded_len, &cid_version, &cid_version_size);
    if ((uv_status != UNSIGNED_VARINT_OK) || (cid_version != (uint64_t)MULTICODEC_CIDV1))
    {
        status = PEER_ID_ERR_INVALID_STRING;
    }
    else
    {
        offset += cid_version_size;
    }

    if (status == PEER_ID_OK)
    {
        uv_status = unsigned_varint_decode(decoded + offset, decoded_len - offset, &codec, &codec_size);
        if ((uv_status != UNSIGNED_VARINT_OK) || (codec != (uint64_t)MULTICODEC_LIBP2P_KEY))
        {
            status = PEER_ID_ERR_INVALID_STRING;
        }
        else
        {
            offset += codec_size;
            if (offset >= decoded_len)
            {
                status = PEER_ID_ERR_INVALID_STRING;
            }
        }
    }

    if (status == PEER_ID_OK)
    {
        status = peer_id_new_from_multihash(decoded + offset, decoded_len - offset, out);
    }

    if (decoded != NULL)
    {
        free(decoded);
    }

    return status;
}

peer_id_error_t peer_id_internal_text_parse(const char *text, peer_id_t **out)
{
    if ((text == NULL) || (out == NULL))
    {
        return PEER_ID_ERR_NULL_PTR;
    }

    *out = NULL;

    if (text[0] == '\0')
    {
        return PEER_ID_ERR_INVALID_STRING;
    }

    if ((text[0] == '1') || ((text[0] == 'Q') && (text[1] == 'm')))
    {
        return peer_id_parse_legacy_base58(text, out);
    }

    if (peer_id_base_from_prefix(text[0]) != (multibase_t)-1)
    {
        return peer_id_parse_cid(text, out);
    }

    return PEER_ID_ERR_INVALID_STRING;
}

peer_id_error_t peer_id_internal_text_write(const peer_id_t *pid,
                                            peer_id_text_format_t fmt,
                                            char *out,
                                            size_t out_cap,
                                            size_t *out_len)
{
    peer_id_error_t status;
    ptrdiff_t mb_rc;
    size_t written;

    status = PEER_ID_OK;
    mb_rc = (ptrdiff_t)0;
    written = (size_t)0U;

    if ((pid == NULL) || (out == NULL) || (out_len == NULL))
    {
        return PEER_ID_ERR_NULL_PTR;
    }

    *out_len = (size_t)0U;
    if (out_cap == (size_t)0U)
    {
        return PEER_ID_ERR_BUFFER_TOO_SMALL;
    }
    out[0] = '\0';

    if ((pid->multihash == NULL) || (pid->multihash_len == (size_t)0U))
    {
        return PEER_ID_ERR_INVALID_INPUT;
    }

    if (fmt == PEER_ID_TEXT_LEGACY_BASE58)
    {
        mb_rc = multibase_encode(MULTIBASE_BASE58_BTC, pid->multihash, pid->multihash_len, out, out_cap);
        if ((mb_rc <= 1) || (out[0] != BASE58_BTC_CHARACTER))
        {
            return PEER_ID_ERR_ENCODING;
        }
        written = (size_t)mb_rc - (size_t)1U;
        (void)memmove(out, out + 1, written + (size_t)1U);
        *out_len = written;
        return PEER_ID_OK;
    }

    if (fmt == PEER_ID_TEXT_CIDV1_BASE32)
    {
        uint8_t codec_buf[UNSIGNED_VARINT_MAX_ENCODED_SIZE];
        size_t codec_size;
        size_t cid_len;
        uint8_t *cid;

        codec_size = (size_t)0U;
        cid_len = (size_t)0U;
        cid = NULL;

        if (unsigned_varint_encode((uint64_t)MULTICODEC_LIBP2P_KEY, codec_buf, sizeof(codec_buf), &codec_size) !=
            UNSIGNED_VARINT_OK)
        {
            return PEER_ID_ERR_ENCODING;
        }

        if ((peer_id_size_add((size_t)1U, codec_size, &cid_len) == false) ||
            (peer_id_size_add(cid_len, pid->multihash_len, &cid_len) == false))
        {
            return PEER_ID_ERR_RANGE;
        }

        cid = (uint8_t *)malloc(cid_len);
        if (cid == NULL)
        {
            return PEER_ID_ERR_ALLOC;
        }

        cid[0] = (uint8_t)MULTICODEC_CIDV1;
        (void)memcpy(cid + 1, codec_buf, codec_size);
        (void)memcpy(cid + 1 + codec_size, pid->multihash, pid->multihash_len);

        mb_rc = multibase_encode(MULTIBASE_BASE32, cid, cid_len, out, out_cap);
        free(cid);
        if (mb_rc <= 0)
        {
            return PEER_ID_ERR_ENCODING;
        }
        *out_len = (size_t)mb_rc;
        return PEER_ID_OK;
    }

    status = PEER_ID_ERR_INVALID_INPUT;
    return status;
}
