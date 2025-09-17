#include "protocol/noise/protocol_noise_extensions.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include <stdlib.h>
#include <string.h>

static inline int varint_is_minimal(uint64_t v, size_t len)
{
    uint8_t tmp[10];
    size_t min_len;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &min_len) != UNSIGNED_VARINT_OK)
        return 0;
    return min_len == len;
}

int parse_noise_extensions(const uint8_t *buf, size_t len, noise_extensions_t **out_ext)
{
    if (!buf || !out_ext)
        return -1;
    noise_extensions_t *ext = calloc(1, sizeof(*ext));
    if (!ext)
        return -1;
    size_t offset = 0, len_sz = 0;
    while (offset < len)
    {
        uint64_t hdr = 0, fld_len = 0;
        if (unsigned_varint_decode(buf + offset, len - offset, &hdr, &len_sz) != UNSIGNED_VARINT_OK || !varint_is_minimal(hdr, len_sz))
        {
            noise_extensions_free(ext);
            return -1;
        }
        offset += len_sz;
        if (unsigned_varint_decode(buf + offset, len - offset, &fld_len, &len_sz) != UNSIGNED_VARINT_OK || fld_len > len - offset - len_sz ||
            !varint_is_minimal(fld_len, len_sz))
        {
            noise_extensions_free(ext);
            return -1;
        }
        offset += len_sz;
        const uint8_t *fld = buf + offset;
        offset += (size_t)fld_len;
        if (hdr == NOISE_EXT_WEBTRANSPORT_CERTHASHES)
        { /* webtransport_certhashes */
            uint8_t *copy = malloc(fld_len);
            if (!copy)
            {
                noise_extensions_free(ext);
                return -1;
            }
            memcpy(copy, fld, fld_len);
            uint8_t **hashes = realloc(ext->webtransport_certhashes, (ext->num_webtransport_certhashes + 1) * sizeof(uint8_t *));
            size_t *lens = realloc(ext->webtransport_certhashes_lens, (ext->num_webtransport_certhashes + 1) * sizeof(size_t));
            if (!hashes || !lens)
            {
                free(copy);
                free(hashes);
                free(lens);
                noise_extensions_free(ext);
                return -1;
            }
            ext->webtransport_certhashes = hashes;
            ext->webtransport_certhashes_lens = lens;
            ext->webtransport_certhashes[ext->num_webtransport_certhashes] = copy;
            ext->webtransport_certhashes_lens[ext->num_webtransport_certhashes] = (size_t)fld_len;
            ext->num_webtransport_certhashes++;
        }
        else if (hdr == NOISE_EXT_STREAM_MUXERS)
        { /* stream_muxers */
            char *copy = malloc(fld_len + 1);
            if (!copy)
            {
                noise_extensions_free(ext);
                return -1;
            }
            memcpy(copy, fld, fld_len);
            copy[fld_len] = '\0';
            char **muxers = realloc(ext->stream_muxers, (ext->num_stream_muxers + 1) * sizeof(char *));
            if (!muxers)
            {
                free(copy);
                noise_extensions_free(ext);
                return -1;
            }
            ext->stream_muxers = muxers;
            ext->stream_muxers[ext->num_stream_muxers] = copy;
            ext->num_stream_muxers++;
        }
        else
        {
            if (hdr <= NOISE_EXT_REGISTRY_MAX)
            {
                noise_extensions_free(ext);
                return -1; /* unknown but reserved */
            }
            /* Unknown experimental field - ignore */
        }
    }
    *out_ext = ext;
    return 0;
}

void noise_extensions_free(noise_extensions_t *ext)
{
    if (!ext)
        return;
    for (size_t i = 0; i < ext->num_webtransport_certhashes; i++)
        free(ext->webtransport_certhashes[i]);
    free(ext->webtransport_certhashes);
    free(ext->webtransport_certhashes_lens);
    for (size_t i = 0; i < ext->num_stream_muxers; i++)
        free(ext->stream_muxers[i]);
    free(ext->stream_muxers);
    free(ext);
}
