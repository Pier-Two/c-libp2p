#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/lpmsg.h"
#include "libp2p/protocol_introspect.h"
#include "libp2p/protocol_listen.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/identify/protocol_identify.h"

#define IDENTIFY_PUBLIC_KEY_TAG 0x0A
#define IDENTIFY_LISTEN_ADDRS_TAG 0x12
#define IDENTIFY_PROTOCOLS_TAG 0x1A
#define IDENTIFY_OBSERVED_ADDR_TAG 0x22
#define IDENTIFY_PROTOCOL_VERSION_TAG 0x2A
#define IDENTIFY_AGENT_VERSION_TAG 0x32

static inline int varint_is_minimal(uint64_t v, size_t len)
{
    uint8_t tmp[10];
    size_t min_len;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &min_len) != UNSIGNED_VARINT_OK)
        return 0;
    return min_len == len;
}

int libp2p_identify_message_decode(const uint8_t *buf, size_t len, libp2p_identify_t **out_msg)
{
    if (!buf || !out_msg)
        return -1;
    libp2p_identify_t *msg = calloc(1, sizeof(*msg));
    if (!msg)
        return -1;
    size_t off = 0, sz = 0;
    while (off < len)
    {
        uint64_t tag = 0, flen = 0;
        if (unsigned_varint_decode(buf + off, len - off, &tag, &sz) != UNSIGNED_VARINT_OK || !varint_is_minimal(tag, sz))
            goto fail;
        off += sz;
        if (unsigned_varint_decode(buf + off, len - off, &flen, &sz) != UNSIGNED_VARINT_OK || flen > len - off - sz || !varint_is_minimal(flen, sz))
            goto fail;
        off += sz;
        const uint8_t *field = buf + off;
        off += (size_t)flen;
        switch (tag)
        {
            case IDENTIFY_PUBLIC_KEY_TAG:
                msg->public_key = malloc(flen);
                if (!msg->public_key)
                    goto fail;
                memcpy(msg->public_key, field, flen);
                msg->public_key_len = (size_t)flen;
                break;
            case IDENTIFY_LISTEN_ADDRS_TAG:
            {
                uint8_t **addrs = realloc(msg->listen_addrs, (msg->num_listen_addrs + 1) * sizeof(uint8_t *));
                size_t *lens = realloc(msg->listen_addrs_lens, (msg->num_listen_addrs + 1) * sizeof(size_t));
                if (!addrs || !lens)
                {
                    free(addrs);
                    free(lens);
                    goto fail;
                }
                msg->listen_addrs = addrs;
                msg->listen_addrs_lens = lens;
                uint8_t *copy = malloc(flen);
                if (!copy)
                    goto fail;
                memcpy(copy, field, flen);
                msg->listen_addrs[msg->num_listen_addrs] = copy;
                msg->listen_addrs_lens[msg->num_listen_addrs] = (size_t)flen;
                msg->num_listen_addrs++;
                break;
            }
            case IDENTIFY_PROTOCOLS_TAG:
            {
                char **protos = realloc(msg->protocols, (msg->num_protocols + 1) * sizeof(char *));
                if (!protos)
                    goto fail;
                msg->protocols = protos;
                char *copy = malloc(flen + 1);
                if (!copy)
                    goto fail;
                memcpy(copy, field, flen);
                copy[flen] = '\0';
                msg->protocols[msg->num_protocols] = copy;
                msg->num_protocols++;
                break;
            }
            case IDENTIFY_OBSERVED_ADDR_TAG:
                msg->observed_addr = malloc(flen);
                if (!msg->observed_addr)
                    goto fail;
                memcpy(msg->observed_addr, field, flen);
                msg->observed_addr_len = (size_t)flen;
                break;
            case IDENTIFY_PROTOCOL_VERSION_TAG:
                msg->protocol_version = malloc(flen + 1);
                if (!msg->protocol_version)
                    goto fail;
                memcpy(msg->protocol_version, field, flen);
                msg->protocol_version[flen] = '\0';
                break;
            case IDENTIFY_AGENT_VERSION_TAG:
                msg->agent_version = malloc(flen + 1);
                if (!msg->agent_version)
                    goto fail;
                memcpy(msg->agent_version, field, flen);
                msg->agent_version[flen] = '\0';
                break;
            default:
                /* unknown field - ignore */
                break;
        }
    }
    *out_msg = msg;
    return 0;
fail:
    libp2p_identify_free(msg);
    return -1;
}

int libp2p_identify_message_encode(const libp2p_identify_t *msg, uint8_t **out_buf, size_t *out_len)
{
    if (!msg || !out_buf || !out_len)
        return -1;

    *out_buf = NULL;
    *out_len = 0;

    // Calculate total size needed
    size_t total_size = 0;

    // Field 1: public_key
    if (msg->public_key && msg->public_key_len > 0)
    {
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(msg->public_key_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + msg->public_key_len;
    }

    // Field 2: listen_addrs (repeated)
    for (size_t i = 0; i < msg->num_listen_addrs; i++)
    {
        if (msg->listen_addrs[i] && msg->listen_addrs_lens[i] > 0)
        {
            total_size += 1; // tag
            size_t len_varint_size = 0;
            uint8_t tmp[10];
            if (unsigned_varint_encode(msg->listen_addrs_lens[i], tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
                return -1;
            total_size += len_varint_size + msg->listen_addrs_lens[i];
        }
    }

    // Field 3: protocols (repeated)
    for (size_t i = 0; i < msg->num_protocols; i++)
    {
        if (msg->protocols[i])
        {
            size_t proto_len = strlen(msg->protocols[i]);
            total_size += 1; // tag
            size_t len_varint_size = 0;
            uint8_t tmp[10];
            if (unsigned_varint_encode(proto_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
                return -1;
            total_size += len_varint_size + proto_len;
        }
    }

    // Field 4: observed_addr
    if (msg->observed_addr && msg->observed_addr_len > 0)
    {
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(msg->observed_addr_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + msg->observed_addr_len;
    }

    // Field 5: protocol_version
    if (msg->protocol_version)
    {
        size_t proto_version_len = strlen(msg->protocol_version);
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(proto_version_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + proto_version_len;
    }

    // Field 6: agent_version
    if (msg->agent_version)
    {
        size_t agent_version_len = strlen(msg->agent_version);
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(agent_version_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + agent_version_len;
    }

    if (total_size == 0)
    {
        // Empty message
        *out_buf = malloc(1);
        if (!*out_buf)
            return -1;
        *out_len = 0;
        return 0;
    }

    // Allocate buffer
    uint8_t *buf = malloc(total_size);
    if (!buf)
        return -1;

    size_t offset = 0;

    // Encode Field 1: public_key
    if (msg->public_key && msg->public_key_len > 0)
    {
        buf[offset++] = IDENTIFY_PUBLIC_KEY_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(msg->public_key_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->public_key, msg->public_key_len);
        offset += msg->public_key_len;
    }

    // Encode Field 2: listen_addrs (repeated)
    for (size_t i = 0; i < msg->num_listen_addrs; i++)
    {
        if (msg->listen_addrs[i] && msg->listen_addrs_lens[i] > 0)
        {
            buf[offset++] = IDENTIFY_LISTEN_ADDRS_TAG;
            size_t len_varint_size = 0;
            if (unsigned_varint_encode(msg->listen_addrs_lens[i], buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
            {
                free(buf);
                return -1;
            }
            offset += len_varint_size;
            memcpy(buf + offset, msg->listen_addrs[i], msg->listen_addrs_lens[i]);
            offset += msg->listen_addrs_lens[i];
        }
    }

    // Encode Field 3: protocols (repeated)
    for (size_t i = 0; i < msg->num_protocols; i++)
    {
        if (msg->protocols[i])
        {
            size_t proto_len = strlen(msg->protocols[i]);
            buf[offset++] = IDENTIFY_PROTOCOLS_TAG;
            size_t len_varint_size = 0;
            if (unsigned_varint_encode(proto_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
            {
                free(buf);
                return -1;
            }
            offset += len_varint_size;
            memcpy(buf + offset, msg->protocols[i], proto_len);
            offset += proto_len;
        }
    }

    // Encode Field 4: observed_addr
    if (msg->observed_addr && msg->observed_addr_len > 0)
    {
        buf[offset++] = IDENTIFY_OBSERVED_ADDR_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(msg->observed_addr_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->observed_addr, msg->observed_addr_len);
        offset += msg->observed_addr_len;
    }

    // Encode Field 5: protocol_version
    if (msg->protocol_version)
    {
        size_t proto_version_len = strlen(msg->protocol_version);
        buf[offset++] = IDENTIFY_PROTOCOL_VERSION_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(proto_version_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->protocol_version, proto_version_len);
        offset += proto_version_len;
    }

    // Encode Field 6: agent_version
    if (msg->agent_version)
    {
        size_t agent_version_len = strlen(msg->agent_version);
        buf[offset++] = IDENTIFY_AGENT_VERSION_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(agent_version_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->agent_version, agent_version_len);
        offset += agent_version_len;
    }

    *out_buf = buf;
    *out_len = offset;
    return 0;
}

void libp2p_identify_free(libp2p_identify_t *msg)
{
    if (msg)
    {
        if (msg->public_key)
            free(msg->public_key);
        if (msg->listen_addrs)
        {
            for (size_t i = 0; i < msg->num_listen_addrs; i++)
            {
                if (msg->listen_addrs[i])
                    free(msg->listen_addrs[i]);
            }
            free(msg->listen_addrs);
        }
        if (msg->listen_addrs_lens)
            free(msg->listen_addrs_lens);
        if (msg->observed_addr)
            free(msg->observed_addr);
        if (msg->protocols)
        {
            for (size_t i = 0; i < msg->num_protocols; i++)
            {
                if (msg->protocols[i])
                    free(msg->protocols[i]);
            }
            free(msg->protocols);
        }
        if (msg->protocol_version)
            free(msg->protocol_version);
        if (msg->agent_version)
            free(msg->agent_version);
        free(msg);
    }
}

/* ===== Local Length-Prefixed Message Functions via generic stream ===== */

/* The handler and dial helpers using the legacy protocol handler API were removed.
 * Identify now provides only message encode/decode utilities.
 */

/* Minimal Identify service moved into libp2p_unified (src/host/identify_service.c) */
