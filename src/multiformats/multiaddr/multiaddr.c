#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"

#ifdef _WIN32
#include <Ws2tcpip.h> /* for inet_pton on Windows */
#define strtok_r(str, delim, saveptr) strtok_s((str), (delim), (saveptr))
#else
#include <arpa/inet.h> /* for inet_pton, inet_ntop */
#endif

/**
 * @brief Structure representing a multiaddr.
 */
struct multiaddr_s
{
    size_t size;    /* Number of bytes in 'bytes' */
    uint8_t *bytes; /* The raw, serialized multiaddr data */
};

/**
 * @brief Enumeration for protocol address lengths.
 */
typedef enum
{
    ADDR_LEN_UNKNOWN = -1, /* not recognized in this implementation */
    ADDR_LEN_VARIABLE = -2 /* address length is variable */
} protocol_len_e;

/**
 * @brief Retrieve the address length for a given protocol code.
 *
 * @param code The protocol code as a 64-bit unsigned integer.
 * @return The number of bytes for the protocol's address, ADDR_LEN_VARIABLE for
 * variable length, or ADDR_LEN_UNKNOWN if the protocol is unrecognized.
 */
static int get_protocol_addr_len(uint64_t code)
{
    switch (code)
    {
        case MULTICODEC_IP4:
        {
            return 4;
        } /* 4 bytes for IPv4 */
        case MULTICODEC_IP6:
        {
            return 16;
        } /* 16 bytes for IPv6 */
        case MULTICODEC_TCP:
        case MULTICODEC_UDP:
        {
            return 2;
        } /* 2 bytes for port */
        case MULTICODEC_WS:
        case MULTICODEC_WSS:
        case MULTICODEC_QUIC:
        case MULTICODEC_QUIC_V1:
        case MULTICODEC_P2P_CIRCUIT:
        {
            return 0;
        } /* no address bytes */
        case MULTICODEC_DNS:
        case MULTICODEC_DNS4:
        case MULTICODEC_DNS6:
        case MULTICODEC_DNSADDR:
        case MULTICODEC_P2P:
        case MULTICODEC_IPFS: /* legacy alias for /p2p/ */
        {
            return ADDR_LEN_VARIABLE;
        }
        default:
        {
            return ADDR_LEN_UNKNOWN;
        }
    }
}

/**
 * @brief Structure representing a buffer for multiaddr data.
 */
typedef struct
{
    uint8_t *data;
    size_t size;
    size_t capacity;
} ma_buf_t;

/**
 * @brief Initialize a multiaddr buffer.
 *
 * @param b Pointer to the ma_buf_t structure to initialize.
 */
static void ma_buf_init(ma_buf_t *b)
{
    b->data = NULL;
    b->size = 0;
    b->capacity = 0;
}

/**
 * @brief Free the memory allocated for a multiaddr buffer.
 *
 * @param b Pointer to the ma_buf_t structure to free.
 */
static void ma_buf_free(ma_buf_t *b)
{
    if (b->data)
    {
        free(b->data);
    }
    b->data = NULL;
    b->size = 0;
    b->capacity = 0;
}

/**
 * @brief Ensure the buffer has enough capacity for additional data.
 *
 * @param b Pointer to the ma_buf_t structure.
 * @param needed The additional number of bytes needed.
 * @return 0 on success, or -1 on memory allocation failure.
 */
static int ma_buf_ensure(ma_buf_t *b, size_t needed)
{
    if (b->size + needed <= b->capacity)
    {
        return 0;
    }
    size_t newcap = (b->capacity > 0) ? b->capacity : 32;
    while (newcap < b->size + needed)
    {
        newcap *= 2;
    }
    uint8_t *tmp = (uint8_t *)realloc(b->data, newcap);
    if (!tmp)
    {
        return -1;
    }
    b->data = tmp;
    b->capacity = newcap;
    return 0;
}

/**
 * @brief Append data to the multiaddr buffer.
 *
 * @param b Pointer to the ma_buf_t structure.
 * @param src Pointer to the source data to append.
 * @param n Number of bytes to append.
 * @return 0 on success, or -1 on failure.
 */
static int ma_buf_append(ma_buf_t *b, const uint8_t *src, size_t n)
{
    if (ma_buf_ensure(b, n) < 0)
    {
        return -1;
    }
    memcpy(b->data + b->size, src, n);
    b->size += n;
    return 0;
}

/**
 * @brief Append a single byte to the multiaddr buffer.
 *
 * This function appends a single byte to the buffer, ensuring that the buffer
 * has enough capacity.
 *
 * @param b Pointer to the ma_buf_t structure.
 * @param c The byte to append.
 * @return 0 on success, or -1 on failure.
 */
static int ma_buf_append_byte(ma_buf_t *b, uint8_t c)
{
    if (ma_buf_ensure(b, 1) < 0)
    {
        return -1;
    }
    b->data[b->size++] = c;
    return 0;
}

/**
 * @brief Append a varint encoded 64-bit unsigned integer to the multiaddr
 * buffer.
 *
 * @param b Pointer to the ma_buf_t structure.
 * @param val The 64-bit unsigned integer to encode and append.
 * @return 0 on success, or -1 on failure.
 */
static int ma_buf_append_varint(ma_buf_t *b, uint64_t val)
{
    uint8_t tmp[10];
    size_t written = 0;
    unsigned_varint_err_t ret = unsigned_varint_encode(val, tmp, sizeof(tmp), &written);
    if (ret != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    return ma_buf_append(b, tmp, written);
}

/**
 * @brief Validate the structure of a multiaddr byte array.
 *
 * @param bytes Pointer to the multiaddr byte array.
 * @param len Length of the byte array.
 * @return MULTIADDR_SUCCESS if valid, or an error code (e.g.,
 * MULTIADDR_ERR_INVALID_DATA) on failure.
 */
static int validate_multiaddr_bytes(const uint8_t *bytes, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(bytes + offset, len - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        offset += csize;

        const char *proto_name = multicodec_name_from_code(code);
        if (!proto_name)
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }

        int addr_len = get_protocol_addr_len(code);
        if (addr_len == ADDR_LEN_UNKNOWN)
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
        else if (addr_len >= 0)
        {
            if (offset + (size_t)addr_len > len)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += addr_len;
        }
        else
        {
            uint64_t addr_size = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(bytes + offset, len - offset, &addr_size, &csize2) != UNSIGNED_VARINT_OK)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += csize2;
            if (offset + addr_size > len)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += addr_size;
        }
    }
    if (offset != len)
    {
        return MULTIADDR_ERR_INVALID_DATA;
    }
    return MULTIADDR_SUCCESS;
}

/**
 * @brief Parse an IPv4 address string into a 4-byte representation.
 *
 * @param addr_str The IPv4 address string.
 * @param out Output array of 4 bytes to store the parsed address.
 * @return 0 on success, or -1 if parsing fails.
 */
static int parse_ip4(const char *addr_str, uint8_t out[4])
{
    int parts[4];
    if (sscanf(addr_str, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]) != 4)
    {
        return -1;
    }
    for (int i = 0; i < 4; i++)
    {
        if (parts[i] < 0 || parts[i] > 255)
        {
            return -1;
        }
        out[i] = (uint8_t)parts[i];
    }
    return 0;
}

/**
 * @brief Parse an IPv6 address string into a 16-byte representation.
 *
 * @param addr_str The IPv6 address string.
 * @param out Output array of 16 bytes to store the parsed address.
 * @return 0 on success, or -1 if parsing fails.
 */
static int parse_ip6(const char *addr_str, uint8_t out[16])
{
    if (inet_pton(AF_INET6, addr_str, out) == 1)
    {
        return 0;
    }
    return -1;
}

/**
 * @brief Parse a port number string into a 2-byte representation.
 *
 * @param addr_str The port number string.
 * @param out Output array of 2 bytes to store the parsed port.
 * @return 0 on success, or -1 if parsing fails.
 */
static int parse_port(const char *addr_str, uint8_t out[2])
{
    char *endptr = NULL;
    long val = strtol(addr_str, &endptr, 10);
    if (!endptr || *endptr != '\0' || val < 0 || val > 65535)
    {
        return -1;
    }
    out[0] = (uint8_t)((val >> 8) & 0xFF);
    out[1] = (uint8_t)(val & 0xFF);
    return 0;
}

/**
 * @brief Parse a peer-to-peer identifier string into its binary representation.
 *
 * @param id_str The peer-to-peer identifier string.
 * @param out_buf Buffer to store the decoded identifier.
 * @param out_len Pointer to a variable holding the size of the output buffer;
 * updated with the length of the decoded identifier.
 * @return 0 on success, or -1 if decoding fails.
 */
static int parse_p2p_id(const char *id_str, uint8_t *out_buf, size_t *out_len)
{
    size_t encoded_len = strlen(id_str);
    int ret = multibase_base58_btc_decode(id_str, encoded_len, out_buf, *out_len);
    if (ret < 0)
    {
        return -1; // decoding error
    }
    *out_len = (size_t)ret;
    return 0;
}

/**
 * @brief Parse a protocol and its address from strings and append their encoded
 * representation to a buffer.
 *
 * @param proto_str The protocol name as a string.
 * @param addr_str The address string associated with the protocol.
 * @param b Pointer to the ma_buf_t structure where the encoded protocol and
 * address will be appended.
 * @return MULTIADDR_SUCCESS on success, or an appropriate error code on
 * failure.
 */
static int parse_and_append_protocol(const char *proto_str, const char *addr_str, ma_buf_t *b)
{
    uint64_t code = multicodec_code_from_name(proto_str);
    if (code == 0)
    {
        return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
    }
    if (ma_buf_append_varint(b, code) < 0)
    {
        return MULTIADDR_ERR_ALLOC_FAILURE;
    }

    int addr_len = get_protocol_addr_len(code);
    if (addr_len == ADDR_LEN_UNKNOWN)
    {
        return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
    }

    if (addr_len == 0)
    {
        if (addr_str && addr_str[0] != '\0')
        {
            return MULTIADDR_ERR_INVALID_STRING;
        }
        return MULTIADDR_SUCCESS;
    }

    if (!addr_str || addr_str[0] == '\0')
    {
        return MULTIADDR_ERR_INVALID_STRING;
    }

    if (addr_len > 0)
    {
        uint8_t tmp[16];
        if ((size_t)addr_len > sizeof(tmp))
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
        memset(tmp, 0, sizeof(tmp));

        if (code == MULTICODEC_IP4)
        {
            if (parse_ip4(addr_str, tmp) < 0)
            {
                return MULTIADDR_ERR_INVALID_STRING;
            }
        }
        else if (code == MULTICODEC_IP6)
        {
            if (parse_ip6(addr_str, tmp) < 0)
            {
                return MULTIADDR_ERR_INVALID_STRING;
            }
        }
        else if (code == MULTICODEC_TCP || code == MULTICODEC_UDP)
        {
            if (parse_port(addr_str, tmp) < 0)
            {
                return MULTIADDR_ERR_INVALID_STRING;
            }
        }
        else
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
        if (ma_buf_append(b, tmp, (size_t)addr_len) < 0)
        {
            return MULTIADDR_ERR_ALLOC_FAILURE;
        }
    }
    else
    {
        if (addr_len == ADDR_LEN_VARIABLE)
        {
            uint8_t tmp[256];
            size_t tmp_len = 0;
            if (code == MULTICODEC_P2P || code == MULTICODEC_IPFS)
            {
                tmp_len = sizeof(tmp);
                if (parse_p2p_id(addr_str, tmp, &tmp_len) < 0)
                {
                    return MULTIADDR_ERR_INVALID_STRING;
                }
            }
            else if (code == MULTICODEC_DNS || code == MULTICODEC_DNS4 || code == MULTICODEC_DNS6 || code == MULTICODEC_DNSADDR)
            {
                tmp_len = strlen(addr_str);
                if (tmp_len > sizeof(tmp))
                {
                    return MULTIADDR_ERR_INVALID_STRING;
                }
                memcpy(tmp, addr_str, tmp_len);
            }
            else
            {
                return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            }
            if (ma_buf_append_varint(b, (uint64_t)tmp_len) < 0)
            {
                return MULTIADDR_ERR_ALLOC_FAILURE;
            }
            if (ma_buf_append(b, tmp, tmp_len) < 0)
            {
                return MULTIADDR_ERR_ALLOC_FAILURE;
            }
        }
        else
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
    }
    return MULTIADDR_SUCCESS;
}

/**
 * @brief Create a new multiaddr from its string representation.
 *
 * @param str The multiaddr string.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to the newly created multiaddr_t structure, or NULL on
 * failure.
 */
multiaddr_t *multiaddr_new_from_str(const char *str, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!str)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    if (str[0] != '/')
    {
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_STRING;
        }
        return NULL;
    }

    ma_buf_t buf;
    ma_buf_init(&buf);

    char *temp = strdup(str + 1); /* skip leading '/' */
    if (!temp)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }

    int ret_code = MULTIADDR_SUCCESS;
    char *saveptr = NULL;
    char *token = strtok_r(temp, "/", &saveptr);

    while (token)
    {
        const char *proto_str = token;
        uint64_t code_test = multicodec_code_from_name(proto_str);
        if (code_test == 0)
        {
            ret_code = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            break;
        }
        int alen = get_protocol_addr_len(code_test);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            ret_code = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            break;
        }

        const char *addr_candidate = NULL;
        if (alen != 0)
        {
            addr_candidate = strtok_r(NULL, "/", &saveptr);
        }

        int rr = parse_and_append_protocol(proto_str, addr_candidate, &buf);
        if (rr != MULTIADDR_SUCCESS)
        {
            ret_code = rr;
            break;
        }

        token = strtok_r(NULL, "/", &saveptr);
    }

    free(temp);

    if (ret_code != MULTIADDR_SUCCESS)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = ret_code;
        }
        return NULL;
    }

    if (validate_multiaddr_bytes(buf.data, buf.size) < 0)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }

    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->size = buf.size;
    m->bytes = buf.data;
    return m;
}

/**
 * @brief Create a new multiaddr from a byte array.
 *
 * @param bytes Pointer to the multiaddr byte array.
 * @param length Length of the byte array.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to the newly created multiaddr_t structure, or NULL on
 * failure.
 */
multiaddr_t *multiaddr_new_from_bytes(const uint8_t *bytes, size_t length, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!bytes)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    if (validate_multiaddr_bytes(bytes, length) < 0)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->bytes = (uint8_t *)malloc(length);
    if (!m->bytes)
    {
        free(m);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    memcpy(m->bytes, bytes, length);
    m->size = length;
    return m;
}

/**
 * @brief Create a copy of an existing multiaddr.
 *
 * @param addr Pointer to the multiaddr_t structure to copy.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to the newly allocated copy of the multiaddr, or NULL on
 * failure.
 */
multiaddr_t *multiaddr_copy(const multiaddr_t *addr, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->bytes = (uint8_t *)malloc(addr->size);
    if (!m->bytes)
    {
        free(m);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    memcpy(m->bytes, addr->bytes, addr->size);
    m->size = addr->size;
    return m;
}

/**
 * @brief Free a multiaddr structure.
 *
 * @param addr Pointer to the multiaddr_t structure to free.
 */
void multiaddr_free(multiaddr_t *addr)
{
    if (!addr)
    {
        return;
    }
    if (addr->bytes)
    {
        free(addr->bytes);
    }
    free(addr);
}

/**
 * @brief Retrieve the byte representation of a multiaddr.
 *
 * @param addr Pointer to the multiaddr_t structure.
 * @param buffer Buffer to copy the byte data into.
 * @param buffer_len Size of the provided buffer.
 * @return The number of bytes copied on success, or an error code on failure.
 */
int multiaddr_get_bytes(const multiaddr_t *addr, uint8_t *buffer, size_t buffer_len)
{
    if (!addr || !buffer)
    {
        return MULTIADDR_ERR_NULL_POINTER;
    }
    if (buffer_len < addr->size)
    {
        return MULTIADDR_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer, addr->bytes, addr->size);
    return (int)addr->size;
}

/**
 * @brief Convert an IPv4 address from binary to string representation.
 *
 * @param addr_bytes Pointer to the 4-byte IPv4 address.
 * @param out Output buffer to store the formatted IPv4 string.
 * @param out_size Size of the output buffer.
 * @return 0 on success, or -1 if the output buffer is too small.
 */
static int sprint_ip4(const uint8_t *addr_bytes, char *out, size_t out_size)
{
    if (out_size < 16)
    {
        return -1;
    }
    snprintf(out, out_size, "%u.%u.%u.%u", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
    return 0;
}

/**
 * @brief Convert an IPv6 address from binary to string representation.
 *
 * @param addr_bytes Pointer to the 16-byte IPv6 address.
 * @param out Output buffer to store the formatted IPv6 string.
 * @param out_size Size of the output buffer.
 * @return 0 on success, or -1 if conversion fails or the buffer is too small.
 */
static int sprint_ip6(const uint8_t *addr_bytes, char *out, size_t out_size)
{
    struct in6_addr in6;
    memcpy(&in6, addr_bytes, 16);
    char tmp[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, &in6, tmp, sizeof(tmp)))
    {
        return -1;
    }
    if (strlen(tmp) + 1 > out_size)
    {
        return -1;
    }
    strcpy(out, tmp);
    return 0;
}

/**
 * @brief Convert a port number from binary to string representation.
 *
 * @param addr_bytes Pointer to the 2-byte port number.
 * @param out Output buffer to store the formatted port string.
 * @param out_size Size of the output buffer.
 * @return 0 on success, or -1 if the output buffer is too small.
 */
static int sprint_port(const uint8_t *addr_bytes, char *out, size_t out_size)
{
    if (out_size < 6)
    {
        return -1;
    }
    unsigned int val = ((unsigned)addr_bytes[0] << 8) | (unsigned)addr_bytes[1];
    snprintf(out, out_size, "%u", val);
    return 0;
}

/**
 * @brief Convert a peer-to-peer identifier from binary to a base58 encoded
 * string.
 *
 * @param addr_bytes Pointer to the binary p2p identifier.
 * @param addr_len Length of the p2p identifier.
 * @param out Output buffer to store the base58 encoded string.
 * @param out_size Size of the output buffer.
 * @return 0 on success, or -1 if encoding fails or the buffer is too small.
 */
static int sprint_p2p(const uint8_t *addr_bytes, size_t addr_len, char *out, size_t out_size)
{
    int ret = multibase_base58_btc_encode(addr_bytes, addr_len, out, out_size);
    if (ret < 0)
    {
        return -1;
    }
    if ((size_t)ret >= out_size)
    {
        return -1;
    }
    out[ret] = '\0';
    return 0;
}

/**
 * @brief Convert a multiaddr to its string representation.
 *
 * @param addr Pointer to the multiaddr_t structure.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to a null-terminated string representing the multiaddr, or
 * NULL on failure.
 */
char *multiaddr_to_str(const multiaddr_t *addr, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }

    ma_buf_t sbuf;
    ma_buf_init(&sbuf);
    size_t offset = 0;

    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            ma_buf_free(&sbuf);
            if (err)
            {
                *err = MULTIADDR_ERR_INVALID_DATA;
            }
            return NULL;
        }
        offset += csize;
        const char *proto_str = multicodec_name_from_code(code);
        if (!proto_str)
        {
            ma_buf_free(&sbuf);
            if (err)
            {
                *err = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            }
            return NULL;
        }
        size_t pslen = strlen(proto_str);
        if (ma_buf_append_byte(&sbuf, '/') < 0)
        {
            goto oom;
        }
        if (ma_buf_append(&sbuf, (const uint8_t *)proto_str, pslen) < 0)
        {
            goto oom;
        }

        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            goto invalid;
        }
        if (alen >= 0)
        {
            if (offset + (size_t)alen > addr->size)
            {
                goto invalid;
            }
            if (alen > 0)
            {
                char tmp[INET6_ADDRSTRLEN + 10];
                tmp[0] = '\0';
                if (code == MULTICODEC_IP4)
                {
                    if (sprint_ip4(addr->bytes + offset, tmp, sizeof(tmp)) < 0)
                    {
                        goto invalid;
                    }
                }
                else if (code == MULTICODEC_IP6)
                {
                    if (sprint_ip6(addr->bytes + offset, tmp, sizeof(tmp)) < 0)
                    {
                        goto invalid;
                    }
                }
                else if (code == MULTICODEC_TCP || code == MULTICODEC_UDP)
                {
                    if (sprint_port(addr->bytes + offset, tmp, sizeof(tmp)) < 0)
                    {
                        goto invalid;
                    }
                }
                if (strlen(tmp) > 0)
                {
                    if (ma_buf_append_byte(&sbuf, '/') < 0)
                    {
                        goto oom;
                    }
                    if (ma_buf_append(&sbuf, (const uint8_t *)tmp, strlen(tmp)) < 0)
                    {
                        goto oom;
                    }
                }
            }
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                goto invalid;
            }
            offset += csize2;
            if (offset + vlen > addr->size)
            {
                goto invalid;
            }
            if (code == MULTICODEC_P2P || code == MULTICODEC_IPFS)
            {
                char tmp[512];
                if (sprint_p2p(addr->bytes + offset, (size_t)vlen, tmp, sizeof(tmp)) < 0)
                {
                    goto invalid;
                }
                if (ma_buf_append_byte(&sbuf, '/') < 0)
                {
                    goto oom;
                }
                if (ma_buf_append(&sbuf, (const uint8_t *)tmp, strlen(tmp)) < 0)
                {
                    goto oom;
                }
            }
            else if (code == MULTICODEC_DNS || code == MULTICODEC_DNS4 || code == MULTICODEC_DNS6 || code == MULTICODEC_DNSADDR)
            {
                if (ma_buf_append_byte(&sbuf, '/') < 0)
                {
                    goto oom;
                }
                if (ma_buf_append(&sbuf, addr->bytes + offset, (size_t)vlen) < 0)
                {
                    goto oom;
                }
            }
            else
            {
                goto invalid;
            }
            offset += vlen;
        }
    }

    if (ma_buf_append_byte(&sbuf, '\0') < 0)
    {
        goto oom;
    }
    return (char *)sbuf.data;

oom:
    ma_buf_free(&sbuf);
    if (err)
    {
        *err = MULTIADDR_ERR_ALLOC_FAILURE;
    }
    return NULL;
invalid:
    ma_buf_free(&sbuf);
    if (err)
    {
        *err = MULTIADDR_ERR_INVALID_DATA;
    }
    return NULL;
}

/**
 * @brief Count the number of protocol components in a multiaddr.
 *
 * @param addr Pointer to the multiaddr_t structure.
 * @return The number of protocols in the multiaddr, or 0 if invalid.
 */
size_t multiaddr_nprotocols(const multiaddr_t *addr)
{
    if (!addr)
    {
        return 0;
    }
    size_t count = 0, offset = 0;
    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return 0;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            return 0;
        }
        else if (alen >= 0)
        {
            if (offset + (size_t)alen > addr->size)
            {
                return 0;
            }
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                return 0;
            }
            offset += csize2;
            if (offset + vlen > addr->size)
            {
                return 0;
            }
            offset += vlen;
        }
        count++;
    }
    if (offset != addr->size)
    {
        return 0;
    }
    return count;
}

/**
 * @brief Retrieve the protocol code at a specified index in a multiaddr.
 *
 * @param addr Pointer to the multiaddr_t structure.
 * @param index The index of the protocol to retrieve.
 * @param proto_out Pointer to store the retrieved protocol code.
 * @return 0 on success, or an error code if the protocol is not found or data
 * is invalid.
 */
int multiaddr_get_protocol_code(const multiaddr_t *addr, size_t index, uint64_t *proto_out)
{
    if (!addr || !proto_out)
    {
        return MULTIADDR_ERR_NULL_POINTER;
    }
    size_t i = 0, offset = 0;
    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        if (i == index)
        {
            *proto_out = code;
            return 0;
        }
        if (alen >= 0)
        {
            if (offset + (size_t)alen > addr->size)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            if (offset + csize2 + vlen > addr->size)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += csize2 + vlen;
        }
        i++;
    }
    return MULTIADDR_ERR_INVALID_DATA;
}

/**
 * @brief Retrieve the address bytes for a protocol at a specified index in a
 * multiaddr.
 *
 * @param addr Pointer to the multiaddr_t structure.
 * @param index The index of the protocol.
 * @param buf Buffer to store the extracted address bytes.
 * @param buf_len Pointer to the size of the buffer; updated with the length of
 * the address bytes.
 * @return 0 on success, or an error code if extraction fails or the buffer is
 * too small.
 */
int multiaddr_get_address_bytes(const multiaddr_t *addr, size_t index, uint8_t *buf, size_t *buf_len)
{
    if (!addr || !buf || !buf_len)
    {
        return MULTIADDR_ERR_NULL_POINTER;
    }
    size_t i = 0, offset = 0;
    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        if (i == index)
        {
            if (alen >= 0)
            {
                if (offset + (size_t)alen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (*buf_len < (size_t)alen)
                {
                    *buf_len = alen;
                    return MULTIADDR_ERR_BUFFER_TOO_SMALL;
                }
                memcpy(buf, addr->bytes + offset, alen);
                *buf_len = alen;
                return 0;
            }
            else
            {
                uint64_t vlen = 0;
                size_t csize2 = 0;
                if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (offset + csize2 + vlen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (*buf_len < vlen)
                {
                    *buf_len = vlen;
                    return MULTIADDR_ERR_BUFFER_TOO_SMALL;
                }
                memcpy(buf, addr->bytes + offset + csize2, vlen);
                *buf_len = vlen;
                return 0;
            }
        }
        else
        {
            if (alen >= 0)
            {
                if (offset + (size_t)alen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                offset += alen;
            }
            else
            {
                uint64_t vlen = 0;
                size_t csize2 = 0;
                if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (offset + csize2 + vlen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                offset += csize2 + vlen;
            }
        }
        i++;
    }
    return MULTIADDR_ERR_INVALID_DATA;
}

/**
 * @brief Encapsulate one multiaddr within another.
 *
 * @param addr Pointer to the primary multiaddr_t structure.
 * @param sub Pointer to the sub multiaddr_t structure to encapsulate.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to the new encapsulated multiaddr, or NULL on failure.
 */
multiaddr_t *multiaddr_encapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr || !sub)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    if (validate_multiaddr_bytes(addr->bytes, addr->size) < 0 || validate_multiaddr_bytes(sub->bytes, sub->size) < 0)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->size = addr->size + sub->size;
    m->bytes = (uint8_t *)malloc(m->size);
    if (!m->bytes)
    {
        free(m);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    memcpy(m->bytes, addr->bytes, addr->size);
    memcpy(m->bytes + addr->size, sub->bytes, sub->size);
    return m;
}

/**
 * @brief Structure representing a multiaddr component.
 */
typedef struct
{
    uint64_t code;
    const uint8_t *addr;
    size_t addr_len;
} ma_component_t;

/**
 * @brief Parse a multiaddr into its component protocols and addresses.
 *
 * @param m Pointer to the multiaddr_t structure.
 * @param out_list Pointer to an array that will be allocated with the parsed
 * components.
 * @param count Pointer to store the number of components parsed.
 * @return 0 on success, or -1 on failure.
 */
static int parse_multiaddr_components(const multiaddr_t *m, ma_component_t **out_list, size_t *count)
{
    *out_list = NULL;
    *count = 0;
    size_t capacity = 4;
    ma_component_t *list = (ma_component_t *)malloc(capacity * sizeof(ma_component_t));
    if (!list)
    {
        return -1;
    }
    size_t offset = 0, i = 0;
    while (offset < m->size)
    {
        if (i == capacity)
        {
            capacity *= 2;
            ma_component_t *tmp = (ma_component_t *)realloc(list, capacity * sizeof(ma_component_t));
            if (!tmp)
            {
                free(list);
                return -1;
            }
            list = tmp;
        }
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(m->bytes + offset, m->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            free(list);
            return -1;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            free(list);
            return -1;
        }
        else if (alen >= 0)
        {
            if (offset + (size_t)alen > m->size)
            {
                free(list);
                return -1;
            }
            list[i].code = code;
            list[i].addr = m->bytes + offset;
            list[i].addr_len = alen;
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(m->bytes + offset, m->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                free(list);
                return -1;
            }
            if (offset + csize2 + vlen > m->size)
            {
                free(list);
                return -1;
            }
            list[i].code = code;
            list[i].addr = m->bytes + offset + csize2;
            list[i].addr_len = vlen;
            offset += csize2 + vlen;
        }
        i++;
    }
    *out_list = list;
    *count = i;
    return 0;
}

/**
 * @brief Build a multiaddr from an array of components.
 *
 * @param list Array of ma_component_t structures representing the multiaddr
 * components.
 * @param count Number of components in the list.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to the newly constructed multiaddr_t structure, or NULL on
 * failure.
 */
static multiaddr_t *build_multiaddr_from_components(const ma_component_t *list, size_t count, int *err)
{
    ma_buf_t buf;
    ma_buf_init(&buf);
    for (size_t i = 0; i < count; i++)
    {
        if (ma_buf_append_varint(&buf, list[i].code) < 0)
        {
            ma_buf_free(&buf);
            if (err)
            {
                *err = MULTIADDR_ERR_ALLOC_FAILURE;
            }
            return NULL;
        }
        int known_len = get_protocol_addr_len(list[i].code);
        if (known_len >= 0)
        {
            if ((size_t)known_len != list[i].addr_len)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_INVALID_DATA;
                }
                return NULL;
            }
            if (ma_buf_append(&buf, list[i].addr, list[i].addr_len) < 0)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_ALLOC_FAILURE;
                }
                return NULL;
            }
        }
        else
        {
            if (ma_buf_append_varint(&buf, list[i].addr_len) < 0)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_ALLOC_FAILURE;
                }
                return NULL;
            }
            if (ma_buf_append(&buf, list[i].addr, list[i].addr_len) < 0)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_ALLOC_FAILURE;
                }
                return NULL;
            }
        }
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->size = buf.size;
    m->bytes = buf.data;
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    return m;
}

/**
 * @brief Decapsulate a sub multiaddr from a parent multiaddr.
 *
 * @param addr Pointer to the parent multiaddr_t structure.
 * @param sub Pointer to the sub multiaddr_t structure to remove.
 * @param err Pointer to an integer to store error codes; set to
 * MULTIADDR_SUCCESS on success.
 * @return Pointer to the resulting multiaddr after decapsulation, or NULL if no
 * match is found or on failure.
 */
multiaddr_t *multiaddr_decapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr || !sub)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    ma_component_t *alist = NULL, *slist = NULL;
    size_t acount = 0, scount = 0;
    if ((parse_multiaddr_components(addr, &alist, &acount) < 0) || (parse_multiaddr_components(sub, &slist, &scount) < 0))
    {
        if (alist)
        {
            free(alist);
        }
        if (slist)
        {
            free(slist);
        }
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }
    if (scount == 0 || scount > acount)
    {
        free(alist);
        free(slist);
        if (err)
        {
            *err = MULTIADDR_ERR_NO_MATCH;
        }
        return NULL;
    }

    int bestMatch = -1;
    for (size_t i = 0; i <= acount - scount; i++)
    {
        int match = 1;
        for (size_t j = 0; j < scount; j++)
        {
            if (alist[i + j].code != slist[j].code || alist[i + j].addr_len != slist[j].addr_len ||
                memcmp(alist[i + j].addr, slist[j].addr, alist[i + j].addr_len) != 0)
            {
                match = 0;
                break;
            }
        }
        if (match)
        {
            bestMatch = (int)i;
        }
    }
    if (bestMatch == -1)
    {
        free(alist);
        free(slist);
        if (err)
        {
            *err = MULTIADDR_ERR_NO_MATCH;
        }
        return NULL;
    }

    multiaddr_t *res = NULL;
    if (bestMatch == 0)
    {
        res = build_multiaddr_from_components(NULL, 0, err);
    }
    else
    {
        res = build_multiaddr_from_components(alist, bestMatch, err);
    }
    free(alist);
    free(slist);
    if (!res && (err && *err == MULTIADDR_SUCCESS))
    {
        *err = MULTIADDR_ERR_ALLOC_FAILURE;
    }
    return res;
}
