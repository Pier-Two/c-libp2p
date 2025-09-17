#ifndef MULTIADDR_H
#define MULTIADDR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

typedef enum
{
    MULTIADDR_SUCCESS = 0,               /**< No error.                          */
    MULTIADDR_ERR_NULL_POINTER = -1,     /**< A null pointer was passed.         */
    MULTIADDR_ERR_INVALID_STRING = -2,   /**< Failed to parse multiaddr string.  */
    MULTIADDR_ERR_INVALID_DATA = -3,     /**< Binary data not a valid multiaddr. */
    MULTIADDR_ERR_BUFFER_TOO_SMALL = -4, /**< Insufficient out buffer size.   */
    MULTIADDR_ERR_NO_MATCH = -5,         /**< Decapsulation match not found.     */
    MULTIADDR_ERR_ALLOC_FAILURE = -6,    /**< Memory allocation failed.           */
    MULTIADDR_ERR_UNKNOWN_PROTOCOL = -7  /**< Protocol code is not recognized. */
} multiaddr_error_t;

/**
 * @brief Multiaddr opaque struct.
 *
 * Internally, a multiaddr is often stored in its binary format:
 *   <proto code (varint)><addr bytes>... repeated ...
 */
typedef struct multiaddr_s multiaddr_t;

/**
 * @brief Create a new multiaddr by parsing a human-readable string.
 *
 * @param[in]  str       Null-terminated multiaddr string (e.g. "/ip4/127.0.0.1/tcp/8080").
 * @param[out] err       On failure, set to one of the multiaddr_error_t codes. On success, set to
 * MULTIADDR_SUCCESS.
 *
 * @return Pointer to a newly allocated multiaddr_t. NULL on error.
 *
 * @note The caller must call `multiaddr_free()` when done.
 */
multiaddr_t *multiaddr_new_from_str(const char *str, int *err);

/**
 * @brief Create a new multiaddr from its serialized binary format.
 *
 * @param[in]  bytes     Pointer to a buffer containing the binary multiaddr.
 * @param[in]  length    Size of `bytes` in bytes.
 * @param[out] err       On failure, set to one of the multiaddr_error_t codes.
 *                       On success, set to MULTIADDR_SUCCESS.
 *
 * @return Pointer to a newly allocated multiaddr_t. NULL on error.
 *
 * @note The caller must call `multiaddr_free()` when done.
 */
multiaddr_t *multiaddr_new_from_bytes(const uint8_t *bytes, size_t length, int *err);

/**
 * @brief Create a deep copy of an existing multiaddr.
 *
 * @param[in]  addr   Pointer to the source multiaddr.
 * @param[out] err    On failure, set to MULTIADDR_ERR_ALLOC_FAILURE if memory
 *                    allocation fails. Otherwise MULTIADDR_SUCCESS.
 *
 * @return Pointer to a newly allocated multiaddr_t copy. NULL on error.
 */
multiaddr_t *multiaddr_copy(const multiaddr_t *addr, int *err);

/**
 * @brief Free the memory for a multiaddr object.
 *
 * @param[in] addr  Pointer to a multiaddr previously allocated by any of the
 *                  `multiaddr_new_*()` functions.
 */
void multiaddr_free(multiaddr_t *addr);

/**
 * @brief Serialize (copy) the internal multiaddr bytes into an external buffer.
 *
 * @param[in]  addr        Pointer to the multiaddr.
 * @param[out] buffer      The output buffer where multiaddr bytes will be written.
 * @param[in]  buffer_len  The size of `buffer`.
 *
 * @return The number of bytes written on success,
 *         or a negative multiaddr_error_t code on error.
 *         - MULTIADDR_ERR_NULL_POINTER if `addr` or `buffer` is NULL
 *         - MULTIADDR_ERR_BUFFER_TOO_SMALL if buffer_len < multiaddr_size(addr)
 */
int multiaddr_get_bytes(const multiaddr_t *addr, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Convert a multiaddr to a newly allocated null-terminated string.
 *
 * @param[in]  addr    Pointer to the multiaddr.
 * @param[out] err     On failure, set to a negative multiaddr_error_t code.
 *                     Otherwise MULTIADDR_SUCCESS on success.
 *
 * @return Null-terminated string representing the multiaddr (e.g. "/ip4/127.0.0.1/tcp/8080").
 *         The caller must free this string via `free()`. Returns NULL on error.
 */
char *multiaddr_to_str(const multiaddr_t *addr, int *err);

/**
 * @brief Return how many protocols (or "components") are contained in this multiaddr.
 *
 * For example, "/ip4/127.0.0.1/tcp/8080" has 2 protocols: ip4, tcp.
 *
 * @param[in] addr  Pointer to the multiaddr.
 * @return Number of protocols, or 0 if addr is NULL or invalid.
 */
size_t multiaddr_nprotocols(const multiaddr_t *addr);

/**
 * @brief Retrieve the protocol code at a given index in the stack.
 *
 * @param[in]  addr      Pointer to the multiaddr.
 * @param[in]  index     0-based index of the desired protocol.
 * @param[out] proto_out On success, the numeric protocol code (as a multicodec).
 *
 * @return 0 on success, or a negative multiaddr_error_t code on error:
 *         - MULTIADDR_ERR_NULL_POINTER if addr is NULL
 *         - MULTIADDR_ERR_INVALID_DATA if the index is out of range
 */
int multiaddr_get_protocol_code(const multiaddr_t *addr, size_t index, uint64_t *proto_out);

/**
 * @brief Extract the raw address bytes (if any) associated with a particular protocol in the stack.
 *
 * For example, if the component is "/ip4/127.0.0.1", the raw address bytes
 * (in network order) are 0x7F 0x00 0x00 0x01.
 *
 * @param[in]      addr        Pointer to the multiaddr.
 * @param[in]      index       0-based index of the desired protocol.
 * @param[out]     buf         Buffer to copy address bytes into.
 * @param[in, out] buf_len     On input, size of `buf`. On output, the number
 *                             of bytes actually written.
 *
 * @return 0 on success, or a negative multiaddr_error_t code on error.
 */
int multiaddr_get_address_bytes(const multiaddr_t *addr, size_t index, uint8_t *buf, size_t *buf_len);

/**
 * @brief Create a new multiaddr that is `addr` encapsulated with another (sub) multiaddr.
 *
 * For example, if `addr = /ip4/127.0.0.1` and `sub = /tcp/8080`,
 * then the result is `/ip4/127.0.0.1/tcp/8080`.
 *
 * @param[in]  addr      Pointer to the "outer" multiaddr.
 * @param[in]  sub       Pointer to the "inner" multiaddr to be appended.
 * @param[out] err       On error, set to negative multiaddr_error_t code. Otherwise
 * MULTIADDR_SUCCESS.
 *
 * @return A newly allocated multiaddr_t, or NULL on error.
 */
multiaddr_t *multiaddr_encapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err);

/**
 * @brief Create a new multiaddr by decapsulating the last occurrence of `sub` from `addr`.
 *
 * For example:
 *   If `addr = /ip4/127.0.0.1/tcp/8080/ws`
 *   and `sub  = /tcp/8080/ws`
 *   The result will be `/ip4/127.0.0.1`
 *
 * Note that decapsulating `/ws` alone from the above example also yields `/ip4/127.0.0.1/tcp/8080`.
 * In general, removing the last occurrence of `sub` also removes everything after it.
 *
 * @param[in]  addr  The original multiaddr (outer).
 * @param[in]  sub   The sub-multiaddr to remove from the end of `addr`.
 * @param[out] err   On error, set to negative multiaddr_error_t code. Otherwise MULTIADDR_SUCCESS.
 *
 * @return A newly allocated multiaddr_t. Returns NULL if no match is found
 *         or if an error occurs.
 */
multiaddr_t *multiaddr_decapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err);

#ifdef __cplusplus
}
#endif

#endif /* MULTIADDR_H */