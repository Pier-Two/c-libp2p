#ifndef PEER_ID_PROTO_H
#define PEER_ID_PROTO_H

#include "peer_id/peer_id.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Build a protobuf-encoded PublicKey message from a raw public key.
 *
 * The protobuf has two fields:
 *
 *   1) required KeyType Type = 1;   // varint
 *   2) required bytes   Data = 2;   // length-delimited
 *
 * This function:
 *   - varint-encodes `KeyType`
 *   - writes field #1 header (tag=1, wire=varint)
 *   - writes field #2 header (tag=2, wire=length-delimited)
 *   - varint-encodes the length of @p raw_key_data
 *   - copies @p raw_key_data
 *
 * @param key_type       The libp2p KeyType (0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA).
 * @param raw_key_data   Pointer to the raw public key bytes.
 * @param raw_key_len    Length of the raw public key in bytes.
 * @param out_buf        [out] On success, allocated buffer containing the protobuf.
 * @param out_size       [out] Number of bytes in @p out_buf.
 *
 * @return PEER_ID_SUCCESS on success, an error code otherwise.
 * @note   The caller must free() @p out_buf.
 */
peer_id_error_t peer_id_build_public_key_protobuf(uint64_t key_type, const uint8_t *raw_key_data, size_t raw_key_len, uint8_t **out_buf,
                                                  size_t *out_size);

/**
 * @brief Parse a protobuf-encoded PublicKey message.
 *
 * The expected message format is:
 *
 *   message PublicKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * This function parses the message and extracts:
 *   - out_key_type: The key type (0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA).
 *   - out_key_data: Pointer into the buffer for the key data.
 *   - out_key_data_len: The length of the key data in bytes.
 *
 * @param buf              Pointer to the protobuf-encoded data.
 * @param len              Length of the data in bytes.
 * @param out_key_type     [out] Parsed key type.
 * @param out_key_data     [out] Pointer to the raw key data.
 * @param out_key_data_len [out] Length of the raw key data.
 *
 * @return 0 on success, a negative error code on failure.
 */
int parse_public_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data, size_t *out_key_data_len);

/**
 * @brief Parse a protobuf-encoded PrivateKey message.
 *
 * The expected message format is:
 *
 *   message PrivateKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * This function parses the message and extracts:
 *   - out_key_type: The key type (0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA).
 *   - out_key_data: Pointer into the buffer for the key data.
 *   - out_key_data_len: The length of the key data in bytes.
 *
 * @param buf              Pointer to the protobuf-encoded data.
 * @param len              Length of the data in bytes.
 * @param out_key_type     [out] Parsed key type.
 * @param out_key_data     [out] Pointer to the raw key data.
 * @param out_key_data_len [out] Length of the raw key data.
 *
 * @return 0 on success, a negative error code on failure.
 */
int parse_private_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data, size_t *out_key_data_len);

#endif /* PEER_ID_PROTO_H */