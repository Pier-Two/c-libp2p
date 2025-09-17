#ifndef PEER_ID_SECP256K1_H
#define PEER_ID_SECP256K1_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#include "../../lib/secp256k1/include/secp256k1.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"

#define PEER_ID_SECP256K1_KEY_TYPE 2

/**
 * @brief Creates a peer ID from a secp256k1 private key.
 *
 * This function validates the provided private key, derives the corresponding compressed
 * public key (33 bytes), and returns it.
 *
 * @param key_data A pointer to the private key data.
 * @param key_data_len The length of the private key data. Must be exactly 32 bytes for secp256k1.
 * @param pubkey_buf Output pointer to the allocated buffer containing the compressed public key.
 *                   The caller is responsible for freeing this memory.
 * @param pubkey_len Output parameter to store the length of the public key buffer (33 bytes).
 *
 * @return PEER_ID_SUCCESS on success, or an appropriate error code on failure.
 */
peer_id_error_t peer_id_create_from_private_key_secp256k1(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len);

#ifdef __cplusplus
}
#endif

#endif /* PEER_ID_SECP256K1_H */