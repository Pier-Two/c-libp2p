#ifndef PEER_ID_ECDSA_H
#define PEER_ID_ECDSA_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>

#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"

#define PEER_ID_ECDSA_KEY_TYPE 3

/**
 * @brief Creates a peer ID from an ECDSA private key.
 *
 * This function processes the ECDSA private key to generate the corresponding public key.
 *
 * @param key_data A pointer to the private key data.
 * @param key_data_len The length of the private key data.
 * @param pubkey_buf Output pointer to the allocated buffer containing the public key.
 *                   The caller is responsible for freeing this memory.
 * @param pubkey_len Output parameter to store the length of the public key buffer.
 *
 * @return PEER_ID_SUCCESS on success, or an appropriate error code on failure.
 */
peer_id_error_t peer_id_create_from_private_key_ecdsa(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len);

#ifdef __cplusplus
}
#endif

#endif /* PEER_ID_ECDSA_H */
