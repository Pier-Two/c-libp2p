#ifndef LIBP2P_PEERSTORE_H
#define LIBP2P_PEERSTORE_H

#include <stddef.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_peerstore libp2p_peerstore_t;

/* Basic peerstore API (sufficient for host_open_stream by peer id) */
libp2p_peerstore_t *libp2p_peerstore_new(void);
void libp2p_peerstore_free(libp2p_peerstore_t *ps);

/* Add an address for a peer. ttl_ms is currently advisory (not enforced). */
int libp2p_peerstore_add_addr(libp2p_peerstore_t *ps, const peer_id_t *peer, const multiaddr_t *addr, int ttl_ms);

/* Returns a newly allocated array of address clones; caller must free via libp2p_peerstore_free_addrs. */
int libp2p_peerstore_get_addrs(const libp2p_peerstore_t *ps, const peer_id_t *peer, const multiaddr_t ***out_addrs, size_t *out_len);
void libp2p_peerstore_free_addrs(const multiaddr_t **addrs, size_t len);

/* Optional: store remote peer's public key (protobuf-encoded PublicKey).
 * Replaces any previous value. */
int libp2p_peerstore_set_public_key(libp2p_peerstore_t *ps, const peer_id_t *peer, const uint8_t *pubkey_pb, size_t pubkey_pb_len);

/* Retrieve a copy of the stored public key for a peer (protobuf-encoded PublicKey).
 * Returns 0 on success; if not present, sets *out_pb=NULL and *out_len=0 and returns 0.
 * Caller must free(*out_pb) with free(). */
int libp2p_peerstore_get_public_key(const libp2p_peerstore_t *ps, const peer_id_t *peer, uint8_t **out_pb, size_t *out_len);

/* Optional: store remote peer's supported protocol IDs (exact strings).
 * Replaces any previous list. */
int libp2p_peerstore_set_protocols(libp2p_peerstore_t *ps, const peer_id_t *peer, const char *const *protocols, size_t n_protocols);

/* Retrieve protocols for a peer (copies; caller frees with free_protocols). */
int libp2p_peerstore_get_protocols(const libp2p_peerstore_t *ps, const peer_id_t *peer, const char ***out_protocols, size_t *out_len);
void libp2p_peerstore_free_protocols(const char **protocols, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PEERSTORE_H */
