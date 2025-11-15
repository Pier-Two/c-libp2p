#ifndef LIBP2P_HOST_H
#define LIBP2P_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libp2p/conn_manager.h"
#include "libp2p/errors.h"
#include "libp2p/peerstore.h"
/* resource manager removed */
#include "libp2p/stream.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_host libp2p_host_t;

/* Host flags (bitmask) */
#define LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND (1u << 0)
#define LIBP2P_HOST_F_AUTO_IDENTIFY_INBOUND (1u << 1)

typedef struct
{
    size_t struct_size;
    const char *const *listen_addrs;
    size_t num_listen_addrs;
    const char *const *security_proposals;
    size_t num_security_proposals;
    const char *const *muxer_proposals;
    size_t num_muxer_proposals;
    const char *const *transport_names;
    size_t num_transport_names;
    int multiselect_handshake_timeout_ms;
    bool multiselect_enable_ls;
    int max_inbound_conns;
    int max_outbound_conns;
    int per_conn_max_inbound_streams;
    int per_conn_max_outbound_streams;
    int dial_timeout_ms;
    int handshake_timeout_ms;
    int num_runtime_threads;
    uint32_t flags;
} libp2p_host_options_t;

int libp2p_host_options_default(libp2p_host_options_t *out);

int libp2p_host_new(const libp2p_host_options_t *opts, libp2p_host_t **out);
int libp2p_host_start(libp2p_host_t *host);
int libp2p_host_stop(libp2p_host_t *host);
void libp2p_host_free(libp2p_host_t *host);

int libp2p_host_new_default(const char *const *listen_addrs, size_t num_listen_addrs, libp2p_host_t **out);
int libp2p_host_listen(libp2p_host_t *host, const char *multiaddr_str);
int libp2p_host_listen_ma(libp2p_host_t *host, const multiaddr_t *addr);

/*
 * Application callback invoked when a dial/open completes.
 *
 * Threading: executed on the host's single-threaded application callback
 * executor (never on transport/muxer worker threads). This provides a
 * consistent execution context for all user callbacks.
 */
typedef void (*libp2p_on_stream_open_fn)(libp2p_stream_t *s, void *user_data, int err);
int libp2p_host_dial_protocol(libp2p_host_t *host, const char *remote_multiaddr, const char *protocol_id, libp2p_on_stream_open_fn on_open,
                              void *user_data);

int libp2p_host_dial_protocol_blocking(libp2p_host_t *host, const char *remote_multiaddr, const char *protocol_id, int timeout_ms,
                                       libp2p_stream_t **out);

typedef enum
{
    LIBP2P_GATER_DECISION_ACCEPT = 1,
    LIBP2P_GATER_DECISION_REJECT = 0
} libp2p_gater_decision_t;
typedef libp2p_gater_decision_t (*libp2p_conn_gater_fn)(const char *remote_multiaddr, const peer_id_t *pid, void *user_data);
int libp2p_host_set_conn_gater(libp2p_host_t *host, libp2p_conn_gater_fn fn, void *user_data);

/* Peerstore integration */
int libp2p_host_set_peerstore(libp2p_host_t *host, libp2p_peerstore_t *ps);

/* Convenience: seed an address for a peer in the host's peerstore. If the
 * host does not yet have a peerstore, a default one is created. */
int libp2p_host_add_peer_addr(libp2p_host_t *host, const peer_id_t *peer, const multiaddr_t *addr, int ttl_ms);

/* Convenience: string variant that parses a multiaddr and inserts it. */
int libp2p_host_add_peer_addr_str(libp2p_host_t *host, const peer_id_t *peer, const char *multiaddr_str, int ttl_ms);

/* Open stream by peer id using peerstore addresses; tries all until success. */
/*
 * Open a stream to a peer for a specific protocol.
 * The `on_open` callback runs on the host's callback executor.
 */
int libp2p_host_open_stream(libp2p_host_t *host, const peer_id_t *peer, const char *protocol_id, libp2p_on_stream_open_fn on_open, void *user_data);

/* Non-blocking variant: opens a stream to a peer using the peerstore.
 * Spawns a background thread to attempt dialing across known addresses.
 * On success or failure, invokes `on_open` exactly once.
 * Attempts to reuse an existing negotiated stream for the given
 * protocol and remote address before dialing.
 */
/*
 * Non-blocking variant. Spawns a background worker to attempt the dial, but
 * always posts the `on_open` callback onto the host's callback executor,
 * ensuring a predictable single-threaded application context.
 */
int libp2p_host_open_stream_async(libp2p_host_t *host, const peer_id_t *peer, const char *protocol_id, libp2p_on_stream_open_fn on_open,
                                  void *user_data);

/* Optional: attach managers */
int libp2p_host_set_conn_manager(libp2p_host_t *host, libp2p_conn_mgr_t *cm);

/* Optional: attach metrics (counters/histograms) */
struct libp2p_metrics; /* fwd */
int libp2p_host_set_metrics(libp2p_host_t *host, struct libp2p_metrics *m);

/* Peer identity (host-level) */
/*
 * Set the host's private identity key from a protobuf-encoded PrivateKey.
 * This computes and stores the local Peer ID and updates security (Noise)
 * to use this identity for handshakes. Should be called before start.
 */
int libp2p_host_set_private_key(libp2p_host_t *host, const uint8_t *privkey_pb, size_t privkey_len);

/*
 * Get a copy of the host's local Peer ID. Caller must call peer_id_destroy().
 */
int libp2p_host_get_peer_id(const libp2p_host_t *host, peer_id_t **out);

/* Convenience accessors for peer metadata via host (backed by peerstore).
 *
 * This call is non-blocking and only returns cached protocol information.
 * Callers that require fresh data should subscribe to
 * LIBP2P_EVT_PEER_PROTOCOLS_UPDATED and retry when notified. If no cached
 * entry exists yet, the function returns LIBP2P_ERR_AGAIN.
 */
int libp2p_host_peer_protocols(const libp2p_host_t *host, const peer_id_t *peer, const char ***out_protocols, size_t *out_len);
void libp2p_host_free_peer_protocols(const char **protocols, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_HOST_H */
