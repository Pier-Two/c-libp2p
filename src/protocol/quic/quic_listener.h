#ifndef LIBP2P_QUIC_LISTENER_H
#define LIBP2P_QUIC_LISTENER_H

#include "quic_internal.h"

#include "transport/listener.h"
#include "transport/transport.h"
#include "peer_id/peer_id.h"

struct quic_listener_ctx;
typedef struct quic_listener_ctx quic_listener_ctx_t;

libp2p_transport_err_t quic_listener_create(libp2p_transport_t *transport,
                                            quic_transport_ctx_t *transport_ctx,
                                            const multiaddr_t *addr,
                                            libp2p_listener_t **out);

void quic_listener_store_verified_peer(quic_listener_ctx_t *ctx, void *tls_ctx, peer_id_t *peer);

peer_id_t *quic_listener_take_verified_peer(quic_listener_ctx_t *ctx, void *tls_ctx);

void quic_listener_remove_verified_peer(quic_listener_ctx_t *ctx, void *tls_ctx);

void quic_listener_handle_connection_closed(quic_listener_ctx_t *ctx, picoquic_cnx_t *cnx);

picoquic_quic_t *quic_listener_get_quic(quic_listener_ctx_t *ctx);

int quic_listener_start(quic_listener_ctx_t *ctx);

#endif /* LIBP2P_QUIC_LISTENER_H */
