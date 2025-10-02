#ifndef LIBP2P_QUIC_INTERNAL_H
#define LIBP2P_QUIC_INTERNAL_H

#include "protocol/quic/protocol_quic.h"

#include "multiformats/multiaddr/multiaddr.h"

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_set_textlog.h"

#include <pthread.h>
#include <stdatomic.h>

typedef struct quic_transport_ctx
{
    libp2p_quic_config_t cfg;
    pthread_mutex_t lock;
    uint8_t *identity_key;
    size_t identity_key_len;
    uint64_t identity_key_type;
    uint32_t dial_timeout_ms;
} quic_transport_ctx_t;

int libp2p__quic_transport_copy_identity(quic_transport_ctx_t *ctx,
                                         uint8_t **out_key,
                                         size_t *out_len,
                                         uint64_t *out_type);

libp2p_quic_config_t libp2p__quic_transport_get_config(const quic_transport_ctx_t *ctx);

void libp2p__quic_transport_clear_buffer(uint8_t *buffer, size_t len);

struct libp2p_host;

/* Internal helpers exposed for tests and transport wiring. */

libp2p_quic_session_t *libp2p__quic_session_wrap(picoquic_quic_t *quic, picoquic_cnx_t *cnx);

void libp2p__quic_session_retain(libp2p_quic_session_t *session);

void libp2p__quic_session_release(libp2p_quic_session_t *session);

void libp2p__quic_session_set_host(libp2p_quic_session_t *session, struct libp2p_host *host);

picoquic_quic_t *libp2p__quic_session_quic(libp2p_quic_session_t *session);

picoquic_cnx_t *libp2p__quic_session_native(libp2p_quic_session_t *session);

void libp2p__quic_session_wake(libp2p_quic_session_t *session);

int libp2p__quic_session_start_loop(libp2p_quic_session_t *session,
                                    const multiaddr_t *local_addr,
                                    const multiaddr_t *remote_addr);

void libp2p__quic_session_stop_loop(libp2p_quic_session_t *session);

void libp2p__quic_session_attach_thread(libp2p_quic_session_t *session,
                                        picoquic_network_thread_ctx_t *thread_ctx);

int libp2p__quic_multiaddr_to_sockaddr_udp(const multiaddr_t *addr,
                                           struct sockaddr_storage *ss,
                                           socklen_t *ss_len);

multiaddr_t *libp2p__quic_multiaddr_from_sockaddr(const struct sockaddr *sa,
                                                   socklen_t len);

int libp2p__quic_apply_tls_key(picoquic_quic_t *quic, const uint8_t *key_der, size_t key_len);

#endif /* LIBP2P_QUIC_INTERNAL_H */
