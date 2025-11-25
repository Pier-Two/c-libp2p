#ifndef PROTOCOL_QUIC_H
#define PROTOCOL_QUIC_H

/*
 * @file protocol_quic.h
 * @brief QUIC transport skeleton for C-libp2p (picoquic-based).
 *
 * Phase 1 provides a minimal transport that advertises capability via
 * can_handle() once wired, but dials/listens return UNSUPPORTED until
 * subsequent phases implement actual QUIC sessions and listeners.
 */

#include "transport/transport.h"
#include "transport/muxer.h"
#include "peer_id/peer_id.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBP2P_QUIC_TLS_ALPN "libp2p"

typedef struct
{
    /* Application-Layer Protocol Negotiation value for QUIC transport. */
    const char *alpn;
    /* Reserved for future configuration knobs. */
    uint32_t reserved;
} libp2p_quic_config_t;

static inline libp2p_quic_config_t libp2p_quic_config_default(void)
{
    libp2p_quic_config_t cfg;
    cfg.alpn = LIBP2P_QUIC_TLS_ALPN;
    cfg.reserved = 0;
    return cfg;
}

/* Opaque session handle type (e.g., picoquic_cnx_t). */
#ifndef LIBP2P_QUIC_SESSION_TYPEDEF
#define LIBP2P_QUIC_SESSION_TYPEDEF
typedef struct libp2p_quic_session libp2p_quic_session_t;
#endif
struct libp2p_host;

/*
 * Construct a libp2p_conn_t wrapper bound to a QUIC session.
 *
 * - local/remote: multiaddrs identifying the UDP endpoint pair. The function
 *   copies them internally, the caller retains ownership of its arguments.
 * - session: opaque pointer to a QUIC session implementation.
 * - session_close: optional callback to perform an orderly shutdown.
 * - session_free: optional callback to free the session handle.
 */
libp2p_conn_t *libp2p_quic_conn_new(
    const multiaddr_t *local,
    const multiaddr_t *remote,
    libp2p_quic_session_t *session,
    void (*session_close)(libp2p_quic_session_t *),
    void (*session_free)(libp2p_quic_session_t *),
    peer_id_t *verified_peer);

libp2p_quic_session_t *libp2p_quic_conn_session(libp2p_conn_t *conn);

void libp2p_quic_conn_detach_session(libp2p_conn_t *conn);

int libp2p_quic_conn_set_verified_peer(libp2p_conn_t *conn, peer_id_t *peer);

int libp2p_quic_conn_copy_verified_peer(const libp2p_conn_t *conn, peer_id_t **out_peer);

int libp2p_quic_conn_set_local(libp2p_conn_t *conn, const multiaddr_t *local);

int libp2p_quic_conn_set_verify_ctx(libp2p_conn_t *conn, void *verify_ctx, void (*verify_ctx_free)(void *));

/* Lightweight wrapper for picoquic session handles used by the muxer/stream
 * layer. Ownership of the underlying picoquic objects is external; the
 * wrapper only tracks references so various abstractions (conn, muxer,
 * streams) can coordinate lifetime. */
/* Construct a libp2p_muxer_t exposing QUIC streams. local/remote multiaddrs
 * are deep-copied so the caller retains ownership of the arguments. */
libp2p_muxer_t *libp2p_quic_muxer_new(struct libp2p_host *host,
                                      libp2p_quic_session_t *session,
                                      const multiaddr_t *local,
                                      const multiaddr_t *remote,
                                      libp2p_conn_t *conn);

typedef struct libp2p_quic_tls_certificate
{
    uint8_t *cert_der; /* self-signed certificate in DER */
    size_t cert_len;
    uint8_t *key_der;  /* TLS private key (PKCS#8 DER) */
    size_t key_len;
} libp2p_quic_tls_certificate_t;

typedef struct libp2p_quic_tls_cert_options
{
    uint64_t identity_key_type;   /* libp2p key type (matches peer_id KeyType) */
    const uint8_t *identity_key;  /* raw private key bytes from PrivateKey.Data */
    size_t identity_key_len;
    uint32_t not_after_lifetime;  /* certificate validity window in seconds */
} libp2p_quic_tls_cert_options_t;

static inline libp2p_quic_tls_cert_options_t libp2p_quic_tls_cert_options_default(void)
{
    libp2p_quic_tls_cert_options_t opts;
    opts.identity_key_type = 0;
    opts.identity_key = NULL;
    opts.identity_key_len = 0;
    opts.not_after_lifetime = 3600; /* 1 hour */
    return opts;
}

int libp2p_quic_tls_generate_certificate(const libp2p_quic_tls_cert_options_t *opts,
                                         libp2p_quic_tls_certificate_t *out);

void libp2p_quic_tls_certificate_clear(libp2p_quic_tls_certificate_t *cert);

typedef struct libp2p_quic_tls_identity
{
    peer_id_t *peer;           /* derived peer identity */
    uint8_t *public_key_proto; /* protobuf-encoded PublicKey */
    size_t public_key_len;     /* length of public_key_proto */
    uint64_t key_type;         /* libp2p key type enum */
} libp2p_quic_tls_identity_t;

int libp2p_quic_tls_identity_from_certificate(const uint8_t *cert_der,
                                              size_t cert_len,
                                              libp2p_quic_tls_identity_t *out);

void libp2p_quic_tls_identity_clear(libp2p_quic_tls_identity_t *id);

/* Create a new QUIC transport instance. */
libp2p_transport_t *libp2p_quic_transport_new(const libp2p_quic_config_t *cfg);

int libp2p_quic_transport_set_identity(libp2p_transport_t *t, const libp2p_quic_tls_cert_options_t *opts);

int libp2p_quic_transport_set_dial_timeout(libp2p_transport_t *t, uint32_t timeout_ms);

bool libp2p_quic_transport_is(const libp2p_transport_t *t);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_QUIC_H */
