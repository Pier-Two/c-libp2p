#ifndef LIBP2P_HOST_INTERNAL_H
#define LIBP2P_HOST_INTERNAL_H

#include <pthread.h>
#include <stdatomic.h>

#include "libp2p/conn_manager.h"
#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/muxer.h"
#include "libp2p/peerstore.h"
#include "libp2p/protocol.h"
#include "libp2p/protocol_match.h"
/* resource manager removed */
#include "libp2p/metrics.h"
#include "libp2p/security.h"
#include "libp2p/transport.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/quic/protocol_quic.h"
#include "transport/transport.h"
#include "transport/upgrader.h"
#include "conn_pool.h"

/* Opaque forward declarations */
struct libp2p_protocol_server;

/* Internal protocol entry used by exact registrations */
typedef struct protocol_entry
{
    libp2p_protocol_def_t def;
    struct protocol_entry *next;
} protocol_entry_t;

/* Internal protocol matcher entry used by prefix/semver registrations */
typedef struct protocol_match_entry
{
    libp2p_protocol_matcher_t matcher;
    libp2p_protocol_def_t def;
    struct protocol_match_entry *next;
} protocol_match_entry_t;

typedef struct listener_node
{
    libp2p_listener_t *lst;
    pthread_t thread;
    int thread_running;
    int thread_started;
    struct listener_node *next;
    struct libp2p_host *host;
    /* Cached bound address string for event emissions */
    char *addr_str;
    /* Ensure CLOSED/ERROR are emitted at most once per lifecycle */
    int emitted_closed;
    int emitted_error;
} listener_node_t;

/* Forward decl for yamux inbound session callback context */
struct yamux_cb_ctx;

/* Track active inbound session threads so we can stop/join on host_stop */
typedef struct session_node
{
    pthread_t thread;          /* session thread id */
    struct libp2p_runtime *rt; /* per-session runtime (for stop) */
    /* Optional refs to help shutdown quickly */
    struct libp2p_yamux_ctx *yctx;  /* mux context for GO_AWAY/shutdown */
    struct libp2p_muxer *mx;        /* parent muxer */
    struct libp2p_connection *conn; /* secured connection */
    /* Inbound yamux session callback context (owned by session; freed on host_stop) */
    struct yamux_cb_ctx *yamux_cb;
    /* Ready signaling to avoid polling during shutdown */
    pthread_mutex_t ready_mtx;
    pthread_cond_t ready_cv;
    int is_quic; /* when set, muxer/conn belong to QUIC session (no yamux thread) */
    struct session_node *next;
} session_node_t;

typedef struct event_node
{
    libp2p_event_t evt;
    struct event_node *next;
} event_node_t;

/* Separate queue for async subscriber dispatch */
typedef struct dispatch_node
{
    libp2p_event_t evt;
    struct dispatch_node *next;
} dispatch_node_t;

/* Per-protocol server options (selected fields) tracked for listeners */
typedef struct proto_server_cfg
{
    char *proto;                           /* protocol id */
    int handshake_timeout_ms;              /* multistream-select timeout override */
    size_t max_inflight_application_bytes; /* push-mode inflight cap (not yet enforced) */
    int require_identified_peer;           /* if true, require Identify success (not yet enforced) */
    struct proto_server_cfg *next;
} proto_server_cfg_t;

/* Track active streams for optional reuse */
typedef struct stream_entry
{
    struct libp2p_stream *s;
    const char *protocol_id; /* borrowed from stream */
    const char *remote_addr; /* borrowed from stream */
    int initiator;
    struct stream_entry *next;
} stream_entry_t;

/* Implementation of forward-declared subscription type */
struct libp2p_subscription
{
    libp2p_event_cb cb;
    void *user_data;
    struct libp2p_subscription *next;
};

/* Main host object (internal layout) */
struct libp2p_host
{
    libp2p_host_options_t opts;
    pthread_mutex_t mtx;

    /* Registered protocols (exact match for initial skeleton) */
    protocol_entry_t *protocols;

    /* Registered protocol matchers (prefix/semver) */
    protocol_match_entry_t *matchers;

    /* Transports: one or more (e.g., TCP, QUIC) */
    libp2p_transport_t **transports;
    size_t num_transports;
    /* Minimal security + mux defaults (Noise + Yamux) */
    libp2p_security_t *noise;
    libp2p_muxer_t *yamux; /* placeholder for generic muxers list */

    /* Optional peerstore */
    libp2p_peerstore_t *peerstore;

    /* Optional connection gater */
    libp2p_conn_gater_fn gater_fn;
    void *gater_ud;

    /* Optional managers */
    libp2p_conn_mgr_t *conn_mgr;

    /* Event bus: simple subscription list and queue for pull API */
    struct libp2p_subscription *subs; /* forward-declared in events.h */
    struct event_node *evt_head;
    struct event_node *evt_tail;
    pthread_cond_t evt_cv;

    /* Worker lifecycle synchronization: signal when worker_count reaches 0 */
    pthread_cond_t worker_cv;

    /* Async event dispatch to subscribers */
    pthread_t disp_thread;
    int disp_thread_started;
    int disp_stop;
    dispatch_node_t *disp_head;
    dispatch_node_t *disp_tail;
    size_t disp_len;
    size_t disp_max;
    pthread_cond_t disp_cv;

    /* Teardown mode: when set, event dispatch enqueue never blocks.
     * This shields host_stop and listener shutdown paths from subscriber stalls. */
    int tearing_down;

    /* Single-threaded application callback executor (protocol/dial on_open) */
    pthread_t cb_thread;
    int cb_thread_started;
    int cb_stop;
    struct cb_task_node *cb_head;
    struct cb_task_node *cb_tail;
    pthread_cond_t cb_cv;

    /* Listener management */
    atomic_int running;              /* host_start() -> 1, host_stop() -> 0 */
    struct listener_node *listeners; /* linked list of active listeners */
    struct session_node *sessions;   /* linked list of inbound sessions */

    /* Active streams registry (for reuse) */
    stream_entry_t *active_streams;

    /* Registered per-protocol server option overrides */
    proto_server_cfg_t *proto_cfgs;

    /* Local identity */
    uint8_t *identity_key;   /* raw private key bytes from PrivateKey.Data */
    size_t identity_key_len; /* length of identity_key */
    int identity_type;       /* 0=RSA,1=Ed25519,2=Secp256k1,3=ECDSA */
    int have_identity;       /* 1 if set via libp2p_host_set_private_key */
    peer_id_t local_peer;    /* derived local Peer ID (bytes allocated when have_identity=1) */

    /* Built-in services */
    struct libp2p_protocol_server *identify_server;      /* minimal /ipfs/id/1.0.0 responder */
    struct libp2p_protocol_server *identify_push_server; /* /ipfs/id/push/1.0.0 updates */
    /* Internal subscriptions */
    struct libp2p_subscription *identify_push_sub;

    /* Detached worker threads (identify, substream workers, async openers). */
    atomic_int worker_count;

    /* Optional metrics sink */
    libp2p_metrics_t *metrics;

    /* Identify Push publication state (event-driven, no busy-wait) */
    int idpush_pending;   /* set when LOCAL_PROTOCOLS_UPDATED occurs or retry needed */
    int idpush_inflight;  /* set while an async publisher is running */
    int idpush_attempts;  /* bounded attempts to avoid storms */

    /* Connection pool for QUIC session reuse (reduces CPU by reusing connections) */
    libp2p_conn_pool_t *conn_pool;
};

/* Internal helper to enqueue an event for pull-based APIs and notify waiters. */
void libp2p__enqueue_event(struct libp2p_host *host, const libp2p_event_t *evt);

/* Select a transport capable of handling the given multiaddr, or NULL. */
libp2p_transport_t *libp2p__host_select_transport(const struct libp2p_host *host, const multiaddr_t *addr);

/* No ping-specific helpers; stream accounting handled by resource manager. */

/* Worker lifecycle helpers */
void libp2p__worker_inc(struct libp2p_host *host);
void libp2p__worker_dec(struct libp2p_host *host);

/* Async dispatcher lifecycle */
int libp2p__event_dispatcher_start(struct libp2p_host *host);
void libp2p__event_dispatcher_stop(struct libp2p_host *host);

/* Callback executor (single-thread) lifecycle + enqueue */
typedef void (*libp2p_cbexec_fn)(void *user_data);
int libp2p__cbexec_start(struct libp2p_host *host);
void libp2p__cbexec_stop(struct libp2p_host *host);
void libp2p__exec_on_cb_thread(struct libp2p_host *host, libp2p_cbexec_fn fn, void *user_data);

/* Proactively schedule an Identify Push publication once (non-blocking). */
void libp2p__schedule_identify_push(struct libp2p_host *host);

/* Internal publish service (Identify Push encapsulation) */
int libp2p_publish_service_start(struct libp2p_host *host);
void libp2p_publish_service_stop(struct libp2p_host *host);

/* === Shared upgrader helpers (internal) === */
/* Upgrade an outbound raw connection using host defaults.
 * When allow_mplex is non-zero, include mplex as a fallback muxer. On error,
 * publishes OUTGOING_CONNECTION_ERROR and frees the raw connection. On success,
 * returns a newly allocated uconn carrying secured conn, selected muxer and
 * remote peer (caller assumes ownership and must free the uconn struct). */
int libp2p__host_upgrade_outbound(struct libp2p_host *host,
                                  struct libp2p_connection *raw,
                                  const peer_id_t *remote_hint,
                                  int allow_mplex,
                                 libp2p_uconn_t **out_uc);

/* Upgrade an inbound raw connection using host defaults.
 * When allow_mplex is non-zero, include mplex as a fallback muxer. On error,
 * publishes INCOMING_CONNECTION_ERROR and frees the raw connection. On success,
 * returns a newly allocated uconn carrying secured conn, selected muxer and
 * remote peer (caller assumes ownership and must free the uconn struct). */
int libp2p__host_upgrade_inbound(struct libp2p_host *host,
                                 struct libp2p_connection *raw,
                                 int allow_mplex,
                                 libp2p_uconn_t **out_uc);

/* QUIC-specific bypass helpers: construct a uconn directly from a QUIC
 * session-bound libp2p_conn_t. No security or muxer negotiation performed. */
int libp2p__host_upgrade_outbound_quic(struct libp2p_host *host,
                                       struct libp2p_connection *session_conn,
                                       libp2p_uconn_t **out_uc);

int libp2p__host_upgrade_inbound_quic(struct libp2p_host *host,
                                      struct libp2p_connection *session_conn,
                                      libp2p_uconn_t **out_uc);

void libp2p__host_set_quic_muxer_factory(libp2p_muxer_t *(*factory)(struct libp2p_host *host,
                                                                   libp2p_quic_session_t *session,
                                                                   const multiaddr_t *local,
                                                                   const multiaddr_t *remote,
                                                                   struct libp2p_connection *conn));

/* === Event emission helpers (internal) === */
void libp2p__emit_dialing(struct libp2p_host *host, const char *addr);
void libp2p__emit_outgoing_error(struct libp2p_host *host, libp2p_err_t code, const char *msg);
void libp2p__emit_incoming_error(struct libp2p_host *host, libp2p_err_t code, const char *msg);
void libp2p__emit_incoming_error_with_peer(struct libp2p_host *host, const peer_id_t *peer, libp2p_err_t code, const char *msg);
void libp2p__emit_conn_opened(struct libp2p_host *host, bool inbound, const peer_id_t *peer, const multiaddr_t *addr);
void libp2p__emit_protocol_negotiated(struct libp2p_host *host, const char *protocol_id);
void libp2p__emit_stream_opened(struct libp2p_host *host, const char *protocol_id, const peer_id_t *peer, bool initiator);
void libp2p__notify_peer_protocols_updated(struct libp2p_host *host, const peer_id_t *peer, const char *const *protocols, size_t num_protocols);

#endif /* LIBP2P_HOST_INTERNAL_H */
