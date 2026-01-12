#ifndef LIBP2P_QUIC_INTERNAL_H
#define LIBP2P_QUIC_INTERNAL_H

#include "protocol/quic/protocol_quic.h"

#include "multiformats/multiaddr/multiaddr.h"

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_set_textlog.h"

#include <limits.h>

static inline void libp2p__quic_configure_textlog(picoquic_quic_t *quic)
{
    const char *path = getenv("LIBP2P_QUIC_TEXTLOG");
    if (!path || path[0] == '\0') {
        return;
    }
    picoquic_set_textlog(quic, path);
}

static inline int libp2p__quic_socket_buffer_size(void)
{
    const char *env = getenv("LANTERN_QUIC_SOCKET_BUFFER");
    if (env && env[0] != '\0') {
        char *endptr = NULL;
        unsigned long val = strtoul(env, &endptr, 10);
        if (endptr && endptr != env && *endptr == '\0' && val > 0 && val <= INT_MAX) {
            return (int)val;
        }
    }
    return 4 * 1024 * 1024;
}

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <stdio.h>
#include <stdlib.h>
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

/* Disable and detach a session's cnx pointer so other threads stop using it. */
void libp2p__quic_session_disable_cnx(libp2p_quic_session_t *session);

/* Set external quic mutex for listener sessions.
 * For sessions sharing a picoquic context (listener inbound connections),
 * this allows them to use the listener's mutex instead of their own. */
void libp2p__quic_session_set_quic_mtx(libp2p_quic_session_t *session, pthread_mutex_t *mtx);

/* Get the quic mutex for this session.
 * Returns the active mutex (own or listener's) that should be used to protect
 * picoquic API calls that manipulate internal data structures. */
pthread_mutex_t *libp2p__quic_session_get_quic_mtx(libp2p_quic_session_t *session);

/* Record packet loop IO stats for diagnostics. */
void libp2p__quic_session_note_rx(libp2p_quic_session_t *session, uint64_t now_ms);
void libp2p__quic_session_note_tx(libp2p_quic_session_t *session, uint64_t now_ms);
void libp2p__quic_session_get_io_stats(libp2p_quic_session_t *session,
                                       uint64_t *last_rx_ms,
                                       uint64_t *last_tx_ms,
                                       uint64_t *rx_count,
                                       uint64_t *tx_count);
uint16_t libp2p__quic_session_last_local_port(libp2p_quic_session_t *session);

picoquic_quic_t *libp2p__quic_session_quic(libp2p_quic_session_t *session);

picoquic_cnx_t *libp2p__quic_session_native(libp2p_quic_session_t *session);

void libp2p__quic_session_wake(libp2p_quic_session_t *session);

/* Flush queued outgoing stream data on the network thread. quic_mtx must be held. */
void libp2p__quic_session_flush_outgoing_locked(libp2p_quic_session_t *session,
                                                picoquic_cnx_t *cnx);

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

static inline const char *libp2p__quic_state_name(picoquic_state_enum state)
{
    switch (state)
    {
        case picoquic_state_client_init:
            return "client_init";
        case picoquic_state_client_init_sent:
            return "client_init_sent";
        case picoquic_state_client_renegotiate:
            return "client_renegotiate";
        case picoquic_state_client_retry_received:
            return "client_retry_received";
        case picoquic_state_client_init_resent:
            return "client_init_resent";
        case picoquic_state_server_init:
            return "server_init";
        case picoquic_state_server_handshake:
            return "server_handshake";
        case picoquic_state_client_handshake_start:
            return "client_handshake_start";
        case picoquic_state_handshake_failure:
            return "handshake_failure";
        case picoquic_state_handshake_failure_resend:
            return "handshake_failure_resend";
        case picoquic_state_client_almost_ready:
            return "client_almost_ready";
        case picoquic_state_server_false_start:
            return "server_false_start";
        case picoquic_state_server_almost_ready:
            return "server_almost_ready";
        case picoquic_state_client_ready_start:
            return "client_ready_start";
        case picoquic_state_ready:
            return "ready";
        case picoquic_state_disconnecting:
            return "disconnecting";
        case picoquic_state_closing_received:
            return "closing_received";
        case picoquic_state_closing:
            return "closing";
        case picoquic_state_draining:
            return "draining";
        case picoquic_state_disconnected:
            return "disconnected";
        default:
            return "unknown";
    }
}

static inline const char *libp2p__quic_event_name(picoquic_call_back_event_t event)
{
    switch (event)
    {
        case picoquic_callback_stream_data:
            return "stream_data";
        case picoquic_callback_stream_fin:
            return "stream_fin";
        case picoquic_callback_stream_reset:
            return "stream_reset";
        case picoquic_callback_stop_sending:
            return "stop_sending";
        case picoquic_callback_stateless_reset:
            return "stateless_reset";
        case picoquic_callback_close:
            return "connection_close";
        case picoquic_callback_application_close:
            return "application_close";
        case picoquic_callback_stream_gap:
            return "stream_gap";
        case picoquic_callback_prepare_to_send:
            return "prepare_to_send";
        case picoquic_callback_almost_ready:
            return "almost_ready";
        case picoquic_callback_ready:
            return "ready";
        case picoquic_callback_datagram:
            return "datagram";
        case picoquic_callback_version_negotiation:
            return "version_negotiation";
        case picoquic_callback_request_alpn_list:
            return "request_alpn_list";
        case picoquic_callback_set_alpn:
            return "set_alpn";
        case picoquic_callback_pacing_changed:
            return "pacing_changed";
        case picoquic_callback_prepare_datagram:
            return "prepare_datagram";
        case picoquic_callback_datagram_acked:
            return "datagram_acked";
        case picoquic_callback_datagram_lost:
            return "datagram_lost";
        case picoquic_callback_datagram_spurious:
            return "datagram_spurious";
        case picoquic_callback_path_available:
            return "path_available";
        case picoquic_callback_path_suspended:
            return "path_suspended";
        case picoquic_callback_path_deleted:
            return "path_deleted";
        case picoquic_callback_path_quality_changed:
            return "path_quality_changed";
        case picoquic_callback_path_address_observed:
            return "path_address_observed";
        case picoquic_callback_app_wakeup:
            return "app_wakeup";
        case picoquic_callback_next_path_allowed:
            return "next_path_allowed";
        default:
            return "unknown";
    }
}

static inline void libp2p__quic_format_cid(const picoquic_connection_id_t *cid, char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0)
        return;
    buf[0] = '\0';
    if (!cid || cid->id_len == 0)
        return;
    size_t pos = 0;
    for (uint8_t i = 0; i < cid->id_len && (pos + 2) < buf_len; ++i)
    {
        int written = snprintf(buf + pos, buf_len - pos, "%02x", cid->id[i]);
        if (written <= 0)
            break;
        pos += (size_t)written;
        if (pos >= buf_len - 1)
            break;
    }
    if (buf_len > 0)
        buf[buf_len - 1] = '\0';
}

static inline char *libp2p__quic_sockaddr_to_string(const struct sockaddr *sa)
{
    if (!sa)
        return NULL;

    socklen_t slen = 0;
    if (sa->sa_family == AF_INET)
        slen = (socklen_t)sizeof(struct sockaddr_in);
#ifdef AF_INET6
    else if (sa->sa_family == AF_INET6)
        slen = (socklen_t)sizeof(struct sockaddr_in6);
#endif
    else
        return NULL;

    multiaddr_t *ma = libp2p__quic_multiaddr_from_sockaddr(sa, slen);
    if (!ma)
        return NULL;

    int serr = 0;
    char *str = multiaddr_to_str(ma, &serr);
    multiaddr_free(ma);
    if (serr != 0)
    {
        if (str)
            free(str);
        return NULL;
    }
    return str;
}

#endif /* LIBP2P_QUIC_INTERNAL_H */
