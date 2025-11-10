#include "protocol/quic/protocol_quic.h"
#include "quic_internal.h"
#include "quic_listener.h"

#include "libp2p/errors.h"
#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif
#include "libp2p/log.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include "picotls.h"
#include <picotls/openssl.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include "picoquic.h"
#include "picoquic_internal.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#include "picoquic_crypto_provider_api.h"
#include "picoquic_packet_loop.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

/* --- Minimal QUIC transport skeleton ------------------------------------ */

struct quic_listener_ctx;

static bool quic_transport_matches(const libp2p_transport_t *t);

static const uint16_t VERIFY_ALGOS[] = {
    PTLS_SIGNATURE_ED25519,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    UINT16_MAX};

static void quic_log_handshake_diag(const char *reason,
                                    picoquic_cnx_t *cnx,
                                    picoquic_state_enum st,
                                    uint64_t local_err,
                                    uint64_t remote_err)
{
    char initial_cid_buf[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1] = {0};
    char local_cid_buf[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1] = {0};
    char remote_cid_buf[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1] = {0};
    char *remote_addr = NULL;
    char *local_addr = NULL;
    const char *state_name = libp2p__quic_state_name(st);

    if (cnx)
    {
        picoquic_connection_id_t initial_cid = picoquic_get_initial_cnxid(cnx);
        picoquic_connection_id_t local_cid = picoquic_get_local_cnxid(cnx);
        picoquic_connection_id_t remote_cid = picoquic_get_remote_cnxid(cnx);

        libp2p__quic_format_cid(&initial_cid, initial_cid_buf, sizeof(initial_cid_buf));
        libp2p__quic_format_cid(&local_cid, local_cid_buf, sizeof(local_cid_buf));
        libp2p__quic_format_cid(&remote_cid, remote_cid_buf, sizeof(remote_cid_buf));

        struct sockaddr *sa_remote = NULL;
        struct sockaddr *sa_local = NULL;
        picoquic_get_peer_addr(cnx, &sa_remote);
        picoquic_get_local_addr(cnx, &sa_local);
        remote_addr = libp2p__quic_sockaddr_to_string(sa_remote);
        local_addr = libp2p__quic_sockaddr_to_string(sa_local);
    }

    LP_LOGE("QUIC",
            "%s state=%s(%d) local_err=%" PRIu64 " (%s) remote_err=%" PRIu64 " (%s) "
            "initial_cid=%s local_cid=%s remote_cid=%s local_addr=%s remote_addr=%s",
            reason ? reason : "handshake diagnostic",
            state_name ? state_name : "unknown",
            st,
            local_err,
            picoquic_error_name(local_err),
            remote_err,
            picoquic_error_name(remote_err),
            initial_cid_buf[0] ? initial_cid_buf : "-",
            local_cid_buf[0] ? local_cid_buf : "-",
            remote_cid_buf[0] ? remote_cid_buf : "-",
            local_addr ? local_addr : "-",
            remote_addr ? remote_addr : "-");

    if (remote_addr)
        free(remote_addr);
    if (local_addr)
        free(local_addr);
}

int libp2p__quic_transport_copy_identity(quic_transport_ctx_t *ctx,
                                         uint8_t **out_key,
                                         size_t *out_len,
                                         uint64_t *out_type)
{
    if (!ctx || !out_key || !out_len || !out_type)
        return -1;

    *out_key = NULL;
    *out_len = 0;
    *out_type = 0;

    pthread_mutex_lock(&ctx->lock);
    if (!ctx->identity_key || ctx->identity_key_len == 0)
    {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    uint8_t *copy = (uint8_t *)malloc(ctx->identity_key_len);
    if (!copy)
    {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    memcpy(copy, ctx->identity_key, ctx->identity_key_len);
    size_t len = ctx->identity_key_len;
    uint64_t type = ctx->identity_key_type;
    pthread_mutex_unlock(&ctx->lock);

    *out_key = copy;
    *out_len = len;
    *out_type = type;
    return 0;
}

libp2p_quic_config_t libp2p__quic_transport_get_config(const quic_transport_ctx_t *ctx)
{
    if (!ctx)
        return libp2p_quic_config_default();
    return ctx->cfg;
}

void libp2p__quic_transport_clear_buffer(uint8_t *buffer, size_t len)
{
    if (!buffer || len == 0)
        return;
    memset(buffer, 0, len);
}

typedef struct quic_transport_verify_ctx
{
    ptls_verify_certificate_t super;
    libp2p_conn_t *conn;
    struct quic_listener_ctx *listener;
} quic_transport_verify_ctx_t;

static void quic_sleep_short(void)
{
#ifndef _WIN32
    usleep(2000);
#else
    Sleep(2);
#endif
}

static void quic_transport_verify_ctx_free(ptls_verify_certificate_t *self)
{
    if (!self)
        return;
    quic_transport_verify_ctx_t *ctx = (quic_transport_verify_ctx_t *)((uint8_t *)self - offsetof(quic_transport_verify_ctx_t, super));
    free(ctx);
}

static int quic_verify_sign_accept(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
    (void)verify_ctx;
    (void)algo;
    (void)data;
    (void)sign;
    return 0;
}

static int quic_transport_verify_cb(struct st_ptls_verify_certificate_t *self,
                                    ptls_t *tls,
                                    const char *server_name,
                                    int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
                                    void **verify_data,
                                    ptls_iovec_t *certs,
                                    size_t num_certs)
{
    (void)tls;
    (void)server_name;
    if (!self || !certs || num_certs == 0)
        return -1;

    quic_transport_verify_ctx_t *ctx = (quic_transport_verify_ctx_t *)((uint8_t *)self - offsetof(quic_transport_verify_ctx_t, super));
    if (!ctx)
        return -1;

    libp2p_quic_tls_identity_t ident = {0};
    if (libp2p_quic_tls_identity_from_certificate(certs[0].base, certs[0].len, &ident) != 0)
        return -1;

    if (ctx->conn)
    {
        peer_id_t *peer = ident.peer;
        ident.peer = NULL;
        if (libp2p_quic_conn_set_verified_peer(ctx->conn, peer) != 0)
        {
            if (peer)
            {
                peer_id_destroy(peer);
                free(peer);
            }
            libp2p_quic_tls_identity_clear(&ident);
            return -1;
        }
    }
    else if (ctx->listener)
    {
        peer_id_t *peer = ident.peer;
        ident.peer = NULL;
        quic_listener_store_verified_peer(ctx->listener, tls, peer);
    }

    libp2p_quic_tls_identity_clear(&ident);
    *verify_sign = quic_verify_sign_accept;
    *verify_data = ctx;
    return 0;
}

int libp2p__quic_apply_tls_key(picoquic_quic_t *quic, const uint8_t *key_der, size_t key_len)
{
    if (!quic || !key_der || key_len == 0)
        return -1;

    ptls_context_t *tls_ctx = (ptls_context_t *)quic->tls_master_ctx;
    if (!tls_ctx)
        return -1;

    const uint8_t *p = key_der;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, (long)key_len);
    if (!pkey)
        return -1;

    ptls_openssl_sign_certificate_t *signer = (ptls_openssl_sign_certificate_t *)calloc(1, sizeof(*signer));
    if (!signer)
    {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (ptls_openssl_init_sign_certificate(signer, pkey) != 0)
    {
        EVP_PKEY_free(pkey);
        free(signer);
        return -1;
    }

    EVP_PKEY_free(pkey);

    if (tls_ctx->sign_certificate != NULL)
    {
        if (picoquic_dispose_sign_certificate_fn)
            picoquic_dispose_sign_certificate_fn(tls_ctx->sign_certificate);
        else
            free(tls_ctx->sign_certificate);
        tls_ctx->sign_certificate = NULL;
    }

    tls_ctx->sign_certificate = &signer->super;
    return 0;
}

int libp2p__quic_multiaddr_to_sockaddr_udp(const multiaddr_t *addr, struct sockaddr_storage *ss, socklen_t *ss_len)
{
    if (!addr || !ss || !ss_len)
        return -1;

    const size_t n = multiaddr_nprotocols(addr);
    if (n < 3)
        return -1;

    uint64_t code0 = 0;
    if (multiaddr_get_protocol_code(addr, 0, &code0) != 0)
        return -1;

    if (code0 == MULTICODEC_IP4)
    {
        uint8_t ip[4];
        size_t ip_len = sizeof(ip);
        if (multiaddr_get_address_bytes(addr, 0, ip, &ip_len) != MULTIADDR_SUCCESS || ip_len != sizeof(ip))
            return -1;

        uint8_t pb[2];
        size_t pb_len = sizeof(pb);
        if (multiaddr_get_address_bytes(addr, 1, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != sizeof(pb))
            return -1;

        struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
        memset(v4, 0, sizeof(*v4));
        v4->sin_family = AF_INET;
#ifdef __APPLE__
        v4->sin_len = sizeof(*v4);
#endif
        memcpy(&v4->sin_addr, ip, sizeof(ip));
        v4->sin_port = htons((uint16_t)((pb[0] << 8) | pb[1]));
        *ss_len = sizeof(*v4);
        return 0;
    }

#ifdef AF_INET6
    if (code0 == MULTICODEC_IP6)
    {
        uint8_t ip6[16];
        size_t ip6_len = sizeof(ip6);
        if (multiaddr_get_address_bytes(addr, 0, ip6, &ip6_len) != MULTIADDR_SUCCESS || ip6_len != sizeof(ip6))
            return -1;

        size_t idx = 1;
        uint64_t code = 0;
        if (multiaddr_get_protocol_code(addr, idx, &code) != 0)
            return -1;

        char zonebuf[IFNAMSIZ] = {0};
        unsigned long zone_index = 0;

        if (code == MULTICODEC_IP6ZONE)
        {
            size_t zl = IFNAMSIZ - 1;
            if (multiaddr_get_address_bytes(addr, idx, (uint8_t *)zonebuf, &zl) != MULTIADDR_SUCCESS || zl == 0)
                return -1;
            zonebuf[zl] = '\0';
#if defined(__APPLE__) || defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
            zone_index = if_nametoindex(zonebuf);
#elif defined(_WIN32)
            zone_index = if_nametoindex(zonebuf);
#else
            zone_index = 0;
#endif
            idx++;
            if (idx >= n || multiaddr_get_protocol_code(addr, idx, &code) != 0)
                return -1;
        }

        if (code != MULTICODEC_UDP)
            return -1;

        uint8_t pb[2];
        size_t pb_len = sizeof(pb);
        if (multiaddr_get_address_bytes(addr, idx, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != sizeof(pb))
            return -1;

        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
        memset(v6, 0, sizeof(*v6));
        v6->sin6_family = AF_INET6;
#ifdef __APPLE__
        v6->sin6_len = sizeof(*v6);
#endif
        memcpy(&v6->sin6_addr, ip6, sizeof(ip6));
        v6->sin6_port = htons((uint16_t)((pb[0] << 8) | pb[1]));
        v6->sin6_scope_id = (uint32_t)zone_index;
        *ss_len = sizeof(*v6);
        return 0;
    }
#endif

    return -1;
}

multiaddr_t *libp2p__quic_multiaddr_from_sockaddr(const struct sockaddr *sa, socklen_t len)
{
    if (!sa)
        return NULL;
    char buf[INET6_ADDRSTRLEN] = {0};
    char zonebuf[IFNAMSIZ] = {0};
    char ma_str[128] = {0};

    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in))
    {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)sa;
        if (!inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf)))
            return NULL;
        snprintf(ma_str, sizeof(ma_str), "/ip4/%s/udp/%u", buf, (unsigned)ntohs(v4->sin_port));
    }
#ifdef AF_INET6
    else if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6))
    {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
        if (!inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf)))
            return NULL;
        if (v6->sin6_scope_id)
        {
#if defined(__APPLE__) || defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(_WIN32)
            if (if_indextoname(v6->sin6_scope_id, zonebuf))
                snprintf(ma_str, sizeof(ma_str), "/ip6/%s/ip6zone/%s/udp/%u", buf, zonebuf, (unsigned)ntohs(v6->sin6_port));
            else
                snprintf(ma_str, sizeof(ma_str), "/ip6/%s/udp/%u", buf, (unsigned)ntohs(v6->sin6_port));
#else
            snprintf(ma_str, sizeof(ma_str), "/ip6/%s/udp/%u", buf, (unsigned)ntohs(v6->sin6_port));
#endif
        }
        else
        {
            snprintf(ma_str, sizeof(ma_str), "/ip6/%s/udp/%u", buf, (unsigned)ntohs(v6->sin6_port));
        }
    }
#endif
    else
    {
        return NULL;
    }

    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str(ma_str, &err);
    if (err != 0)
    {
        if (ma)
            multiaddr_free(ma);
        return NULL;
    }
    return ma;
}

static void quic_sni_from_sockaddr(const struct sockaddr *sa, char *buf, size_t len)
{
    if (!buf || len == 0)
        return;
    buf[0] = '\0';
    if (!sa)
        return;
    switch (sa->sa_family)
    {
        case AF_INET:
            inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buf, len);
            break;
#ifdef AF_INET6
        case AF_INET6:
            inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf, len);
            break;
#endif
        default:
            break;
    }
    if (buf[0] == '\0')
        snprintf(buf, len, "localhost");
}

static libp2p_transport_err_t quic_wait_for_ready(libp2p_quic_session_t *session,
                                                  picoquic_cnx_t *cnx,
                                                  uint64_t timeout_ms)
{
    const uint64_t default_timeout = 10000ULL; /* 10 seconds */
    const uint64_t limit_ms = timeout_ms ? timeout_ms : default_timeout;
    const uint64_t deadline = picoquic_current_time() + (limit_ms * 1000ULL);

    picoquic_state_enum last_state = (picoquic_state_enum)(-1);
    for (;;)
    {
        picoquic_state_enum st = picoquic_get_cnx_state(cnx);
        if (st != last_state)
        {
            LP_LOGT("QUIC", "wait state=%s(%d)", libp2p__quic_state_name(st), st);
            last_state = st;
        }
        if (st == picoquic_state_ready)
            return LIBP2P_TRANSPORT_OK;
        if (st == picoquic_state_disconnected || st == picoquic_state_handshake_failure ||
            st == picoquic_state_handshake_failure_resend || st == picoquic_state_disconnecting ||
            st == picoquic_state_closing || st == picoquic_state_closing_received || st == picoquic_state_draining)
        {
            uint64_t local_err = picoquic_get_local_error(cnx);
            uint64_t remote_err = picoquic_get_remote_error(cnx);
            quic_log_handshake_diag("handshake failed", cnx, st, local_err, remote_err);
            return LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
        }

        if (picoquic_current_time() > deadline)
        {
            uint64_t local_err = picoquic_get_local_error(cnx);
            uint64_t remote_err = picoquic_get_remote_error(cnx);
            quic_log_handshake_diag("handshake timeout", cnx, st, local_err, remote_err);
            return LIBP2P_TRANSPORT_ERR_TIMEOUT;
        }

        libp2p__quic_session_wake(session);
        quic_sleep_short();
    }
}

static int quic_state_finished(picoquic_state_enum st)
{
    switch (st)
    {
        case picoquic_state_disconnected:
        case picoquic_state_draining:
        case picoquic_state_handshake_failure:
        case picoquic_state_handshake_failure_resend:
            return 1;
        default:
            return 0;
    }
}

static void quic_transport_session_close(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    picoquic_cnx_t *cnx = libp2p__quic_session_native(session);
    if (cnx)
    {
        picoquic_state_enum state_before = picoquic_get_cnx_state(cnx);
        uint64_t local_err = picoquic_get_local_error(cnx);
        uint64_t remote_err = picoquic_get_remote_error(cnx);
        uint64_t app_err = picoquic_get_application_error(cnx);
        LP_LOGW("QUIC",
                "session_close begin session=%p cnx=%p state=%s(%d) client=%d local_err=%" PRIu64 " (%s) remote_err=%" PRIu64 " (%s) app_err=%" PRIu64,
                (void *)session,
                (void *)cnx,
                libp2p__quic_state_name(state_before),
                (int)state_before,
                picoquic_is_client(cnx),
                local_err,
                picoquic_error_name(local_err),
                remote_err,
                picoquic_error_name(remote_err),
                app_err);
        (void)picoquic_close(cnx, 0);
        libp2p__quic_session_wake(session);
        picoquic_state_enum st = picoquic_get_cnx_state(cnx);
        uint64_t elapsed = 0;
        if (!quic_state_finished(st))
        {
            const uint64_t start = picoquic_current_time();
            const uint64_t deadline = start + 2000000ULL; /* ~2 s */
            while (!quic_state_finished(st))
            {
                quic_sleep_short();
                libp2p__quic_session_wake(session);
                st = picoquic_get_cnx_state(cnx);
                if (picoquic_current_time() >= deadline)
                    break;
            }
            elapsed = picoquic_current_time() - start;
        }
        uint64_t final_local = picoquic_get_local_error(cnx);
        uint64_t final_remote = picoquic_get_remote_error(cnx);
        uint64_t final_app = picoquic_get_application_error(cnx);
        LP_LOGD("QUIC",
                "session_close end session=%p cnx=%p state=%s(%d) elapsed_us=%" PRIu64 " local_err=%" PRIu64 " (%s) remote_err=%" PRIu64 " (%s) app_err=%" PRIu64,
                (void *)session,
                (void *)cnx,
                libp2p__quic_state_name(st),
                (int)st,
                elapsed,
                final_local,
                picoquic_error_name(final_local),
                final_remote,
                picoquic_error_name(final_remote),
                final_app);
    }
    libp2p__quic_session_wake(session);
}

static void quic_transport_session_free(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    picoquic_quic_t *quic = libp2p__quic_session_quic(session);
    picoquic_cnx_t *cnx = libp2p__quic_session_native(session);
    if (cnx)
        picoquic_set_callback(cnx, NULL, NULL);
    libp2p__quic_session_stop_loop(session);
    if (quic)
        picoquic_free(quic);
    libp2p__quic_session_release(session);
}

/* Local helper mirroring TCP's transport code set */
static inline bool quic_is_transport_code(uint64_t code)
{
    switch (code)
    {
        case MULTICODEC_UDP:               /* /udp */
        case MULTICODEC_QUIC_V1:           /* /quic-v1 */
        case MULTICODEC_WS:                /* /ws */
        case MULTICODEC_WSS:               /* /wss */
        case MULTICODEC_TLS:               /* /tls */
        case MULTICODEC_WEBRTC:            /* /webrtc */
        case MULTICODEC_WEBRTC_DIRECT:     /* /webrtc-direct */
        case MULTICODEC_WEBTRANSPORT:      /* /webtransport */
        case MULTICODEC_P2P_WEBRTC_STAR:   /* /p2p-webrtc-star */
        case MULTICODEC_P2P_WEBRTC_DIRECT: /* /p2p-webrtc-direct */
            return true;
        default:
            return false;
    }
}

static bool quic_can_handle(const multiaddr_t *addr)
{
    if (addr == NULL)
        return false;

    size_t n = multiaddr_nprotocols(addr);
    if (n < 3)
        return false; /* need ip + udp + quic* */

    uint64_t code = 0;
    if (multiaddr_get_protocol_code(addr, 0, &code) != 0)
        return false;

    if (!(code == MULTICODEC_IP4 || code == MULTICODEC_IP6))
        return false;

    size_t idx = 1; /* after ip4/ip6 */
    uint64_t current = 0;
    if (idx >= n || multiaddr_get_protocol_code(addr, idx, &current) != 0)
        return false;

    if (code == MULTICODEC_IP6 && current == MULTICODEC_IP6ZONE)
    {
        idx++;
        if (idx >= n || multiaddr_get_protocol_code(addr, idx, &current) != 0)
            return false;
    }

    if (current != MULTICODEC_UDP)
        return false;

    /* expect quic or quic-v1 next */
    if (idx + 1 >= n)
        return false;
    uint64_t next = 0;
    if (multiaddr_get_protocol_code(addr, idx + 1, &next) != 0)
        return false;
    if (!(next == MULTICODEC_QUIC_V1 || next == MULTICODEC_QUIC))
        return false;

    /* reject if additional transport layering follows (allow /p2p, etc.) */
    if (idx + 2 < n)
    {
        uint64_t after = 0;
        if (multiaddr_get_protocol_code(addr, idx + 2, &after) == 0 && quic_is_transport_code(after))
            return false;
    }

    return true;
}

static libp2p_transport_err_t quic_dial(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out)
{
    if (!self || !self->ctx || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;

    *out = NULL;

    if (!quic_can_handle(addr))
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;

    quic_transport_ctx_t *ctx = (quic_transport_ctx_t *)self->ctx;
    struct sockaddr_storage remote_ss;
    socklen_t remote_len = 0;
    if (libp2p__quic_multiaddr_to_sockaddr_udp(addr, &remote_ss, &remote_len) != 0)
        return LIBP2P_TRANSPORT_ERR_INVALID_ARG;

    uint8_t *identity_copy = NULL;
    size_t identity_len = 0;
    uint64_t identity_type = 0;
    uint32_t dial_timeout_ms = 0;

    pthread_mutex_lock(&ctx->lock);
    if (ctx->identity_key && ctx->identity_key_len > 0)
    {
        identity_copy = (uint8_t *)malloc(ctx->identity_key_len);
        if (identity_copy)
        {
            memcpy(identity_copy, ctx->identity_key, ctx->identity_key_len);
            identity_len = ctx->identity_key_len;
            identity_type = ctx->identity_key_type;
        }
    }
    dial_timeout_ms = ctx->dial_timeout_ms;
    pthread_mutex_unlock(&ctx->lock);

    if (!identity_copy || identity_len == 0)
    {
        if (identity_copy)
        {
            memset(identity_copy, 0, identity_len);
            free(identity_copy);
        }
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p_quic_tls_cert_options_t cert_opts = libp2p_quic_tls_cert_options_default();
    cert_opts.identity_key_type = identity_type;
    cert_opts.identity_key = identity_copy;
    cert_opts.identity_key_len = identity_len;

    libp2p_quic_tls_certificate_t cert;
    memset(&cert, 0, sizeof(cert));
    if (libp2p_quic_tls_generate_certificate(&cert_opts, &cert) != 0)
    {
        memset(identity_copy, 0, identity_len);
        free(identity_copy);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    memset(identity_copy, 0, identity_len);
    free(identity_copy);
    identity_copy = NULL;
    identity_len = 0;

    picoquic_quic_t *quic = picoquic_create(1,
                                            NULL,
                                            NULL,
                                            NULL,
                                            ctx->cfg.alpn,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            picoquic_current_time(),
                                            NULL,
                                            NULL,
                                            NULL,
                                            0);
    if (!quic)
    {
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    picoquic_set_default_lossbit_policy(quic, picoquic_lossbit_none);

    picoquic_tp_t client_tp = *picoquic_get_default_tp(quic);
    client_tp.enable_loss_bit = 0;
    client_tp.min_ack_delay = 0;
    if (picoquic_set_default_tp(quic, &client_tp) != 0)
    {
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    LP_LOGD("QUIC",
            "client transport params configured loss_bit=%d min_ack_delay=%" PRIu64,
            client_tp.enable_loss_bit,
            client_tp.min_ack_delay);

    ptls_iovec_t *chain = (ptls_iovec_t *)calloc(1, sizeof(*chain));
    if (!chain)
    {
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    chain[0].base = cert.cert_der;
    chain[0].len = cert.cert_len;
    picoquic_set_tls_certificate_chain(quic, chain, 1);
    cert.cert_der = NULL;
    cert.cert_len = 0;

    if (libp2p__quic_apply_tls_key(quic, cert.key_der, cert.key_len) != 0)
    {
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    quic_transport_verify_ctx_t *verify_ctx = (quic_transport_verify_ctx_t *)calloc(1, sizeof(*verify_ctx));
    if (!verify_ctx)
    {
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    verify_ctx->super.cb = quic_transport_verify_cb;
    verify_ctx->super.algos = VERIFY_ALGOS;
    verify_ctx->conn = NULL;

    char sni[INET6_ADDRSTRLEN] = {0};
    quic_sni_from_sockaddr((struct sockaddr *)&remote_ss, sni, sizeof(sni));

    picoquic_cnx_t *cnx = picoquic_create_cnx(quic,
                                              picoquic_null_connection_id,
                                              picoquic_null_connection_id,
                                              (struct sockaddr *)&remote_ss,
                                              picoquic_current_time(),
                                              0,
                                              (sni[0] != '\0') ? sni : NULL,
                                              ctx->cfg.alpn,
                                              1);
    if (!cnx)
    {
        quic_transport_verify_ctx_free(&verify_ctx->super);
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p_quic_session_t *session = libp2p__quic_session_wrap(quic, cnx);
    if (!session)
    {
        quic_transport_verify_ctx_free(&verify_ctx->super);
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p_conn_t *conn = libp2p_quic_conn_new(NULL, addr, session, quic_transport_session_close, quic_transport_session_free, NULL);
    if (!conn)
    {
        quic_transport_verify_ctx_free(&verify_ctx->super);
        quic_transport_session_free(session);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    verify_ctx->conn = conn;
    picoquic_set_verify_certificate_callback(quic, &verify_ctx->super, quic_transport_verify_ctx_free);
    picoquic_set_client_authentication(quic, 1);
    libp2p__quic_configure_textlog(quic);
    picoquic_set_default_padding(quic, 0, 1200);
    quic->dont_coalesce_init = 1; /* keep Initial datagrams padded instead of relying on coalescing */

    libp2p_transport_err_t result = LIBP2P_TRANSPORT_ERR_INTERNAL;

    if (picoquic_start_client_cnx(cnx) != 0)
    {
        result = LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
        goto fail;
    }

    if (libp2p__quic_session_start_loop(session, NULL, addr) != 0)
    {
        goto fail;
    }

    libp2p__quic_session_wake(session);

    result = quic_wait_for_ready(session, cnx, dial_timeout_ms);
    if (result != LIBP2P_TRANSPORT_OK)
        goto fail;

    peer_id_t *tmp_peer = NULL;
    if (libp2p_quic_conn_copy_verified_peer(conn, &tmp_peer) != 0 || !tmp_peer)
    {
        if (tmp_peer)
        {
            peer_id_destroy(tmp_peer);
            free(tmp_peer);
        }
        result = LIBP2P_TRANSPORT_ERR_DIAL_FAIL;
        goto fail;
    }
    peer_id_destroy(tmp_peer);
    free(tmp_peer);

    struct sockaddr *local_sa = NULL;
    picoquic_get_local_addr(cnx, &local_sa);
    if (local_sa)
    {
        struct sockaddr_storage local_copy;
        memset(&local_copy, 0, sizeof(local_copy));
        socklen_t local_len = 0;
        if (local_sa->sa_family == AF_INET)
        {
            memcpy(&local_copy, local_sa, sizeof(struct sockaddr_in));
            local_len = sizeof(struct sockaddr_in);
        }
#ifdef AF_INET6
        else if (local_sa->sa_family == AF_INET6)
        {
            memcpy(&local_copy, local_sa, sizeof(struct sockaddr_in6));
            local_len = sizeof(struct sockaddr_in6);
        }
#endif
        multiaddr_t *local_ma = libp2p__quic_multiaddr_from_sockaddr((struct sockaddr *)&local_copy, local_len);
        if (local_ma)
        {
            (void)libp2p_quic_conn_set_local(conn, local_ma);
            multiaddr_free(local_ma);
        }
    }

    libp2p_quic_tls_certificate_clear(&cert);
    *out = conn;
    return LIBP2P_TRANSPORT_OK;

fail:
    if (conn)
    {
        libp2p_conn_close(conn);
        libp2p_conn_free(conn);
    }
    libp2p_quic_tls_certificate_clear(&cert);
    return result;
}

static libp2p_transport_err_t quic_listen(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out)
{
    if (!self || !self->ctx || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;

    if (!quic_transport_matches(self))
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;

    if (!quic_can_handle(addr))
        return LIBP2P_TRANSPORT_ERR_UNSUPPORTED;

    quic_transport_ctx_t *ctx = (quic_transport_ctx_t *)self->ctx;

    libp2p_listener_t *listener = NULL;
    libp2p_transport_err_t rc = quic_listener_create(self, ctx, addr, &listener);
    if (rc != LIBP2P_TRANSPORT_OK)
        return rc;

    quic_listener_ctx_t *lctx = (quic_listener_ctx_t *)atomic_load_explicit(&listener->ctx, memory_order_acquire);
    if (!lctx)
    {
        libp2p_listener_free(listener);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    quic_transport_verify_ctx_t *verify_ctx = (quic_transport_verify_ctx_t *)calloc(1, sizeof(*verify_ctx));
    if (!verify_ctx)
    {
        libp2p_listener_free(listener);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    verify_ctx->super.cb = quic_transport_verify_cb;
    verify_ctx->super.algos = VERIFY_ALGOS;
    verify_ctx->conn = NULL;
    verify_ctx->listener = lctx;

    picoquic_quic_t *quic = quic_listener_get_quic(lctx);
    picoquic_set_verify_certificate_callback(quic, &verify_ctx->super, quic_transport_verify_ctx_free);

    if (quic_listener_start(lctx) != 0)
    {
        picoquic_set_verify_certificate_callback(quic, NULL, NULL);
        libp2p_listener_free(listener);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    *out = listener;
    return LIBP2P_TRANSPORT_OK;
}

int libp2p_quic_transport_set_identity(libp2p_transport_t *t, const libp2p_quic_tls_cert_options_t *opts)
{
    if (!quic_transport_matches(t))
        return LIBP2P_ERR_UNSUPPORTED;
    if (!t->ctx)
        return LIBP2P_ERR_NULL_PTR;

    quic_transport_ctx_t *ctx = (quic_transport_ctx_t *)t->ctx;
    pthread_mutex_lock(&ctx->lock);
    if (ctx->identity_key)
    {
        memset(ctx->identity_key, 0, ctx->identity_key_len);
        free(ctx->identity_key);
        ctx->identity_key = NULL;
        ctx->identity_key_len = 0;
        ctx->identity_key_type = 0;
    }

    if (opts && opts->identity_key && opts->identity_key_len > 0)
    {
        ctx->identity_key = (uint8_t *)malloc(opts->identity_key_len);
        if (!ctx->identity_key)
        {
            pthread_mutex_unlock(&ctx->lock);
            return LIBP2P_ERR_INTERNAL;
        }
        memcpy(ctx->identity_key, opts->identity_key, opts->identity_key_len);
        ctx->identity_key_len = opts->identity_key_len;
        ctx->identity_key_type = opts->identity_key_type;
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int libp2p_quic_transport_set_dial_timeout(libp2p_transport_t *t, uint32_t timeout_ms)
{
    if (!quic_transport_matches(t))
        return LIBP2P_ERR_UNSUPPORTED;
    if (!t->ctx)
        return LIBP2P_ERR_NULL_PTR;
    quic_transport_ctx_t *ctx = (quic_transport_ctx_t *)t->ctx;
    pthread_mutex_lock(&ctx->lock);
    ctx->dial_timeout_ms = timeout_ms;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

static libp2p_transport_err_t quic_close(libp2p_transport_t *self)
{
    (void)self;
    return LIBP2P_TRANSPORT_OK;
}

static void quic_free(libp2p_transport_t *self)
{
    if (!self)
        return;
    if (self->ctx)
    {
        quic_transport_ctx_t *ctx = (quic_transport_ctx_t *)self->ctx;
        pthread_mutex_lock(&ctx->lock);
        if (ctx->identity_key)
        {
            memset(ctx->identity_key, 0, ctx->identity_key_len);
            free(ctx->identity_key);
            ctx->identity_key = NULL;
            ctx->identity_key_len = 0;
            ctx->identity_key_type = 0;
        }
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        self->ctx = NULL;
    }
    free(self);
}

static const libp2p_transport_vtbl_t QUIC_VTBL = {
    .can_handle = quic_can_handle,
    .dial = quic_dial,
    .listen = quic_listen,
    .close = quic_close,
    .free = quic_free,
};

static bool quic_transport_matches(const libp2p_transport_t *t)
{
    return t && t->vt == &QUIC_VTBL;
}

libp2p_transport_t *libp2p_quic_transport_new(const libp2p_quic_config_t *cfg)
{
    libp2p_quic_config_t effective = cfg ? *cfg : libp2p_quic_config_default();
    if (!effective.alpn)
        effective.alpn = LIBP2P_QUIC_TLS_ALPN;

    libp2p_transport_t *t = (libp2p_transport_t *)calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    quic_transport_ctx_t *state = (quic_transport_ctx_t *)calloc(1, sizeof(*state));
    if (!state)
    {
        free(t);
        return NULL;
    }
    if (pthread_mutex_init(&state->lock, NULL) != 0)
    {
        free(state);
        free(t);
        return NULL;
    }
    state->cfg = effective;
    state->identity_key = NULL;
    state->identity_key_len = 0;
    state->identity_key_type = 0;
    state->dial_timeout_ms = 0;
    t->vt = &QUIC_VTBL;
    t->ctx = state;
    return t;
}

bool libp2p_quic_transport_is(const libp2p_transport_t *t)
{
    return quic_transport_matches(t);
}
