#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include "libp2p/dial.h"
#include "libp2p/errors.h"
#include "libp2p/host.h"
#include "libp2p/log.h"
#include "libp2p/muxer.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"
#include "protocol/quic/protocol_quic.h"
#include "src/host/host_internal.h"

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
#include "picoquic_packet_loop.h"
#include "picoquic_crypto_provider_api.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

static void sleep_ms(unsigned ms)
{
#ifndef _WIN32
    usleep(ms * 1000);
#else
    Sleep(ms);
#endif
}

static int apply_tls_key(picoquic_quic_t *quic, const uint8_t *key_der, size_t key_len)
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

static const uint8_t SERVER_ID_KEY[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
    0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1f};

/* ED25519 PrivateKey protobuf (from peer_id tests). */
#define CLIENT_PRIVATE_KEY_HEX "080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

typedef struct quic_server_ctx
{
    pthread_mutex_t lock;
    pthread_cond_t cv;
    uint16_t port;
    int port_ready;
    picoquic_quic_t *quic;
    picoquic_network_thread_ctx_t *thread_ctx;
    picoquic_packet_loop_param_t loop_param;
    int thread_started;
} quic_server_ctx_t;

static int quic_server_stream_cb(picoquic_cnx_t *cnx,
                                 uint64_t stream_id,
                                 uint8_t *bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void *app_ctx,
                                 void *stream_ctx)
{
    (void)app_ctx;
    (void)stream_ctx;

    if (event == picoquic_callback_stream_data || event == picoquic_callback_stream_fin)
    {
        if (length > 0)
        {
            int fin = (event == picoquic_callback_stream_fin) ? 1 : 0;
            (void)picoquic_add_to_stream(cnx, stream_id, bytes, length, fin);
        }
        else if (event == picoquic_callback_stream_fin)
        {
            (void)picoquic_add_to_stream(cnx, stream_id, NULL, 0, 1);
        }
        return 0;
    }

    if (event == picoquic_callback_stop_sending)
    {
        picoquic_reset_stream(cnx, stream_id, 0);
        return 0;
    }

    return 0;
}

static uint8_t hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (uint8_t)(10 + c - 'a');
    if (c >= 'A' && c <= 'F')
        return (uint8_t)(10 + c - 'A');
    return 0;
}

static int quic_server_ctx_init(quic_server_ctx_t *ctx)
{
    if (pthread_mutex_init(&ctx->lock, NULL) != 0)
        return -1;
    if (pthread_cond_init(&ctx->cv, NULL) != 0)
    {
        pthread_mutex_destroy(&ctx->lock);
        return -1;
    }
    ctx->port = 0;
    ctx->port_ready = 0;
    ctx->quic = NULL;
    ctx->thread_ctx = NULL;
    memset(&ctx->loop_param, 0, sizeof(ctx->loop_param));
    ctx->thread_started = 0;
    return 0;
}

static void quic_server_ctx_destroy(quic_server_ctx_t *ctx)
{
    pthread_cond_destroy(&ctx->cv);
    pthread_mutex_destroy(&ctx->lock);
}

static void quic_server_set_port(quic_server_ctx_t *ctx, uint16_t port)
{
    pthread_mutex_lock(&ctx->lock);
    ctx->port = port;
    ctx->port_ready = 1;
    pthread_cond_signal(&ctx->cv);
    pthread_mutex_unlock(&ctx->lock);
}

static int quic_server_wait_for_port(quic_server_ctx_t *ctx, uint64_t timeout_ms, uint16_t *out_port)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000ULL;
    if (ts.tv_nsec >= 1000000000L)
    {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&ctx->lock);
    while (!ctx->port_ready)
    {
        int rc = pthread_cond_timedwait(&ctx->cv, &ctx->lock, &ts);
        if (rc != 0)
        {
            pthread_mutex_unlock(&ctx->lock);
            return -1;
        }
    }
    if (out_port)
        *out_port = ctx->port;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

static int quic_server_wait_thread_ready(quic_server_ctx_t *ctx, uint64_t timeout_ms)
{
    if (!ctx || !ctx->thread_ctx)
        return -1;
    uint64_t start = picoquic_current_time();
    while (!ctx->thread_ctx->thread_is_ready)
    {
        if (picoquic_current_time() - start > timeout_ms * 1000ULL)
            return -1;
        sleep_ms(1);
    }
    return 0;
}

static void quic_server_wake(quic_server_ctx_t *ctx)
{
    if (ctx && ctx->thread_ctx)
        (void)picoquic_wake_up_network_thread(ctx->thread_ctx);
}

static int quic_server_loop_cb(picoquic_quic_t *quic,
                               picoquic_packet_loop_cb_enum cb_mode,
                               void *callback_ctx,
                               void *callback_arg)
{
    (void)quic;
    quic_server_ctx_t *ctx = (quic_server_ctx_t *)callback_ctx;
    if (!ctx)
        return 0;

    if (cb_mode == picoquic_packet_loop_ready && callback_arg)
    {
        picoquic_packet_loop_options_t *opts = (picoquic_packet_loop_options_t *)callback_arg;
        opts->do_time_check = 1;
    }
    else if (cb_mode == picoquic_packet_loop_port_update && callback_arg)
    {
        const struct sockaddr *addr = (const struct sockaddr *)callback_arg;
        uint16_t port = 0;
        if (addr->sa_family == AF_INET)
        {
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
            port = ntohs(v4->sin_port);
        }
#ifdef AF_INET6
        else if (addr->sa_family == AF_INET6)
        {
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
            port = ntohs(v6->sin6_port);
        }
#endif
        if (port != 0)
            quic_server_set_port(ctx, port);
    }

    return 0;
}

static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0)
        return NULL;
    size_t bytes_len = len / 2;
    uint8_t *buf = (uint8_t *)malloc(bytes_len);
    if (!buf)
        return NULL;
    for (size_t i = 0; i < bytes_len; i++)
    {
        buf[i] = (uint8_t)((hex_value(hex[2 * i]) << 4) | hex_value(hex[2 * i + 1]));
    }
    if (out_len)
        *out_len = bytes_len;
    return buf;
}

typedef struct dial_sync
{
    pthread_mutex_t mtx;
    libp2p_stream_t *stream;
    int err;
    int done;
} dial_sync_t;

static void dial_sync_init(dial_sync_t *sync)
{
    pthread_mutex_init(&sync->mtx, NULL);
    sync->stream = NULL;
    sync->err = 0;
    sync->done = 0;
}

static void dial_sync_destroy(dial_sync_t *sync)
{
    pthread_mutex_destroy(&sync->mtx);
}

static void host_dial_on_open(libp2p_stream_t *s, void *user_data, int err)
{
    dial_sync_t *sync = (dial_sync_t *)user_data;
    if (!sync)
        return;
    pthread_mutex_lock(&sync->mtx);
    sync->stream = s;
    sync->err = err;
    sync->done = 1;
    pthread_mutex_unlock(&sync->mtx);
}

static int dial_sync_wait(dial_sync_t *sync, int timeout_ms, libp2p_stream_t **out_stream, int *out_err)
{
    if (!sync)
        return 0;

    const uint64_t start = picoquic_current_time();
    const uint64_t budget = timeout_ms > 0 ? (uint64_t)timeout_ms * 1000ULL : 0;
    for (;;)
    {
        pthread_mutex_lock(&sync->mtx);
        if (sync->done)
        {
            if (out_stream)
                *out_stream = sync->stream;
            if (out_err)
                *out_err = sync->err;
            pthread_mutex_unlock(&sync->mtx);
            return 1;
        }
        pthread_mutex_unlock(&sync->mtx);
        if (timeout_ms > 0)
        {
            uint64_t now = picoquic_current_time();
            if (now - start > budget)
                return 0;
        }
        sleep_ms(1);
    }
}

int main(void)
{
    libp2p_log_set_level(LIBP2P_LOG_ERROR);

    int ok = 1;
    int server_ctx_inited = 0;
    libp2p_quic_tls_cert_options_t server_opts = libp2p_quic_tls_cert_options_default();
    server_opts.identity_key_type = 1; /* ED25519 */
    server_opts.identity_key = SERVER_ID_KEY;
    server_opts.identity_key_len = sizeof(SERVER_ID_KEY);

    libp2p_quic_tls_certificate_t server_cert;
    memset(&server_cert, 0, sizeof(server_cert));
    libp2p_quic_tls_identity_t server_ident = {0};
    peer_id_t *expected_server_peer = NULL;
    quic_server_ctx_t server_ctx;
    picoquic_quic_t *server_q = NULL;
    libp2p_host_t *host = NULL;
    libp2p_conn_t *conn = NULL;
    libp2p_muxer_t *mx = NULL;
    libp2p_stream_t *stream = NULL;
    libp2p_stream_t *base_stream = NULL;
    multiaddr_t *remote_ma = NULL;
    uint8_t *sk = NULL;
    size_t sk_len = 0;
    uint16_t server_port = 0;
    if (libp2p_quic_tls_generate_certificate(&server_opts, &server_cert) != 0)
    {
        ok = 0;
        goto cleanup;
    }

    int ident_rc = libp2p_quic_tls_identity_from_certificate(server_cert.cert_der, server_cert.cert_len, &server_ident);
    if (ident_rc != 0 || !server_ident.peer)
    {
        ok = 0;
        goto cleanup;
    }

    expected_server_peer = server_ident.peer;
    server_ident.peer = NULL;
    libp2p_quic_tls_identity_clear(&server_ident);

    if (quic_server_ctx_init(&server_ctx) != 0)
    {
        ok = 0;
        goto cleanup;
    }
    server_ctx_inited = 1;

    server_q = picoquic_create(8,
                               NULL,
                               NULL,
                               NULL,
                               LIBP2P_QUIC_TLS_ALPN,
                               quic_server_stream_cb,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               picoquic_current_time(),
                               NULL,
                               NULL,
                               NULL,
                               0);
    if (!server_q)
    {
        ok = 0;
        goto cleanup;
    }

    ptls_iovec_t *chain = (ptls_iovec_t *)calloc(1, sizeof(*chain));
    if (!chain)
    {
        ok = 0;
        goto cleanup;
    }
    chain[0].base = server_cert.cert_der;
    chain[0].len = server_cert.cert_len;
    picoquic_set_tls_certificate_chain(server_q, chain, 1);
    server_cert.cert_der = NULL;
    server_cert.cert_len = 0;

    if (apply_tls_key(server_q, server_cert.key_der, server_cert.key_len) != 0)
    {
        ok = 0;
        goto cleanup;
    }

    server_q->enforce_client_only = 0;

    picoquic_set_null_verifier(server_q);

    server_ctx.quic = server_q;
    memset(&server_ctx.loop_param, 0, sizeof(server_ctx.loop_param));
    server_ctx.loop_param.local_af = AF_INET;
    server_ctx.loop_param.local_port = 0;

    int loop_ret = 0;
    server_ctx.thread_ctx = picoquic_start_network_thread(server_q,
                                                          &server_ctx.loop_param,
                                                          quic_server_loop_cb,
                                                          &server_ctx,
                                                          &loop_ret);
    if (!server_ctx.thread_ctx || loop_ret != 0)
    {
        ok = 0;
        goto cleanup;
    }
    server_ctx.thread_started = 1;
    if (quic_server_wait_thread_ready(&server_ctx, 2000) != 0)
    {
        ok = 0;
        goto cleanup;
    }

    if (quic_server_wait_for_port(&server_ctx, 2000, &server_port) != 0)
    {
        ok = 0;
        goto cleanup;
    }
    quic_server_wake(&server_ctx);

    libp2p_host_options_t opts;
    if (libp2p_host_options_default(&opts) != 0)
    {
        ok = 0;
        goto cleanup;
    }
    const char *transports[] = {"quic"};
    opts.transport_names = transports;
    opts.num_transport_names = 1;

    if (libp2p_host_new(&opts, &host) != 0)
    {
        ok = 0;
        goto cleanup;
    }

    sk = hex_to_bytes(CLIENT_PRIVATE_KEY_HEX, &sk_len);
    if (!sk || libp2p_host_set_private_key(host, sk, sk_len) != 0)
    {
        ok = 0;
        goto cleanup;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/udp/%" PRIu16 "/quic-v1", server_port);
    int ma_err = 0;
    remote_ma = multiaddr_new_from_str(addr_str, &ma_err);
    if (!remote_ma || ma_err != 0)
    {
        ok = 0;
        goto cleanup;
    }

    dial_sync_t dial_sync;
    dial_sync_init(&dial_sync);

    libp2p_dial_opts_t dial_opts = {
        .struct_size = sizeof(dial_opts),
        .remote_multiaddr = addr_str,
        .protocol_id = NULL,
        .timeout_ms = 5000,
        .enable_happy_eyeballs = false,
    };

    if (libp2p_host_dial_opts(host, &dial_opts, host_dial_on_open, &dial_sync) != 0)
    {
        dial_sync_destroy(&dial_sync);
        ok = 0;
        goto cleanup;
    }

    int dial_err = 0;
    if (!dial_sync_wait(&dial_sync, 5000, &base_stream, &dial_err) || dial_err != 0 || !base_stream)
    {
        dial_sync_destroy(&dial_sync);
        ok = 0;
        goto cleanup;
    }
    dial_sync_destroy(&dial_sync);

    conn = libp2p__stream_raw_conn(base_stream);
    if (!conn)
    {
        ok = 0;
        goto cleanup;
    }

    {
        const peer_id_t *remote_peer = libp2p_stream_remote_peer(base_stream);
        if (!remote_peer || peer_id_equals(remote_peer, expected_server_peer) != 1)
        {
            ok = 0;
            goto cleanup;
        }
    }

    libp2p_quic_session_t *session = libp2p_quic_conn_session(conn);
    if (!session)
    {
        ok = 0;
        goto cleanup;
    }
    mx = libp2p_quic_muxer_new(host,
                                session,
                                libp2p_conn_local_addr(conn),
                                remote_ma,
                                conn);
    if (!mx)
    {
        ok = 0;
        goto cleanup;
    }

    if (mx->vt->open_stream(mx, NULL, 0, &stream) != LIBP2P_MUXER_OK || !stream)
    {
        ok = 0;
        goto cleanup;
    }

    static const uint8_t PAYLOAD[] = "hello-quic";
    if (libp2p_stream_write(stream, PAYLOAD, sizeof(PAYLOAD)) != (ssize_t)sizeof(PAYLOAD))
    {
        ok = 0;
        goto cleanup;
    }

    {
        uint8_t recv_buf[sizeof(PAYLOAD)] = {0};
        ssize_t r = 0;
        uint64_t start = picoquic_current_time();
        while ((r = libp2p_stream_read(stream, recv_buf, sizeof(recv_buf))) == LIBP2P_ERR_AGAIN)
        {
            if (picoquic_current_time() - start > 2000ULL * 1000ULL)
            {
                ok = 0;
                goto cleanup;
            }
            sleep_ms(5);
        }
        if (r != (ssize_t)sizeof(PAYLOAD) || memcmp(recv_buf, PAYLOAD, sizeof(PAYLOAD)) != 0)
        {
            ok = 0;
            goto cleanup;
        }
    }

cleanup:
    if (stream)
    {
        libp2p_stream_close(stream);
    }
    if (mx)
    {
        libp2p_muxer_free(mx);
        mx = NULL;
        stream = NULL;
    }
    if (stream)
    {
        libp2p_stream_free(stream);
        stream = NULL;
    }
    if (base_stream)
    {
        libp2p_stream_close(base_stream);
        libp2p_stream_free(base_stream);
        base_stream = NULL;
        conn = NULL;
    }
    if (conn)
    {
        libp2p_conn_close(conn);
        libp2p_conn_free(conn);
    }

    if (remote_ma)
        multiaddr_free(remote_ma);
    if (sk)
    {
        memset(sk, 0, sk_len);
        free(sk);
    }
    if (host)
        libp2p_host_free(host);

    if (server_ctx.thread_ctx)
    {
        quic_server_wake(&server_ctx);
        picoquic_delete_network_thread(server_ctx.thread_ctx);
    }
    if (server_q)
        picoquic_free(server_q);

    libp2p_quic_tls_certificate_clear(&server_cert);
    if (expected_server_peer)
    {
        peer_id_destroy(expected_server_peer);
        free(expected_server_peer);
    }

    if (server_ctx_inited)
        quic_server_ctx_destroy(&server_ctx);

    return ok ? 0 : 1;
}
