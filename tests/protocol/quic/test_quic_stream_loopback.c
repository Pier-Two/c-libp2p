#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#endif

#include "protocol/quic/protocol_quic.h"
#include "src/protocol/quic/quic_internal.h"

#include "libp2p/errors.h"
#include "libp2p/log.h"
#include "libp2p/muxer.h"
#include "libp2p/stream.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_set_textlog.h"
#include "picoquic_utils.h"
#include "picotls.h"
#include "external/picoquic/loglib/autoqlog.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CHECK(cond, msg)            \
    do                             \
    {                              \
        if (!(cond))               \
        {                          \
            fprintf(stderr, msg);  \
            fprintf(stderr, "\n"); \
            ok = 0;                \
            goto cleanup;          \
        }                          \
    } while (0)

#ifndef _WIN32
static void sleep_ms(unsigned int ms)
{
    usleep(ms * 1000);
}
#else
static void sleep_ms(unsigned int ms)
{
    Sleep(ms);
}
#endif

static const uint16_t VERIFY_ALGOS[] = {
    PTLS_SIGNATURE_ED25519,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    UINT16_MAX};

typedef struct quic_verify_ctx
{
    ptls_verify_certificate_t super;
    peer_id_t *peer;
} quic_verify_ctx_t;

static void quic_verify_ctx_init(quic_verify_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.cb = NULL; /* set later */
    ctx->super.algos = VERIFY_ALGOS;
    ctx->peer = NULL;
}

static void quic_verify_ctx_clear(quic_verify_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->peer)
    {
        peer_id_destroy(ctx->peer);
        free(ctx->peer);
        ctx->peer = NULL;
    }
}

static int quic_verify_sign_accept(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
    (void)verify_ctx;
    (void)algo;
    (void)data;
    (void)sign;
    return 0;
}

static int quic_verify_cb(struct st_ptls_verify_certificate_t *self,
                          ptls_t *tls,
                          const char *server_name,
                          int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
                          void **verify_data,
                          ptls_iovec_t *certs,
                          size_t num_certs)
{
    (void)tls;
    (void)server_name;

    quic_verify_ctx_t *ctx = (quic_verify_ctx_t *)((uint8_t *)self - offsetof(quic_verify_ctx_t, super));
    if (num_certs == 0 || !certs)
        return -1;

    libp2p_quic_tls_identity_t ident = {0};
    if (libp2p_quic_tls_identity_from_certificate(certs[0].base, certs[0].len, &ident) != 0)
    {
        return -1;
    }

    if (ctx->peer)
    {
        peer_id_destroy(ctx->peer);
        free(ctx->peer);
        ctx->peer = NULL;
    }

    ctx->peer = ident.peer;
    ident.peer = NULL;
    libp2p_quic_tls_identity_clear(&ident);

    *verify_sign = quic_verify_sign_accept;
    *verify_data = ctx;
    return 0;
}

typedef struct quic_server_ctx
{
    quic_verify_ctx_t verify;
    pthread_mutex_t lock;
    pthread_cond_t cv;
    uint16_t port;
    int port_ready;
    picoquic_quic_t *quic;
    picoquic_network_thread_ctx_t *thread_ctx;
    picoquic_packet_loop_param_t loop_param;
    int thread_started;
} quic_server_ctx_t;

static int quic_server_ctx_init(quic_server_ctx_t *ctx)
{
    if (pthread_mutex_init(&ctx->lock, NULL) != 0)
        return -1;
    if (pthread_cond_init(&ctx->cv, NULL) != 0)
    {
        pthread_mutex_destroy(&ctx->lock);
        return -1;
    }
    quic_verify_ctx_init(&ctx->verify);
    ctx->verify.super.cb = quic_verify_cb;
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
    quic_verify_ctx_clear(&ctx->verify);
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
    fprintf(stderr, "server bound port %u (custom)\n", (unsigned)port);
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
    else if (cb_mode == picoquic_packet_loop_after_receive && callback_arg)
    {
        size_t nb = *(size_t *)callback_arg;
        fprintf(stderr, "server after_receive %zu\n", nb);
    }
    else if (cb_mode == picoquic_packet_loop_after_send && callback_arg)
    {
        size_t nb = *(size_t *)callback_arg;
        fprintf(stderr, "server after_send %zu\n", nb);
    }
    else if (cb_mode == picoquic_packet_loop_wake_up)
    {
        fprintf(stderr, "server wake\n");
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
        {
            pthread_mutex_lock(&ctx->lock);
            ctx->port = port;
            ctx->port_ready = 1;
            pthread_cond_signal(&ctx->cv);
            pthread_mutex_unlock(&ctx->lock);
            fprintf(stderr, "server bound port %u (af=%d) ctx=%p\n", (unsigned)port, addr->sa_family, (void*)ctx);
        }
    }

    return 0;
}

static int quic_server_wait_for_port(quic_server_ctx_t *ctx, uint64_t timeout_ms, uint16_t *port_out)
{
    if (!ctx)
        return -1;

    uint64_t start = picoquic_current_time();
    for (;;)
    {
        pthread_mutex_lock(&ctx->lock);
        int ready = ctx->port_ready;
        uint16_t port = ctx->port;
        pthread_mutex_unlock(&ctx->lock);

        if (ready)
        {
            if (port_out)
                *port_out = port;
            return 0;
        }

        uint64_t now = picoquic_current_time();
        if (now - start > timeout_ms * 1000ULL)
            return -1;

        sleep_ms(1);
    }
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
    {
        (void)picoquic_wake_up_network_thread(ctx->thread_ctx);
    }
}

static const char RESET_TAG[] = "reset-me";

static int quic_server_stream_cb(picoquic_cnx_t *cnx,
                                 uint64_t stream_id,
                                 uint8_t *bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void *callback_ctx,
                                 void *stream_ctx)
{
    (void)callback_ctx;
    (void)stream_ctx;

    if (event == picoquic_callback_stream_data || event == picoquic_callback_stream_fin)
    {
        if (length >= sizeof(RESET_TAG) - 1 && memcmp(bytes, RESET_TAG, sizeof(RESET_TAG) - 1) == 0)
        {
            (void)picoquic_reset_stream(cnx, stream_id, 0);
            return 0;
        }

        int fin = (event == picoquic_callback_stream_fin) ? 1 : 0;
        (void)picoquic_add_to_stream(cnx, stream_id, bytes, length, fin);
        return 0;
    }

    if (event == picoquic_callback_stream_reset)
        return 0;

    return 0;
}

static peer_id_t *derive_peer_id_from_ed25519(const uint8_t *sk, size_t len)
{
    uint8_t *pub_pb = NULL;
    size_t pub_len = 0;
    uint8_t tmp[64];

    if (len > sizeof(tmp))
        return NULL;
    memcpy(tmp, sk, len);

    if (peer_id_create_from_private_key_ed25519(tmp, len, &pub_pb, &pub_len) != PEER_ID_SUCCESS)
        return NULL;

    peer_id_t *pid = (peer_id_t *)calloc(1, sizeof(*pid));
    if (!pid)
    {
        free(pub_pb);
        return NULL;
    }

    if (peer_id_create_from_public_key(pub_pb, pub_len, pid) != PEER_ID_SUCCESS)
    {
        free(pub_pb);
        peer_id_destroy(pid);
        free(pid);
        return NULL;
    }

    free(pub_pb);
    return pid;
}

static int wait_for_ready(libp2p_quic_session_t *session,
                          quic_server_ctx_t *server_ctx,
                          picoquic_cnx_t *cnx,
                          uint64_t timeout_ms)
{
    const uint64_t start = picoquic_current_time();
    const uint64_t budget = timeout_ms * 1000ULL;
    picoquic_state_enum last = -1;
    while (picoquic_current_time() - start < budget)
    {
        const uint64_t now = picoquic_current_time();
        picoquic_state_enum st = picoquic_get_cnx_state(cnx);
        if (st != last)
        {
            fprintf(stderr, "state=%d\n", st);
            last = st;
        }
        if (st == picoquic_state_ready)
            return 0;
        if (session)
            libp2p__quic_session_wake(session);
        sleep_ms(5);
    }
    return -1;
}

static int write_der_cert_to_pem(const uint8_t *der, size_t der_len, char *path_out, size_t path_len)
{
#ifdef _WIN32
    char tmp_dir[MAX_PATH];
    if (!GetTempPathA((DWORD)sizeof(tmp_dir), tmp_dir))
        return -1;
    if (!GetTempFileNameA(tmp_dir, "lpq", 0, path_out))
        return -1;
    FILE *fp = fopen(path_out, "wb");
    if (!fp)
        return -1;
#else
    char tmpl[] = "/tmp/libp2p_quicXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    if (strlen(tmpl) + 1 > path_len)
    {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    strcpy(path_out, tmpl);
    FILE *fp = fdopen(fd, "w");
    if (!fp)
    {
        close(fd);
        unlink(path_out);
        return -1;
    }
#endif
    const uint8_t *p = der;
    X509 *cert = d2i_X509(NULL, &p, der_len);
    if (!cert)
    {
        fclose(fp);
#ifdef _WIN32
        _unlink(path_out);
#else
        unlink(path_out);
#endif
        return -1;
    }
    int rc = PEM_write_X509(fp, cert);
    X509_free(cert);
    fclose(fp);
    if (rc != 1)
    {
#ifdef _WIN32
        _unlink(path_out);
#else
        unlink(path_out);
#endif
        return -1;
    }
    return 0;
}

static int write_der_key_to_pem(const uint8_t *der, size_t der_len, char *path_out, size_t path_len)
{
#ifdef _WIN32
    char tmp_dir[MAX_PATH];
    if (!GetTempPathA((DWORD)sizeof(tmp_dir), tmp_dir))
        return -1;
    if (!GetTempFileNameA(tmp_dir, "lpq", 0, path_out))
        return -1;
    FILE *fp = fopen(path_out, "wb");
    if (!fp)
        return -1;
#else
    char tmpl[] = "/tmp/libp2p_quicXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    if (strlen(tmpl) + 1 > path_len)
    {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    strcpy(path_out, tmpl);
    FILE *fp = fdopen(fd, "w");
    if (!fp)
    {
        close(fd);
        unlink(path_out);
        return -1;
    }
#endif
    const uint8_t *p = der;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, der_len);
    if (!pkey)
    {
        fclose(fp);
#ifdef _WIN32
        _unlink(path_out);
#else
        unlink(path_out);
#endif
        return -1;
    }
    int rc = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    EVP_PKEY_free(pkey);
    fclose(fp);
    if (rc != 1)
    {
#ifdef _WIN32
        _unlink(path_out);
#else
        unlink(path_out);
#endif
        return -1;
    }
    return 0;
}

static void test_session_close(libp2p_quic_session_t *session)
{
    picoquic_cnx_t *cnx = libp2p__quic_session_native(session);
    if (cnx)
        (void)picoquic_close(cnx, 0);
}

static void test_session_free(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    picoquic_cnx_t *cnx = libp2p__quic_session_native(session);
    picoquic_quic_t *quic = libp2p__quic_session_quic(session);
    libp2p__quic_session_stop_loop(session);
    if (cnx)
        picoquic_delete_cnx(cnx);
    libp2p__quic_session_release(session);
    if (quic)
        picoquic_free(quic);
}

static multiaddr_t *make_remote_multiaddr(uint16_t port)
{
    char addr[80];
    snprintf(addr, sizeof(addr), "/ip4/127.0.0.1/udp/%" PRIu16 "/quic_v1", port);
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str(addr, &err);
    if (err != 0)
        return NULL;
    return ma;
}

static const uint8_t SERVER_ID_KEY[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
    0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1f};

static const uint8_t CLIENT_ID_KEY[32] = {
    0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87,
    0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};

int main(void)
{
    libp2p_log_set_level(LIBP2P_LOG_ERROR);
    debug_printf_push_stream(stderr);

    int ok = 1;

    peer_id_t *expected_server = NULL;
    peer_id_t *expected_client = NULL;

    quic_server_ctx_t server_ctx;
    CHECK(quic_server_ctx_init(&server_ctx) == 0, "server ctx init");
    fprintf(stderr, "server_ctx=%p\n", (void*)&server_ctx);

    quic_verify_ctx_t client_verify;
    quic_verify_ctx_init(&client_verify);
    client_verify.super.cb = quic_verify_cb;

    libp2p_quic_tls_cert_options_t server_opts = libp2p_quic_tls_cert_options_default();
    server_opts.identity_key_type = PEER_ID_ED25519_KEY_TYPE;
    server_opts.identity_key = SERVER_ID_KEY;
    server_opts.identity_key_len = sizeof(SERVER_ID_KEY);

    libp2p_quic_tls_cert_options_t client_opts = libp2p_quic_tls_cert_options_default();
    client_opts.identity_key_type = PEER_ID_ED25519_KEY_TYPE;
    client_opts.identity_key = CLIENT_ID_KEY;
    client_opts.identity_key_len = sizeof(CLIENT_ID_KEY);

    libp2p_quic_tls_certificate_t server_cert;
    libp2p_quic_tls_certificate_t client_cert;
    memset(&server_cert, 0, sizeof(server_cert));
    memset(&client_cert, 0, sizeof(client_cert));

    CHECK(libp2p_quic_tls_generate_certificate(&server_opts, &server_cert) == 0, "server cert");
    libp2p_quic_tls_identity_t server_ident = {0};
    CHECK(libp2p_quic_tls_identity_from_certificate(server_cert.cert_der, server_cert.cert_len, &server_ident) == 0, "server cert parse");
    expected_server = server_ident.peer;
    server_ident.peer = NULL;
    libp2p_quic_tls_identity_clear(&server_ident);

    CHECK(libp2p_quic_tls_generate_certificate(&client_opts, &client_cert) == 0, "client cert");
    libp2p_quic_tls_identity_t client_ident = {0};
    CHECK(libp2p_quic_tls_identity_from_certificate(client_cert.cert_der, client_cert.cert_len, &client_ident) == 0, "client cert parse");
    expected_client = client_ident.peer;
    client_ident.peer = NULL;
    libp2p_quic_tls_identity_clear(&client_ident);

    char server_cert_path[PATH_MAX] = {0};
    char server_key_path[PATH_MAX] = {0};
    char client_cert_path[PATH_MAX] = {0};
    char client_key_path[PATH_MAX] = {0};
    int server_cert_created = 0;
    int server_key_created = 0;
    int client_cert_created = 0;
    int client_key_created = 0;

    CHECK(write_der_cert_to_pem(server_cert.cert_der, server_cert.cert_len, server_cert_path, sizeof(server_cert_path)) == 0,
          "write server cert");
    server_cert_created = 1;
    CHECK(write_der_key_to_pem(server_cert.key_der, server_cert.key_len, server_key_path, sizeof(server_key_path)) == 0,
          "write server key");
    server_key_created = 1;
    CHECK(write_der_cert_to_pem(client_cert.cert_der, client_cert.cert_len, client_cert_path, sizeof(client_cert_path)) == 0,
          "write client cert");
    client_cert_created = 1;
    CHECK(write_der_key_to_pem(client_cert.key_der, client_cert.key_len, client_key_path, sizeof(client_key_path)) == 0,
          "write client key");
    client_key_created = 1;

    picoquic_quic_t *server_q = picoquic_create(8,
                                               server_cert_path,
                                               server_key_path,
                                               NULL,
                                               LIBP2P_QUIC_TLS_ALPN,
                                               quic_server_stream_cb,
                                               &server_ctx,
                                               NULL,
                                               NULL,
                                               NULL,
                                               picoquic_current_time(),
                                               NULL,
                                               NULL,
                                               NULL,
                                               0);
    CHECK(server_q != NULL, "server quic create");

    picoquic_set_null_verifier(server_q);
    picoquic_set_log_level(server_q, 1);
    if (picoquic_set_textlog(server_q, "server.log") != 0)
        fprintf(stderr, "failed to set server textlog\n");

    server_ctx.quic = server_q;
    memset(&server_ctx.loop_param, 0, sizeof(server_ctx.loop_param));
    server_ctx.loop_param.local_af = AF_INET;
    server_ctx.loop_param.local_port = 0;
    server_ctx.loop_param.dest_if = 0;
    server_ctx.loop_param.socket_buffer_size = 0;
    server_ctx.loop_param.do_not_use_gso = 0;
    (void)server_ctx.loop_param.dest_if;

    int loop_ret = 0;
    picoquic_network_thread_ctx_t *thread_ctx = picoquic_start_network_thread(server_q,
                                                                              &server_ctx.loop_param,
                                                                              quic_server_loop_cb,
                                                                              &server_ctx,
                                                                              &loop_ret);
    CHECK(thread_ctx != NULL && loop_ret == 0, "server network thread");
    server_ctx.thread_ctx = thread_ctx;
    server_ctx.thread_started = 1;
    fprintf(stderr, "server thread ctx=%p\n", (void*)thread_ctx);

    CHECK(quic_server_wait_thread_ready(&server_ctx, 2000) == 0, "server thread ready");
    fprintf(stderr, "loop_param.local_port=%u\n", (unsigned)server_ctx.loop_param.local_port);

    uint16_t server_port = 0;
    CHECK(quic_server_wait_for_port(&server_ctx, 2000, &server_port) == 0, "server port wait");
    fprintf(stderr, "server_port=%u\n", (unsigned)server_port);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(server_port);
#ifdef __APPLE__
    server_addr.sin_len = sizeof(server_addr);
#endif

#ifndef _WIN32
    int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_fd >= 0)
    {
        struct sockaddr_in probe_local;
        memset(&probe_local, 0, sizeof(probe_local));
        probe_local.sin_family = AF_INET;
        probe_local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        probe_local.sin_port = htons(0);
        (void)bind(probe_fd, (struct sockaddr *)&probe_local, sizeof(probe_local));
        const char probe_msg[] = "probe";
        (void)sendto(probe_fd, probe_msg, sizeof(probe_msg), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        close(probe_fd);
    }
#endif

    quic_server_wake(&server_ctx);

    picoquic_quic_t *client_q = picoquic_create(8,
                                               client_cert_path,
                                               client_key_path,
                                               NULL,
                                               LIBP2P_QUIC_TLS_ALPN,
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
    CHECK(client_q != NULL, "client quic create");

    picoquic_set_null_verifier(client_q);
    picoquic_set_verify_certificate_callback(client_q, &client_verify.super, NULL);
    picoquic_set_log_level(client_q, 1);
    if (picoquic_set_textlog(client_q, "client.log") != 0)
        fprintf(stderr, "failed to set client textlog\n");

    picoquic_cnx_t *client_cnx = picoquic_create_cnx(client_q,
                                                      picoquic_null_connection_id,
                                                      picoquic_null_connection_id,
                                                      (struct sockaddr *)&server_addr,
                                                      picoquic_current_time(),
                                                      0,
                                                      "localhost",
                                                      LIBP2P_QUIC_TLS_ALPN,
                                                      1);
    CHECK(client_cnx != NULL, "client cnx");

    libp2p_quic_session_t *session = libp2p__quic_session_wrap(client_q, client_cnx);
    CHECK(session != NULL, "session wrap");

    multiaddr_t *remote_ma = make_remote_multiaddr(server_port);
    CHECK(remote_ma != NULL, "remote multiaddr");

    int local_err = 0;
    multiaddr_t *local_ma = multiaddr_new_from_str("/ip4/0.0.0.0/udp/0", &local_err);
    CHECK(local_ma != NULL && local_err == 0, "local multiaddr");

    CHECK(libp2p__quic_session_start_loop(session, local_ma, remote_ma) == 0, "start loop");
    CHECK(picoquic_start_client_cnx(client_cnx) == 0, "start client cnx");
    libp2p__quic_session_wake(session);
    quic_server_wake(&server_ctx);

    libp2p_conn_t *conn = libp2p_quic_conn_new(local_ma, remote_ma, session, test_session_close, test_session_free, NULL);
    CHECK(conn != NULL, "conn new");

    if (wait_for_ready(session, &server_ctx, client_cnx, 5000) != 0)
    {
        picoquic_state_enum st = picoquic_get_cnx_state(client_cnx);
        uint64_t local_err = picoquic_get_local_error(client_cnx);
        uint64_t remote_err = picoquic_get_remote_error(client_cnx);
        uint64_t app_err = picoquic_get_application_error(client_cnx);
        fprintf(stderr, "handshake failed: state=%d local=%" PRIu64 " remote=%" PRIu64 " app=%" PRIu64 "\n",
                st, local_err, remote_err, app_err);
        ok = 0;
        goto cleanup;
    }

    if (client_verify.peer)
        fprintf(stderr, "client peer captured\n");
    else
        fprintf(stderr, "client peer missing\n");
    CHECK(client_verify.peer != NULL, "client verify peer");
    fprintf(stderr, "actual bytes: ");
    for (size_t i = 0; i < client_verify.peer->size; i++)
        fprintf(stderr, "%02x", client_verify.peer->bytes[i]);
    fprintf(stderr, "\n");
    int peer_cmp = peer_id_equals(client_verify.peer, expected_server);
    char expected_str[256] = {0};
    char actual_str[256] = {0};
    int expected_len = peer_id_to_string(expected_server, PEER_ID_FMT_BASE58_LEGACY, expected_str, sizeof(expected_str));
    if (expected_len < 0)
        strcpy(expected_str, "<err>");
    int actual_len = peer_id_to_string(client_verify.peer, PEER_ID_FMT_BASE58_LEGACY, actual_str, sizeof(actual_str));
    if (actual_len < 0)
        strcpy(actual_str, "<err>");
    fprintf(stderr, "expected peer=%s\n", expected_str);
    fprintf(stderr, "actual peer=%s\n", actual_str);
    fprintf(stderr, "expected bytes: ");
    for (size_t i = 0; i < expected_server->size; i++)
        fprintf(stderr, "%02x", expected_server->bytes[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "peer equals=%d\n", peer_cmp);
    CHECK(peer_cmp == 1, "server peer mismatch");
    CHECK(libp2p_quic_conn_set_verified_peer(conn, client_verify.peer) == 0, "set verified peer");
    client_verify.peer = NULL;

    libp2p_muxer_t *mx = libp2p_quic_muxer_new(NULL, session, NULL, remote_ma, conn);
    CHECK(mx != NULL, "muxer new");

    libp2p_stream_t *stream1 = NULL;
    CHECK(mx->vt && mx->vt->open_stream && mx->vt->open_stream(mx, NULL, 0, &stream1) == LIBP2P_MUXER_OK && stream1,
          "open stream1");

    const uint8_t payload1[] = "ping-quic";
    CHECK(libp2p_stream_write(stream1, payload1, sizeof(payload1)) == (ssize_t)sizeof(payload1), "stream write");

    uint8_t recv1[sizeof(payload1)] = {0};
    ssize_t r1 = 0;
    uint64_t read_start = picoquic_current_time();
    while ((r1 = libp2p_stream_read(stream1, recv1, sizeof(recv1))) == LIBP2P_ERR_AGAIN)
    {
        libp2p__quic_session_wake(session);
        quic_server_wake(&server_ctx);
        if (picoquic_current_time() - read_start > 2000ULL * 1000ULL)
            break;
        sleep_ms(5);
    }
    CHECK(r1 == (ssize_t)sizeof(payload1), "stream read len");
    CHECK(memcmp(recv1, payload1, sizeof(payload1)) == 0, "stream read data");

    CHECK(libp2p_stream_write(stream1, (const uint8_t *)RESET_TAG, sizeof(RESET_TAG) - 1) == (ssize_t)(sizeof(RESET_TAG) - 1),
          "write reset");

    int saw_reset = 0;
    uint64_t reset_start = picoquic_current_time();
    while (!saw_reset)
    {
        uint8_t tmp[8];
        ssize_t rc = libp2p_stream_read(stream1, tmp, sizeof(tmp));
        if (rc == LIBP2P_ERR_RESET)
        {
            saw_reset = 1;
            break;
        }
        if (rc == LIBP2P_ERR_AGAIN)
        {
            libp2p__quic_session_wake(session);
            if (picoquic_current_time() - reset_start > 2000ULL * 1000ULL)
                break;
            sleep_ms(5);
            continue;
        }
        if (rc < 0)
            break;
    }
    CHECK(saw_reset, "expected reset");

cleanup:
    if (stream1)
    {
        libp2p_stream_close(stream1);
        libp2p_stream_free(stream1);
        stream1 = NULL;
    }
    if (mx)
    {
        libp2p_muxer_free(mx);
        mx = NULL;
    }
    if (conn)
    {
        libp2p_conn_close(conn);
        libp2p_conn_free(conn);
        conn = NULL;
        session = NULL;
        client_q = NULL;
        client_cnx = NULL;
    }
    if (session)
        libp2p__quic_session_release(session);
    if (remote_ma)
        multiaddr_free(remote_ma);
    if (local_ma)
        multiaddr_free(local_ma);

    quic_verify_ctx_clear(&client_verify);

    if (server_ctx.thread_started && server_ctx.thread_ctx)
    {
        quic_server_wake(&server_ctx);
        picoquic_delete_network_thread(server_ctx.thread_ctx);
        server_ctx.thread_ctx = NULL;
        server_ctx.thread_started = 0;
    }

    if (server_q)
    {
        picoquic_cnx_t *srv = picoquic_get_first_cnx(server_q);
        if (srv)
        {
            fprintf(stderr, "server had cnx state=%d\n", picoquic_get_cnx_state(srv));
        }
        picoquic_free(server_q);
    }
    if (client_q)
        picoquic_free(client_q);

    quic_server_ctx_destroy(&server_ctx);

    if (client_key_created)
#ifdef _WIN32
        _unlink(client_key_path);
#else
        unlink(client_key_path);
#endif
    if (client_cert_created)
#ifdef _WIN32
        _unlink(client_cert_path);
#else
        unlink(client_cert_path);
#endif
    if (server_key_created)
#ifdef _WIN32
        _unlink(server_key_path);
#else
        unlink(server_key_path);
#endif
    if (server_cert_created)
#ifdef _WIN32
        _unlink(server_cert_path);
#else
        unlink(server_cert_path);
#endif

    libp2p_quic_tls_certificate_clear(&client_cert);
    libp2p_quic_tls_certificate_clear(&server_cert);

    if (expected_client)
    {
        peer_id_destroy(expected_client);
        free(expected_client);
    }
    if (expected_server)
    {
        peer_id_destroy(expected_server);
        free(expected_server);
    }

    return ok ? 0 : 1;
}
