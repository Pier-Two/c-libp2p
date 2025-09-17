#include "peer_id/peer_id_ecdsa.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_rsa.h"
#include "peer_id/peer_id_secp256k1.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/noise/protocol_noise_conn.h"
#include "protocol/noise/protocol_noise_extensions.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/tcp/protocol_tcp_conn.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include <fcntl.h>
#include <noise/protocol.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <io.h>
/* Windows lacks POSIX fcntl file-status flag manipulation used in the tests
   to toggle O_NONBLOCK.  For unit-test purposes we can safely turn these
   calls into no-ops and provide dummy definitions so the code compiles. */
#ifndef F_GETFL
#define F_GETFL 0
#endif
#ifndef F_SETFL
#define F_SETFL 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif
static inline int fcntl(int fd, int cmd, long arg)
{
    (void)fd;
    (void)cmd;
    (void)arg;
    return 0;
}
#endif /* _WIN32 */

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-70s | PASS\n", test_name);
    else
        printf("TEST: %-70s | FAIL: %s\n", test_name, details);
}

static int failures = 0;
#define TEST_OK(name, cond, fmt, ...)                                                                                                                \
    do                                                                                                                                               \
    {                                                                                                                                                \
        if (cond)                                                                                                                                    \
            print_standard(name, "", 1);                                                                                                             \
        else                                                                                                                                         \
        {                                                                                                                                            \
            char _details[256];                                                                                                                      \
            snprintf(_details, sizeof(_details), fmt, ##__VA_ARGS__);                                                                                \
            print_standard(name, _details, 0);                                                                                                       \
            failures++;                                                                                                                              \
        }                                                                                                                                            \
    } while (0)

void ed25519_genpub(uint8_t pub[32], const uint8_t sec[32]);

static int accept_with_timeout(libp2p_listener_t *lst, libp2p_conn_t **out, int attempts, int sleep_us)
{
    int rc = LIBP2P_LISTENER_ERR_AGAIN;
    for (int i = 0; i < attempts; i++)
    {
        rc = libp2p_listener_accept(lst, out);
        if (rc == 0)
            return 0;
        if (rc != LIBP2P_LISTENER_ERR_AGAIN)
            return rc;
        usleep(sleep_us);
    }
    return rc;
}

static int test_creation(void)
{
    libp2p_noise_config_t cfg = {0};
    libp2p_security_t *sec = libp2p_noise_security_new(&cfg);
    int ok = sec != NULL;
    if (sec)
        libp2p_security_free(sec);
    print_standard("noise security allocation", ok ? "" : "alloc failed", ok);
    return ok ? 0 : 1;
}

static void test_identity_key_length(void)
{
    uint8_t key[32] = {0};
    libp2p_noise_config_t cfg = {.identity_private_key = key, .identity_private_key_len = sizeof(key), .identity_key_type = PEER_ID_ED25519_KEY_TYPE};
    libp2p_security_t *sec = libp2p_noise_security_new(&cfg);
    TEST_OK("identity key accepted", sec != NULL, "sec=%p", (void *)sec);
    if (sec)
        libp2p_security_free(sec);
}

struct hs_args
{
    libp2p_security_t *sec;
    libp2p_conn_t *conn;
    const peer_id_t *hint;
    libp2p_conn_t *out;
    peer_id_t *remote_peer;
    libp2p_security_err_t rc;
};

static void free_hs_args(struct hs_args *a)
{
    if (!a)
        return;

    if (a->out)
    {
        libp2p_conn_close(a->out);
        libp2p_conn_free(a->out);
    }
    else if (a->conn)
    {
        libp2p_conn_close(a->conn);
        libp2p_conn_free(a->conn);
    }

    if (a->remote_peer)
    {
        peer_id_destroy(a->remote_peer);
        free(a->remote_peer);
    }

    a->out = NULL;
    a->conn = NULL;
    a->remote_peer = NULL;
}

static int peer_id_from_ed25519_priv(const uint8_t *sk, peer_id_t *pid)
{
    uint8_t pub[32];
    ed25519_genpub(pub, sk);
    uint8_t *pubpb = NULL;
    size_t pubpb_len = 0;
    if (peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE, pub, sizeof(pub), &pubpb, &pubpb_len) != PEER_ID_SUCCESS)
        return -1;
    int ret = peer_id_create_from_public_key(pubpb, pubpb_len, pid);
    free(pubpb);
    return ret == PEER_ID_SUCCESS ? 0 : -1;
}

static int gen_rsa_private(uint8_t **key, size_t *key_len)
{
    register_all_prngs();
    register_hash(&sha256_desc);
    extern const ltc_math_descriptor ltm_desc;
    extern ltc_math_descriptor ltc_mp;
    ltc_mp = ltm_desc;
    prng_state prng;
    int prng_idx = find_prng("sprng");
    if (prng_idx == -1 || rng_make_prng(128, prng_idx, &prng, NULL) != CRYPT_OK)
        return -1;
    rsa_key rsa;
    if (rsa_make_key(&prng, prng_idx, 1024 / 8, 65537, &rsa) != CRYPT_OK)
        return -1;
    size_t len = 1, old_len = 0;
    uint8_t *buf = malloc(len);
    if (!buf)
    {
        rsa_free(&rsa);
        return -1;
    }
    int err = rsa_export(buf, (unsigned long *)&len, PK_PRIVATE | PK_STD, &rsa);
    while (err == CRYPT_BUFFER_OVERFLOW)
    {
        old_len = len;
        uint8_t *tmp = realloc(buf, len);
        if (!tmp)
        {
            free(buf);
            rsa_free(&rsa);
            return -1;
        }
        buf = tmp;
        err = rsa_export(buf, (unsigned long *)&len, PK_PRIVATE | PK_STD, &rsa);
    }
    // printf("gen_rsa_private: export len=%zu\n", len); /* debug removed */
    if (err != CRYPT_OK)
    {
        free(buf);
        rsa_free(&rsa);
        return -1;
    }
    rsa_free(&rsa);
    *key = buf;
    *key_len = len;
    return 0;
}

static int gen_ecdsa_private(uint8_t **key, size_t *key_len)
{
    register_all_prngs();
    register_hash(&sha256_desc);
    extern const ltc_math_descriptor ltm_desc;
    extern ltc_math_descriptor ltc_mp;
    ltc_mp = ltm_desc;
    prng_state prng;
    int prng_idx = find_prng("sprng");
    if (prng_idx == -1 || rng_make_prng(128, prng_idx, &prng, NULL) != CRYPT_OK)
        return -1;
    ecc_key ecc;
    if (ecc_make_key(&prng, prng_idx, 32, &ecc) != CRYPT_OK)
        return -1;
    unsigned long len = 1, old_len = 0;
    uint8_t *buf = malloc(len);
    if (!buf)
    {
        ecc_free(&ecc);
        return -1;
    }
    int err = ecc_export_openssl(buf, &len, PK_PRIVATE | PK_CURVEOID, &ecc);
    while (err == CRYPT_BUFFER_OVERFLOW)
    {
        old_len = len;
        uint8_t *tmp = realloc(buf, len);
        if (!tmp)
        {
            free(buf);
            ecc_free(&ecc);
            return -1;
        }
        buf = tmp;
        err = ecc_export_openssl(buf, &len, PK_PRIVATE | PK_CURVEOID, &ecc);
    }
    if (err != CRYPT_OK)
    {
        free(buf);
        ecc_free(&ecc);
        return -1;
    }
    ecc_free(&ecc);
    *key = buf;
    *key_len = len;
    return 0;
}

static int peer_id_from_rsa_priv(const uint8_t *key, size_t key_len, peer_id_t *pid)
{
    // printf("peer_id_from_rsa_priv: first bytes before call:");
    // for (size_t i = 0; i < key_len && i < 8; i++)
    //     printf(" %02x", key[i]);
    // printf("\n");

    uint8_t *tmp = malloc(key_len);
    if (!tmp)
        return -1;
    memcpy(tmp, key, key_len);

    uint8_t *pubpb = NULL;
    size_t pubpb_len = 0;
    int rc = peer_id_create_from_private_key_rsa(tmp, key_len, &pubpb, &pubpb_len);
    free(tmp);

    // printf("peer_id_from_rsa_priv: first bytes after call:");
    // for (size_t i = 0; i < key_len && i < 8; i++)
    //     printf(" %02x", key[i]);
    // printf("\n");

    if (rc != PEER_ID_SUCCESS)
        return -1;
    int ret = peer_id_create_from_public_key(pubpb, pubpb_len, pid);
    free(pubpb);
    return ret == PEER_ID_SUCCESS ? 0 : -1;
}

static int peer_id_from_ecdsa_priv(const uint8_t *key, size_t key_len, peer_id_t *pid)
{
    uint8_t *tmp = malloc(key_len);
    if (!tmp)
        return -1;
    memcpy(tmp, key, key_len);

    uint8_t *pubpb = NULL;
    size_t pubpb_len = 0;
    int rc = peer_id_create_from_private_key_ecdsa(tmp, key_len, &pubpb, &pubpb_len);
    free(tmp);

    if (rc != PEER_ID_SUCCESS)
        return -1;
    int ret = peer_id_create_from_public_key(pubpb, pubpb_len, pid);
    free(pubpb);
    return ret == PEER_ID_SUCCESS ? 0 : -1;
}

static void *outbound_thread(void *arg)
{
    struct hs_args *a = (struct hs_args *)arg;
    a->rc = libp2p_noise_negotiate_outbound(a->sec, a->conn, a->hint, 0, &a->out, &a->remote_peer);
    return NULL;
}

static void *inbound_thread(void *arg)
{
    struct hs_args *a = (struct hs_args *)arg;
    a->rc = libp2p_noise_negotiate_inbound(a->sec, a->conn, 0, &a->out, &a->remote_peer);
    return NULL;
}

static void test_handshake_success(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("security objects allocated", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 6000 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr parse", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listener create", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept", rc == 0 && srv, "rc=%d", rc);

    /* use blocking mode for handshake */
    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake return codes", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc,
            srv_args.rc);
    // printf("cli_out=%p srv_out=%p\n", (void *)cli_args.out, (void *)srv_args.out); /* debug removed */

    const char ping[] = "ping";
    libp2p_conn_write(cli, ping, sizeof(ping));
    char buf[16] = {0};
    ssize_t n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(srv, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(100);
    }
    // printf("read bytes:");
    // for (int i = 0; i < n && i < 16; i++)
    //     printf(" %02x", (unsigned char)buf[i]);
    // printf("\n");
    // printf("read bytes:");
    // for (int i = 0; i < n && i < 16; i++)
    //     printf(" %02x", (unsigned char)buf[i]);
    // printf("\n");
    // printf("read bytes:");
    // for (int i = 0; i < n && i < 16; i++)
    //     printf(" %02x", (unsigned char)buf[i]);
    // printf("\n");
    TEST_OK("data after handshake", n == sizeof(ping) && memcmp(buf, ping, sizeof(ping)) == 0, "read %zd bytes", n);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_identity_handshake_success(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32] = {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                          0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
    uint8_t id_srv[32] = {0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
                          0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};

    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));

    peer_id_t expected_srv = {0};
    TEST_OK("derive server peer id", peer_id_from_ed25519_priv(id_srv, &expected_srv) == 0, "srv peer id derivation failed");

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    peer_id_t expected_cli = {0};
    TEST_OK("derive client peer id", peer_id_from_ed25519_priv(id_cli, &expected_cli) == 0, "cli peer id derivation failed");

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("security objects allocated (id)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 7000 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr parse (id)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listener create (id)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (id)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (id)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake return codes (id)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc,
            srv_args.rc);
    TEST_OK("remote peer verified", cli_args.remote_peer && peer_id_equals(cli_args.remote_peer, &expected_srv) == 1, "match=%d",
            cli_args.remote_peer ? peer_id_equals(cli_args.remote_peer, &expected_srv) : -1);
    TEST_OK("server saw client", srv_args.remote_peer && peer_id_equals(srv_args.remote_peer, &expected_cli) == 1, "match=%d",
            srv_args.remote_peer ? peer_id_equals(srv_args.remote_peer, &expected_cli) : -1);

    const char ping[] = "ping";
    libp2p_conn_write(cli, ping, sizeof(ping));
    char buf[16] = {0};
    ssize_t n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(srv, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(100);
    }
    // printf("read bytes:");
    // for (int i = 0; i < n && i < 16; i++)
    //     printf(" %02x", (unsigned char)buf[i]);
    // printf("\n");
    TEST_OK("data after handshake (id)", n == sizeof(ping) && memcmp(buf, ping, sizeof(ping)) == 0, "read %zd bytes", n);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
    peer_id_destroy(&expected_cli);
    peer_id_destroy(&expected_srv);
}

static void test_identity_hint_mismatch(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    peer_id_t expected_cli = {0};
    TEST_OK("derive client pid (mm)", peer_id_from_ed25519_priv(id_cli, &expected_cli) == 0, "pid fail");

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (mm)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 7500 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (mm)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (mm)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (mm)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (mm)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = &expected_cli, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("client handshake fail", cli_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE, "rc=%d", cli_args.rc);
    TEST_OK("server handshake ok", srv_args.rc == LIBP2P_SECURITY_OK, "rc=%d", srv_args.rc);
    TEST_OK("client remote null", cli_args.remote_peer == NULL, "np=%p", (void *)cli_args.remote_peer);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
    peer_id_destroy(&expected_cli);
}

static void test_secp256k1_identity_handshake_success(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32] = {0x85, 0x51, 0x15, 0xf4, 0xe0, 0xe7, 0x8a, 0xd2, 0x81, 0x10, 0x17, 0xee, 0x12, 0xa9, 0x6c, 0x65,
                          0xcf, 0x8c, 0x24, 0x34, 0xae, 0x86, 0x5e, 0x89, 0xc9, 0x50, 0x10, 0xd8, 0x70, 0xbd, 0xe2, 0x7c};
    uint8_t id_srv[32] = {0x6f, 0x38, 0x31, 0xe1, 0xe1, 0x34, 0x3b, 0x9d, 0x8f, 0x33, 0x8e, 0x61, 0xb8, 0x4f, 0x51, 0xbe,
                          0xfb, 0x5a, 0xcc, 0x95, 0x7c, 0x91, 0x8e, 0x82, 0xc8, 0x5a, 0xc6, 0x43, 0x4d, 0xb7, 0xef, 0x9c};

    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_SECP256K1_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_SECP256K1_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("security objects allocated (secp256k1)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 8000 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr parse (secp256k1)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listener create (secp256k1)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (secp256k1)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (secp256k1)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake return codes (secp256k1)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d",
            cli_args.rc, srv_args.rc);

    const char ping[] = "ping";
    libp2p_conn_write(cli, ping, sizeof(ping));
    char buf[16] = {0};
    ssize_t n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(srv, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(100);
    }
    // printf("read bytes:");
    // for (int i = 0; i < n && i < 16; i++)
    //     printf(" %02x", (unsigned char)buf[i]);
    // printf("\n");
    TEST_OK("data after handshake (secp256k1)", n == sizeof(ping) && memcmp(buf, ping, sizeof(ping)) == 0, "read %zd bytes", n);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_rsa_identity_handshake_success(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t *id_cli = NULL;
    uint8_t *id_srv = NULL;
    size_t id_cli_len = 0, id_srv_len = 0;
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    gen_rsa_private(&id_cli, &id_cli_len);
    gen_rsa_private(&id_srv, &id_srv_len);
    // printf("generated RSA client key len=%zu\n", id_cli_len); /* debug removed */
    // printf("generated RSA server key len=%zu\n", id_srv_len); /* debug removed */

    peer_id_t expected_cli = {0};
    peer_id_t expected_srv = {0};
    TEST_OK("derive cli rsa peer id", peer_id_from_rsa_priv(id_cli, id_cli_len, &expected_cli) == 0, "pid fail");
    TEST_OK("derive srv rsa peer id", peer_id_from_rsa_priv(id_srv, id_srv_len, &expected_srv) == 0, "pid fail");

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = id_cli_len,
                                     .identity_key_type = PEER_ID_RSA_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = id_srv_len,
                                     .identity_key_type = PEER_ID_RSA_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("security objects allocated (rsa)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 8100 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr parse (rsa)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listener create (rsa)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (rsa)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (rsa)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake return codes (rsa)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc,
            srv_args.rc);
    TEST_OK("remote peer verified (rsa)", cli_args.remote_peer && peer_id_equals(cli_args.remote_peer, &expected_srv) == 1, "match=%d",
            cli_args.remote_peer ? peer_id_equals(cli_args.remote_peer, &expected_srv) : -1);
    TEST_OK("server saw client (rsa)", srv_args.remote_peer && peer_id_equals(srv_args.remote_peer, &expected_cli) == 1, "match=%d",
            srv_args.remote_peer ? peer_id_equals(srv_args.remote_peer, &expected_cli) : -1);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
    peer_id_destroy(&expected_cli);
    peer_id_destroy(&expected_srv);
    free(id_cli);
    free(id_srv);
}

static void test_ecdsa_identity_handshake_success(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t *id_cli = NULL;
    uint8_t *id_srv = NULL;
    size_t id_cli_len = 0, id_srv_len = 0;
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    gen_ecdsa_private(&id_cli, &id_cli_len);
    gen_ecdsa_private(&id_srv, &id_srv_len);

    peer_id_t expected_cli = {0};
    peer_id_t expected_srv = {0};
    TEST_OK("derive cli ecdsa peer id", peer_id_from_ecdsa_priv(id_cli, id_cli_len, &expected_cli) == 0, "pid fail");
    TEST_OK("derive srv ecdsa peer id", peer_id_from_ecdsa_priv(id_srv, id_srv_len, &expected_srv) == 0, "pid fail");

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = id_cli_len,
                                     .identity_key_type = PEER_ID_ECDSA_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = id_srv_len,
                                     .identity_key_type = PEER_ID_ECDSA_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("security objects allocated (ecdsa)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 8200 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr parse (ecdsa)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listener create (ecdsa)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (ecdsa)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (ecdsa)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake return codes (ecdsa)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc,
            srv_args.rc);
    TEST_OK("remote peer verified (ecdsa)", cli_args.remote_peer && peer_id_equals(cli_args.remote_peer, &expected_srv) == 1, "match=%d",
            cli_args.remote_peer ? peer_id_equals(cli_args.remote_peer, &expected_srv) : -1);
    TEST_OK("server saw client (ecdsa)", srv_args.remote_peer && peer_id_equals(srv_args.remote_peer, &expected_cli) == 1, "match=%d",
            srv_args.remote_peer ? peer_id_equals(srv_args.remote_peer, &expected_cli) : -1);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
    peer_id_destroy(&expected_cli);
    peer_id_destroy(&expected_srv);
    free(id_cli);
    free(id_srv);
}

static void test_early_data_extensions(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    uint8_t cli_ed[] = {0x01, 0x02, 0x03};
    uint8_t srv_ed[] = {0x04, 0x05};
    uint8_t cli_ext[] = {0x0A, 0x01, 0xAA};
    uint8_t srv_ext[] = {0x0A, 0x02, 0xBB, 0xCC};

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .early_data = cli_ed,
                                     .early_data_len = sizeof(cli_ed),
                                     .extensions = cli_ext,
                                     .extensions_len = sizeof(cli_ext),
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .early_data = srv_ed,
                                     .early_data_len = sizeof(srv_ed),
                                     .extensions = srv_ext,
                                     .extensions_len = sizeof(srv_ext),
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (ed)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 8600 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (ed)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (ed)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (ed)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (ed)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake ok (ed)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc, srv_args.rc);

    size_t len = 0;
    const uint8_t *ed_from_srv = noise_conn_get_early_data(cli_args.out, &len);
    TEST_OK("cli got srv early data", len == sizeof(srv_ed) && memcmp(ed_from_srv, srv_ed, len) == 0, "len=%zu", len);
    const uint8_t *ext_from_srv = noise_conn_get_extensions(cli_args.out, &len);
    TEST_OK("cli got srv ext", len == sizeof(srv_ext) && memcmp(ext_from_srv, srv_ext, len) == 0, "len=%zu", len);
    const uint8_t *ed_from_cli = noise_conn_get_early_data(srv_args.out, &len);
    TEST_OK("srv got cli early data", len == sizeof(cli_ed) && memcmp(ed_from_cli, cli_ed, len) == 0, "len=%zu", len);
    const uint8_t *ext_from_cli = noise_conn_get_extensions(srv_args.out, &len);
    TEST_OK("srv got cli ext", len == sizeof(cli_ext) && memcmp(ext_from_cli, cli_ext, len) == 0, "len=%zu", len);
    const noise_extensions_t *pex_srv = noise_conn_get_parsed_extensions(cli_args.out);
    TEST_OK("cli parsed srv ext",
            pex_srv && pex_srv->num_webtransport_certhashes == 1 && pex_srv->webtransport_certhashes_lens[0] == 2 &&
                memcmp(pex_srv->webtransport_certhashes[0], srv_ext + 2, 2) == 0 && pex_srv->num_stream_muxers == 0,
            "");
    const noise_extensions_t *pex_cli = noise_conn_get_parsed_extensions(srv_args.out);
    TEST_OK("srv parsed cli ext",
            pex_cli && pex_cli->num_webtransport_certhashes == 1 && pex_cli->webtransport_certhashes_lens[0] == 1 &&
                pex_cli->webtransport_certhashes[0][0] == 0xAA && pex_cli->num_stream_muxers == 0,
            "");

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_missing_static_key(void)
{
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    libp2p_noise_config_t cfg_cli = {.identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (msk)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9200 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (msk)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (msk)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (msk)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (msk)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake ok with generated static keys", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d",
            cli_args.rc, srv_args.rc);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

/* ------------------------------------------------------------------------- */
/*  Negative test helpers                                                    */
/* ------------------------------------------------------------------------- */

typedef struct corrupt_ctx
{
    libp2p_conn_t *inner;
    int write_idx;
    int seen;
} corrupt_ctx_t;

static ssize_t corrupt_read(libp2p_conn_t *c, void *buf, size_t len)
{
    corrupt_ctx_t *ctx = c->ctx;
    return libp2p_conn_read(ctx->inner, buf, len);
}

static ssize_t corrupt_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    corrupt_ctx_t *ctx = c->ctx;
    ctx->seen++;
    if (ctx->seen == ctx->write_idx && len > 2)
    {
        uint8_t *tmp = malloc(len);
        if (!tmp)
            return LIBP2P_CONN_ERR_INTERNAL;
        memcpy(tmp, buf, len);
        tmp[len - 1] ^= 0x01;
        ssize_t rc = libp2p_conn_write(ctx->inner, tmp, len);
        free(tmp);
        return rc;
    }
    return libp2p_conn_write(ctx->inner, buf, len);
}

static libp2p_conn_err_t corrupt_deadline(libp2p_conn_t *c, uint64_t ms)
{
    corrupt_ctx_t *ctx = c->ctx;
    return libp2p_conn_set_deadline(ctx->inner, ms);
}

static const multiaddr_t *corrupt_local(libp2p_conn_t *c)
{
    corrupt_ctx_t *ctx = c->ctx;
    return libp2p_conn_local_addr(ctx->inner);
}

static const multiaddr_t *corrupt_remote(libp2p_conn_t *c)
{
    corrupt_ctx_t *ctx = c->ctx;
    return libp2p_conn_remote_addr(ctx->inner);
}

static libp2p_conn_err_t corrupt_close(libp2p_conn_t *c)
{
    corrupt_ctx_t *ctx = c->ctx;
    return libp2p_conn_close(ctx->inner);
}

static void corrupt_free(libp2p_conn_t *c)
{
    if (!c)
        return;
    corrupt_ctx_t *ctx = c->ctx;
    if (ctx)
    {
        libp2p_conn_free(ctx->inner);
        free(ctx);
    }
    free(c);
}

static const libp2p_conn_vtbl_t CORRUPT_VTBL = {
    .read = corrupt_read,
    .write = corrupt_write,
    .set_deadline = corrupt_deadline,
    .local_addr = corrupt_local,
    .remote_addr = corrupt_remote,
    .close = corrupt_close,
    .free = corrupt_free,
};

static libp2p_conn_t *make_corrupt_conn(libp2p_conn_t *inner, int write_idx)
{
    corrupt_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->inner = inner;
    ctx->write_idx = write_idx;
    libp2p_conn_t *c = calloc(1, sizeof(*c));
    if (!c)
    {
        free(ctx);
        return NULL;
    }
    c->vt = &CORRUPT_VTBL;
    c->ctx = ctx;
    return c;
}

/* ------------------------------------------------------------------------- */
/*  Helper: initiator sends payload in first handshake message               */
/* ------------------------------------------------------------------------- */

typedef struct libp2p_noise_ctx_test
{
    unsigned char static_key[32];
    uint8_t *identity_key;
    size_t identity_key_len;
    int have_identity;
    int identity_type;
    uint8_t *early_data;
    size_t early_data_len;
    uint8_t *extensions;
    size_t extensions_len;
    size_t max_plaintext;
} libp2p_noise_ctx_test;

static libp2p_security_err_t first_msg_payload_handshake(libp2p_security_t *sec, libp2p_conn_t *raw)
{
    if (!sec || !raw)
        return LIBP2P_SECURITY_ERR_NULL_PTR;

    libp2p_noise_ctx_test *ctx = sec->ctx;

    if (noise_init() != NOISE_ERROR_NONE)
        return LIBP2P_SECURITY_ERR_INTERNAL;

    NoiseHandshakeState *hs = NULL;
    int err = noise_handshakestate_new_by_name(&hs, "Noise_XX_25519_ChaChaPoly_SHA256", NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE)
        return LIBP2P_SECURITY_ERR_INTERNAL;

    if (noise_handshakestate_needs_local_keypair(hs))
    {
        NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(hs);
        noise_dhstate_set_keypair_private(dh, ctx->static_key, sizeof(ctx->static_key));
    }

    err = noise_handshakestate_start(hs);
    if (err != NOISE_ERROR_NONE)
    {
        noise_handshakestate_free(hs);
        return LIBP2P_SECURITY_ERR_HANDSHAKE;
    }

    uint8_t buf[65535];
    uint8_t lenbuf[2];
    NoiseBuffer mbuf;
    unsigned msg_idx = 0;
    uint8_t dummy = 0xAA;

    for (;;)
    {
        int action = noise_handshakestate_get_action(hs);
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
            noise_buffer_set_output(mbuf, buf, sizeof(buf));
            NoiseBuffer pbuf;
            if (msg_idx == 0)
            {
                noise_buffer_set_input(pbuf, &dummy, 1);
                err = noise_handshakestate_write_message(hs, &mbuf, &pbuf);
            }
            else
            {
                err = noise_handshakestate_write_message(hs, &mbuf, NULL);
            }
            msg_idx++;
            if (err != NOISE_ERROR_NONE)
            {
                noise_handshakestate_free(hs);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            uint16_t l = (uint16_t)mbuf.size;
            lenbuf[0] = (uint8_t)(l >> 8);
            lenbuf[1] = (uint8_t)l;
            if (libp2p_conn_write(raw, lenbuf, 2) != 2 || libp2p_conn_write(raw, buf, mbuf.size) != (ssize_t)mbuf.size)
            {
                noise_handshakestate_free(hs);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {
            if (libp2p_conn_read(raw, lenbuf, 2) != 2)
            {
                noise_handshakestate_free(hs);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            uint16_t l = ((uint16_t)lenbuf[0] << 8) | lenbuf[1];
            if (l > sizeof(buf))
            {
                noise_handshakestate_free(hs);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            if (libp2p_conn_read(raw, buf, l) != l)
            {
                noise_handshakestate_free(hs);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
            noise_buffer_set_input(mbuf, buf, l);
            uint8_t pbuf_data[NOISE_MAX_PAYLOAD_LEN];
            NoiseBuffer pbuf;
            noise_buffer_set_output(pbuf, pbuf_data, sizeof(pbuf_data));
            err = noise_handshakestate_read_message(hs, &mbuf, &pbuf);
            if (err != NOISE_ERROR_NONE)
            {
                noise_handshakestate_free(hs);
                return LIBP2P_SECURITY_ERR_HANDSHAKE;
            }
        }
        else
        {
            break;
        }
    }

    noise_handshakestate_free(hs);
    return LIBP2P_SECURITY_OK;
}

static libp2p_security_err_t first_msg_payload_negotiate_outbound(libp2p_security_t *sec, libp2p_conn_t *conn)
{
    const char *props[] = {LIBP2P_NOISE_PROTO_ID, NULL};
    if (libp2p_multiselect_dial(conn, props, 0, NULL) != LIBP2P_MULTISELECT_OK)
        return LIBP2P_SECURITY_ERR_HANDSHAKE;

    return first_msg_payload_handshake(sec, conn);
}

static void *first_payload_thread(void *arg)
{
    struct hs_args *a = arg;
    a->rc = first_msg_payload_negotiate_outbound(a->sec, a->conn);
    a->out = NULL;
    a->remote_peer = NULL;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*  Negative test cases                                                      */
/* ------------------------------------------------------------------------- */

static void test_corrupt_payload(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (corrupt)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9400 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (corrupt)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (corrupt)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli_raw = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli_raw);
    TEST_OK("dial (corrupt)", rc == 0 && cli_raw, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (corrupt)", rc == 0 && srv, "rc=%d", rc);

    libp2p_conn_t *cli = make_corrupt_conn(cli_raw, 3);
    TEST_OK("wrap conn (corrupt)", cli != NULL, "cli_wrap=%p", (void *)cli);
    if (!cli)
    {
        libp2p_conn_close(cli_raw);
        libp2p_conn_free(cli_raw);
        goto cleanup_srv;
    }

    libp2p_conn_set_deadline(cli, 1000);
    libp2p_conn_set_deadline(srv, 1000);

    tcp_conn_ctx_t *cctx = cli_raw->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake fail on corrupt payload", cli_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE && srv_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE,
            "cli=%d srv=%d", cli_args.rc, srv_args.rc);


cleanup_srv:
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_oversized_payload(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    size_t big_len = NOISE_MAX_PAYLOAD_LEN + 1;
    uint8_t *big = malloc(big_len);
    memset(big, 0xAA, big_len);

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .early_data = big,
                                     .early_data_len = big_len,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (oversize)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
    {
        free(big);
        return;
    }

    int port = 9500 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (oversize)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (oversize)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (oversize)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (oversize)", rc == 0 && srv, "rc=%d", rc);

    libp2p_conn_set_deadline(cli, 1000);
    libp2p_conn_set_deadline(srv, 1000);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake fail on oversize payload", cli_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE && srv_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE,
            "cli=%d srv=%d", cli_args.rc, srv_args.rc);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);

    free(big);
}

static void test_initiator_payload_msg1(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (msg1)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9450 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (msg1)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (msg1)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (msg1)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (msg1)", rc == 0 && srv, "rc=%d", rc);

    libp2p_conn_set_deadline(cli, 1000);
    libp2p_conn_set_deadline(srv, 1000);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, first_payload_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake fail on msg1 payload", cli_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE && srv_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE,
            "cli=%d srv=%d", cli_args.rc, srv_args.rc);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_max_plaintext_limit(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 8};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 8};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (maxpt)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9600 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (maxpt)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (maxpt)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (maxpt)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (maxpt)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake (maxpt)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc, srv_args.rc);

    size_t max_plaintext = noise_conn_debug_get_max_plaintext(cli_args.out);
    TEST_OK("maxpt stored", max_plaintext == 8, "max=%zu", max_plaintext);

    libp2p_conn_t *sc = cli_args.out;
    libp2p_conn_t *ss = srv_args.out;

    const char ping[] = "ping";
    size_t ping_len = 4;
    libp2p_conn_write(sc, ping, ping_len);
    char buf[16] = {0};
    ssize_t n = libp2p_conn_read(ss, buf, sizeof(buf));
    TEST_OK("ping ok (maxpt)", n == (ssize_t)ping_len, "n=%zd", n);

    const char big[] = "0123456789ABCDEF";
    ssize_t w = libp2p_conn_write(sc, big, sizeof(big));
    TEST_OK("write limited", w == LIBP2P_CONN_ERR_INTERNAL, "w=%zd", w);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_message_counter_limit(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (msgcnt)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9650 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (msgcnt)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (msgcnt)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (msgcnt)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (msgcnt)", rc == 0 && srv, "rc=%d", rc);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake (msgcnt)", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc, srv_args.rc);

    noise_conn_debug_set_send_count(cli_args.out, UINT64_MAX);
    ssize_t w = libp2p_conn_write(cli_args.out, "x", 1);
    TEST_OK("send limit", w == LIBP2P_CONN_ERR_CLOSED, "w=%zd", w);

    noise_conn_debug_set_send_count(cli_args.out, 0);
    noise_conn_debug_set_recv_count(cli_args.out, UINT64_MAX);
    char tmp[1];
    ssize_t r = libp2p_conn_read(cli_args.out, tmp, sizeof(tmp));
    TEST_OK("recv limit", r == LIBP2P_CONN_ERR_CLOSED, "r=%zd", r);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_unregistered_extension(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    uint8_t ext[] = {0x01, 0x01, 0xAA};

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .extensions = ext,
                                     .extensions_len = sizeof(ext),
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .extensions = ext,
                                     .extensions_len = sizeof(ext),
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (ureg)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9600 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (ureg)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (ureg)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (ureg)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (ureg)", rc == 0 && srv, "rc=%d", rc);

    libp2p_conn_set_deadline(cli, 1000);
    libp2p_conn_set_deadline(srv, 1000);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake fail on unregistered ext", cli_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE && srv_args.rc == LIBP2P_SECURITY_ERR_HANDSHAKE,
            "cli=%d srv=%d", cli_args.rc, srv_args.rc);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

static void test_experimental_extension(void)
{
    uint8_t key_cli[32];
    uint8_t key_srv[32];
    uint8_t id_cli[32];
    uint8_t id_srv[32];
    noise_randstate_generate_simple(key_cli, sizeof(key_cli));
    noise_randstate_generate_simple(key_srv, sizeof(key_srv));
    noise_randstate_generate_simple(id_cli, sizeof(id_cli));
    noise_randstate_generate_simple(id_srv, sizeof(id_srv));

    uint8_t ext[] = {0x9A, 0x08, 0x01, 0xAA};

    libp2p_noise_config_t cfg_cli = {.static_private_key = key_cli,
                                     .static_private_key_len = sizeof(key_cli),
                                     .identity_private_key = id_cli,
                                     .identity_private_key_len = sizeof(id_cli),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .extensions = ext,
                                     .extensions_len = sizeof(ext),
                                     .max_plaintext = 0};
    libp2p_noise_config_t cfg_srv = {.static_private_key = key_srv,
                                     .static_private_key_len = sizeof(key_srv),
                                     .identity_private_key = id_srv,
                                     .identity_private_key_len = sizeof(id_srv),
                                     .identity_key_type = PEER_ID_ED25519_KEY_TYPE,
                                     .extensions = ext,
                                     .extensions_len = sizeof(ext),
                                     .max_plaintext = 0};

    libp2p_security_t *sec_cli = libp2p_noise_security_new(&cfg_cli);
    libp2p_security_t *sec_srv = libp2p_noise_security_new(&cfg_srv);
    TEST_OK("sec alloc (exp)", sec_cli && sec_srv, "cli=%p srv=%p", (void *)sec_cli, (void *)sec_srv);
    if (!sec_cli || !sec_srv)
        return;

    int port = 9700 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port);
    int err;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("addr parse (exp)", addr && err == 0, "err=%d", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("listen (exp)", rc == 0 && lst, "rc=%d", rc);

    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("dial (exp)", rc == 0 && cli, "rc=%d", rc);

    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, 20, 100);
    TEST_OK("accept (exp)", rc == 0 && srv, "rc=%d", rc);

    libp2p_conn_set_deadline(cli, 1000);
    libp2p_conn_set_deadline(srv, 1000);

    tcp_conn_ctx_t *cctx = cli->ctx;
    tcp_conn_ctx_t *sctx = srv->ctx;
    int flags = fcntl(cctx->fd, F_GETFL, 0);
    fcntl(cctx->fd, F_SETFL, flags & ~O_NONBLOCK);
    flags = fcntl(sctx->fd, F_GETFL, 0);
    fcntl(sctx->fd, F_SETFL, flags & ~O_NONBLOCK);

    struct hs_args cli_args = {.sec = sec_cli, .conn = cli, .hint = NULL, .out = NULL, .remote_peer = NULL};
    struct hs_args srv_args = {.sec = sec_srv, .conn = srv, .hint = NULL, .out = NULL, .remote_peer = NULL};
    pthread_t t_cli, t_srv;
    pthread_create(&t_cli, NULL, outbound_thread, &cli_args);
    pthread_create(&t_srv, NULL, inbound_thread, &srv_args);
    pthread_join(t_cli, NULL);
    pthread_join(t_srv, NULL);

    TEST_OK("handshake ok with exp ext", cli_args.rc == LIBP2P_SECURITY_OK && srv_args.rc == LIBP2P_SECURITY_OK, "cli=%d srv=%d", cli_args.rc,
            srv_args.rc);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(addr);

    libp2p_security_free(sec_cli);
    libp2p_security_free(sec_srv);
    free_hs_args(&cli_args);
    free_hs_args(&srv_args);
}

int main(void)
{
    failures += test_creation();
    test_identity_key_length();
    test_handshake_success();
    test_identity_handshake_success();
    test_identity_hint_mismatch();
    test_secp256k1_identity_handshake_success();
    test_ecdsa_identity_handshake_success();
    test_rsa_identity_handshake_success();
    test_early_data_extensions();
    test_missing_static_key();
    test_corrupt_payload();
    test_initiator_payload_msg1();
    test_oversized_payload();
    test_max_plaintext_limit();
    test_message_counter_limit();
    test_unregistered_extension();
    test_experimental_extension();
    if (failures)
        printf("\nSome tests failed - total failures: %d\n", failures);
    return failures ? 1 : 0;
}
