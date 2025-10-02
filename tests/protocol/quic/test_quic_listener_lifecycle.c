#include "protocol/quic/protocol_quic.h"

#include "libp2p/errors.h"
#include "transport/transport.h"
#include "transport/listener.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KEY_TYPE_ED25519 1

static void print_result(const char *name, const char *details, int ok)
{
    if (ok)
        printf("TEST: %-70s | PASS\n", name);
    else
        printf("TEST: %-70s | FAIL: %s\n", name, details ? details : "");
    fflush(stdout);
}

static int failures = 0;

#define TEST_CHECK(name, cond, fmt, ...)                                                                                                             \
    do                                                                                                                                              \
    {                                                                                                                                               \
        if (cond)                                                                                                                                   \
            print_result(name, "", 1);                                                                                                             \
        else                                                                                                                                        \
        {                                                                                                                                           \
            char _msg[256];                                                                                                                         \
            snprintf(_msg, sizeof(_msg), fmt, ##__VA_ARGS__);                                                                                       \
            print_result(name, _msg, 0);                                                                                                            \
            failures++;                                                                                                                             \
        }                                                                                                                                           \
    } while (0)

static int hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
    if (!hex || !out_len)
        return NULL;
    size_t digits = 0;
    for (const char *p = hex; *p; ++p)
    {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
            continue;
        if (hex_char_to_val(*p) < 0)
            return NULL;
        digits++;
    }
    if ((digits & 1U) != 0)
        return NULL;
    size_t len = digits / 2;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf)
        return NULL;
    size_t idx = 0;
    int high = -1;
    for (const char *p = hex; *p; ++p)
    {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
            continue;
        int val = hex_char_to_val(*p);
        if (val < 0)
        {
            free(buf);
            return NULL;
        }
        if (high < 0)
            high = val;
        else
        {
            buf[idx++] = (uint8_t)((high << 4) | val);
            high = -1;
        }
    }
    *out_len = len;
    return buf;
}

static const uint8_t SERVER_ID_KEY[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
    0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1f};

#define CLIENT_PRIVATE_KEY_HEX "080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

static libp2p_listener_err_t accept_with_backoff(libp2p_listener_t *lst, libp2p_conn_t **out_conn)
{
    const int max_attempts = 200;
    for (int i = 0; i < max_attempts; i++)
    {
        libp2p_listener_err_t rc = libp2p_listener_accept(lst, out_conn);
        if (rc == LIBP2P_LISTENER_OK || rc == LIBP2P_LISTENER_ERR_CLOSED)
            return rc;
        if (rc != LIBP2P_LISTENER_ERR_AGAIN)
            return rc;
        usleep(2000);
    }
    return LIBP2P_LISTENER_ERR_TIMEOUT;
}

int main(void)
{
    libp2p_transport_t *server = libp2p_quic_transport_new(NULL);
    TEST_CHECK("Server transport allocation", server != NULL, "server transport null");
    if (!server)
        return 1;

    libp2p_quic_tls_cert_options_t server_opts = libp2p_quic_tls_cert_options_default();
    server_opts.identity_key_type = KEY_TYPE_ED25519;
    server_opts.identity_key = SERVER_ID_KEY;
    server_opts.identity_key_len = sizeof(SERVER_ID_KEY);
    TEST_CHECK("Server identity setup", libp2p_quic_transport_set_identity(server, &server_opts) == 0, "set identity failed");

    libp2p_transport_t *client = libp2p_quic_transport_new(NULL);
    TEST_CHECK("Client transport allocation", client != NULL, "client transport null");
    if (!client)
    {
        libp2p_transport_free(server);
        return 1;
    }

    size_t client_key_len = 0;
    uint8_t *client_key = hex_to_bytes(CLIENT_PRIVATE_KEY_HEX, &client_key_len);
    TEST_CHECK("Client key decode", client_key != NULL && client_key_len > 0, "hex decode failed");
    if (!client_key)
    {
        libp2p_transport_free(server);
        libp2p_transport_free(client);
        return 1;
    }

    libp2p_quic_tls_cert_options_t client_opts = libp2p_quic_tls_cert_options_default();
    client_opts.identity_key_type = KEY_TYPE_ED25519;
    client_opts.identity_key = client_key;
    client_opts.identity_key_len = client_key_len;
    TEST_CHECK("Client identity setup", libp2p_quic_transport_set_identity(client, &client_opts) == 0, "set identity failed");

    int addr_err = 0;
    multiaddr_t *listen_addr = multiaddr_new_from_str("/ip4/127.0.0.1/udp/0/quic_v1", &addr_err);
    TEST_CHECK("Listen multiaddr parse", listen_addr != NULL && addr_err == 0, "parse err=%d", addr_err);

    libp2p_listener_t *listener = NULL;
    libp2p_transport_err_t lrc = libp2p_transport_listen(server, listen_addr, &listener);
    TEST_CHECK("Transport listen", lrc == LIBP2P_TRANSPORT_OK && listener != NULL, "listen rc=%d", lrc);

    multiaddr_t *bound_addr = NULL;
    if (listener)
    {
        libp2p_listener_err_t laddr_rc = libp2p_listener_local_addr(listener, &bound_addr);
        TEST_CHECK("Retrieve bound address", laddr_rc == LIBP2P_LISTENER_OK && bound_addr != NULL, "local addr rc=%d", laddr_rc);
        if (bound_addr)
        {
            int s_err = 0;
            char *s = multiaddr_to_str(bound_addr, &s_err);
            if (s)
            {
                printf("INFO: Bound address %s (err=%d)\n", s, s_err);
                fflush(stdout);
                free(s);
            }
        }
    }

    libp2p_conn_t *client_conn = NULL;
    libp2p_transport_err_t dial_rc = libp2p_transport_dial(client, bound_addr, &client_conn);
    TEST_CHECK("Client dial", dial_rc == LIBP2P_TRANSPORT_OK && client_conn != NULL, "dial rc=%d", dial_rc);

    libp2p_conn_t *server_conn = NULL;
    libp2p_listener_err_t acc_rc = accept_with_backoff(listener, &server_conn);
    TEST_CHECK("Server accept", acc_rc == LIBP2P_LISTENER_OK && server_conn != NULL, "accept rc=%d", acc_rc);

    peer_id_t *client_peer = NULL;
    if (client_conn)
    {
        int prc = libp2p_quic_conn_copy_verified_peer(client_conn, &client_peer);
        TEST_CHECK("Client verified peer", prc == LIBP2P_ERR_OK && client_peer != NULL, "rc=%d", prc);
    }

    peer_id_t *server_peer = NULL;
    if (server_conn)
    {
        int prc = libp2p_quic_conn_copy_verified_peer(server_conn, &server_peer);
        TEST_CHECK("Server verified peer", prc == LIBP2P_ERR_OK && server_peer != NULL, "rc=%d", prc);
    }

    if (client_peer)
    {
        peer_id_destroy(client_peer);
        free(client_peer);
    }
    if (server_peer)
    {
        peer_id_destroy(server_peer);
        free(server_peer);
    }

    if (client_conn)
    {
        libp2p_conn_close(client_conn);
        libp2p_conn_free(client_conn);
    }
    if (server_conn)
    {
        libp2p_conn_close(server_conn);
        libp2p_conn_free(server_conn);
    }

    if (listener)
    {
        libp2p_listener_close(listener);
        libp2p_listener_err_t post_rc = libp2p_listener_accept(listener, &server_conn);
        TEST_CHECK("Accept after close", post_rc == LIBP2P_LISTENER_ERR_CLOSED, "post rc=%d", post_rc);
        libp2p_listener_free(listener);
    }

    libp2p_transport_close(client);
    libp2p_transport_close(server);
    libp2p_transport_free(client);
    libp2p_transport_free(server);

    multiaddr_free(listen_addr);
    multiaddr_free(bound_addr);
    if (client_key)
    {
        memset(client_key, 0, client_key_len);
        free(client_key);
    }

    return failures == 0 ? 0 : 1;
}
