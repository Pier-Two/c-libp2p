#include <inttypes.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "libp2p/errors.h"
#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/protocol.h"
#include "libp2p/stream.h"
#include "peer_id/peer_id.h"

#define TEST_PROTO_ID "/test/quic/host-loopback/1.0.0"
#define SERVER_PRIVATE_KEY_HEX "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"
#define CLIENT_PRIVATE_KEY_HEX "080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

static const int k_short_wait_ms = 1500;
static const int k_close_wait_ms = 500;
static const int k_read_timeout_ms = 2000;

static void sleep_ms(unsigned ms)
{
#ifndef _WIN32
    usleep(ms * 1000);
#else
    Sleep(ms);
#endif
}

static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
    if (!hex)
        return NULL;
    size_t len = strlen(hex);
    if ((len & 1U) != 0)
        return NULL;
    size_t bytes_len = len / 2;
    uint8_t *buf = (uint8_t *)malloc(bytes_len);
    if (!buf)
        return NULL;
    for (size_t i = 0; i < bytes_len; i++)
    {
        char chunk[3] = {hex[2 * i], hex[2 * i + 1], '\0'};
        buf[i] = (uint8_t)strtoul(chunk, NULL, 16);
    }
    if (out_len)
        *out_len = bytes_len;
    return buf;
}

static int wait_for_listen_addr(libp2p_host_t *host, char *out, size_t out_len, int timeout_ms)
{
    if (!host || !out || out_len == 0)
        return 0;
    const int step = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(host, step, &evt);
        if (got == 1)
        {
            int match = (evt.kind == LIBP2P_EVT_LISTEN_ADDR_ADDED && evt.u.listen_addr_added.addr);
            if (match)
            {
                snprintf(out, out_len, "%s", evt.u.listen_addr_added.addr);
                libp2p_event_free(&evt);
                return 1;
            }
            libp2p_event_free(&evt);
        }
        waited += step;
    }
    return 0;
}

static int wait_for_event_kind(libp2p_host_t *host, libp2p_event_kind_t kind, int timeout_ms)
{
    if (!host)
        return 0;
    const int step = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(host, step, &evt);
        if (got == 1)
        {
            int match = (evt.kind == kind);
            libp2p_event_free(&evt);
            if (match)
                return 1;
        }
        waited += step;
    }
    return 0;
}

static int wait_for_flag(libp2p_host_t *host, atomic_int *flag, int timeout_ms)
{
    if (!flag)
        return 0;
    const int step = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        if (atomic_load_explicit(flag, memory_order_acquire))
            return 1;
        if (host)
        {
            libp2p_event_t evt = {0};
            int got = libp2p_host_next_event(host, step, &evt);
            if (got == 1)
                libp2p_event_free(&evt);
        }
        else
        {
            sleep_ms(step);
        }
        waited += step;
    }
    return atomic_load_explicit(flag, memory_order_acquire) ? 1 : 0;
}

typedef struct server_ctx
{
    const peer_id_t *expected_remote;
    const uint8_t *expected_payload;
    size_t expected_len;
    atomic_int open_seen;
    atomic_int echoed;
} server_ctx_t;

static void server_on_open(libp2p_stream_t *s, void *user_data)
{
    server_ctx_t *ctx = (server_ctx_t *)user_data;
    if (!ctx || !s)
        return;
    const peer_id_t *remote = libp2p_stream_remote_peer(s);
    if (ctx->expected_remote && remote && peer_id_equals(remote, ctx->expected_remote) == 1)
        atomic_store_explicit(&ctx->open_seen, 1, memory_order_release);
}

static void server_on_data(libp2p_stream_t *s, const uint8_t *data, size_t len, void *user_data)
{
    server_ctx_t *ctx = (server_ctx_t *)user_data;
    if (!ctx || !s || !data || len == 0)
        return;
    if (ctx->expected_payload && len == ctx->expected_len && memcmp(data, ctx->expected_payload, len) == 0)
    {
        ssize_t w = libp2p_stream_write(s, data, len);
        if (w == (ssize_t)len)
            atomic_store_explicit(&ctx->echoed, 1, memory_order_release);
    }
}

int main(void)
{
    int exit_code = 1;
    libp2p_host_builder_t *srv_builder = NULL;
    libp2p_host_builder_t *cli_builder = NULL;
    libp2p_host_t *server = NULL;
    libp2p_host_t *client = NULL;
    uint8_t *server_sk = NULL;
    uint8_t *client_sk = NULL;
    size_t server_sk_len = 0;
    size_t client_sk_len = 0;
    peer_id_t *server_peer = NULL;
    peer_id_t *client_peer = NULL;
    libp2p_stream_t *stream = NULL;
    int protocol_registered = 0;
    int server_started = 0;
    server_ctx_t srv_ctx;
    memset(&srv_ctx, 0, sizeof(srv_ctx));
    atomic_init(&srv_ctx.open_seen, 0);
    atomic_init(&srv_ctx.echoed, 0);
    static const uint8_t PAYLOAD[] = "quic-host-loopback";
    srv_ctx.expected_payload = PAYLOAD;
    srv_ctx.expected_len = sizeof(PAYLOAD) - 1;
    char server_addr[256] = {0};

    srv_builder = libp2p_host_builder_new();
    if (!srv_builder)
        goto cleanup;
    (void)libp2p_host_builder_listen_addr(srv_builder, "/ip4/127.0.0.1/udp/0/quic_v1");
    (void)libp2p_host_builder_transport(srv_builder, "quic");
    (void)libp2p_host_builder_flags(srv_builder, 0);

    if (libp2p_host_builder_build(srv_builder, &server) != 0 || !server)
        goto cleanup;
    libp2p_host_builder_free(srv_builder);
    srv_builder = NULL;

    server_sk = hex_to_bytes(SERVER_PRIVATE_KEY_HEX, &server_sk_len);
    if (!server_sk || libp2p_host_set_private_key(server, server_sk, server_sk_len) != 0)
        goto cleanup;

    libp2p_protocol_def_t proto = {
        .protocol_id = TEST_PROTO_ID,
        .read_mode = LIBP2P_READ_PUSH,
        .on_open = server_on_open,
        .on_data = server_on_data,
        .on_eof = NULL,
        .on_close = NULL,
        .on_error = NULL,
        .user_data = &srv_ctx,
    };
    if (libp2p_register_protocol(server, &proto) != 0)
        goto cleanup;
    protocol_registered = 1;

    if (libp2p_host_start(server) != 0)
        goto cleanup;
    server_started = 1;

    if (!wait_for_listen_addr(server, server_addr, sizeof(server_addr), 2000))
        goto cleanup;
    fprintf(stderr, "[test] server listening on %s\n", server_addr);

    cli_builder = libp2p_host_builder_new();
    if (!cli_builder)
        goto cleanup;
    (void)libp2p_host_builder_transport(cli_builder, "quic");
    (void)libp2p_host_builder_flags(cli_builder, 0);
    if (libp2p_host_builder_build(cli_builder, &client) != 0 || !client)
        goto cleanup;
    libp2p_host_builder_free(cli_builder);
    cli_builder = NULL;

    client_sk = hex_to_bytes(CLIENT_PRIVATE_KEY_HEX, &client_sk_len);
    if (!client_sk || libp2p_host_set_private_key(client, client_sk, client_sk_len) != 0)
        goto cleanup;

    if (libp2p_host_get_peer_id(server, &server_peer) != 0 || !server_peer)
        goto cleanup;
    if (libp2p_host_get_peer_id(client, &client_peer) != 0 || !client_peer)
        goto cleanup;
    srv_ctx.expected_remote = client_peer;

    if (libp2p_host_dial_protocol_blocking(client, server_addr, TEST_PROTO_ID, 5000, &stream) != 0 || !stream)
        goto cleanup;
    fprintf(stderr, "[test] dial succeeded\n");

    if (!wait_for_event_kind(client, LIBP2P_EVT_STREAM_OPENED, k_short_wait_ms))
        goto cleanup;
    if (!wait_for_flag(server, &srv_ctx.open_seen, k_short_wait_ms))
        goto cleanup;
    fprintf(stderr, "[test] stream opened events observed\n");

    const peer_id_t *remote = libp2p_stream_remote_peer(stream);
    if (!remote || peer_id_equals(remote, server_peer) != 1)
        goto cleanup;
    fprintf(stderr, "[test] remote peer verified\n");

    size_t payload_len = sizeof(PAYLOAD) - 1;
    if (libp2p_stream_write(stream, PAYLOAD, payload_len) != (ssize_t)payload_len)
        goto cleanup;

    uint8_t recv_buf[sizeof(PAYLOAD)] = {0};
    size_t received = 0;
    int waited = 0;
    while (received < payload_len && waited < k_read_timeout_ms)
    {
        ssize_t n = libp2p_stream_read(stream, recv_buf + received, payload_len - received);
        if (n == LIBP2P_ERR_AGAIN)
        {
            sleep_ms(20);
            waited += 20;
            continue;
        }
        if (n <= 0)
        {
            fprintf(stderr, "[test] stream read failed: %zd\n", n);
            goto cleanup;
        }
        received += (size_t)n;
    }
    if (received != payload_len || memcmp(recv_buf, PAYLOAD, payload_len) != 0)
    {
        fprintf(stderr, "[test] payload mismatch or timeout (received=%zu waited=%d)\n", received, waited);
        goto cleanup;
    }
    if (!wait_for_flag(server, &srv_ctx.echoed, k_short_wait_ms))
        goto cleanup;
    fprintf(stderr, "[test] payload echoed\n");

    libp2p_stream_close(stream);
    libp2p_stream_free(stream);
    stream = NULL;

    (void)wait_for_event_kind(client, LIBP2P_EVT_STREAM_CLOSED, k_close_wait_ms);
    (void)wait_for_event_kind(server, LIBP2P_EVT_STREAM_CLOSED, k_close_wait_ms);

    exit_code = 0;

cleanup:
    if (stream)
    {
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
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
    if (client)
        libp2p_host_free(client);
    if (server)
    {
        if (protocol_registered)
            libp2p_unregister_protocol(server, TEST_PROTO_ID);
        if (server_started)
            libp2p_host_stop(server);
        libp2p_host_free(server);
    }
    if (cli_builder)
        libp2p_host_builder_free(cli_builder);
    if (srv_builder)
        libp2p_host_builder_free(srv_builder);
    if (client_sk)
    {
        memset(client_sk, 0, client_sk_len);
        free(client_sk);
    }
    if (server_sk)
    {
        memset(server_sk, 0, server_sk_len);
        free(server_sk);
    }
    return exit_code;
}
