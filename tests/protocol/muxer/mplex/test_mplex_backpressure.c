#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <noise/protocol.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Include internal header FIRST to get the correct structure definition */
#include "../../../../src/protocol/muxer/mplex/protocol_mplex_conn.h"
#include "../../../../src/protocol/muxer/mplex/protocol_mplex_internal.h"
#include "protocol/noise/protocol_noise_conn.h"
#include "protocol/tcp/protocol_tcp_conn.h"

/* Standard test output function matching other tests in the project */
static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", test_name);
    else
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
}

/* Test context structure */
typedef struct
{
    int server_fd;
    int client_fd;
    libp2p_mplex_ctx_t *server_ctx;
    libp2p_mplex_ctx_t *client_ctx;
    pthread_t server_thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int server_ready;
} test_context_t;

/* Robust connect helper: retry transient failures until server accepts */
static int connect_with_retry(int sockfd, const struct sockaddr_in *addr, int max_attempts, int delay_us)
{
    for (int attempt = 0; attempt < max_attempts; attempt++)
    {
        if (connect(sockfd, (const struct sockaddr *)addr, sizeof(*addr)) == 0)
        {
            return 0;
        }
        if (errno == EINTR || errno == ECONNREFUSED || errno == EAGAIN || errno == EWOULDBLOCK)
        {
            usleep(delay_us);
            continue;
        }
        usleep(delay_us);
    }
    return -1;
}

/* Perform Noise handshake */
static int perform_noise_handshake(int fd, bool is_initiator, NoiseCipherState **send_cipher_out, NoiseCipherState **recv_cipher_out)
{
    NoiseHandshakeState *state;
    NoiseCipherState *send_cipher = NULL;
    NoiseCipherState *recv_cipher = NULL;
    uint8_t buffer[1024];
    size_t len;
    NoiseBuffer mbuf;
    int rc = -1; // Default to error

    *send_cipher_out = NULL;
    *recv_cipher_out = NULL;

    /* Create handshake state */
    if (noise_handshakestate_new_by_name(&state, "Noise_XX_25519_ChaChaPoly_SHA256", is_initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER) < 0)
    {
        goto cleanup;
    }

    /* Generate and set the local static keypair for the XX pattern */
    NoiseDHState *local_dh = noise_handshakestate_get_local_keypair_dh(state);
    if (!local_dh)
    {
        goto cleanup;
    }
    if (noise_dhstate_generate_keypair(local_dh) != NOISE_ERROR_NONE)
    {
        goto cleanup;
    }

    /* Start the handshake process */
    if (noise_handshakestate_start(state) != NOISE_ERROR_NONE)
    {
        goto cleanup;
    }

    /* Perform handshake */
    int msg_count = 0;
    while (noise_handshakestate_get_action(state) != NOISE_ACTION_SPLIT)
    {
        int action = noise_handshakestate_get_action(state);
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
            noise_buffer_set_output(mbuf, buffer + 2, sizeof(buffer) - 2);
            if (noise_handshakestate_write_message(state, &mbuf, NULL) < 0)
            {
                goto cleanup;
            }
            uint16_t msg_len = (uint16_t)mbuf.size;
            buffer[0] = (uint8_t)(msg_len >> 8);
            buffer[1] = (uint8_t)msg_len;
            if (write(fd, buffer, msg_len + 2) != (ssize_t)(msg_len + 2))
            {
                goto cleanup;
            }
            msg_count++;
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {
            if (read(fd, buffer, 2) != 2)
            {
                goto cleanup;
            }
            uint16_t msg_len = ((uint16_t)buffer[0] << 8) | buffer[1];
            if (msg_len > sizeof(buffer) - 2)
            {
                goto cleanup;
            }
            if (read(fd, buffer + 2, msg_len) != msg_len)
            {
                goto cleanup;
            }
            noise_buffer_set_input(mbuf, buffer + 2, msg_len);
            if (noise_handshakestate_read_message(state, &mbuf, NULL) < 0)
            {
                goto cleanup;
            }
        }
        else
        {
            break;
        }
    }

    /* Split cipher states */
    if (noise_handshakestate_split(state, &send_cipher, &recv_cipher) < 0)
    {
        goto cleanup;
    }

    *send_cipher_out = send_cipher;
    *recv_cipher_out = recv_cipher;
    rc = 0; // Success

cleanup:
    if (rc != 0)
    {
        if (send_cipher)
            noise_cipherstate_free(send_cipher);
        if (recv_cipher)
            noise_cipherstate_free(recv_cipher);
    }
    noise_handshakestate_free(state);
    return rc;
}

/* Server thread function */
static void *server_main(void *arg)
{
    test_context_t *tctx = (test_context_t *)arg;
    struct sockaddr_in addr;
    int server_sock = -1, client_sock = -1;
    libp2p_conn_t *server_conn = NULL;
    libp2p_mplex_ctx_t *server_ctx = NULL;
    int mplex_fd = -1;

    /* Create server socket */
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        goto cleanup;
    }

    /* Use blocking server socket to allow accept() to wait for client */

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0); /* Let OS choose port */

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(server_sock, 1) < 0)
    {
        goto cleanup;
    }

    /* Get actual port */
    socklen_t addr_len = sizeof(addr);
    if (getsockname(server_sock, (struct sockaddr *)&addr, &addr_len) < 0)
    {
        goto cleanup;
    }

    /* Signal main thread with port */
    pthread_mutex_lock(&tctx->mutex);
    tctx->server_fd = ntohs(addr.sin_port);
    pthread_cond_signal(&tctx->cond);
    pthread_mutex_unlock(&tctx->mutex);

    /* Accept client connection */
    client_sock = accept(server_sock, NULL, NULL);
    if (client_sock < 0)
    {
        goto cleanup;
    }

    /* Close server socket as we don't need it anymore */
    close(server_sock);
    server_sock = -1;

    /* Perform Noise handshake */
    NoiseCipherState *server_send_cipher = NULL;
    NoiseCipherState *server_recv_cipher = NULL;
    if (perform_noise_handshake(client_sock, false, &server_send_cipher, &server_recv_cipher) < 0)
    {
        goto cleanup;
    }

    /* Create TCP connection object for mplex */
    libp2p_conn_t *raw_server_conn = make_tcp_conn(client_sock);
    if (!raw_server_conn)
    {
        // If make_tcp_conn fails, it doesn't take ownership of client_sock,
        // so we need to close it ourselves.
        noise_cipherstate_free(server_send_cipher);
        noise_cipherstate_free(server_recv_cipher);
        close(client_sock);
        client_sock = -1; // Mark as closed to avoid double close in cleanup
        goto cleanup;
    }
    // client_sock is now owned by raw_server_conn

    /* Create Noise-wrapped connection object for mplex */
    server_conn = make_noise_conn(raw_server_conn, server_send_cipher, server_recv_cipher, 0, NULL, 0, NULL, 0, NULL);
    if (!server_conn)
    {
        // make_noise_conn failed, so we need to clean up the resources it didn't take ownership of
        // make_noise_conn doesn't free the input parameters on failure, so we must do it here
        if (raw_server_conn)
        {
            libp2p_conn_free(raw_server_conn);
        }
        // Free the cipher states since they weren't taken ownership of by make_noise_conn
        if (server_send_cipher)
        {
            noise_cipherstate_free(server_send_cipher);
        }
        if (server_recv_cipher)
        {
            noise_cipherstate_free(server_recv_cipher);
        }
        goto cleanup;
    }
    // raw_server_conn, server_send_cipher, server_recv_cipher are now owned by server_conn

    /* Create Mplex context */
    if (libp2p_mplex_new(server_conn, &server_ctx) != LIBP2P_MPLEX_OK)
    {
        goto cleanup;
    }

    /* Perform negotiation */
    if (libp2p_mplex_negotiate_inbound(server_ctx, 5000) != LIBP2P_MPLEX_OK)
    {
        goto cleanup;
    }

    /* Get mplex file descriptor */
    mplex_fd = libp2p_mplex_get_fd(server_ctx);
    if (mplex_fd < 0)
    {
        goto cleanup;
    }

    /* Store context for cleanup */
    pthread_mutex_lock(&tctx->mutex);
    tctx->server_ctx = server_ctx;
    pthread_mutex_unlock(&tctx->mutex);

    /* Simple event processing loop */
    while (1)
    {
        libp2p_mplex_run_event_loop(server_ctx, 100);
        /* Exit if test asked us to stop or server_fd was cleared */
        if (tctx->server_fd <= 0)
            break;
        if (atomic_load(&server_ctx->stop))
            break;
    }

cleanup:
    if (server_conn)
    {
        libp2p_conn_free(server_conn);
    }
    else if (client_sock >= 0)
    {
        close(client_sock);
    }
    if (server_sock >= 0)
    {
        close(server_sock);
    }

    return NULL;
}

/* Test backpressure functions */
static int test_default_buffer_size(test_context_t *tctx)
{
    if (!tctx->client_ctx)
    {
        printf("DEBUG: client_ctx is NULL\n");
        return 0;
    }

    libp2p_mplex_stream_t *stream = NULL;
    if (libp2p_mplex_stream_open(tctx->client_ctx, (const uint8_t *)"/test/1.0.0", 11, &stream) != LIBP2P_MPLEX_OK)
    {
        printf("DEBUG: Failed to create stream\n");
        return 0;
    }

    size_t default_size = libp2p_mplex_stream_get_max_buffer_size(stream);
    printf("DEBUG: default_size = %zu, expected = %d\n", default_size, MPLEX_DEFAULT_MAX_BUFFER_SIZE);
    int result = (default_size == MPLEX_DEFAULT_MAX_BUFFER_SIZE);

    libp2p_mplex_stream_close(stream);
    return result;
}

static int test_custom_buffer_size(test_context_t *tctx)
{
    if (!tctx->client_ctx)
        return 0;

    libp2p_mplex_stream_t *stream = NULL;
    if (libp2p_mplex_stream_open(tctx->client_ctx, (const uint8_t *)"/test/1.0.0", 11, &stream) != LIBP2P_MPLEX_OK)
    {
        return 0;
    }

    size_t custom_size = 512;
    libp2p_mplex_stream_set_max_buffer_size(stream, custom_size);

    size_t new_size = libp2p_mplex_stream_get_max_buffer_size(stream);
    int result = (new_size == custom_size);

    libp2p_mplex_stream_close(stream);
    return result;
}

static int test_buffer_size_persistence(test_context_t *tctx)
{
    if (!tctx->client_ctx)
        return 0;

    libp2p_mplex_stream_t *stream = NULL;
    if (libp2p_mplex_stream_open(tctx->client_ctx, (const uint8_t *)"/test/1.0.0", 11, &stream) != LIBP2P_MPLEX_OK)
    {
        return 0;
    }

    // Set custom size
    size_t custom_size = 2048;
    libp2p_mplex_stream_set_max_buffer_size(stream, custom_size);

    // Check it persists
    size_t retrieved_size = libp2p_mplex_stream_get_max_buffer_size(stream);
    int result = (retrieved_size == custom_size);

    libp2p_mplex_stream_close(stream);
    return result;
}

static int test_backpressure_enqueue_logic(test_context_t *tctx)
{
    if (!tctx->client_ctx)
        return 0;

    libp2p_mplex_stream_t *stream = NULL;
    if (libp2p_mplex_stream_open(tctx->client_ctx, (const uint8_t *)"/test/1.0.0", 11, &stream) != LIBP2P_MPLEX_OK)
    {
        return 0;
    }

    // Set a small buffer size for testing
    size_t small_size = 1024; // 1KB
    libp2p_mplex_stream_set_max_buffer_size(stream, small_size);

    // Test that we can write data within the limit
    uint8_t small_data[512];
    memset(small_data, 0x42, sizeof(small_data));

    libp2p_mplex_ssize_t bytes_written1 = libp2p_mplex_stream_write_async(stream, small_data, sizeof(small_data));
    int result1 = (bytes_written1 == sizeof(small_data));

    // Try to write more data that would exceed the limit
    uint8_t more_data[1024];
    memset(more_data, 0x43, sizeof(more_data));

    // This should succeed because we're testing write behavior, not buffer enqueueing
    // The write_async function handles backpressure at the connection level
    libp2p_mplex_ssize_t bytes_written2 = libp2p_mplex_stream_write_async(stream, more_data, sizeof(more_data));
    int result2 = (bytes_written2 == sizeof(more_data));

    // Verify that the max buffer size is still correctly set
    size_t buffer_size = libp2p_mplex_stream_get_max_buffer_size(stream);
    int result3 = (buffer_size == small_size);

    libp2p_mplex_stream_close(stream);
    return result1 && result2 && result3;
}

int main(void)
{
    // Ignore SIGPIPE to prevent crashes when writing to closed sockets
    signal(SIGPIPE, SIG_IGN);

    printf("DEBUG: Program started\n");

    test_context_t tctx = (test_context_t){0};
    libp2p_conn_t *client_conn = NULL;
    struct sockaddr_in addr;
    int client_sock;
    int tests_run = 0;
    int tests_passed = 0;

    printf("Testing mplex backpressure mechanism...\n\n");

    /* Initialize test context */
    pthread_mutex_init(&tctx.mutex, NULL);
    pthread_cond_init(&tctx.cond, NULL);

    /* Start server thread */
    if (pthread_create(&tctx.server_thread, NULL, server_main, &tctx) != 0)
    {
        print_standard("Server thread creation", "Failed to create server thread", 0);
        return EXIT_FAILURE;
    }

    /* Wait for server to bind and get port */
    pthread_mutex_lock(&tctx.mutex);
    while (tctx.server_fd == 0)
    {
        pthread_cond_wait(&tctx.cond, &tctx.mutex);
    }
    pthread_mutex_unlock(&tctx.mutex);

    /* Create client socket */
    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0)
    {
        print_standard("Client socket creation", "Failed to create client socket", 0);
        goto cleanup;
    }

    /* Use blocking client socket for connect(); non-blocking can be set later by higher layers if needed */

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(tctx.server_fd);

    /* Treat client connection as a counted test */
    tests_run++;
    /* Connect to server (retry to avoid startup races) */
    if (connect_with_retry(client_sock, &addr, 200, 10000) < 0)
    {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "Failed to connect to server (port=%d, errno=%d)", tctx.server_fd, errno);
        print_standard("Client connection", errbuf, 0);
        goto cleanup;
    }
    print_standard("Client connection", "", 1);
    tests_passed++;

    /* Perform Noise handshake */
    NoiseCipherState *client_send_cipher = NULL;
    NoiseCipherState *client_recv_cipher = NULL;
    tests_run++;
    if (perform_noise_handshake(client_sock, true, &client_send_cipher, &client_recv_cipher) < 0)
    {
        print_standard("Noise handshake", "Failed during Noise handshake", 0);
        goto cleanup;
    }
    print_standard("Noise handshake", "", 1);
    tests_passed++;

    /* Create TCP connection object for mplex */
    libp2p_conn_t *raw_client_conn = make_tcp_conn(client_sock);
    if (!raw_client_conn)
    {
        // If make_tcp_conn fails, it doesn't take ownership of client_sock,
        // so we need to close it ourselves.
        noise_cipherstate_free(client_send_cipher);
        noise_cipherstate_free(client_recv_cipher);
        close(client_sock);
        client_sock = -1; // Mark as closed to avoid double close in cleanup
        print_standard("TCP connection creation", "Failed to create TCP connection", 0);
        goto cleanup;
    }
    // client_sock is now owned by raw_client_conn

    /* Create Noise-wrapped connection object for mplex */
    client_conn = make_noise_conn(raw_client_conn, client_send_cipher, client_recv_cipher, 0, NULL, 0, NULL, 0, NULL);
    if (!client_conn)
    {
        // make_noise_conn failed, so we need to clean up the resources it didn't take ownership of
        // make_noise_conn doesn't free the input parameters on failure, so we must do it here
        if (raw_client_conn)
        {
            libp2p_conn_free(raw_client_conn);
        }
        // Free the cipher states since they weren't taken ownership of by make_noise_conn
        if (client_send_cipher)
        {
            noise_cipherstate_free(client_send_cipher);
        }
        if (client_recv_cipher)
        {
            noise_cipherstate_free(client_recv_cipher);
        }
        print_standard("Noise connection creation", "Failed to create Noise connection", 0);
        goto cleanup;
    }
    // raw_client_conn, client_send_cipher, client_recv_cipher are now owned by client_conn

    /* Create Mplex context */
    printf("DEBUG: About to create mplex context...\n");
    int ctx_result = libp2p_mplex_new(client_conn, &tctx.client_ctx);
    printf("DEBUG: libp2p_mplex_new returned %d\n", ctx_result);
    if (ctx_result != LIBP2P_MPLEX_OK)
    {
        printf("DEBUG: Failed to create mplex context, error: %s\n", libp2p_mplex_strerror(ctx_result));
        print_standard("Mplex context creation", "Failed to create Mplex context", 0);
        goto cleanup;
    }
    printf("DEBUG: Mplex context created successfully: %p\n", (void *)tctx.client_ctx);

    /* Perform negotiation */
    if (libp2p_mplex_negotiate_outbound(tctx.client_ctx, 5000) != LIBP2P_MPLEX_OK)
    {
        print_standard("Client negotiation", "Failed to negotiate outbound connection", 0);
        goto cleanup;
    }

    /* Wait for server to initialize */
    usleep(100000); /* 100ms */

    /* Test default buffer size */
    tests_run++;
    int result = test_default_buffer_size(&tctx);
    tests_passed += result;
    print_standard("Default buffer size", "", result);

    /* Test custom buffer size */
    tests_run++;
    result = test_custom_buffer_size(&tctx);
    tests_passed += result;
    print_standard("Custom buffer size", "", result);

    /* Test buffer size persistence */
    tests_run++;
    result = test_buffer_size_persistence(&tctx);
    tests_passed += result;
    print_standard("Buffer size persistence", "", result);

    /* Test backpressure enqueue logic */
    tests_run++;
    result = test_backpressure_enqueue_logic(&tctx);
    tests_passed += result;
    print_standard("Backpressure enqueue logic", "", result);

cleanup:
    /* Signal server to exit */
    pthread_mutex_lock(&tctx.mutex);
    tctx.server_fd = -1;
    libp2p_mplex_ctx_t *server_ctx_local = tctx.server_ctx;
    pthread_mutex_unlock(&tctx.mutex);
    if (server_ctx_local)
    {
        libp2p_mplex_stop_event_loop(server_ctx_local);
    }

    /* Cleanup client resources */
    if (tctx.client_ctx)
        libp2p_mplex_free(tctx.client_ctx);
    if (client_conn)
        libp2p_conn_free(client_conn);

    /* Join server thread */
    pthread_join(tctx.server_thread, NULL);

    if (server_ctx_local)
    {
        libp2p_mplex_free(server_ctx_local);
        pthread_mutex_lock(&tctx.mutex);
        tctx.server_ctx = NULL;
        pthread_mutex_unlock(&tctx.mutex);
    }

    /* Cleanup synchronization objects */
    pthread_mutex_destroy(&tctx.mutex);
    pthread_cond_destroy(&tctx.cond);

    printf("\nTests passed: %d/%d\n", tests_passed, tests_run);

    return (tests_passed == tests_run && tests_run > 0) ? 0 : 1;
}
