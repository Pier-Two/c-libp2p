#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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
#include "transport/connection.h"

/* Standard test output function matching other tests in the project */
static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", test_name);
    else
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
}

static int failures = 0;
#define DBG(fmt, ...)                                                                                                                               \
    do                                                                                                                                               \
    {                                                                                                                                                \
        fprintf(stderr, "[mplex-basic][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);                                                      \
        fflush(stderr);                                                                                                                              \
    } while (0)
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

/* Test cases */
static void test_ctx_create_destroy(void)
{
    DBG("ENTER %s", __func__);
    // Create socket pair for testing
    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    // Create mplex connection wrapper
    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    DBG("mplex_conn_new(conn=%p, fd=%d)", (void *)conn, sockfds[0]);
    assert(conn != NULL);

    // Test context creation
    libp2p_mplex_ctx_t *ctx = NULL;
    int rc = libp2p_mplex_new(conn, &ctx);
    DBG("libp2p_mplex_new(ctx=%p) rc=%d", (void *)ctx, rc);
    TEST_OK("Context creation", rc == LIBP2P_MPLEX_OK && ctx != NULL, "Failed to create context");

    // Test null pointer checks
    TEST_OK("Context creation with NULL connection", libp2p_mplex_new(NULL, &ctx) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL connection");

    TEST_OK("Context creation with NULL context pointer", libp2p_mplex_new(conn, NULL) == LIBP2P_MPLEX_ERR_NULL_PTR,
            "Should reject NULL context pointer");

    // Clean up
    DBG("libp2p_mplex_free(ctx=%p)", (void *)ctx);
    libp2p_mplex_free(ctx);
    DBG("libp2p_conn_free(conn=%p)", (void *)conn);
    libp2p_conn_free(conn);
    close(sockfds[1]);
}

static void test_stream_open_close(void)
{
    DBG("ENTER %s", __func__);
    // Create a single connected socketpair; use each end for client/server
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) != 0)
    {
        perror("socketpair failed");
        TEST_OK("socketpair setup", 0, "socketpair failed: %s", strerror(errno));
        return;
    }

    // Create mplex connection wrappers
    libp2p_conn_t *client_conn = mplex_conn_new(socks[0]);
    libp2p_conn_t *server_conn = mplex_conn_new(socks[1]);
    DBG("client_conn=%p fd=%d, server_conn=%p fd=%d", (void *)client_conn, socks[0], (void *)server_conn, socks[1]);

    libp2p_mplex_ctx_t *client_ctx = NULL;
    libp2p_mplex_ctx_t *server_ctx = NULL;

    int rc_client_new = libp2p_mplex_new(client_conn, &client_ctx);
    int rc_server_new = libp2p_mplex_new(server_conn, &server_ctx);
    DBG("libp2p_mplex_new client rc=%d ctx=%p; server rc=%d ctx=%p", rc_client_new, (void *)client_ctx, rc_server_new, (void *)server_ctx);
    TEST_OK("Client context creation", rc_client_new == LIBP2P_MPLEX_OK, "Failed to create client context");
    TEST_OK("Server context creation", rc_server_new == LIBP2P_MPLEX_OK, "Failed to create server context");

    // Simulate negotiation completion
    client_ctx->negotiated = true;
    server_ctx->negotiated = true;
    DBG("negotiated set true client_ctx=%p server_ctx=%p", (void *)client_ctx, (void *)server_ctx);

    // Test stream opening without negotiation (toggle negotiated flag)
    libp2p_mplex_stream_t *unneg_stream = NULL;
    client_ctx->negotiated = false;
    int rc_unneg_open = libp2p_mplex_stream_open(client_ctx, (const uint8_t *)"test", 4, &unneg_stream);
    DBG("unnegotiated open rc=%d stream=%p", rc_unneg_open, (void *)unneg_stream);
    TEST_OK("Stream open without negotiation", rc_unneg_open == LIBP2P_MPLEX_ERR_HANDSHAKE, "Should fail when not negotiated");
    client_ctx->negotiated = true;

    // Test stream opening
    libp2p_mplex_stream_t *stream = NULL;
    const char *protocol = "/test/1.0.0";
    int rc = libp2p_mplex_stream_open(client_ctx, (const uint8_t *)protocol, strlen(protocol), &stream);
    DBG("open stream rc=%d stream=%p", rc, (void *)stream);
    TEST_OK("Stream open", rc == LIBP2P_MPLEX_OK && stream != NULL, "Failed to open stream");

    // Test stream properties
    if (stream != NULL)
    {
        TEST_OK("Stream ID assignment", stream->id == 1, "Stream ID should be 1");
        TEST_OK("Stream initiator flag", stream->initiator == true, "Stream should be marked as initiator");
        TEST_OK("Stream name length", stream->name_len == strlen(protocol), "Stream name length mismatch");
        TEST_OK("Stream name content", memcmp(stream->name, protocol, strlen(protocol)) == 0, "Stream name content mismatch");
    }

    // Test user data
    if (stream != NULL)
    {
        void *test_data = (void *)0x12345678;
        libp2p_mplex_stream_set_user_data(stream, test_data);
        TEST_OK("User data get/set", libp2p_mplex_stream_get_user_data(stream) == test_data, "User data mismatch");
    }

    // Test stream close
    if (stream != NULL)
    {
        rc = libp2p_mplex_stream_close(stream);
        DBG("stream_close rc=%d stream=%p", rc, (void *)stream);
        TEST_OK("Stream close", rc == LIBP2P_MPLEX_OK, "Failed to close stream");

        // Test double close
        rc = libp2p_mplex_stream_close(stream);
        DBG("stream_close (double) rc=%d stream=%p", rc, (void *)stream);
        TEST_OK("Stream double close", rc == LIBP2P_MPLEX_OK, "Double close should be OK");
    }

    // Test stream reset
    libp2p_mplex_stream_t *stream2 = NULL;
    rc = libp2p_mplex_stream_open(client_ctx, (const uint8_t *)protocol, strlen(protocol), &stream2);
    DBG("open stream2 rc=%d stream2=%p", rc, (void *)stream2);
    TEST_OK("Second stream open", rc == LIBP2P_MPLEX_OK, "Failed to open second stream");

    if (stream2 != NULL)
    {
        rc = libp2p_mplex_stream_reset(stream2);
        DBG("stream_reset rc=%d stream2=%p", rc, (void *)stream2);
        TEST_OK("Stream reset", rc == LIBP2P_MPLEX_OK, "Failed to reset stream");

        // Test operations after reset
        char buf[100];
        TEST_OK("Read after reset", libp2p_mplex_stream_read(stream2, buf, sizeof(buf)) == LIBP2P_MPLEX_ERR_RESET, "Should fail with RESET error");
        TEST_OK("Write after reset", libp2p_mplex_stream_write_async(stream2, "test", 4) == LIBP2P_MPLEX_ERR_RESET, "Should fail with RESET error");
    }

    // Clean up - free mplex contexts first, then connections
    DBG("free client_ctx=%p server_ctx=%p", (void *)client_ctx, (void *)server_ctx);
    libp2p_mplex_free(client_ctx);
    libp2p_mplex_free(server_ctx);
    libp2p_conn_free(client_conn);
    libp2p_conn_free(server_conn);
}

static void test_stream_read_write(void)
{
    DBG("ENTER %s", __func__);
    // Create a single connected socketpair; use each end for client/server
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) != 0)
    {
        perror("socketpair failed");
        TEST_OK("socketpair setup", 0, "socketpair failed: %s", strerror(errno));
        return;
    }

    // Create mplex connection wrappers
    libp2p_conn_t *client_conn = mplex_conn_new(socks[0]);
    libp2p_conn_t *server_conn = mplex_conn_new(socks[1]);

    libp2p_mplex_ctx_t *client_ctx = NULL;
    libp2p_mplex_ctx_t *server_ctx = NULL;

    int rc_client = libp2p_mplex_new(client_conn, &client_ctx);
    int rc_server = libp2p_mplex_new(server_conn, &server_ctx);
    DBG("client_ctx rc=%d ptr=%p; server_ctx rc=%d ptr=%p", rc_client, (void *)client_ctx, rc_server, (void *)server_ctx);
    assert(rc_client == LIBP2P_MPLEX_OK);
    assert(rc_server == LIBP2P_MPLEX_OK);

    client_ctx->negotiated = true;
    server_ctx->negotiated = true;

    libp2p_mplex_stream_t *stream = NULL;
    int rc_open = libp2p_mplex_stream_open(client_ctx, (const uint8_t *)"test", 4, &stream);
    DBG("stream_open rc=%d stream=%p", rc_open, (void *)stream);
    assert(rc_open == LIBP2P_MPLEX_OK);

    // Test write
    const char *test_data = "Hello, World!";
    libp2p_mplex_ssize_t written = libp2p_mplex_stream_write_async(stream, test_data, strlen(test_data));
    DBG("write_async len=%zu -> %zd", strlen(test_data), (ssize_t)written);
    TEST_OK("Stream write", written == (libp2p_mplex_ssize_t)strlen(test_data), "Write length mismatch");

    // Test write with null data
    libp2p_mplex_ssize_t wnull = libp2p_mplex_stream_write_async(stream, NULL, 10);
    DBG("write_async NULL -> %zd", (ssize_t)wnull);
    TEST_OK("Write with null data", wnull == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL data");

    // Test write with zero length
    libp2p_mplex_ssize_t wzero = libp2p_mplex_stream_write_async(stream, test_data, 0);
    DBG("write_async zero -> %zd", (ssize_t)wzero);
    TEST_OK("Write with zero length", wzero == 0, "Zero length write should return 0");

    // Test write with too large data
    char large_data[LIBP2P_MPLEX_MAX_MESSAGE + 1];
    memset(large_data, 'X', sizeof(large_data));
    libp2p_mplex_ssize_t wlarge = libp2p_mplex_stream_write_async(stream, large_data, sizeof(large_data));
    DBG("write_async oversized -> %zd", (ssize_t)wlarge);
    TEST_OK("Write oversized data", wlarge == LIBP2P_MPLEX_ERR_PROTOCOL, "Should reject oversized data");

    // Test read without data (should return AGAIN)
    char read_buf[100];
    libp2p_mplex_ssize_t r1 = libp2p_mplex_stream_read(stream, read_buf, sizeof(read_buf));
    DBG("read no-data -> %zd", (ssize_t)r1);
    TEST_OK("Read without data", r1 == LIBP2P_MPLEX_ERR_AGAIN, "Should return AGAIN when no data");

    // Test read with null buffer
    libp2p_mplex_ssize_t rnull = libp2p_mplex_stream_read(stream, NULL, 10);
    DBG("read NULL -> %zd", (ssize_t)rnull);
    TEST_OK("Read with null buffer", rnull == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL buffer");

    // Test read with zero length
    TEST_OK("Read with zero length", libp2p_mplex_stream_read(stream, read_buf, 0) == 0, "Zero length read should return 0");

    // Clean up - free mplex contexts first, then connections
    libp2p_mplex_free(client_ctx);
    libp2p_mplex_free(server_ctx);
    libp2p_conn_free(client_conn);
    libp2p_conn_free(server_conn);
}

static void test_callback_functionality(void)
{
    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
}

static void test_error_handling(void)
{
    // Test error string function
    TEST_OK("Error string for OK", strcmp(libp2p_mplex_strerror(LIBP2P_MPLEX_OK), "ok") == 0, "Incorrect error string for OK");
    TEST_OK("Error string for NULL_PTR", strcmp(libp2p_mplex_strerror(LIBP2P_MPLEX_ERR_NULL_PTR), "null pointer") == 0,
            "Incorrect error string for NULL_PTR");
    TEST_OK("Error string for PROTOCOL", strcmp(libp2p_mplex_strerror(LIBP2P_MPLEX_ERR_PROTOCOL), "protocol error") == 0,
            "Incorrect error string for PROTOCOL");
    TEST_OK("Error string for unknown", strcmp(libp2p_mplex_strerror(-999), "unknown") == 0, "Incorrect error string for unknown code");

    // Test null pointer handling
    TEST_OK("Stream open with NULL context", libp2p_mplex_stream_open(NULL, (const uint8_t *)"test", 4, NULL) == LIBP2P_MPLEX_ERR_NULL_PTR,
            "Should reject NULL context");
    TEST_OK("Accept stream with NULL context", libp2p_mplex_accept_stream(NULL, NULL) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL context");
    TEST_OK("Stream write with NULL stream", libp2p_mplex_stream_write_async(NULL, "test", 4) == LIBP2P_MPLEX_ERR_NULL_PTR,
            "Should reject NULL stream");
    TEST_OK("Stream read with NULL stream", libp2p_mplex_stream_read(NULL, NULL, 0) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL stream");
    TEST_OK("Stream close with NULL stream", libp2p_mplex_stream_close(NULL) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL stream");
    TEST_OK("Stream reset with NULL stream", libp2p_mplex_stream_reset(NULL) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL stream");
    TEST_OK("Process one with NULL context", libp2p_mplex_process_events(NULL, 10) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL context");
    TEST_OK("Process loop with NULL context", libp2p_mplex_run_event_loop(NULL, 0) == LIBP2P_MPLEX_ERR_NULL_PTR, "Should reject NULL context");

    // Test safe null handling
    libp2p_mplex_free(NULL);
    libp2p_mplex_stream_set_user_data(NULL, NULL);
    TEST_OK("Get user data with NULL stream", libp2p_mplex_stream_get_user_data(NULL) == NULL, "Should return NULL for NULL stream");
    libp2p_mplex_stop_event_loop(NULL);
}

static void alarm_handler(int sig)
{
    (void)sig;
    write(STDERR_FILENO, "[test_mplex_basic] Timeout hit, aborting\n", 37);
    _exit(124);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, alarm_handler);
    alarm(20);
    test_ctx_create_destroy();
    test_stream_open_close();
    test_stream_read_write();
    test_callback_functionality();
    test_error_handling();

    if (failures)
    {
        printf("\nSome tests failed. Total failures: %d\n", failures);
        return EXIT_FAILURE;
    }
    else
    {
        printf("\nAll tests passed!\n");
        return EXIT_SUCCESS;
    }
}
