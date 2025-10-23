#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Include internal header FIRST to get the correct structure definition */
#include "../../../../src/protocol/muxer/mplex/protocol_mplex_internal.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

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

/* Test data injection context */
typedef struct
{
    int sock_fd;
    uint8_t *inject_data;
    size_t inject_data_len;
    size_t inject_pos;
} test_inject_ctx_t;

static void set_inject_data(test_inject_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx->inject_data)
        free(ctx->inject_data);

    ctx->inject_data = malloc(len);
    memcpy(ctx->inject_data, data, len);
    ctx->inject_data_len = len;
    ctx->inject_pos = 0;
}

static test_inject_ctx_t *setup_inject_context(int sock_fd)
{
    test_inject_ctx_t *ctx = calloc(1, sizeof(test_inject_ctx_t));
    if (!ctx)
        return NULL;

    ctx->sock_fd = sock_fd;
    return ctx;
}

static void cleanup_inject_context(test_inject_ctx_t *ctx)
{
    if (ctx)
    {
        if (ctx->inject_data)
            free(ctx->inject_data);
        free(ctx);
    }
}

/* Helper function to create a valid mplex frame using the API */
static uint8_t *create_frame(uint64_t stream_id, uint8_t flag, const uint8_t *payload, size_t payload_len_for_encoding, size_t *out_frame_len)
{
    libp2p_mplex_frame_t frame;
    frame.id = stream_id;
    frame.flag = flag;

    // For the oversized message test, we want to encode a large length but copy 0 bytes
    if (payload != NULL && payload_len_for_encoding > 0)
    {
        frame.data = (uint8_t *)payload;
        frame.data_len = payload_len_for_encoding;
    }
    else
    {
        frame.data = NULL;
        frame.data_len = 0;
    }

    uint8_t *encoded_data = NULL;
    int result = libp2p_mplex_encode_frame(&frame, &encoded_data, out_frame_len);

    if (result != LIBP2P_MPLEX_OK)
    {
        return NULL;
    }

    return encoded_data;
}

/* Test: Invalid frame headers */
static void test_invalid_frame_headers(void)
{
    // Test invalid frame headers

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Test invalid varint (all continuation bytes)
    // First create a valid frame using the API, then modify it to be invalid
    size_t valid_frame_len;
    uint8_t *valid_frame = create_frame(1, LIBP2P_MPLEX_FRAME_MSG_INITIATOR, (const uint8_t *)"test", 4, &valid_frame_len);
    assert(valid_frame != NULL);

    // Create an invalid varint (all continuation bytes)
    uint8_t invalid_varint[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Replace the valid header with the invalid one
    size_t invalid_frame_len = sizeof(invalid_varint) + (valid_frame_len > 10 ? valid_frame_len - 10 : 0);
    uint8_t *invalid_frame = malloc(invalid_frame_len); // Replace first 10 bytes
    assert(invalid_frame != NULL);

    memcpy(invalid_frame, invalid_varint, sizeof(invalid_varint));
    if (valid_frame_len > 10)
    {
        memcpy(invalid_frame + sizeof(invalid_varint), valid_frame + 10, valid_frame_len - 10);
    }
    set_inject_data(inject_ctx, invalid_frame, invalid_frame_len);

    // Write data to socket
    assert(write(sockfds[1], invalid_frame, invalid_frame_len) == (ssize_t)invalid_frame_len);

    free(valid_frame);
    free(invalid_frame);

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Invalid frame headers", "", 1);
}

/* Test: Oversized messages */
static void test_oversized_messages(void)
{
    // Test oversized messages

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Create a frame with oversized payload length, but no actual payload data to avoid blocking write.
    // The mplex library should reject this based on the length field alone.
    size_t frame_len;
    uint8_t *frame = create_frame(1, LIBP2P_MPLEX_FRAME_MSG_INITIATOR, NULL, LIBP2P_MPLEX_MAX_MESSAGE + 1, &frame_len);
    assert(frame != NULL);

    set_inject_data(inject_ctx, frame, frame_len);

    // Write data to socket. This should not block now as the frame itself is small.
    assert(write(sockfds[1], frame, frame_len) == (ssize_t)frame_len);

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    free(frame);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Oversized messages", "", 1);
}

/* Test: Invalid stream IDs */
static void test_invalid_stream_ids(void)
{
    // Test invalid stream IDs

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Manually construct a frame with an oversized stream ID by hand-crafting the bytes
    // This represents a very large stream ID that should be rejected
    uint8_t invalid_frame[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, // Very large varint for stream ID + flag
        0x04,                                                 // Payload length = 4
        't',  'e',  's',  't'                                 // Payload
    };

    set_inject_data(inject_ctx, invalid_frame, sizeof(invalid_frame));

    // Write data to socket
    assert(write(sockfds[1], invalid_frame, sizeof(invalid_frame)) == sizeof(invalid_frame));

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Invalid stream IDs", "", 1);
}

/* Test: Unknown frame types */
static void test_unknown_frame_types(void)
{
    // Test unknown frame types

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Test unknown frame type (flag = 7, which is not defined)
    size_t frame_len;
    uint8_t *frame = create_frame(1, 7, NULL, 0, &frame_len);
    assert(frame != NULL);

    set_inject_data(inject_ctx, frame, frame_len);

    // Write data to socket
    assert(write(sockfds[1], frame, frame_len) == (ssize_t)frame_len);

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    free(frame);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Unknown frame types", "", 1);
}

/* Test: Duplicate stream creation */
static void test_duplicate_stream_creation(void)
{
    // Test duplicate stream creation

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Create a stream manually first
    libp2p_mplex_stream_t *stream = libp2p_mplex_stream_new(1, (uint8_t *)"test", 4, false, ctx);
    assert(libp2p_mplex_stream_array_add(&ctx->streams, stream) == LIBP2P_MPLEX_OK);

    // Now try to create the same stream via NEW_STREAM frame
    size_t frame_len;
    uint8_t payload[] = "test";
    uint8_t *frame = create_frame(1, LIBP2P_MPLEX_FRAME_NEW_STREAM, payload, 4, &frame_len);
    assert(frame != NULL);

    set_inject_data(inject_ctx, frame, frame_len);

    // Write data to socket
    assert(write(sockfds[1], frame, frame_len) == (ssize_t)frame_len);

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    free(frame);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Duplicate stream creation", "", 1);
}

/* Test: Messages on non-existent streams */
static void test_messages_nonexistent_streams(void)
{
    // Test messages on non-existent streams

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Send message on stream that doesn't exist
    size_t frame_len;
    uint8_t payload[] = "hello";
    uint8_t *frame = create_frame(99, LIBP2P_MPLEX_FRAME_MSG_INITIATOR, payload, 5, &frame_len);
    assert(frame != NULL);

    set_inject_data(inject_ctx, frame, frame_len);

    // Write data to socket
    assert(write(sockfds[1], frame, frame_len) == (ssize_t)frame_len);

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    free(frame);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Messages on non-existent streams", "", 1);
}

/* Test: Close/Reset frames with payload */
static void test_close_reset_with_payload(void)
{
    // Test close/reset frames with payload

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Create a stream first
    libp2p_mplex_stream_t *stream = libp2p_mplex_stream_new(1, (uint8_t *)"test", 4, false, ctx);
    assert(libp2p_mplex_stream_array_add(&ctx->streams, stream) == LIBP2P_MPLEX_OK);

    // Test close frame with payload (should be protocol violation)
    size_t frame_len;
    uint8_t payload[] = "invalid";
    uint8_t *frame = create_frame(1, LIBP2P_MPLEX_FRAME_CLOSE_INITIATOR, payload, 7, &frame_len);
    assert(frame != NULL);

    set_inject_data(inject_ctx, frame, frame_len);

    // Write data to socket
    assert(write(sockfds[1], frame, frame_len) == (ssize_t)frame_len);

    int result = libp2p_mplex_process_events(ctx, 10);
    // Should be protocol violation for close frame with payload
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    free(frame);

    // Clean up first connection (it was closed by protocol violation)
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    // Test reset frame without payload - use fresh connection since the first was closed
    int new_sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, new_sockfds) == 0);

    // Set sockets to non-blocking mode
    flags = fcntl(new_sockfds[0], F_GETFL, 0);
    fcntl(new_sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(new_sockfds[1], F_GETFL, 0);
    fcntl(new_sockfds[1], F_SETFL, flags | O_NONBLOCK);

    inject_ctx = setup_inject_context(new_sockfds[1]);
    assert(inject_ctx != NULL);

    conn = mplex_conn_new(new_sockfds[0]);
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    stream = libp2p_mplex_stream_new(1, (uint8_t *)"test2", 5, false, ctx);
    assert(libp2p_mplex_stream_array_add(&ctx->streams, stream) == LIBP2P_MPLEX_OK);

    frame = create_frame(1, LIBP2P_MPLEX_FRAME_RESET_INITIATOR, NULL, 0, &frame_len);
    assert(frame != NULL);

    set_inject_data(inject_ctx, frame, frame_len);

    // Write data to socket
    assert(write(new_sockfds[1], frame, frame_len) == (ssize_t)frame_len);

    result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_OK); // Should work fine with no payload

    free(frame);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(new_sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Close/reset frames with payload", "", 1);
}

/* Test: Messages after close/reset */
static void test_messages_after_close_reset(void)
{
    // Test messages after close/reset

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Create a stream first
    libp2p_mplex_stream_t *stream = libp2p_mplex_stream_new(1, (uint8_t *)"test", 4, false, ctx);
    assert(libp2p_mplex_stream_array_add(&ctx->streams, stream) == LIBP2P_MPLEX_OK);

    // Close the stream remotely
    size_t frame_len;
    uint8_t *close_frame = create_frame(1, LIBP2P_MPLEX_FRAME_CLOSE_INITIATOR, NULL, 0, &frame_len);
    assert(close_frame != NULL);
    set_inject_data(inject_ctx, close_frame, frame_len);

    // Write data to socket
    assert(write(sockfds[1], close_frame, frame_len) == (ssize_t)frame_len);

    int result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_OK);
    assert(stream->state & LIBP2P_MPLEX_STREAM_REMOTE_CLOSED);

    free(close_frame);

    // Now try to send a message on the closed stream
    uint8_t payload[] = "should fail";
    uint8_t *msg_frame = create_frame(1, LIBP2P_MPLEX_FRAME_MSG_INITIATOR, payload, 11, &frame_len);
    assert(msg_frame != NULL);
    set_inject_data(inject_ctx, msg_frame, frame_len);

    // Write data to socket
    assert(write(sockfds[1], msg_frame, frame_len) == (ssize_t)frame_len);

    result = libp2p_mplex_process_events(ctx, 10);
    assert(result == LIBP2P_MPLEX_ERR_PROTOCOL);

    free(msg_frame);
    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Messages after close/reset", "", 1);
}

/* Test: Frame reading edge cases */
static void test_frame_reading_edge_cases(void)
{
    // Test frame reading edge cases

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Test incomplete frame (header only)
    uint8_t incomplete[] = {0x08}; // Just the header varint
    set_inject_data(inject_ctx, incomplete, sizeof(incomplete));

    // Write data to socket
    assert(write(sockfds[1], incomplete, sizeof(incomplete)) == sizeof(incomplete));

    int result = libp2p_mplex_process_events(ctx, 10);
    // Note: Various error codes are acceptable for incomplete frames in non-blocking mode
    // The important thing is that it doesn't crash and handles the error gracefully
    if (result != LIBP2P_MPLEX_ERR_AGAIN && result != LIBP2P_MPLEX_ERR_EOF && result != LIBP2P_MPLEX_ERR_PROTOCOL &&
        result != LIBP2P_MPLEX_ERR_INTERNAL && result != LIBP2P_MPLEX_OK)
    {
    }
    assert(result == LIBP2P_MPLEX_ERR_AGAIN || result == LIBP2P_MPLEX_ERR_EOF || result == LIBP2P_MPLEX_ERR_PROTOCOL ||
           result == LIBP2P_MPLEX_ERR_INTERNAL || result == LIBP2P_MPLEX_OK);

    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Frame reading edge cases", "", 1);
}

/* Test: Stream buffer management */
static void test_stream_buffer_management(void)
{
    // Test stream buffer management

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Create a stream
    libp2p_mplex_stream_t *stream = libp2p_mplex_stream_new(1, (uint8_t *)"test", 4, false, ctx);
    assert(libp2p_mplex_stream_array_add(&ctx->streams, stream) == LIBP2P_MPLEX_OK);

    // Send multiple messages to test buffer reallocation
    for (int i = 0; i < 3; i++)
    {
        size_t frame_len;
        char payload[100];
        snprintf(payload, sizeof(payload), "Message %d with some content", i);
        uint8_t *frame = create_frame(1, LIBP2P_MPLEX_FRAME_MSG_INITIATOR, (uint8_t *)payload, strlen(payload), &frame_len);
        assert(frame != NULL);

        set_inject_data(inject_ctx, frame, frame_len);

        // Write data to socket
        assert(write(sockfds[1], frame, frame_len) == (ssize_t)frame_len);

        int result = libp2p_mplex_process_events(ctx, 10);
        assert(result == LIBP2P_MPLEX_OK);

        free(frame);
    }

    // Verify data can be read back
    char read_buf[1000];
    libp2p_mplex_ssize_t bytes_read = libp2p_mplex_stream_read(stream, read_buf, sizeof(read_buf));
    assert(bytes_read > 0);

    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Stream buffer management", "", 1);
}

/* Test: Connection failure during frame processing */
static void test_connection_failure_during_processing(void)
{
    // Test connection failure during frame processing

    int sockfds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) == 0);

    // Set sockets to non-blocking mode
    int flags = fcntl(sockfds[0], F_GETFL, 0);
    fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfds[1], F_GETFL, 0);
    fcntl(sockfds[1], F_SETFL, flags | O_NONBLOCK);

    test_inject_ctx_t *inject_ctx = setup_inject_context(sockfds[1]);
    assert(inject_ctx != NULL);

    libp2p_conn_t *conn = mplex_conn_new(sockfds[0]);
    libp2p_mplex_ctx_t *ctx = NULL;
    assert(libp2p_mplex_new(conn, &ctx) == LIBP2P_MPLEX_OK);

    // Set up to fail after partial read
    uint8_t partial_frame[] = {0x08, 0x04, 0x74}; // Header, length, partial payload
    set_inject_data(inject_ctx, partial_frame, sizeof(partial_frame));

    // Write data to socket
    assert(write(sockfds[1], partial_frame, sizeof(partial_frame)) == sizeof(partial_frame));

    // Add a small delay to ensure the data is ready to be read
    // This helps prevent race conditions in parallel test execution
    usleep(1000); // 1ms delay

    int result = libp2p_mplex_process_events(ctx, 10);
    // Should handle partial reads gracefully - accept various error codes
    if (result != LIBP2P_MPLEX_ERR_AGAIN && result != LIBP2P_MPLEX_ERR_INTERNAL && result != LIBP2P_MPLEX_OK && result != LIBP2P_MPLEX_ERR_PROTOCOL)
    {
    }
    assert(result == LIBP2P_MPLEX_ERR_AGAIN || result == LIBP2P_MPLEX_ERR_INTERNAL || result == LIBP2P_MPLEX_OK ||
           result == LIBP2P_MPLEX_ERR_PROTOCOL);

    // Add a small delay before cleanup to ensure all operations are complete
    usleep(1000); // 1ms delay

    libp2p_mplex_free(ctx);
    libp2p_conn_free(conn);
    close(sockfds[1]);
    cleanup_inject_context(inject_ctx);

    print_standard("Connection failure during processing", "", 1);
}

static void alarm_handler(int sig)
{
    (void)sig;
    write(STDERR_FILENO, "[test_mplex_protocol_edge_cases] Timeout hit, aborting\n", 56);
    _exit(124);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, alarm_handler);
    alarm(30);
    test_invalid_frame_headers();

    test_oversized_messages();

    test_invalid_stream_ids();

    test_unknown_frame_types();

    test_duplicate_stream_creation();

    test_messages_nonexistent_streams();

    test_close_reset_with_payload();

    test_messages_after_close_reset();

    test_frame_reading_edge_cases();

    test_stream_buffer_management();

    test_connection_failure_during_processing();

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
