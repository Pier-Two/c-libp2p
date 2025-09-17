#ifndef LIBP2P_MPLEX_H
#define LIBP2P_MPLEX_H

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file protocol/muxer/mplex/protocol_mplex.h
 * @brief Multiplexed stream transport for libp2p
 * @defgroup mplex Mplex
 * @{
 * @attention Thread-safety: All functions must be called from the same thread that created the context.
 * Callbacks are invoked from the same thread that calls process_one/process_loop.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(_SSIZE_T_DEFINED)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif

#include "transport/connection.h"
#include "transport/muxer.h"

/**
 * @brief Opaque context type for mplex protocol implementation
 * @note All operations on a context must be performed from the same thread
 *       that created the context.
 */
typedef struct libp2p_mplex_ctx libp2p_mplex_ctx_t;

/**
 * @brief Frame structure for mplex protocol messages
 * @note This structure is used for encoding frames with libp2p_mplex_encode_frame()
 */
typedef struct libp2p_mplex_frame_struct libp2p_mplex_frame_t;

/**
 * @brief Opaque stream type for mplex protocol
 * @note Streams are created via libp2p_mplex_stream_open() or libp2p_mplex_accept_stream()
 *       and must be properly closed with libp2p_mplex_stream_close() when no longer needed.
 */
typedef struct libp2p_mplex_stream libp2p_mplex_stream_t;

/* Frame flag values */
enum libp2p_mplex_frame
{
    LIBP2P_MPLEX_FRAME_NEW_STREAM = 0,
    LIBP2P_MPLEX_FRAME_MSG_RECEIVER = 1,
    LIBP2P_MPLEX_FRAME_MSG_INITIATOR = 2,
    LIBP2P_MPLEX_FRAME_CLOSE_RECEIVER = 3,
    LIBP2P_MPLEX_FRAME_CLOSE_INITIATOR = 4,
    LIBP2P_MPLEX_FRAME_RESET_RECEIVER = 5,
    LIBP2P_MPLEX_FRAME_RESET_INITIATOR = 6
};

/**
 * @brief Protocol identifier string for mplex protocol negotiation
 * @note This is a static constant string that should not be modified.
 */
static const char LIBP2P_MPLEX_PROTO_ID[] = "/mplex/6.7.0";

/**
 * @brief Maximum message size allowed by the mplex protocol
 */
#define LIBP2P_MPLEX_MAX_MESSAGE 1048576u

/**
 * @brief Maximum allowed stream ID value
 * @note Stream IDs must be unique within a single mplex connection and
 *       should monotonically increase for new streams.
 */
#define LIBP2P_MPLEX_MAX_STREAM_ID (UINT64_C(1) << 60)

/* Error codes */
enum libp2p_mplex_err
{
    LIBP2P_MPLEX_OK = 0,
    LIBP2P_MPLEX_ERR_NULL_PTR = -1,
    LIBP2P_MPLEX_ERR_HANDSHAKE = -2,
    LIBP2P_MPLEX_ERR_INTERNAL = -3,
    LIBP2P_MPLEX_ERR_PROTOCOL = -4,
    LIBP2P_MPLEX_ERR_TIMEOUT = -5,
    LIBP2P_MPLEX_ERR_EOF = -6,
    LIBP2P_MPLEX_ERR_AGAIN = -7,
    LIBP2P_MPLEX_ERR_RESET = -8
};

/**
 * @brief Portable signed size type for mplex API
 * @note This type is used for return values from functions like
 *       libp2p_mplex_stream_read() and libp2p_mplex_stream_write() where
 *       negative values indicate errors and non-negative values indicate
 *       the number of bytes processed.
 */
typedef ssize_t libp2p_mplex_ssize_t;

/* Event types */
typedef enum
{
    LIBP2P_MPLEX_STREAM_DATA_AVAILABLE, /* Stream has data to read */
    LIBP2P_MPLEX_STREAM_OPENED,         /* New stream opened by remote peer */
    LIBP2P_MPLEX_STREAM_CLOSED,         /* Stream closed by remote peer */
    LIBP2P_MPLEX_STREAM_RESET,          /* Stream reset by remote peer */
    LIBP2P_MPLEX_CONNECTION_ERROR       /* Connection-level error */
} libp2p_mplex_event_t;

/* Event callback types */
typedef void (*libp2p_mplex_stream_callback_t)(libp2p_mplex_stream_t *stream, libp2p_mplex_event_t event, void *user_data);
typedef void (*libp2p_mplex_error_callback_t)(libp2p_mplex_ctx_t *ctx, int error, void *user_data);
typedef void (*libp2p_mplex_stream_write_ready_callback_t)(libp2p_mplex_stream_t *stream, void *user_data);

/* Configuration structure for event callbacks */
typedef struct
{
    libp2p_mplex_stream_callback_t on_stream_event; /* Called for stream events */
    libp2p_mplex_error_callback_t on_error;         /* Called for connection errors */
    void *user_data;                                /* User data passed to callbacks */
} libp2p_mplex_event_callbacks_t;

/**
 * @brief Creates a new event-driven mplex context
 * @param conn The underlying connection
 * @param out_ctx Pointer to store the new context
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 * @note The returned context must be freed with libp2p_mplex_free
 * @note This creates a non-blocking connection wrapper for event loop integration
 */
int libp2p_mplex_new(libp2p_conn_t *conn, libp2p_mplex_ctx_t **out_ctx);

/**
 * @brief Frees an event-driven mplex context
 * @param ctx The context to free
 * @note This function releases all resources associated with the context
 */
void libp2p_mplex_free(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Gets the file descriptor for event loop integration
 * @param ctx The mplex context
 * @return The file descriptor, or -1 on error
 * @note Use this FD with epoll, select, or other event mechanisms
 */
int libp2p_mplex_get_fd(const libp2p_mplex_ctx_t *ctx);

/**
 * @brief Handles readable events on the connection
 * @param ctx The mplex context
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 * @note Call this when the FD becomes readable in your event loop
 */
int libp2p_mplex_on_readable(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Handles writable events on the connection
 * @param ctx The mplex context
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 * @note Call this when the FD becomes writable in your event loop
 */
int libp2p_mplex_on_writable(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Negotiates mplex as an outbound protocol (event-driven version)
 * @param ctx The mplex context
 * @param timeout_ms Timeout in milliseconds
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_negotiate_outbound(libp2p_mplex_ctx_t *ctx, uint64_t timeout_ms);

/**
 * @brief Negotiates mplex as an inbound protocol (event-driven version)
 * @param ctx The mplex context
 * @param timeout_ms Timeout in milliseconds
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_negotiate_inbound(libp2p_mplex_ctx_t *ctx, uint64_t timeout_ms);

/**
 * @brief Opens a new stream
 * @param ctx The mplex context
 * @param name Stream name/protocol identifier
 * @param name_len Length of the name
 * @param out_stream Pointer to store the new stream
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 * @note The stream must be closed with libp2p_mplex_stream_close
 */
int libp2p_mplex_stream_open(libp2p_mplex_ctx_t *ctx, const uint8_t *name, size_t name_len, libp2p_mplex_stream_t **out_stream);

/**
 * @brief Accepts an incoming stream
 * @param ctx The mplex context
 * @param out_stream Pointer to store the accepted stream
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_accept_stream(libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t **out_stream);

/**
 * @brief Reads data from a stream
 * @param stream The stream to read from
 * @param buf Buffer to store read data
 * @param max_len Maximum bytes to read
 * @return Number of bytes read on success, negative error code on failure
 */
libp2p_mplex_ssize_t libp2p_mplex_stream_read(libp2p_mplex_stream_t *stream, void *buf, size_t max_len);

/**
 * @brief Closes a stream
 * @param stream The stream to close
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 * @note This marks the stream as closed but does not free the stream object
 */
int libp2p_mplex_stream_close(libp2p_mplex_stream_t *stream);

/**
 * @brief Resets a stream
 * @param stream The stream to reset
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_stream_reset(libp2p_mplex_stream_t *stream);

/**
 * @brief Sets user data for a stream
 * @param stream The stream
 * @param user_data User data to associate with the stream
 */
void libp2p_mplex_stream_set_user_data(libp2p_mplex_stream_t *stream, void *user_data);

/**
 * @brief Gets user data from a stream
 * @param stream The stream
 * @return The associated user data, or NULL if none
 */
void *libp2p_mplex_stream_get_user_data(const libp2p_mplex_stream_t *stream);

/**
 * @brief Gets the stream ID
 * @param stream The stream
 * @return The stream ID
 */
uint64_t libp2p_mplex_stream_get_id(const libp2p_mplex_stream_t *stream);

/**
 * @brief Sets the maximum buffer size for a stream before backpressure action
 * @param stream The stream
 * @param max_buffer_size Maximum buffer size in bytes
 * @note Default is 1MB (1048576 bytes)
 */
void libp2p_mplex_stream_set_max_buffer_size(libp2p_mplex_stream_t *stream, size_t max_buffer_size);

/**
 * @brief Gets the maximum buffer size for a stream
 * @param stream The stream
 * @return Maximum buffer size in bytes
 */
size_t libp2p_mplex_stream_get_max_buffer_size(const libp2p_mplex_stream_t *stream);

/* Event-loop helpers */
int libp2p_mplex_run_event_loop(libp2p_mplex_ctx_t *ctx, int timeout_ms);
int libp2p_mplex_stop_event_loop(libp2p_mplex_ctx_t *ctx);
int libp2p_mplex_start_event_loop_thread(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Returns a human-readable string for an error code
 * @param err The error code
 * @return A string describing the error
 * @note The returned string is static and must not be freed
 */
const char *libp2p_mplex_strerror(int err);

/* Event callback functions */

/**
 * @brief Built-in event loop
 * @param ctx The mplex context
 * @param timeout_ms Timeout in milliseconds (-1 for infinite)
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_run_event_loop(libp2p_mplex_ctx_t *ctx, int timeout_ms);

/**
 * @brief Stop the built-in event loop
 * @param ctx The mplex context
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_stop_event_loop(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Non-blocking event processing
 * @param ctx The mplex context
 * @param timeout_ms Timeout in milliseconds (-1 for infinite)
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_process_events(libp2p_mplex_ctx_t *ctx, int timeout_ms);

/* Wake a running event loop (best-effort). Safe to call from other threads. */
void libp2p_mplex_wake(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Set event callbacks for the mplex context
 * @param ctx The mplex context
 * @param callbacks The event callbacks configuration
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_set_event_callbacks(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_event_callbacks_t *callbacks);

/**
 * @brief Set event callback for a specific stream
 * @param stream The stream
 * @param callback The stream event callback
 * @param user_data User data to pass to the callback
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_stream_set_event_callback(libp2p_mplex_stream_t *stream, libp2p_mplex_stream_callback_t callback, void *user_data);

/**
 * @brief Set write ready callback for a specific stream
 * @param stream The stream
 * @param callback The write ready callback
 * @param user_data User data to pass to the callback
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_stream_set_write_ready_callback(libp2p_mplex_stream_t *stream, libp2p_mplex_stream_write_ready_callback_t callback, void *user_data);

/**
 * @brief Non-blocking write that handles queuing automatically
 * @param stream The stream to write to
 * @param data Data to write
 * @param len Length of data to write
 * @return Number of bytes written on success, negative error code on failure
 */
libp2p_mplex_ssize_t libp2p_mplex_stream_write_async(libp2p_mplex_stream_t *stream, const void *data, size_t len);

/**
 * @brief Encodes a mplex frame into a byte buffer
 * @param frame The frame to encode
 * @param out_encoded_data Pointer to store the allocated encoded data buffer
 * @param out_encoded_len Pointer to store the length of the encoded data
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 * @note The caller is responsible for freeing the allocated encoded data buffer
 */
int libp2p_mplex_encode_frame(const libp2p_mplex_frame_t *frame, uint8_t **out_encoded_data, size_t *out_encoded_len);

/*
 * Muxer factory to integrate the v2 mplex context with the generic muxer
 * interface used by the upgrader. Stream operations should use the v2 API
 * directly (libp2p_mplex_stream_*).
 */

/* Create a muxer instance that negotiates the v2 mplex context */
libp2p_muxer_t *libp2p_mplex_muxer_new(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MPLEX_H */
