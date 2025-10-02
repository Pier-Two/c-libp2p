#ifndef PROTOCOL_YAMUX_H
#define PROTOCOL_YAMUX_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "protocol/muxer/yamux/protocol_yamux_queue.h"
#include "transport/connection.h"
#include "transport/muxer.h"
#include <stdatomic.h>
#include <stdint.h>

/**
 * @file protocol_yamux.h
 * @brief API for the yamux stream multiplexer.
 */

/** @brief Canonical protocol id (without trailing newline). */
#define LIBP2P_YAMUX_PROTO_ID "/yamux/1.0.0"

/**
 * @brief Error codes returned by yamux operations.
 */
typedef enum
{
    LIBP2P_YAMUX_OK = 0,
    LIBP2P_YAMUX_ERR_NULL_PTR = -1,
    LIBP2P_YAMUX_ERR_HANDSHAKE = -2,
    LIBP2P_YAMUX_ERR_INTERNAL = -3,
    LIBP2P_YAMUX_ERR_PROTO_MAL = -4,
    LIBP2P_YAMUX_ERR_TIMEOUT = -5,
    LIBP2P_YAMUX_ERR_EOF = -6,
    LIBP2P_YAMUX_ERR_AGAIN = -7,
    LIBP2P_YAMUX_ERR_RESET = -8
} libp2p_yamux_err_t;

typedef enum
{
    LIBP2P_YAMUX_DATA = 0x0,
    LIBP2P_YAMUX_WINDOW_UPDATE = 0x1,
    LIBP2P_YAMUX_PING = 0x2,
    LIBP2P_YAMUX_GO_AWAY = 0x3
} libp2p_yamux_type_t;

typedef enum
{
    LIBP2P_YAMUX_SYN = 0x1,
    LIBP2P_YAMUX_ACK = 0x2,
    LIBP2P_YAMUX_FIN = 0x4,
    LIBP2P_YAMUX_RST = 0x8
} libp2p_yamux_flag_t;

/**
 * @brief Structure representing a yamux goaway reason.
 */
typedef enum
{
    LIBP2P_YAMUX_GOAWAY_OK = 0,
    LIBP2P_YAMUX_GOAWAY_PROTOCOL_ERROR = 1,
    LIBP2P_YAMUX_GOAWAY_INTERNAL_ERROR = 2
} libp2p_yamux_goaway_t;

/**
 * @brief Structure representing a yamux frame.
 */
typedef struct
{
    uint8_t version;          /**< Protocol version (0).          */
    libp2p_yamux_type_t type; /**< Frame type.                    */
    uint16_t flags;           /**< Frame flags.                   */
    uint32_t stream_id;       /**< Stream identifier.             */
    uint32_t length;          /**< Length field from header.      */
    uint8_t *data;            /**< Optional payload bytes.        */
    size_t data_len;          /**< Length of @p data.             */
} libp2p_yamux_frame_t;

/**
 * @brief Structure representing a yamux stream.
 */
typedef struct libp2p_yamux_stream
{
    uint32_t id;          /**< Stream identifier.            */
    int initiator;        /**< Non-zero if this side opened it. */
    uint32_t send_window; /**< Remaining send window.        */
    uint32_t recv_window; /**< Remaining receive window.     */
    int local_closed;     /**< Local side closed.            */
    int remote_closed;    /**< Remote side closed.           */
    int reset;            /**< Stream was reset.             */
    int acked;            /**< Stream was acknowledged.      */
    uint8_t *buf;         /**< Data buffer.                  */
    size_t buf_len;       /**< Size of @p buf.               */
    size_t buf_pos;       /**< Current read position.        */
} libp2p_yamux_stream_t;

struct libp2p_yamux_ctx;

/**
 * @brief Callback function for handling ping responses.
 *
 * @param ctx Yamux context
 * @param value Ping value sent
 * @param rtt_ms Round-trip time in milliseconds
 * @param arg Opaque argument passed to callback
 */
typedef void (*libp2p_yamux_ping_cb)(struct libp2p_yamux_ctx *ctx, uint32_t value, uint64_t rtt_ms, void *arg);

/**
 * @brief Structure representing a yamux context.
 */
typedef struct libp2p_yamux_ctx
{
    libp2p_conn_t *conn;               /**< Underlying connection.        */
    libp2p_yamux_stream_t **streams;   /**< Active streams array.         */
    size_t num_streams;                /**< Number of streams in array.   */
    uint32_t next_stream_id;           /**< Next stream id to assign.     */
    int dialer;                        /**< Non-zero if we initiated.     */
    yamux_stream_queue_t incoming;     /**< Queue of incoming streams.    */
    atomic_bool stop;                  /**< Stop processing flag.         */
    pthread_mutex_t mtx;               /**< Protects context state.       */
    uint32_t max_window;               /**< Maximum window size.          */
    size_t ack_backlog;                /**< Streams opened but unacked.   */
    uint64_t keepalive_ms;             /**< Interval between pings (ms).  */
    pthread_t keepalive_th;            /**< Background ping thread.       */
    pthread_mutex_t keepalive_mtx;     /**< Keepalive wait mutex.         */
    pthread_cond_t keepalive_cv;       /**< Keepalive wakeup condition.   */
    atomic_uint refcnt;                /**< Refcount: base=1 + substreams */
    atomic_bool keepalive_active;      /**< Non-zero while thread runs.   */
    libp2p_yamux_goaway_t goaway_code; /**< Last GoAway code received.   */
    int goaway_received;               /**< Non-zero if GoAway seen.      */
    libp2p_yamux_ping_cb ping_cb;      /**< Optional ping callback.       */
    void *ping_arg;                    /**< Opaque callback argument.     */
    struct yamux_ping_pending
    {
        uint32_t value;      /**< Ping value sent.              */
        uint64_t sent_ms;    /**< Timestamp when sent.          */
    } *pings;                /**< Outstanding pings.            */
    size_t num_pings;        /**< Number of outstanding pings.  */
    int pump_in_recv;        /**< If non-zero, stream_recv may pump frames itself.
                                 Set to 0 when a central runtime drives processing. */
    atomic_bool loop_active; /**< Set to true while process_loop is running to
                                 prevent concurrent reads from stream_recv. */
    /* Ensure only one thread performs a conn read/dispatch at a time. */
    atomic_bool io_busy;     /**< Acts as a lightweight global I/O lock for
                                 libp2p_yamux_process_one to prevent concurrent
                                 reads from multiple threads. */
    pthread_mutex_t write_mtx; /**< Serialises writes to the underlying conn. */
} libp2p_yamux_ctx_t;

/**
 * @brief Negotiate yamux protocol as outbound dialer.
 *
 * @param conn Connection to negotiate on
 * @param timeout_ms Timeout for negotiation in milliseconds
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_negotiate_outbound(libp2p_conn_t *conn, uint64_t timeout_ms);

/**
 * @brief Negotiate yamux protocol as inbound listener.
 *
 * @param conn Connection to negotiate on
 * @param timeout_ms Timeout for negotiation in milliseconds
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_negotiate_inbound(libp2p_conn_t *conn, uint64_t timeout_ms);

/**
 * @brief Create a new yamux muxer instance.
 *
 * @return Pointer to new muxer on success, NULL on failure
 */
libp2p_muxer_t *libp2p_yamux_new(void);

/**
 * @brief Send a ping frame with specified value.
 *
 * @param ctx Yamux context
 * @param value Ping value to send
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_ctx_ping(libp2p_yamux_ctx_t *ctx, uint32_t value);

/**
 * @brief Set ping callback for handling ping responses.
 *
 * @param ctx Yamux context
 * @param cb Callback function to call on ping response
 * @param arg Opaque argument passed to callback
 */
void libp2p_yamux_set_ping_cb(libp2p_yamux_ctx_t *ctx, libp2p_yamux_ping_cb cb, void *arg);

/**
 * @brief Send a yamux frame over the connection.
 *
 * @param conn Connection to send on
 * @param fr Frame to send
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_send_frame(libp2p_conn_t *conn, const libp2p_yamux_frame_t *fr);

/**
 * @brief Read a yamux frame from the connection.
 *
 * @param conn Connection to read from
 * @param out Frame structure to populate
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_read_frame(libp2p_conn_t *conn, libp2p_yamux_frame_t *out);

/**
 * @brief Free resources allocated for a yamux frame.
 *
 * @param fr Frame to free
 */
void libp2p_yamux_frame_free(libp2p_yamux_frame_t *fr);

/**
 * @brief Open a new stream with specified ID and window size.
 *
 * @param conn Connection to open stream on
 * @param id Stream identifier
 * @param max_window Maximum window size for the stream
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_open_stream(libp2p_conn_t *conn, uint32_t id, uint32_t max_window);

/**
 * @brief Send data message on a stream.
 *
 * @param conn Connection to send on
 * @param id Stream identifier
 * @param data Data to send
 * @param data_len Length of data
 * @param flags Frame flags
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_send_msg(libp2p_conn_t *conn, uint32_t id, const uint8_t *data, size_t data_len, uint16_t flags);

/**
 * @brief Close a stream gracefully.
 *
 * @param conn Connection the stream is on
 * @param id Stream identifier
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_close_stream(libp2p_conn_t *conn, uint32_t id);

/**
 * @brief Reset a stream abruptly.
 *
 * @param conn Connection the stream is on
 * @param id Stream identifier
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_reset_stream(libp2p_conn_t *conn, uint32_t id);

/**
 * @brief Send window update to increase stream flow control window.
 *
 * @param conn Connection to send on
 * @param id Stream identifier
 * @param delta Amount to increase window by
 * @param flags Frame flags
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_window_update(libp2p_conn_t *conn, uint32_t id, uint32_t delta, uint16_t flags);

/**
 * @brief Send a ping frame.
 *
 * @param conn Connection to send on
 * @param value Ping value
 * @param flags Frame flags
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_ping(libp2p_conn_t *conn, uint32_t value, uint16_t flags);

/**
 * @brief Send a go-away frame to gracefully close the connection.
 *
 * @param conn Connection to send on
 * @param code Reason code for go-away
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_go_away(libp2p_conn_t *conn, libp2p_yamux_goaway_t code);

/**
 * @brief Create a new yamux context for stream multiplexing.
 *
 * @param conn Underlying connection
 * @param dialer Non-zero if this side initiated the connection
 * @param max_window Maximum window size for streams
 * @return Pointer to new context on success, NULL on failure
 */
libp2p_yamux_ctx_t *libp2p_yamux_ctx_new(libp2p_conn_t *conn, int dialer, uint32_t max_window);

/**
 * @brief Enable keepalive pings on the yamux context.
 *
 * @param ctx Yamux context
 * @param interval_ms Interval between pings in milliseconds
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_enable_keepalive(libp2p_yamux_ctx_t *ctx, uint64_t interval_ms);

/**
 * @brief Free resources allocated for yamux context.
 *
 * @param ctx Context to free
 */
void libp2p_yamux_ctx_free(libp2p_yamux_ctx_t *ctx);

/**
 * @brief Open a new outbound stream.
 *
 * @param ctx Yamux context
 * @param out_id Pointer to store assigned stream ID
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_stream_open(libp2p_yamux_ctx_t *ctx, uint32_t *out_id);

/**
 * @brief Send data on a stream.
 *
 * @param ctx Yamux context
 * @param id Stream identifier
 * @param data Data to send
 * @param data_len Length of data
 * @param flags Frame flags
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_stream_send(libp2p_yamux_ctx_t *ctx, uint32_t id, const uint8_t *data, size_t data_len, uint16_t flags);

/**
 * @brief Close a stream gracefully.
 *
 * @param ctx Yamux context
 * @param id Stream identifier
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_stream_close(libp2p_yamux_ctx_t *ctx, uint32_t id);

/**
 * @brief Reset a stream abruptly.
 *
 * @param ctx Yamux context
 * @param id Stream identifier
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_stream_reset(libp2p_yamux_ctx_t *ctx, uint32_t id);

/**
 * @brief Process an incoming yamux frame.
 *
 * @param ctx Yamux context
 * @param fr Frame to process
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_dispatch_frame(libp2p_yamux_ctx_t *ctx, const libp2p_yamux_frame_t *fr);

/**
 * @brief Receive data from a stream.
 *
 * @param ctx Yamux context
 * @param id Stream identifier
 * @param buf Buffer to store received data
 * @param max_len Maximum bytes to receive
 * @param out_len Pointer to store actual bytes received
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_stream_recv(libp2p_yamux_ctx_t *ctx, uint32_t id, uint8_t *buf, size_t max_len, size_t *out_len);

/**
 * @brief Accept an incoming stream.
 *
 * @param ctx Yamux context
 * @param out Pointer to store accepted stream
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_accept_stream(libp2p_yamux_ctx_t *ctx, libp2p_yamux_stream_t **out);

/**
 * @brief Process one incoming frame from the connection.
 *
 * @param ctx Yamux context
 * @return LIBP2P_YAMUX_OK on success, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_process_one(libp2p_yamux_ctx_t *ctx);

/**
 * @brief Stop yamux processing gracefully.
 *
 * @param ctx Yamux context
 */
void libp2p_yamux_stop(libp2p_yamux_ctx_t *ctx);

/**
 * @brief Shutdown yamux context immediately.
 *
 * @param ctx Yamux context
 */
void libp2p_yamux_shutdown(libp2p_yamux_ctx_t *ctx);

/**
 * @brief Main processing loop for yamux frames.
 *
 * @param ctx Yamux context
 * @return LIBP2P_YAMUX_OK when loop exits normally, error code otherwise
 */
libp2p_yamux_err_t libp2p_yamux_process_loop(libp2p_yamux_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_YAMUX_H */
