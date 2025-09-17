#ifndef LIBP2P_MPLEX_INTERNAL_H
#define LIBP2P_MPLEX_INTERNAL_H

#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_conn.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Frame structure for mplex protocol messages
 */
struct libp2p_mplex_frame_struct
{
    uint64_t id;     /**< Stream ID */
    uint8_t flag;    /**< Frame flag/type */
    uint8_t *data;   /**< Payload data */
    size_t data_len; /**< Length of payload */
};

/**
 * @brief Stream state flags
 */
typedef enum
{
    LIBP2P_MPLEX_STREAM_OPEN = 0,
    LIBP2P_MPLEX_STREAM_LOCAL_CLOSED = 1,
    LIBP2P_MPLEX_STREAM_REMOTE_CLOSED = 2,
    LIBP2P_MPLEX_STREAM_STATE_RESET = 4 // Renamed to avoid conflict
} libp2p_mplex_stream_state_t;

/**
 * @brief Fixed-size slice for incoming data buffering
 */
#define MPLEX_SLICE_SIZE 8192 // 8KB to align with rust-libp2p default split_send_size

/**
 * @brief Default maximum buffer size per stream before backpressure action
 */
#define MPLEX_DEFAULT_MAX_BUFFER_SIZE 1048576 // 1MB
typedef struct mplex_slice
{
    uint8_t data[MPLEX_SLICE_SIZE]; /**< Data buffer */
    size_t len;                     /**< Valid bytes in this slice */
    size_t off;                     /**< Read offset inside slice */
    struct mplex_slice *next;       /**< Next slice in chain */
} mplex_slice_t;

/**
 * @brief Internal mplex stream structure
 */
struct libp2p_mplex_stream
{
    uint64_t id;     /**< Stream identifier */
    uint8_t *name;   /**< Stream name/protocol */
    size_t name_len; /**< Length of stream name */

    bool initiator; /**< True if we initiated this stream */
    int state;      /**< Stream state flags */

    // New slice-based buffering system
    struct mplex_slice *head; /**< First unread slice */
    struct mplex_slice *tail; /**< Last unread slice */
    size_t queued;            /**< Total unread bytes */

    // Backpressure mechanism
    size_t max_buffer_size; /**< Maximum buffer size before backpressure action */

    void *user_data;         /**< User-attached data */
    libp2p_mplex_ctx_t *ctx; /**< Parent context */

    /* Thread safety fields */
    pthread_mutex_t lock; /**< Per-stream mutex for local state/buffers */
    atomic_bool freed;    /**< Atomic flag to prevent double-free */

    /* Event callback fields */
    libp2p_mplex_stream_callback_t event_callback;                   /**< Stream-specific event callback */
    void *event_callback_user_data;                                  /**< User data for stream-specific callback */
    libp2p_mplex_stream_write_ready_callback_t write_ready_callback; /**< Write ready callback */
    void *write_ready_callback_user_data;                            /**< User data for write ready callback */
};

/**
 * @brief Queue node for streams
 */
typedef struct libp2p_mplex_stream_queue_node
{
    libp2p_mplex_stream_t *stream;
    struct libp2p_mplex_stream_queue_node *next;
} libp2p_mplex_stream_queue_node_t;

/**
 * @brief Thread-safe queue for incoming streams
 */
typedef struct
{
    libp2p_mplex_stream_queue_node_t *head;
    libp2p_mplex_stream_queue_node_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    atomic_size_t length;
} libp2p_mplex_stream_queue_t;

/**
 * @brief Queue node for pending write frames
 */
typedef struct libp2p_mplex_write_queue_node
{
    libp2p_mplex_frame_t frame;
    struct libp2p_mplex_write_queue_node *next;
} libp2p_mplex_write_queue_node_t;

/**
 * @brief Thread-safe queue for pending writes
 */
typedef struct
{
    libp2p_mplex_write_queue_node_t *head;
    libp2p_mplex_write_queue_node_t *tail;
    size_t length;
    pthread_mutex_t mutex;
} libp2p_mplex_write_queue_t;

/**
 * @brief Dynamic array for active streams
 */
typedef struct
{
    libp2p_mplex_stream_t **streams;
    size_t length;
    size_t capacity;
} libp2p_mplex_stream_array_t;

/**
 * @brief Main mplex context structure
 */
struct libp2p_mplex_ctx
{
    libp2p_conn_t *conn; /**< Underlying connection */

    /* Event-driven fields */
    int fd;                 /**< File descriptor for event loop integration */
    atomic_bool want_write; /**< Indicates pending writes */
    int wake_read_fd;       /**< Read end of self-pipe to wake the event loop */
    int wake_write_fd;      /**< Write end of self-pipe to wake the event loop */

    /* Stream management */
    uint64_t next_stream_id;                /**< Next stream ID to allocate */
    libp2p_mplex_stream_array_t streams;    /**< Active streams */
    libp2p_mplex_stream_queue_t incoming;   /**< Queue of incoming streams */
    libp2p_mplex_write_queue_t write_queue; /**< Queue of pending writes */

    /* Synchronization */
    pthread_mutex_t mutex; /**< Main context mutex */
    atomic_bool stop;      /**< Processing stop flag */
    bool negotiated;       /**< Protocol negotiation complete */

    /* Pending write buffer for partial frame sends */
    uint8_t *pending_write_buf; /**< Remaining bytes to be written */
    size_t pending_write_len;   /**< Total length of pending buffer */
    size_t pending_write_off;   /**< Current offset already written */

    /* Incremental read buffer for event-driven frame parsing */
    uint8_t *rx_buf; /**< Accumulated unread bytes from the socket */
    size_t rx_len;   /**< Number of valid bytes currently stored in rx_buf */
    size_t rx_off;   /**< Read offset within rx_buf */
    size_t rx_cap;   /**< Allocated capacity of rx_buf */

    /* Event callback fields */
    libp2p_mplex_event_callbacks_t event_callbacks; /**< Event callbacks configuration */

    /* Optional background event-loop thread integration */
    pthread_t loop_thread;     /**< Background event loop thread id */
    int loop_thread_started;   /**< 1 if loop_thread is running */
};

/* Internal utility functions */

/**
 * @brief Initialize a stream queue
 */
int libp2p_mplex_stream_queue_init(libp2p_mplex_stream_queue_t *queue);

/**
 * @brief Destroy a stream queue
 */
void libp2p_mplex_stream_queue_destroy(libp2p_mplex_stream_queue_t *queue);

/**
 * @brief Push a stream to the queue
 */
int libp2p_mplex_stream_queue_push(libp2p_mplex_stream_queue_t *queue, libp2p_mplex_stream_t *stream);

/**
 * @brief Pop a stream from the queue (non-blocking)
 */
libp2p_mplex_stream_t *libp2p_mplex_stream_queue_pop(libp2p_mplex_stream_queue_t *queue);

/**
 * @brief Initialize a write queue
 */
int libp2p_mplex_write_queue_init(libp2p_mplex_write_queue_t *queue);

/**
 * @brief Destroy a write queue
 */
void libp2p_mplex_write_queue_destroy(libp2p_mplex_write_queue_t *queue);

/**
 * @brief Push a frame to the write queue
 */
int libp2p_mplex_write_queue_push(libp2p_mplex_write_queue_t *queue, const libp2p_mplex_frame_t *frame);

/**
 * @brief Pop a frame from the write queue (non-blocking)
 */
libp2p_mplex_frame_t *libp2p_mplex_write_queue_pop(libp2p_mplex_write_queue_t *queue);

/**
 * @brief Initialize a stream array
 */
int libp2p_mplex_stream_array_init(libp2p_mplex_stream_array_t *array);

/**
 * @brief Destroy a stream array
 */
void libp2p_mplex_stream_array_destroy(libp2p_mplex_stream_array_t *array);

/**
 * @brief Add a stream to the array
 */
int libp2p_mplex_stream_array_add(libp2p_mplex_stream_array_t *array, libp2p_mplex_stream_t *stream);

/**
 * @brief Remove a stream from the array by index
 */
int libp2p_mplex_stream_array_remove(libp2p_mplex_stream_array_t *array, size_t index);

/**
 * @brief Find a stream by ID and initiator flag
 */
libp2p_mplex_stream_t *libp2p_mplex_find_stream(libp2p_mplex_ctx_t *ctx, uint64_t id, bool initiator, size_t *index);

/**
 * @brief Create a new stream object
 */
libp2p_mplex_stream_t *libp2p_mplex_stream_new(uint64_t id, const uint8_t *name, size_t name_len, bool initiator, libp2p_mplex_ctx_t *ctx);

/**
 * @brief Free a stream object
 */
void libp2p_mplex_stream_free(libp2p_mplex_stream_t *stream);

/**
 * @brief Encode and send a frame (non-blocking)
 */
int libp2p_mplex_send_frame_nonblocking(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_frame_t *frame);

/**
 * @brief Flush pending writes from the write queue
 */
int libp2p_mplex_flush_writes(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Read and decode a frame
 */
int libp2p_mplex_read_frame(libp2p_mplex_ctx_t *ctx, libp2p_mplex_frame_t *frame);

/**
 * @brief Free frame resources
 */
void libp2p_mplex_frame_free(libp2p_mplex_frame_t *frame);

/**
 * @brief Dispatch a received frame
 */
int libp2p_mplex_dispatch_frame(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_frame_t *frame);

/**
 * @brief Append bytes to stream buffer using slice system
 */
int mplex_stream_enqueue(libp2p_mplex_stream_t *st, const uint8_t *src, size_t len);

/**
 * @brief Copy bytes from stream buffer using slice system
 */
size_t mplex_stream_dequeue(libp2p_mplex_stream_t *st, uint8_t *dst, size_t max);

/**
 * @brief Free all slices in a stream
 */
void mplex_stream_free_slices(libp2p_mplex_stream_t *st);

/* Event helper functions */

/**
 * @brief Trigger a stream event
 */
void libp2p_mplex_trigger_stream_event(libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t *stream, libp2p_mplex_event_t event);

/* Background event-loop helper */
int libp2p_mplex_start_event_loop_thread(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Trigger an error event
 */
void libp2p_mplex_trigger_error_event(libp2p_mplex_ctx_t *ctx, int error);

/**
 * @brief Trigger a write ready event
 */
void libp2p_mplex_trigger_write_ready_event(libp2p_mplex_stream_t *stream);

/**
 * @brief Wake the event loop associated with this context, if running.
 *
 * Safe to call from any thread. Intended to be called after toggling
 * flags like want_write or stop so the loop can immediately react without
 * periodic polling.
 */
void libp2p_mplex_wake(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Wake the event loop associated with this context, if running.
 *
 * Safe to call from any thread. Intended to be called after toggling
 * flags like want_write or stop so the loop can immediately react without
 * periodic polling.
 */

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MPLEX_INTERNAL_H */
