#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol_mplex_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

const char *libp2p_mplex_strerror(int err)
{
    switch (err)
    {
        case LIBP2P_MPLEX_OK:
            return "ok";
        case LIBP2P_MPLEX_ERR_NULL_PTR:
            return "null pointer";
        case LIBP2P_MPLEX_ERR_HANDSHAKE:
            return "handshake failed";
        case LIBP2P_MPLEX_ERR_INTERNAL:
            return "internal error";
        case LIBP2P_MPLEX_ERR_PROTOCOL:
            return "protocol error";
        case LIBP2P_MPLEX_ERR_TIMEOUT:
            return "timeout";
        case LIBP2P_MPLEX_ERR_EOF:
            return "eof";
        case LIBP2P_MPLEX_ERR_AGAIN:
            return "again";
        case LIBP2P_MPLEX_ERR_RESET:
            return "reset";
        default:
            return "unknown";
    }
}

/* Frame encoding/decoding functions */

static int mplex_rx_reserve(libp2p_mplex_ctx_t *ctx, size_t min_free)
{
    if (ctx->rx_cap - ctx->rx_len >= min_free)
        return LIBP2P_MPLEX_OK;

    size_t new_cap = ctx->rx_cap ? ctx->rx_cap : 4096;
    while (new_cap - ctx->rx_len < min_free)
        new_cap *= 2;

    uint8_t *nbuf = realloc(ctx->rx_buf, new_cap);
    if (!nbuf)
        return LIBP2P_MPLEX_ERR_INTERNAL;
    ctx->rx_buf = nbuf;
    ctx->rx_cap = new_cap;
    return LIBP2P_MPLEX_OK;
}

static void mplex_rx_compact(libp2p_mplex_ctx_t *ctx)
{
    if (ctx->rx_off == 0)
        return;
    if (ctx->rx_off >= ctx->rx_len)
    {
        ctx->rx_off = 0;
        ctx->rx_len = 0;
        return;
    }
    memmove(ctx->rx_buf, ctx->rx_buf + ctx->rx_off, ctx->rx_len - ctx->rx_off);
    ctx->rx_len -= ctx->rx_off;
    ctx->rx_off = 0;
}

static int mplex_rx_read_more(libp2p_mplex_ctx_t *ctx)
{
    // Ensure there is some free space to read
    int rc = mplex_rx_reserve(ctx, 2048);
    if (rc != LIBP2P_MPLEX_OK)
        return rc;

    ssize_t n = libp2p_conn_read(ctx->conn, ctx->rx_buf + ctx->rx_len, ctx->rx_cap - ctx->rx_len);
    if (n > 0)
    {
        ctx->rx_len += (size_t)n;
        fprintf(stderr, "[MPLEX] rx_read_more ctx=%p read=%zd len=%zu off=%zu cap=%zu\n", (void *)ctx, n, ctx->rx_len, ctx->rx_off, ctx->rx_cap);
        return LIBP2P_MPLEX_OK;
    }
    if (n == LIBP2P_CONN_ERR_AGAIN)
    {
        fprintf(stderr, "[MPLEX] rx_read_more AGAIN ctx=%p len=%zu off=%zu\n", (void *)ctx, ctx->rx_len, ctx->rx_off);
        return LIBP2P_MPLEX_ERR_AGAIN;
    }
    if (n == LIBP2P_CONN_ERR_EOF || n == LIBP2P_CONN_ERR_CLOSED)
        return LIBP2P_MPLEX_ERR_EOF;
    return LIBP2P_MPLEX_ERR_INTERNAL;
}

// Drain as many bytes as are immediately available from the socket into rx_buf
static int mplex_rx_drain_all_now(libp2p_mplex_ctx_t *ctx)
{
    int total_read = 0;
    for (;;)
    {
        int rc = mplex_rx_reserve(ctx, 2048);
        if (rc != LIBP2P_MPLEX_OK)
            return rc;
        ssize_t n = libp2p_conn_read(ctx->conn, ctx->rx_buf + ctx->rx_len, ctx->rx_cap - ctx->rx_len);
        if (n > 0)
        {
            ctx->rx_len += (size_t)n;
            total_read += (int)n;
            continue; // Attempt to read more until it would block
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            return (total_read > 0) ? LIBP2P_MPLEX_OK : LIBP2P_MPLEX_ERR_AGAIN;
        }
        if (n == LIBP2P_CONN_ERR_EOF || n == LIBP2P_CONN_ERR_CLOSED)
        {
            return (total_read > 0) ? LIBP2P_MPLEX_OK : LIBP2P_MPLEX_ERR_EOF;
        }
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }
}

int libp2p_mplex_read_frame(libp2p_mplex_ctx_t *ctx, libp2p_mplex_frame_t *frame)
{
    if (!ctx || !frame)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    memset(frame, 0, sizeof(*frame));

    fprintf(stderr, "[MPLEX] read_frame begin ctx=%p rx_len=%zu rx_off=%zu\n", (void *)ctx, ctx->rx_len, ctx->rx_off);

    // Initialize buffer lazily
    if (!ctx->rx_buf)
    {
        ctx->rx_cap = 4096;
        ctx->rx_buf = malloc(ctx->rx_cap);
        if (!ctx->rx_buf)
            return LIBP2P_MPLEX_ERR_INTERNAL;
        ctx->rx_len = 0;
        ctx->rx_off = 0;
    }

    // Compact if offset is large to keep contiguous space
    if (ctx->rx_off > 0 && (ctx->rx_off > (ctx->rx_cap / 2) || ctx->rx_off == ctx->rx_len))
        mplex_rx_compact(ctx);

    // Pull in all immediately available bytes before parsing
    int _dr = mplex_rx_drain_all_now(ctx);
    if (ctx->rx_len == ctx->rx_off)
    {
        if (_dr == LIBP2P_MPLEX_ERR_AGAIN)
            fprintf(stderr, "[MPLEX] read_frame: no data (AGAIN) ctx=%p\n", (void *)ctx);
        else if (_dr == LIBP2P_MPLEX_ERR_EOF)
            fprintf(stderr, "[MPLEX] read_frame: drain EOF ctx=%p\n", (void *)ctx);
        else if (_dr != LIBP2P_MPLEX_OK)
            fprintf(stderr, "[MPLEX] read_frame: drain rc=%d ctx=%p\n", _dr, (void *)ctx);
        return LIBP2P_MPLEX_ERR_AGAIN;
    }

    // Decode header varint from buffer
    uint64_t header = 0;
    for (;;)
    {
        size_t avail = ctx->rx_len - ctx->rx_off;
        size_t consumed = 0;
        unsigned_varint_err_t err = unsigned_varint_decode(ctx->rx_buf + ctx->rx_off, avail, &header, &consumed);
        if (err == UNSIGNED_VARINT_OK)
        {
            ctx->rx_off += consumed;
            break;
        }
        if (err == UNSIGNED_VARINT_ERR_TOO_LONG)
        {
            // Varint overflow is a protocol violation
            fprintf(stderr, "[MPLEX] header decode TOO_LONG ctx=%p avail=%zu\n", (void *)ctx, avail);
            fprintf(stderr, "[MPLEX] header decode TOO_LONG ctx=%p\n", (void *)ctx);
            return LIBP2P_MPLEX_ERR_PROTOCOL;
        }
        if (err != UNSIGNED_VARINT_ERR_EMPTY_INPUT)
        {
            fprintf(stderr, "[MPLEX] header decode err=%d ctx=%p avail=%zu\n", (int)err, (void *)ctx, avail);
            return LIBP2P_MPLEX_ERR_PROTOCOL;
        }
        // Need more bytes
        int rc = mplex_rx_read_more(ctx);
        if (rc != LIBP2P_MPLEX_OK)
        {
            fprintf(stderr, "[MPLEX] read_frame: read_more rc=%d ctx=%p\n", rc, (void *)ctx);
            return rc;
        }
    }

    frame->flag = header & 0x07;
    frame->id = header >> 3;
    if (frame->id >= LIBP2P_MPLEX_MAX_STREAM_ID)
        return LIBP2P_MPLEX_ERR_PROTOCOL;

    // Decode payload length varint
    uint64_t payload_len = 0;
    for (;;)
    {
        // If buffer got fully consumed, compact and read more
        if (ctx->rx_off >= ctx->rx_len)
        {
            mplex_rx_compact(ctx);
            int rc = mplex_rx_read_more(ctx);
            if (rc != LIBP2P_MPLEX_OK)
                return rc;
        }
        size_t avail = ctx->rx_len - ctx->rx_off;
        size_t consumed = 0;
        unsigned_varint_err_t err = unsigned_varint_decode(ctx->rx_buf + ctx->rx_off, avail, &payload_len, &consumed);
        if (err == UNSIGNED_VARINT_OK)
        {
            ctx->rx_off += consumed;
            break;
        }
        if (err == UNSIGNED_VARINT_ERR_TOO_LONG)
        {
            fprintf(stderr, "[MPLEX] length decode TOO_LONG ctx=%p avail=%zu\n", (void *)ctx, avail);
            return LIBP2P_MPLEX_ERR_PROTOCOL;
        }
        if (err != UNSIGNED_VARINT_ERR_EMPTY_INPUT)
        {
            fprintf(stderr, "[MPLEX] length decode err=%d ctx=%p avail=%zu\n", (int)err, (void *)ctx, avail);
            return LIBP2P_MPLEX_ERR_PROTOCOL;
        }
        int rc = mplex_rx_read_more(ctx);
        if (rc != LIBP2P_MPLEX_OK)
        {
            fprintf(stderr, "[MPLEX] read_frame: read_more(len) rc=%d ctx=%p\n", rc, (void *)ctx);
            return rc;
        }
    }

    if (payload_len > LIBP2P_MPLEX_MAX_MESSAGE)
        return LIBP2P_MPLEX_ERR_PROTOCOL;

    frame->data_len = (size_t)payload_len;

    // Guard: stream id 0 is reserved/invalid in mplex. Consume and skip such
    // frames defensively to re-synchronize without tearing down the session.
    if (frame->id == 0)
    {
        // Ensure payload bytes are available to skip
        while ((ctx->rx_len - ctx->rx_off) < frame->data_len)
        {
            int rc = mplex_rx_read_more(ctx);
            if (rc != LIBP2P_MPLEX_OK)
            {
                fprintf(stderr, "[MPLEX] drop id=0: read_more rc=%d ctx=%p\n", rc, (void *)ctx);
                return rc;
            }
        }
        // Drop payload (if any)
        ctx->rx_off += frame->data_len;
        fprintf(stderr, "[MPLEX] dropped invalid frame id=0 flag=%u len=%zu ctx=%p\n", (unsigned)frame->flag, frame->data_len, (void *)ctx);
        // Tail recursion: parse the next frame
        return libp2p_mplex_read_frame(ctx, frame);
    }

    // Read payload if present
    if (frame->data_len > 0)
    {
        // Ensure payload bytes are available
        while ((ctx->rx_len - ctx->rx_off) < frame->data_len)
        {
            int rc = mplex_rx_read_more(ctx);
            if (rc != LIBP2P_MPLEX_OK)
                return rc;
        }

        frame->data = malloc(frame->data_len);
        if (!frame->data)
        {
            fprintf(stderr, "[MPLEX] read_frame: OOM data_len=%zu ctx=%p\n", frame->data_len, (void *)ctx);
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }
        memcpy(frame->data, ctx->rx_buf + ctx->rx_off, frame->data_len);
        ctx->rx_off += frame->data_len;
    }

    // If buffer fully consumed, reset indices to avoid unbounded growth
    if (ctx->rx_off >= ctx->rx_len)
    {
        ctx->rx_off = 0;
        ctx->rx_len = 0;
    }

    fprintf(stderr, "[MPLEX] read_frame success ctx=%p flag=%u id=%llu len=%zu rx_len=%zu rx_off=%zu\n", (void *)ctx, (unsigned)frame->flag,
            (unsigned long long)frame->id, frame->data_len, ctx->rx_len, ctx->rx_off);
    return LIBP2P_MPLEX_OK;
}

void libp2p_mplex_frame_free(libp2p_mplex_frame_t *frame)
{
    if (!frame)
        return;

    if (frame->data)
    {
        free(frame->data);
        frame->data = NULL;
    }
    frame->data_len = 0;
}

/* Stream management utilities */

libp2p_mplex_stream_t *libp2p_mplex_stream_new(uint64_t id, const uint8_t *name, size_t name_len, bool initiator, libp2p_mplex_ctx_t *ctx)
{
    libp2p_mplex_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream)
        return NULL;

    stream->id = id;
    stream->initiator = initiator;
    stream->state = LIBP2P_MPLEX_STREAM_OPEN;
    stream->ctx = ctx;
    stream->max_buffer_size = MPLEX_DEFAULT_MAX_BUFFER_SIZE;

    if (name && name_len > 0)
    {
        stream->name = malloc(name_len);
        if (!stream->name)
        {
            free(stream);
            return NULL;
        }
        memcpy(stream->name, name, name_len);
        stream->name_len = name_len;
    }

    // Initialize event callback fields
    stream->event_callback = NULL;
    stream->event_callback_user_data = NULL;
    stream->write_ready_callback = NULL;
    stream->write_ready_callback_user_data = NULL;

    // Initialize atomic freed flag to false
    atomic_init(&stream->freed, false);

    // Initialize per-stream mutex
    pthread_mutex_init(&stream->lock, NULL);

    return stream;
}

void libp2p_mplex_stream_free(libp2p_mplex_stream_t *stream)
{
    if (!stream)
        return;

    // Atomic check and set to prevent double-free
    bool expected = false;
    if (!atomic_compare_exchange_strong(&stream->freed, &expected, true))
    {
        return;
    }

    if (stream->name)
    {
        free(stream->name);
        stream->name = NULL;
    }
    // Free buffered slices
    mplex_stream_free_slices(stream);

    // Destroy per-stream mutex
    pthread_mutex_destroy(&stream->lock);
    free(stream);
}

libp2p_mplex_stream_t *libp2p_mplex_find_stream(libp2p_mplex_ctx_t *ctx, uint64_t id, bool initiator, size_t *index)
{
    if (!ctx)
        return NULL;

    for (size_t i = 0; i < ctx->streams.length; i++)
    {
        libp2p_mplex_stream_t *stream = ctx->streams.streams[i];
        if (stream->id == id && stream->initiator == initiator)
        {
            if (index)
                *index = i;
            return stream;
        }
    }

    return NULL;
}

/* Stream queue implementation */

int libp2p_mplex_stream_queue_init(libp2p_mplex_stream_queue_t *queue)
{
    if (!queue)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    queue->head = NULL;
    queue->tail = NULL;
    atomic_init(&queue->length, 0);

    if (pthread_mutex_init(&queue->mutex, NULL) != 0)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    if (pthread_cond_init(&queue->condition, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->mutex);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }

    return LIBP2P_MPLEX_OK;
}

void libp2p_mplex_stream_queue_destroy(libp2p_mplex_stream_queue_t *queue)
{
    if (!queue)
        return;

    // Clean up remaining nodes but don't free the streams (they're also in the array)
    while (queue->head)
    {
        libp2p_mplex_stream_queue_node_t *node = queue->head;
        queue->head = node->next;
        free(node); // Only free the node, not the stream
    }

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->condition);
}

int libp2p_mplex_stream_queue_push(libp2p_mplex_stream_queue_t *queue, libp2p_mplex_stream_t *stream)
{
    if (!queue || !stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    libp2p_mplex_stream_queue_node_t *node = malloc(sizeof(*node));
    if (!node)
        return LIBP2P_MPLEX_ERR_INTERNAL;

    node->stream = stream;
    node->next = NULL;

    pthread_mutex_lock(&queue->mutex);

    if (queue->tail)
    {
        queue->tail->next = node;
        queue->tail = node;
    }
    else
    {
        queue->head = queue->tail = node;
    }

    atomic_fetch_add(&queue->length, 1);
    pthread_cond_signal(&queue->condition);

    pthread_mutex_unlock(&queue->mutex);

    return LIBP2P_MPLEX_OK;
}

libp2p_mplex_stream_t *libp2p_mplex_stream_queue_pop(libp2p_mplex_stream_queue_t *queue)
{
    if (!queue)
        return NULL;

    pthread_mutex_lock(&queue->mutex);

    libp2p_mplex_stream_queue_node_t *node = queue->head;
    if (!node)
    {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    queue->head = node->next;
    if (!queue->head)
    {
        queue->tail = NULL;
    }

    atomic_fetch_sub(&queue->length, 1);

    pthread_mutex_unlock(&queue->mutex);

    libp2p_mplex_stream_t *stream = node->stream;
    free(node);

    return stream;
}

/* Stream array implementation */

int libp2p_mplex_stream_array_init(libp2p_mplex_stream_array_t *array)
{
    if (!array)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    array->streams = NULL;
    array->length = 0;
    array->capacity = 0;

    return LIBP2P_MPLEX_OK;
}

void libp2p_mplex_stream_array_destroy(libp2p_mplex_stream_array_t *array)
{
    if (!array)
        return;

    if (array->streams)
    {
        free(array->streams);
        array->streams = NULL;
    }
    array->length = 0;
    array->capacity = 0;
}

int libp2p_mplex_stream_array_add(libp2p_mplex_stream_array_t *array, libp2p_mplex_stream_t *stream)
{
    if (!array || !stream)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    if (array->length >= array->capacity)
    {
        size_t new_capacity = array->capacity ? array->capacity * 2 : 4;
        libp2p_mplex_stream_t **new_streams = realloc(array->streams, new_capacity * sizeof(*array->streams));
        if (!new_streams)
            return LIBP2P_MPLEX_ERR_INTERNAL;

        array->streams = new_streams;
        array->capacity = new_capacity;
    }

    array->streams[array->length++] = stream;
    return LIBP2P_MPLEX_OK;
}

int libp2p_mplex_stream_array_remove(libp2p_mplex_stream_array_t *array, size_t index)
{
    if (!array || index >= array->length)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    // Move remaining elements down
    for (size_t i = index; i < array->length - 1; i++)
    {
        array->streams[i] = array->streams[i + 1];
    }

    array->length--;
    return LIBP2P_MPLEX_OK;
}

// Slice-based buffering implementation

static mplex_slice_t *mplex_slice_new(void)
{
    mplex_slice_t *s = malloc(sizeof(*s));
    if (!s)
        return NULL;
    s->len = 0;
    s->off = 0;
    s->next = NULL;
    return s;
}

int mplex_stream_enqueue(libp2p_mplex_stream_t *st, const uint8_t *src, size_t len)
{
    if (!st || !src)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    while (len)
    {
        mplex_slice_t *tail = st->tail;
        if (!tail || tail->len == MPLEX_SLICE_SIZE)
        {
            tail = mplex_slice_new();
            if (!tail)
                return LIBP2P_MPLEX_ERR_INTERNAL;
            if (!st->head)
                st->head = tail;
            if (st->tail)
                st->tail->next = tail;
            st->tail = tail;
        }

        size_t avail = MPLEX_SLICE_SIZE - tail->len;
        size_t copy = (len < avail) ? len : avail;
        memcpy(tail->data + tail->len, src, copy);
        tail->len += copy;
        st->queued += copy;
        src += copy;
        len -= copy;
    }
    return LIBP2P_MPLEX_OK;
}

size_t mplex_stream_dequeue(libp2p_mplex_stream_t *st, uint8_t *dst, size_t max)
{
    if (!st || !dst)
        return 0;

    size_t copied = 0;
    while (max && st->head)
    {
        mplex_slice_t *h = st->head;
        size_t avail = h->len - h->off;
        if (!avail)
        {
            // slice exhausted
            st->head = h->next;
            if (!st->head)
                st->tail = NULL;
            free(h);
            continue;
        }

        size_t take = (max < avail) ? max : avail;
        memcpy(dst + copied, h->data + h->off, take);
        h->off += take;
        copied += take;
        max -= take;
        st->queued -= take;
    }
    return copied;
}

void mplex_stream_free_slices(libp2p_mplex_stream_t *st)
{
    if (!st)
        return;

    mplex_slice_t *s = st->head;
    while (s)
    {
        mplex_slice_t *next = s->next;
        free(s);
        s = next;
    }
    // Clear the pointers to prevent double-free
    st->head = st->tail = NULL;
    st->queued = 0;
}
