#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "libp2p/debug_trace.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/conn_util.h"
__attribute__((weak)) void libp2p_debug_trace(const char *tag, const char *fmt, ...)
{
    (void)tag;
    (void)fmt;
}
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define YAMUX_INITIAL_WINDOW (256 * 1024)
#define YAMUX_MAX_BACKLOG 256

static inline libp2p_yamux_err_t map_conn_err(ssize_t v)
{
    switch ((libp2p_conn_err_t)v)
    {
        case LIBP2P_CONN_ERR_TIMEOUT:
            return LIBP2P_YAMUX_ERR_TIMEOUT;
        case LIBP2P_CONN_ERR_EOF:
            return LIBP2P_YAMUX_ERR_EOF;
        case LIBP2P_CONN_ERR_AGAIN:
            return LIBP2P_YAMUX_ERR_AGAIN;
        case LIBP2P_CONN_ERR_CLOSED:
            /* Treat operations after close as EOF for stream semantics. */
            return LIBP2P_YAMUX_ERR_EOF;
        default:
            return LIBP2P_YAMUX_ERR_INTERNAL;
    }
}

static libp2p_yamux_err_t conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    libp2p_conn_err_t rc = libp2p_conn_write_all(c, buf, len, 1000);
    return (rc == LIBP2P_CONN_OK) ? LIBP2P_YAMUX_OK : map_conn_err(rc);
}

static libp2p_yamux_err_t conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
{
    /* Bound per-chunk wait to a short slice so opportunistic pumps do not
     * block callers after buffering a frame. Treat TIMEOUT as EAGAIN so
     * callers can interleave other work. */
    libp2p_conn_err_t rc = libp2p_conn_read_exact_timed(c, buf, len, 50);
    if (rc == LIBP2P_CONN_ERR_TIMEOUT)
        return LIBP2P_YAMUX_ERR_AGAIN;
    return (rc == LIBP2P_CONN_OK) ? LIBP2P_YAMUX_OK : map_conn_err(rc);
}

libp2p_yamux_err_t libp2p_yamux_negotiate_outbound(libp2p_conn_t *conn, uint64_t timeout_ms)
{
    if (!conn)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    const char *proposals[] = {LIBP2P_YAMUX_PROTO_ID, NULL};
    libp2p_multiselect_err_t rc = libp2p_multiselect_dial(conn, proposals, timeout_ms, NULL);
    if (rc != LIBP2P_MULTISELECT_OK)
        return LIBP2P_YAMUX_ERR_HANDSHAKE;
    /* Yamux negotiated successfully. */
    return LIBP2P_YAMUX_OK;
}

libp2p_yamux_err_t libp2p_yamux_negotiate_inbound(libp2p_conn_t *conn, uint64_t timeout_ms)
{
    if (!conn)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    const char *supported[] = {LIBP2P_YAMUX_PROTO_ID, NULL};
    libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
    cfg.handshake_timeout_ms = timeout_ms;
    libp2p_multiselect_err_t rc = libp2p_multiselect_listen(conn, supported, &cfg, NULL);
    if (rc != LIBP2P_MULTISELECT_OK)
        return LIBP2P_YAMUX_ERR_HANDSHAKE;
    /* Yamux negotiated successfully. */
    return LIBP2P_YAMUX_OK;
}

static libp2p_muxer_err_t yamux_negotiate_out(libp2p_muxer_t *self, libp2p_conn_t *c, uint64_t t)
{
    (void)self;
    libp2p_yamux_err_t yamux_err = libp2p_yamux_negotiate_outbound(c, t);

    // Create yamux context after successful negotiation
    if (yamux_err == LIBP2P_YAMUX_OK)
    {
        self->ctx = libp2p_yamux_ctx_new(c, 1, 256 * 1024); // 256KB default window
        if (!self->ctx)
        {
            return LIBP2P_MUXER_ERR_INTERNAL;
        }
    }

    switch (yamux_err)
    {
        case LIBP2P_YAMUX_OK:
            return LIBP2P_MUXER_OK;
        case LIBP2P_YAMUX_ERR_NULL_PTR:
            return LIBP2P_MUXER_ERR_NULL_PTR;
        case LIBP2P_YAMUX_ERR_HANDSHAKE:
            return LIBP2P_MUXER_ERR_HANDSHAKE;
        default:
            return LIBP2P_MUXER_ERR_INTERNAL;
    }
}

static libp2p_muxer_err_t yamux_negotiate_in(libp2p_muxer_t *self, libp2p_conn_t *c, uint64_t t)
{
    (void)self;
    libp2p_yamux_err_t yamux_err = libp2p_yamux_negotiate_inbound(c, t);

    // Create yamux context after successful negotiation
    if (yamux_err == LIBP2P_YAMUX_OK)
    {
        self->ctx = libp2p_yamux_ctx_new(c, 0, 256 * 1024); // 256KB default window
        if (!self->ctx)
        {
            return LIBP2P_MUXER_ERR_INTERNAL;
        }
    }

    switch (yamux_err)
    {
        case LIBP2P_YAMUX_OK:
            return LIBP2P_MUXER_OK;
        case LIBP2P_YAMUX_ERR_NULL_PTR:
            return LIBP2P_MUXER_ERR_NULL_PTR;
        case LIBP2P_YAMUX_ERR_HANDSHAKE:
            return LIBP2P_MUXER_ERR_HANDSHAKE;
        default:
            return LIBP2P_MUXER_ERR_INTERNAL;
    }
}

static libp2p_muxer_err_t yamux_negotiate(libp2p_muxer_t *mx, libp2p_conn_t *c, uint64_t t, bool inbound)
{
    return inbound ? yamux_negotiate_in(mx, c, t) : yamux_negotiate_out(mx, c, t);
}

static libp2p_muxer_err_t yamux_open_stream(libp2p_muxer_t *mx, const uint8_t *name, size_t name_len, libp2p_stream_t **out)
{
    /* Unified API: libp2p_stream_t is opaque here. Full integration
     * will wrap yamux substreams behind the public stream API.
     * For now, signal unsupported to avoid depending on internals. */
    (void)mx;
    (void)name;
    (void)name_len;
    (void)out;
    return LIBP2P_MUXER_ERR_INTERNAL;
}

static ssize_t yamux_stream_read(libp2p_stream_t *s, void *buf, size_t len)
{
    /* Not wired to opaque libp2p_stream_t yet */
    (void)s;
    (void)buf;
    (void)len;
    return -1;
}

static ssize_t yamux_stream_write(libp2p_stream_t *s, const void *buf, size_t len)
{
    (void)s;
    (void)buf;
    (void)len;
    return -1;
}

static void yamux_stream_close(libp2p_stream_t *s) { (void)s; }

static libp2p_muxer_err_t yamux_close(libp2p_muxer_t *self)
{
    if (self && self->ctx)
    {
        libp2p_yamux_ctx_free(self->ctx);
        self->ctx = NULL;
    }
    return LIBP2P_MUXER_OK;
}

static void yamux_free_muxer(libp2p_muxer_t *self)
{
    if (!self)
        return;
    if (self->ctx)
    {
        libp2p_yamux_ctx_free((libp2p_yamux_ctx_t *)self->ctx);
        self->ctx = NULL;
    }
    free(self);
}

static const libp2p_muxer_vtbl_t YAMUX_VTBL = {
    .negotiate = yamux_negotiate,
    .open_stream = yamux_open_stream,
    .stream_read = yamux_stream_read,
    .stream_write = yamux_stream_write,
    .stream_close = yamux_stream_close,
    .free = yamux_free_muxer,
};

libp2p_muxer_t *libp2p_yamux_new(void)
{
    libp2p_muxer_t *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    m->vt = &YAMUX_VTBL;
    m->ctx = NULL;
    return m;
}

static libp2p_yamux_err_t yamux_send_frame_unlocked(libp2p_conn_t *conn, const libp2p_yamux_frame_t *fr)
{
    if (!conn || !fr)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    if (fr->data_len > UINT32_MAX)
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    uint8_t hdr[12];
    hdr[0] = fr->version;
    hdr[1] = (uint8_t)fr->type;
    uint16_t f = htons(fr->flags);
    memcpy(hdr + 2, &f, 2);
    uint32_t sid = htonl(fr->stream_id);
    memcpy(hdr + 4, &sid, 4);
    uint32_t len = htonl(fr->length);
    memcpy(hdr + 8, &len, 4);
    fprintf(stderr, "[YAMUX_SEND] type=%u id=%u flags=0x%X len=%u (data_len=%zu)\n", (unsigned)fr->type, fr->stream_id, fr->flags, fr->length,
            fr->data_len);
    libp2p_yamux_err_t rc = conn_write_all(conn, hdr, sizeof(hdr));
    if (rc)
        return rc;
    if (fr->data_len)
        rc = conn_write_all(conn, fr->data, fr->data_len);
    return rc;
}

libp2p_yamux_err_t libp2p_yamux_send_frame(libp2p_conn_t *conn, const libp2p_yamux_frame_t *fr)
{
    return yamux_send_frame_unlocked(conn, fr);
}

static libp2p_yamux_err_t yamux_send_frame_locked(libp2p_yamux_ctx_t *ctx, const libp2p_yamux_frame_t *fr)
{
    if (!ctx)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    libp2p_conn_t *conn = ctx->conn;
    if (!conn)
        return LIBP2P_YAMUX_ERR_INTERNAL;
    pthread_mutex_lock(&ctx->write_mtx);
    libp2p_yamux_err_t rc = yamux_send_frame_unlocked(conn, fr);
    pthread_mutex_unlock(&ctx->write_mtx);
    return rc;
}

static libp2p_yamux_err_t yamux_send_msg_internal(libp2p_conn_t *conn, libp2p_yamux_ctx_t *ctx, uint32_t id, const uint8_t *data,
                                                  size_t data_len, uint16_t flags)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = flags,
        .stream_id = id,
        .length = (uint32_t)data_len,
        .data = (uint8_t *)data,
        .data_len = data_len,
    };
    if (ctx)
        return yamux_send_frame_locked(ctx, &fr);
    return yamux_send_frame_unlocked(conn, &fr);
}

static libp2p_yamux_err_t yamux_window_update_internal(libp2p_conn_t *conn, libp2p_yamux_ctx_t *ctx, uint32_t id, uint32_t delta, uint16_t flags)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_WINDOW_UPDATE,
        .flags = flags,
        .stream_id = id,
        .length = delta,
        .data = NULL,
        .data_len = 0,
    };
    if (ctx)
        return yamux_send_frame_locked(ctx, &fr);
    return yamux_send_frame_unlocked(conn, &fr);
}

static libp2p_yamux_err_t yamux_ping_internal(libp2p_conn_t *conn, libp2p_yamux_ctx_t *ctx, uint32_t value, uint16_t flags)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_PING,
        .flags = flags,
        .stream_id = 0,
        .length = value,
        .data = NULL,
        .data_len = 0,
    };
    if (ctx)
        return yamux_send_frame_locked(ctx, &fr);
    return yamux_send_frame_unlocked(conn, &fr);
}

static libp2p_yamux_err_t yamux_go_away_internal(libp2p_conn_t *conn, libp2p_yamux_ctx_t *ctx, libp2p_yamux_goaway_t code)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_GO_AWAY,
        .flags = 0,
        .stream_id = 0,
        .length = (uint32_t)code,
        .data = NULL,
        .data_len = 0,
    };
    if (ctx)
        return yamux_send_frame_locked(ctx, &fr);
    return yamux_send_frame_unlocked(conn, &fr);
}

libp2p_yamux_err_t libp2p_yamux_read_frame(libp2p_conn_t *conn, libp2p_yamux_frame_t *out)
{
    if (!conn || !out)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    uint8_t hdr[12];
    libp2p_yamux_err_t rc = conn_read_exact(conn, hdr, sizeof(hdr));
    if (rc)
        return rc;
    out->version = hdr[0];
    if (out->version != 0)
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    out->type = (libp2p_yamux_type_t)hdr[1];
    uint16_t f;
    memcpy(&f, hdr + 2, 2);
    out->flags = ntohs(f);
    uint32_t sid;
    memcpy(&sid, hdr + 4, 4);
    out->stream_id = ntohl(sid);
    uint32_t len;
    memcpy(&len, hdr + 8, 4);
    out->length = ntohl(len);
    if (out->type == LIBP2P_YAMUX_DATA)
        out->data_len = out->length;
    else
        out->data_len = 0;
    out->data = NULL;
    if (out->data_len)
    {
        out->data = malloc(out->data_len);
        if (!out->data)
            return LIBP2P_YAMUX_ERR_INTERNAL;
        rc = conn_read_exact(conn, out->data, out->data_len);
        if (rc)
        {
            free(out->data);
            out->data = NULL;
            out->data_len = 0;
            return rc;
        }
    }

    /* Trace: log every decoded frame header for debugging inbound stream issues */
    fprintf(stderr, "[YAMUX] read frame type=%u id=%u flags=0x%X len=%u\n", (unsigned)out->type, out->stream_id, out->flags, out->length);

    return LIBP2P_YAMUX_OK;
}

void libp2p_yamux_frame_free(libp2p_yamux_frame_t *fr)
{
    if (!fr)
        return;
    free(fr->data);
    fr->data = NULL;
    fr->data_len = 0;
}

libp2p_yamux_err_t libp2p_yamux_open_stream(libp2p_conn_t *conn, uint32_t id, uint32_t max_window)
{
    /*
     * The original Yamux draft (and older libp2p implementations such as
     * rust-libp2p ≤0.53) expect a WINDOW_UPDATE frame with the SYN flag set
     * when opening a stream, whereas more recent implementations allow a
     * zero-length DATA|SYN frame.  To maximise interoperability we always
     * send WINDOW_UPDATE|SYN.  If the desired receive window equals the
     * default (256 KiB) the delta is zero which is accepted by both the old
     * and the new spec variants.
     */

    uint32_t delta = 0;
    if (max_window > YAMUX_INITIAL_WINDOW)
        delta = max_window - YAMUX_INITIAL_WINDOW;

    return libp2p_yamux_window_update(conn, id, delta, LIBP2P_YAMUX_SYN);
}

libp2p_yamux_err_t libp2p_yamux_send_msg(libp2p_conn_t *conn, uint32_t id, const uint8_t *data, size_t data_len, uint16_t flags)
{
    return yamux_send_msg_internal(conn, NULL, id, data, data_len, flags);
}

libp2p_yamux_err_t libp2p_yamux_close_stream(libp2p_conn_t *conn, uint32_t id) { return libp2p_yamux_send_msg(conn, id, NULL, 0, LIBP2P_YAMUX_FIN); }

libp2p_yamux_err_t libp2p_yamux_reset_stream(libp2p_conn_t *conn, uint32_t id) { return libp2p_yamux_send_msg(conn, id, NULL, 0, LIBP2P_YAMUX_RST); }

libp2p_yamux_err_t libp2p_yamux_window_update(libp2p_conn_t *conn, uint32_t id, uint32_t delta, uint16_t flags)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_WINDOW_UPDATE,
        .flags = flags,
        .stream_id = id,
        .length = delta,
        .data = NULL,
        .data_len = 0,
    };
    return libp2p_yamux_send_frame(conn, &fr);
}

libp2p_yamux_err_t libp2p_yamux_ping(libp2p_conn_t *conn, uint32_t value, uint16_t flags)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_PING,
        .flags = flags,
        .stream_id = 0,
        .length = value,
        .data = NULL,
        .data_len = 0,
    };
    return libp2p_yamux_send_frame(conn, &fr);
}

/* local helper mirroring events_bus.c logic */
static inline void timespec_realtime_after_ms(struct timespec *ts, uint64_t ms)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += (time_t)(ms / 1000ull);
    ts->tv_nsec += (long)((ms % 1000ull) * 1000000ull);
    if (ts->tv_nsec >= 1000000000L)
    {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

static void *keepalive_loop(void *arg)
{
    libp2p_yamux_ctx_t *ctx = arg;
    uint32_t counter = 0;
    pthread_mutex_lock(&ctx->keepalive_mtx);
    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed))
    {
        /* send ping */
        pthread_mutex_unlock(&ctx->keepalive_mtx);
        libp2p_yamux_ctx_ping(ctx, counter++);
        pthread_mutex_lock(&ctx->keepalive_mtx);

        uint64_t remain = ctx->keepalive_ms;
        while (remain && !atomic_load_explicit(&ctx->stop, memory_order_relaxed))
        {
            uint64_t slice = (remain > 50) ? 50 : remain; /* responsive slices */
#ifdef __APPLE__
            struct timespec rel = {.tv_sec = (time_t)(slice / 1000ull), .tv_nsec = (long)((slice % 1000ull) * 1000000ull)};
            (void)pthread_cond_timedwait_relative_np(&ctx->keepalive_cv, &ctx->keepalive_mtx, &rel);
#else
            struct timespec ts;
            timespec_realtime_after_ms(&ts, slice);
            (void)pthread_cond_timedwait(&ctx->keepalive_cv, &ctx->keepalive_mtx, &ts);
#endif
            if (atomic_load_explicit(&ctx->stop, memory_order_relaxed))
                break;
            if (ctx->keepalive_ms == 0)
                break;
            remain -= slice;
        }
    }
    pthread_mutex_unlock(&ctx->keepalive_mtx);
    return NULL;
}

libp2p_yamux_err_t libp2p_yamux_enable_keepalive(libp2p_yamux_ctx_t *ctx, uint64_t interval_ms)
{
    if (!ctx)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    if (interval_ms == 0)
        return LIBP2P_YAMUX_OK;
    ctx->keepalive_ms = interval_ms;

    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&ctx->keepalive_active, &expected, true, memory_order_acq_rel, memory_order_acquire))
        return LIBP2P_YAMUX_OK;

    if (pthread_create(&ctx->keepalive_th, NULL, keepalive_loop, ctx) != 0)
    {
        atomic_store_explicit(&ctx->keepalive_active, false, memory_order_release);
        return LIBP2P_YAMUX_ERR_INTERNAL;
    }
    return LIBP2P_YAMUX_OK;
}

libp2p_yamux_err_t libp2p_yamux_go_away(libp2p_conn_t *conn, libp2p_yamux_goaway_t code)
{
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_GO_AWAY,
        .flags = 0,
        .stream_id = 0,
        .length = (uint32_t)code,
        .data = NULL,
        .data_len = 0,
    };
    return libp2p_yamux_send_frame(conn, &fr);
}

void libp2p_yamux_set_ping_cb(libp2p_yamux_ctx_t *ctx, libp2p_yamux_ping_cb cb, void *arg)
{
    if (!ctx)
        return;
    pthread_mutex_lock(&ctx->mtx);
    ctx->ping_cb = cb;
    ctx->ping_arg = arg;
    pthread_mutex_unlock(&ctx->mtx);
}

libp2p_yamux_err_t libp2p_yamux_ctx_ping(libp2p_yamux_ctx_t *ctx, uint32_t value)
{
    if (!ctx)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    pthread_mutex_lock(&ctx->mtx);
    size_t n = ctx->num_pings;
    struct yamux_ping_pending *tmp = realloc(ctx->pings, (n + 1) * sizeof(*tmp));
    if (!tmp)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_INTERNAL;
    }
    ctx->pings = tmp;
    ctx->pings[n].value = value;
    ctx->pings[n].sent_ms = now_mono_ms();
    ctx->num_pings = n + 1;
    pthread_mutex_unlock(&ctx->mtx);
    return yamux_ping_internal(ctx->conn, ctx, value, LIBP2P_YAMUX_SYN);
}

static void *find_stream(libp2p_yamux_ctx_t *ctx, uint32_t id, size_t *idx)
{
    for (size_t i = 0; i < ctx->num_streams; i++)
    {
        if (ctx->streams[i]->id == id)
        {
            if (idx)
                *idx = i;
            return ctx->streams[i];
        }
    }
    return NULL;
}

static void maybe_cleanup_stream(libp2p_yamux_ctx_t *ctx, size_t idx)
{
    libp2p_yamux_stream_t *st = ctx->streams[idx];
    if ((st->local_closed && st->remote_closed) || st->reset)
    {
        free(st->buf);
        free(st);
        for (size_t i = idx + 1; i < ctx->num_streams; i++)
            ctx->streams[i - 1] = ctx->streams[i];
        ctx->num_streams--;
    }
}

static libp2p_yamux_err_t proto_violation(libp2p_yamux_ctx_t *ctx)
{
    if (ctx && ctx->conn)
    {
        /* notify the peer about the error before closing */
        yamux_go_away_internal(ctx->conn, ctx, LIBP2P_YAMUX_GOAWAY_PROTOCOL_ERROR);
        libp2p_conn_close(ctx->conn);
    }
    if (ctx)
        atomic_store_explicit(&ctx->stop, true, memory_order_relaxed);
    return LIBP2P_YAMUX_ERR_PROTO_MAL;
}

libp2p_yamux_ctx_t *libp2p_yamux_ctx_new(libp2p_conn_t *conn, int dialer, uint32_t max_window)
{
    if (!conn)
        return NULL;

    libp2p_yamux_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->conn = conn;
    ctx->dialer = dialer;
    ctx->next_stream_id = dialer ? 1 : 2;
    ctx->max_window = max_window >= YAMUX_INITIAL_WINDOW ? max_window : YAMUX_INITIAL_WINDOW;
    ctx->ack_backlog = 0;
    yq_init(&ctx->incoming);
    atomic_init(&ctx->stop, false);
    atomic_init(&ctx->refcnt, 1); /* base reference held by the session */
    LIBP2P_TRACE("yamux_ref", "ctx=%p ref=%u (init)", (void *)ctx, 1u);
    pthread_mutex_init(&ctx->mtx, NULL);
    pthread_mutex_init(&ctx->keepalive_mtx, NULL);
    pthread_cond_init(&ctx->keepalive_cv, NULL);
    pthread_mutex_init(&ctx->write_mtx, NULL);
    ctx->keepalive_ms = 0;
    atomic_init(&ctx->keepalive_active, false);
    ctx->goaway_code = LIBP2P_YAMUX_GOAWAY_OK;
    ctx->goaway_received = 0;
    ctx->ping_cb = NULL;
    ctx->ping_arg = NULL;
    ctx->pings = NULL;
    ctx->num_pings = 0;
    ctx->pump_in_recv = 1;
    atomic_init(&ctx->loop_active, false);
    atomic_init(&ctx->io_busy, false);

    return ctx;
}

void libp2p_yamux_ctx_free(libp2p_yamux_ctx_t *ctx)
{
    if (!ctx)
        return;

    /* Drop one reference; only free when it reaches zero. */
    unsigned prev = atomic_fetch_sub_explicit(&ctx->refcnt, 1, memory_order_acq_rel);
    if (prev == 0)
    {
        LIBP2P_TRACE("yamux_ref", "ctx=%p ref underflow", (void *)ctx);
        return;
    }
    unsigned new_ref = prev - 1;
    LIBP2P_TRACE("yamux_ref", "ctx=%p ref=%u->%u", (void *)ctx, prev, new_ref);
    if (new_ref != 0)
        return;
    if (!atomic_load_explicit(&ctx->stop, memory_order_relaxed) && ctx->conn)
        libp2p_yamux_stop(ctx);

    if (atomic_exchange_explicit(&ctx->keepalive_active, false, memory_order_acq_rel))
    {
        pthread_join(ctx->keepalive_th, NULL);
        ctx->keepalive_th = (pthread_t)0;
    }

    for (size_t i = 0; i < ctx->num_streams; i++)
    {
        free(ctx->streams[i]->buf);
        free(ctx->streams[i]);
    }
    free(ctx->streams);
    free(ctx->pings);
    while (yq_pop(&ctx->incoming))
        ;
    pthread_mutex_destroy(&ctx->incoming.mtx);
    pthread_cond_destroy(&ctx->incoming.cond);
    pthread_mutex_destroy(&ctx->keepalive_mtx);
    pthread_cond_destroy(&ctx->keepalive_cv);
    pthread_mutex_destroy(&ctx->write_mtx);
    pthread_mutex_destroy(&ctx->mtx);
    LIBP2P_TRACE("yamux_ref", "ctx=%p destroyed", (void *)ctx);
    free(ctx);
}

libp2p_yamux_err_t libp2p_yamux_stream_open(libp2p_yamux_ctx_t *ctx, uint32_t *out_id)
{
    if (!ctx || !out_id)
        return LIBP2P_YAMUX_ERR_NULL_PTR;

    pthread_mutex_lock(&ctx->mtx);
    if (atomic_load_explicit(&ctx->stop, memory_order_relaxed))
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_EOF;
    }
    if (ctx->ack_backlog >= YAMUX_MAX_BACKLOG)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_AGAIN;
    }
    uint32_t id = ctx->next_stream_id;
    ctx->next_stream_id += 2;

    uint32_t delta = 0;
    if (ctx->max_window > YAMUX_INITIAL_WINDOW)
        delta = ctx->max_window - YAMUX_INITIAL_WINDOW;
    libp2p_yamux_err_t rc = yamux_window_update_internal(ctx->conn, ctx, id, delta, LIBP2P_YAMUX_SYN);
    if (rc)
    {
        ctx->next_stream_id -= 2;
        pthread_mutex_unlock(&ctx->mtx);
        return rc;
    }

    libp2p_yamux_stream_t *st = calloc(1, sizeof(*st));
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_INTERNAL;
    }
    st->id = id;
    st->initiator = 1;
    st->acked = 0;
    st->send_window = YAMUX_INITIAL_WINDOW;
    st->recv_window = ctx->max_window;

    libp2p_yamux_stream_t **tmp = realloc(ctx->streams, (ctx->num_streams + 1) * sizeof(*tmp));
    if (!tmp)
    {
        free(st);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_INTERNAL;
    }
    ctx->streams = tmp;
    ctx->streams[ctx->num_streams++] = st;
    ctx->ack_backlog++;
    *out_id = id;
    pthread_mutex_unlock(&ctx->mtx);
    return LIBP2P_YAMUX_OK;
}

libp2p_yamux_err_t libp2p_yamux_stream_send(libp2p_yamux_ctx_t *ctx, uint32_t id, const uint8_t *data, size_t data_len, uint16_t flags)
{
    fprintf(stderr, "[YAMUX_STREAM_SEND] Attempting to send %zu bytes to stream %u\n", data_len, id);

    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_yamux_stream_t *st = find_stream(ctx, id, &idx);
    if (!st)
    {
        fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u not found\n", id);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    }
    if (st->reset)
    {
        fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u is reset\n", id);
        maybe_cleanup_stream(ctx, idx);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_RESET;
    }
    if (st->local_closed)
    {
        fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u is locally closed\n", id);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    }

    fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u: send_window=%u, data_len=%zu, initiator=%d, acked=%d\n", id, st->send_window, data_len,
            st->initiator, st->acked);

    if (!st->initiator && !st->acked)
    {
        fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u: Adding ACK flag\n", id);
        flags |= LIBP2P_YAMUX_ACK;
        st->acked = 1;
    }

    if (data_len > st->send_window)
    {
        fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u: Insufficient send window (need %zu, have %u)\n", id, data_len, st->send_window);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_AGAIN;
    }

    st->send_window -= (uint32_t)data_len;
    fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u: Send window reduced to %u\n", id, st->send_window);
    pthread_mutex_unlock(&ctx->mtx);

    libp2p_yamux_err_t result = yamux_send_msg_internal(ctx->conn, ctx, id, data, data_len, flags);
    fprintf(stderr, "[YAMUX_STREAM_SEND] Stream %u: Send result = %d\n", id, result);
    return result;
}

libp2p_yamux_err_t libp2p_yamux_stream_close(libp2p_yamux_ctx_t *ctx, uint32_t id)
{
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_yamux_stream_t *st = find_stream(ctx, id, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    }
    pthread_mutex_unlock(&ctx->mtx);

    libp2p_yamux_err_t rc = yamux_send_msg_internal(ctx->conn, ctx, id, NULL, 0, LIBP2P_YAMUX_FIN);
    if (rc)
        return rc;

    pthread_mutex_lock(&ctx->mtx);
    st = find_stream(ctx, id, &idx);
    if (st)
    {
        st->local_closed = 1;
        maybe_cleanup_stream(ctx, idx);
    }
    pthread_mutex_unlock(&ctx->mtx);
    return LIBP2P_YAMUX_OK;
}

libp2p_yamux_err_t libp2p_yamux_stream_reset(libp2p_yamux_ctx_t *ctx, uint32_t id)
{
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_yamux_stream_t *st = find_stream(ctx, id, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    }
    pthread_mutex_unlock(&ctx->mtx);

    libp2p_yamux_err_t rc = yamux_send_msg_internal(ctx->conn, ctx, id, NULL, 0, LIBP2P_YAMUX_RST);

    pthread_mutex_lock(&ctx->mtx);
    st = find_stream(ctx, id, &idx);
    if (st)
    {
        if (st->initiator && !st->acked && ctx->ack_backlog > 0)
            ctx->ack_backlog--;
        st->reset = 1;
        st->local_closed = 1;
        st->remote_closed = 1;
        maybe_cleanup_stream(ctx, idx);
    }
    pthread_mutex_unlock(&ctx->mtx);
    return rc;
}

libp2p_yamux_err_t libp2p_yamux_dispatch_frame(libp2p_yamux_ctx_t *ctx, const libp2p_yamux_frame_t *fr)
{
    if (!ctx || !fr)
        return LIBP2P_YAMUX_ERR_NULL_PTR;

    libp2p_yamux_err_t rc = LIBP2P_YAMUX_OK;
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_yamux_stream_t *st = NULL;

    switch (fr->type)
    {
        case LIBP2P_YAMUX_DATA:
            if (fr->stream_id == 0)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (fr->flags & LIBP2P_YAMUX_SYN)
            {
                fprintf(stderr, "[YAMUX_DISPATCH] DATA frame with SYN flag, stream_id=%u\n", fr->stream_id);
                uint32_t parity = ctx->dialer ? 0 : 1;
                if ((fr->stream_id & 1) != parity)
                {
                    fprintf(stderr, "[YAMUX_DISPATCH] Parity violation: stream_id=%u, expected_parity=%u\n", fr->stream_id, parity);
                    rc = proto_violation(ctx);
                    break;
                }
                st = find_stream(ctx, fr->stream_id, &idx);
                if (!st)
                {
                    fprintf(stderr, "[YAMUX_DISPATCH] Creating new stream id=%u\n", fr->stream_id);
                    if (yq_length(&ctx->incoming) >= YAMUX_MAX_BACKLOG)
                    {
                        fprintf(stderr, "[YAMUX_DISPATCH] Backlog full, resetting stream id=%u\n", fr->stream_id);
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        break;
                    }
                    st = calloc(1, sizeof(*st));
                    if (!st)
                    {
                        fprintf(stderr, "[YAMUX_DISPATCH] Failed to allocate stream\n");
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        rc = LIBP2P_YAMUX_ERR_INTERNAL;
                        break;
                    }
                    st->id = fr->stream_id;
                    st->initiator = 0;
                    st->acked = 0;
                    st->send_window = YAMUX_INITIAL_WINDOW;
                    st->recv_window = ctx->max_window;
                    libp2p_yamux_stream_t **tmp = realloc(ctx->streams, (ctx->num_streams + 1) * sizeof(*tmp));
                    if (!tmp)
                    {
                        fprintf(stderr, "[YAMUX_DISPATCH] Failed to reallocate streams array\n");
                        free(st);
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        rc = LIBP2P_YAMUX_ERR_INTERNAL;
                        break;
                    }
                    ctx->streams = tmp;
                    ctx->streams[ctx->num_streams++] = st;
                    fprintf(stderr, "[YAMUX_DISPATCH] Queuing stream id=%u for acceptance (queue length before: %zu)\n", fr->stream_id,
                            yq_length(&ctx->incoming));
                    yq_push(&ctx->incoming, st);
                    fprintf(stderr, "[YAMUX_DISPATCH] Stream queued, queue length now: %zu\n", yq_length(&ctx->incoming));
                    if (ctx->max_window > YAMUX_INITIAL_WINDOW)
                    {
                        st->acked = 1;
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_window_update_internal(ctx->conn, ctx, fr->stream_id, ctx->max_window - YAMUX_INITIAL_WINDOW, LIBP2P_YAMUX_ACK);
                        pthread_mutex_lock(&ctx->mtx);
                    }
                }
                else
                {
                    fprintf(stderr, "[YAMUX_DISPATCH] Stream id=%u already exists\n", fr->stream_id);
                }
            }

            st = find_stream(ctx, fr->stream_id, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }

            if ((fr->flags & LIBP2P_YAMUX_ACK) && st->initiator && !st->acked)
            {
                st->acked = 1;
                if (ctx->ack_backlog > 0)
                    ctx->ack_backlog--;
            }

            if (fr->flags & LIBP2P_YAMUX_RST)
            {
                if (st->initiator && !st->acked && ctx->ack_backlog > 0)
                    ctx->ack_backlog--;
                st->reset = 1;
                st->local_closed = 1;
                st->remote_closed = 1;
                free(st->buf);
                st->buf = NULL;
                st->buf_len = 0;
                st->buf_pos = 0;
                break;
            }

            if (fr->flags & LIBP2P_YAMUX_FIN)
                st->remote_closed = 1;

            if (fr->data_len)
            {
                if (fr->data_len > st->recv_window)
                {
                    rc = proto_violation(ctx);
                    break;
                }
                size_t unread = st->buf_len > st->buf_pos ? st->buf_len - st->buf_pos : 0;
                if (unread && st->buf_pos > 0)
                    memmove(st->buf, st->buf + st->buf_pos, unread);
                uint8_t *tmp = realloc(st->buf, unread + fr->data_len);
                if (!tmp)
                {
                    rc = LIBP2P_YAMUX_ERR_INTERNAL;
                    break;
                }
                memcpy(tmp + unread, fr->data, fr->data_len);
                st->buf = tmp;
                st->buf_len = unread + fr->data_len;
                st->buf_pos = 0;
                st->recv_window -= fr->data_len;
                if (!st->initiator && !st->acked)
                {
                    st->acked = 1;
                    pthread_mutex_unlock(&ctx->mtx);
                    yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_ACK);
                    pthread_mutex_lock(&ctx->mtx);
                }
            }

            maybe_cleanup_stream(ctx, idx);
            break;

        case LIBP2P_YAMUX_WINDOW_UPDATE:
            if (fr->stream_id == 0)
            {
                rc = proto_violation(ctx);
                break;
            }
            /* Some implementations open a stream with WINDOW_UPDATE|SYN (no DATA).
             * Treat such a frame as a stream open event and queue it for
             * acceptance just like DATA|SYN. */
            if (fr->flags & LIBP2P_YAMUX_SYN)
            {
                uint32_t parity = ctx->dialer ? 0 : 1;
                if ((fr->stream_id & 1) != parity)
                {
                    rc = proto_violation(ctx);
                    break;
                }
                st = find_stream(ctx, fr->stream_id, &idx);
                if (!st)
                {
                    st = calloc(1, sizeof(*st));
                    if (!st)
                    {
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        rc = LIBP2P_YAMUX_ERR_INTERNAL;
                        break;
                    }
                    st->id = fr->stream_id;
                    st->initiator = 0;
                    st->acked = 0;
                    st->send_window = YAMUX_INITIAL_WINDOW;
                    st->recv_window = ctx->max_window;
                    libp2p_yamux_stream_t **tmp = realloc(ctx->streams, (ctx->num_streams + 1) * sizeof(*tmp));
                    if (!tmp)
                    {
                        free(st);
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        rc = LIBP2P_YAMUX_ERR_INTERNAL;
                        break;
                    }
                    ctx->streams = tmp;
                    ctx->streams[ctx->num_streams++] = st;
                    fprintf(stderr, "[YAMUX_DISPATCH] (WND|SYN) Queuing stream id=%u for acceptance (queue length before: %zu)\n", fr->stream_id,
                            yq_length(&ctx->incoming));
                    yq_push(&ctx->incoming, st);
                    fprintf(stderr, "[YAMUX_DISPATCH] (WND|SYN) Stream queued, queue length now: %zu\n", yq_length(&ctx->incoming));
                    if (ctx->max_window > YAMUX_INITIAL_WINDOW)
                    {
                        st->acked = 1;
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_window_update_internal(ctx->conn, ctx, fr->stream_id, ctx->max_window - YAMUX_INITIAL_WINDOW, LIBP2P_YAMUX_ACK);
                        pthread_mutex_lock(&ctx->mtx);
                    }
                }
            }
            if (fr->flags & LIBP2P_YAMUX_SYN)
            {
                uint32_t parity = ctx->dialer ? 0 : 1;
                if ((fr->stream_id & 1) != parity)
                {
                    rc = proto_violation(ctx);
                    break;
                }
                st = find_stream(ctx, fr->stream_id, &idx);
                if (!st)
                {
                    if (yq_length(&ctx->incoming) >= YAMUX_MAX_BACKLOG)
                    {
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        break;
                    }
                    st = calloc(1, sizeof(*st));
                    if (!st)
                    {
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        rc = LIBP2P_YAMUX_ERR_INTERNAL;
                        break;
                    }
                    st->id = fr->stream_id;
                    st->initiator = 0;
                    st->acked = 0;
                    st->send_window = YAMUX_INITIAL_WINDOW + fr->length;
                    if (st->send_window > ctx->max_window)
                        st->send_window = ctx->max_window;
                    st->recv_window = ctx->max_window;
                    libp2p_yamux_stream_t **tmp = realloc(ctx->streams, (ctx->num_streams + 1) * sizeof(*tmp));
                    if (!tmp)
                    {
                        free(st);
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_send_msg_internal(ctx->conn, ctx, fr->stream_id, NULL, 0, LIBP2P_YAMUX_RST);
                        pthread_mutex_lock(&ctx->mtx);
                        rc = LIBP2P_YAMUX_ERR_INTERNAL;
                        break;
                    }
                    ctx->streams = tmp;
                    ctx->streams[ctx->num_streams++] = st;
                    yq_push(&ctx->incoming, st);
                    if (ctx->max_window > YAMUX_INITIAL_WINDOW)
                    {
                        st->acked = 1;
                        pthread_mutex_unlock(&ctx->mtx);
                        yamux_window_update_internal(ctx->conn, ctx, fr->stream_id, ctx->max_window - YAMUX_INITIAL_WINDOW, LIBP2P_YAMUX_ACK);
                        pthread_mutex_lock(&ctx->mtx);
                    }
                }
            }

            st = find_stream(ctx, fr->stream_id, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }

            if ((fr->flags & LIBP2P_YAMUX_ACK) && st->initiator && !st->acked)
            {
                st->acked = 1;
                if (ctx->ack_backlog > 0)
                    ctx->ack_backlog--;
            }

            if (fr->flags & LIBP2P_YAMUX_RST)
            {
                if (st->initiator && !st->acked && ctx->ack_backlog > 0)
                    ctx->ack_backlog--;
                st->reset = 1;
                st->local_closed = 1;
                st->remote_closed = 1;
                free(st->buf);
                st->buf = NULL;
                st->buf_len = 0;
                st->buf_pos = 0;
                break;
            }

            if (fr->flags & LIBP2P_YAMUX_FIN)
                st->remote_closed = 1;

            st->send_window += fr->length;

            maybe_cleanup_stream(ctx, idx);
            break;

        case LIBP2P_YAMUX_PING:
            if (fr->stream_id != 0)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (fr->flags != LIBP2P_YAMUX_SYN && fr->flags != LIBP2P_YAMUX_ACK)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (fr->flags == LIBP2P_YAMUX_SYN)
            {
                /* respond with ACK echoing the value */
                pthread_mutex_unlock(&ctx->mtx);
                rc = yamux_ping_internal(ctx->conn, ctx, fr->length, LIBP2P_YAMUX_ACK);
                pthread_mutex_lock(&ctx->mtx);
            }
            else /* ACK */
            {
                uint64_t rtt = 0;
                for (size_t i = 0; i < ctx->num_pings; i++)
                {
                    if (ctx->pings[i].value == fr->length)
                    {
                        rtt = now_mono_ms() - ctx->pings[i].sent_ms;
                        memmove(&ctx->pings[i], &ctx->pings[i + 1], (ctx->num_pings - i - 1) * sizeof(*ctx->pings));
                        ctx->num_pings--;
                        break;
                    }
                }
                libp2p_yamux_ping_cb cb = ctx->ping_cb;
                void *cb_arg = ctx->ping_arg;
                pthread_mutex_unlock(&ctx->mtx);
                if (cb)
                    cb(ctx, fr->length, rtt, cb_arg);
                pthread_mutex_lock(&ctx->mtx);
            }
            break;

        case LIBP2P_YAMUX_GO_AWAY:
            if (fr->stream_id != 0 || fr->flags != 0)
            {
                rc = proto_violation(ctx);
                break;
            }
            /* record the remote code and tear down the session */
            ctx->goaway_code = (libp2p_yamux_goaway_t)fr->length;
            ctx->goaway_received = 1;
            /* tear down the session without replying */
            libp2p_conn_close(ctx->conn);
            atomic_store_explicit(&ctx->stop, true, memory_order_relaxed);
            break;

        default:
            rc = proto_violation(ctx);
            break;
    }

    pthread_mutex_unlock(&ctx->mtx);
    return rc;
}

libp2p_yamux_err_t libp2p_yamux_stream_recv(libp2p_yamux_ctx_t *ctx, uint32_t id, uint8_t *buf, size_t max_len, size_t *out_len)
{
    if (!ctx || !out_len)
        return LIBP2P_YAMUX_ERR_NULL_PTR;

    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_yamux_stream_t *st = find_stream(ctx, id, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_YAMUX_ERR_PROTO_MAL;
    }
    if (st->reset)
    {
        maybe_cleanup_stream(ctx, idx);
        pthread_mutex_unlock(&ctx->mtx);
        *out_len = 0;
        return LIBP2P_YAMUX_ERR_RESET;
    }
    if (st->buf_pos == st->buf_len)
    {
        if (st->remote_closed)
        {
            maybe_cleanup_stream(ctx, idx);
            pthread_mutex_unlock(&ctx->mtx);
            *out_len = 0;
            return LIBP2P_YAMUX_ERR_EOF;
        }
        /* Try to make progress by processing a single incoming frame, but
         * only when no central runtime is active (to avoid concurrent reads
         * from the underlying connection). */
        if (ctx->pump_in_recv && !atomic_load_explicit(&ctx->loop_active, memory_order_acquire))
        {
            pthread_mutex_unlock(&ctx->mtx);
            libp2p_yamux_err_t pr = libp2p_yamux_process_one(ctx);
            if (pr && pr != LIBP2P_YAMUX_ERR_AGAIN)
            {
                /* If the session is stopping or we saw GO_AWAY, surface EOF for
                 * cleaner shutdown semantics instead of INTERNAL. */
                if ((pr == LIBP2P_YAMUX_ERR_INTERNAL || pr == LIBP2P_YAMUX_ERR_TIMEOUT) &&
                    (atomic_load_explicit(&ctx->stop, memory_order_relaxed) || ctx->goaway_received))
                {
                    fprintf(stderr, "[YAMUX_STREAM_RECV] mapping %d->EOF (stopping=%d goaway=%d)\n", (int)pr,
                            (int)atomic_load_explicit(&ctx->stop, memory_order_relaxed), ctx->goaway_received);
                    pr = LIBP2P_YAMUX_ERR_EOF;
                }
                /* Propagate fatal read/EOF/reset up */
                fprintf(stderr, "[YAMUX_STREAM_RECV] process_one returned %d for id=%u (fatal)\n", (int)pr, id);
                *out_len = 0;
                return pr;
            }
            pthread_mutex_lock(&ctx->mtx);
        }
        st = find_stream(ctx, id, &idx);
        if (!st || st->buf_pos == st->buf_len)
        {
            pthread_mutex_unlock(&ctx->mtx);
            *out_len = 0;
            return LIBP2P_YAMUX_ERR_AGAIN;
        }
    }

    size_t n = st->buf_len - st->buf_pos;
    if (n > max_len)
        n = max_len;
    memcpy(buf, st->buf + st->buf_pos, n);
    st->buf_pos += n;
    st->recv_window += (uint32_t)n;
    maybe_cleanup_stream(ctx, idx);
    pthread_mutex_unlock(&ctx->mtx);
    if (n)
        yamux_window_update_internal(ctx->conn, ctx, id, (uint32_t)n, 0);
    *out_len = n;
    return LIBP2P_YAMUX_OK;
}

libp2p_yamux_err_t libp2p_yamux_accept_stream(libp2p_yamux_ctx_t *ctx, libp2p_yamux_stream_t **out)
{
    if (!ctx || !out)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    libp2p_yamux_stream_t *st = yq_pop(&ctx->incoming);
    if (!st)
    {
        return LIBP2P_YAMUX_ERR_AGAIN;
    }
    *out = st;
    return LIBP2P_YAMUX_OK;
}

libp2p_yamux_err_t libp2p_yamux_process_one(libp2p_yamux_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    /* Acquire I/O token to prevent concurrent reads from another thread. */
    if (atomic_exchange_explicit(&ctx->io_busy, true, memory_order_acq_rel))
    {
        /* Someone else is currently processing a frame. Hint caller to retry. */
        return LIBP2P_YAMUX_ERR_AGAIN;
    }

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(ctx->conn, &fr);
    if (rc)
    {
        /* Log read error with session state to aid debugging rare INTERNALs */
        fprintf(stderr, "[YAMUX_PROCESS_ONE] read_frame rc=%d stop=%d goaway=%d\n", (int)rc,
                (int)atomic_load_explicit(&ctx->stop, memory_order_acquire), ctx->goaway_received);
        /* If this is an I/O hiccup (internal/timeout) while still running,
         * surface it as EAGAIN so callers can retry without tearing down
         * sessions. */
        if ((rc == LIBP2P_YAMUX_ERR_INTERNAL || rc == LIBP2P_YAMUX_ERR_TIMEOUT) &&
            !atomic_load_explicit(&ctx->stop, memory_order_acquire) && !ctx->goaway_received)
        {
            atomic_store_explicit(&ctx->io_busy, false, memory_order_release);
            return LIBP2P_YAMUX_ERR_AGAIN;
        }
        if (rc == LIBP2P_YAMUX_ERR_PROTO_MAL)
            rc = proto_violation(ctx);
        atomic_store_explicit(&ctx->io_busy, false, memory_order_release);
        return rc;
    }
    rc = libp2p_yamux_dispatch_frame(ctx, &fr);
    if (rc == LIBP2P_YAMUX_ERR_PROTO_MAL)
        rc = proto_violation(ctx);
    if (rc)
    {
        fprintf(stderr, "[YAMUX_PROCESS_ONE] dispatch rc=%d type=%u id=%u flags=0x%X len=%u stop=%d goaway=%d\n", (int)rc, (unsigned)fr.type,
                fr.stream_id, fr.flags, fr.length, (int)atomic_load_explicit(&ctx->stop, memory_order_acquire), ctx->goaway_received);
    }
    libp2p_yamux_frame_free(&fr);
    atomic_store_explicit(&ctx->io_busy, false, memory_order_release);
    return rc;
}

libp2p_yamux_err_t libp2p_yamux_process_loop(libp2p_yamux_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_YAMUX_ERR_NULL_PTR;
    atomic_store_explicit(&ctx->loop_active, true, memory_order_release);
    while (!atomic_load_explicit(&ctx->stop, memory_order_acquire))
    {
        libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
        if (rc == LIBP2P_YAMUX_ERR_AGAIN)
            continue; /* no frame yet; keep polling */
        if (rc)
        {
            atomic_store_explicit(&ctx->loop_active, false, memory_order_release);
            return rc;
        }
    }
    atomic_store_explicit(&ctx->loop_active, false, memory_order_release);
    return LIBP2P_YAMUX_OK;
}

void libp2p_yamux_stop(libp2p_yamux_ctx_t *ctx)
{
    if (!ctx)
        return;
    bool was_stopped = atomic_exchange_explicit(&ctx->stop, true, memory_order_relaxed);
    if (!was_stopped)
    {
        if (ctx->conn)
            yamux_go_away_internal(ctx->conn, ctx, LIBP2P_YAMUX_GOAWAY_OK);
        fprintf(stderr, "[YAMUX_STOP] ctx=%p stop=1 goaway_sent=1\n", (void *)ctx);
    }

    /* Wake keepalive thread (idempotent) so it can observe stop */
    pthread_cond_broadcast(&ctx->keepalive_cv);

    if (ctx->conn)
        libp2p_conn_close(ctx->conn);

    if (atomic_exchange_explicit(&ctx->keepalive_active, false, memory_order_acq_rel))
    {
        pthread_join(ctx->keepalive_th, NULL);
        ctx->keepalive_th = (pthread_t)0;
    }
}

void libp2p_yamux_shutdown(libp2p_yamux_ctx_t *ctx)
{
    if (!ctx)
        return;
    libp2p_yamux_stop(ctx);
    if (ctx->conn)
        libp2p_conn_close(ctx->conn);
}
