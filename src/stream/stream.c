#include "libp2p/stream.h"
#include "../host/host_internal.h"
#include "libp2p/metrics.h"
#include "libp2p/stream_internal.h"
#include "peer_id/peer_id.h"
#include "transport/connection.h"
#include "libp2p/muxer.h"
#include <stdatomic.h>
#include <stdio.h>
/* resource manager removed: keep rust-libp2p parity */
#include <stdlib.h>
#include <string.h>

/*
 * Temporary minimal stream implementation backed by a single muxed channel
 * using the underlying libp2p_conn_t for I/O. This will be replaced by
 * a proper integration with yamux/mplex contexts and backpressure handling.
 */

typedef struct stream_stub
{
    int initiator;
    char *proto;
    libp2p_conn_t *c; /* if non-NULL, stream is conn-backed */
    struct libp2p_host *host;
    void *ud;
    peer_id_t *peer;
    int read_interest;
    libp2p_on_writable_fn on_writable;
    void *on_writable_ud;
    libp2p_on_readable_fn on_readable;
    void *on_readable_ud;
    char *remote_addr_str; /* cached remote multiaddr string for reuse */
    /* Optional parent session (for true substreams over a muxer). When
     * owns_parent is set, closing this stream will also close and free the
     * parent connection and muxer. */
    libp2p_conn_t *parent_conn;
    struct libp2p_muxer *parent_mx;
    int owns_parent;
    int closed;
    /* Optional custom backend ops for yamux/mplex-backed streams. */
    void *io_ctx;
    libp2p_stream_backend_ops_t ops;
    int has_ops;
    libp2p_stream_cleanup_fn cleanup;
    void *cleanup_ctx;
    atomic_int defer_destroy;
    atomic_int pending_async;
    atomic_int destroy_state;
    atomic_bool freed;
} stream_stub_t;

static stream_stub_t *S(libp2p_stream_t *s) { return (stream_stub_t *)s; }
static const stream_stub_t *SC(const libp2p_stream_t *s) { return (const stream_stub_t *)s; }

ssize_t libp2p_stream_write(libp2p_stream_t *s, const void *buf, size_t len)
{
    stream_stub_t *st = S(s);
    if (!st || atomic_load_explicit(&st->freed, memory_order_acquire))
        return LIBP2P_ERR_NULL_PTR;
    if (st->closed)
        return LIBP2P_ERR_CLOSED;
    if (st->has_ops && st->ops.write)
    {
        ssize_t n = st->ops.write(st->io_ctx, buf, len);
        if (n > 0 && st->host && st->host->metrics)
        {
            const char *pid = st->proto ? st->proto : "unknown";
            char labels[256];
            int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\"}", pid);
            (void)l;
            libp2p_metrics_inc_counter(st->host->metrics, "libp2p_bytes_sent", labels, (double)n);
            libp2p_metrics_observe_histogram(st->host->metrics, "libp2p_stream_write_bytes", labels, (double)n);
        }
        return n;
    }
    if (!st->c)
    {
        /* The underlying connection was already torn down (e.g. session close)
         * but upper layers still hold the stream handle. Treat this as a clean
         * closure so callers can gracefully abort instead of aborting on a
         * null backend. */
        st->closed = 1;
        return LIBP2P_ERR_CLOSED;
    }
    {
        ssize_t n = libp2p_conn_write(st->c, buf, len);
        if (n > 0 && st->host && st->host->metrics)
        {
            const char *pid = st->proto ? st->proto : "unknown";
            char labels[256];
            int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\"}", pid);
            (void)l;
            libp2p_metrics_inc_counter(st->host->metrics, "libp2p_bytes_sent", labels, (double)n);
            libp2p_metrics_observe_histogram(st->host->metrics, "libp2p_stream_write_bytes", labels, (double)n);
        }
        return n;
    }
}

ssize_t libp2p_stream_writev(libp2p_stream_t *s, const struct iovec *iov, int iovcnt)
{
    stream_stub_t *st = S(s);
    if (!st || atomic_load_explicit(&st->freed, memory_order_acquire) || !iov || iovcnt <= 0)
        return LIBP2P_ERR_NULL_PTR;
    if (st->closed)
        return LIBP2P_ERR_CLOSED;

    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++)
    {
        const uint8_t *base = (const uint8_t *)iov[i].iov_base;
        size_t remain = (size_t)iov[i].iov_len;
        while (remain > 0)
        {
            ssize_t n = st->has_ops && st->ops.write ? st->ops.write(st->io_ctx, base, remain)
                                                     : (st->c ? libp2p_conn_write(st->c, base, remain) : LIBP2P_ERR_CLOSED);
            if (n < 0)
            {
                /* if we've written something already, return the progress */
                return total > 0 ? total : n;
            }
            if (n == 0)
            {
                /* treat as would-block */
                return total > 0 ? total : LIBP2P_ERR_AGAIN;
            }
            total += n;
            if (n > 0 && st->host && st->host->metrics)
            {
                const char *pid = st->proto ? st->proto : "unknown";
                char labels[256];
                int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\"}", pid);
                (void)l;
                libp2p_metrics_inc_counter(st->host->metrics, "libp2p_bytes_sent", labels, (double)n);
                libp2p_metrics_observe_histogram(st->host->metrics, "libp2p_stream_write_bytes", labels, (double)n);
            }
            base += (size_t)n;
            remain -= (size_t)n;
        }
    }
    return total;
}

int libp2p_stream_close(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    if (st->closed)
        return 0;
    if (st->host)
    {
        pthread_mutex_lock(&st->host->mtx);
        stream_entry_t **pp = &st->host->active_streams;
        while (*pp)
        {
            if ((*pp)->s == s)
            {
                stream_entry_t *victim = *pp;
                *pp = victim->next;
                free(victim);
                break;
            }
            pp = &(*pp)->next;
        }
        pthread_mutex_unlock(&st->host->mtx);
    }
    /* Resource manager removed: no release accounting */
    int rc = 0;
    if (st->has_ops && st->ops.close)
        rc = st->ops.close(st->io_ctx);
    else if (st->c)
        rc = libp2p_conn_close(st->c);
    else
        rc = LIBP2P_ERR_NULL_PTR;
    /* Once closed, prevent further I/O from using a stale conn pointer. */
    st->c = NULL;
    st->closed = 1;
    /* Emit stream/conn closed events if we have a host */
    if (st->host)
    {
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_STREAM_CLOSED;
            evt.u.stream_closed.reason = 0; /* normal close */
            libp2p_event_publish(st->host, &evt);
        }
        {
            libp2p_event_t evt = {0};
            evt.kind = LIBP2P_EVT_CONN_CLOSED;
            evt.u.conn_closed.peer = st->peer; /* may be NULL */
            evt.u.conn_closed.reason = rc;
            libp2p_event_publish(st->host, &evt);
        }
    }
    if (st->peer)
    {
        peer_id_destroy(st->peer);
        free(st->peer);
        st->peer = NULL;
    }
    if (st->remote_addr_str)
    {
        free(st->remote_addr_str);
        st->remote_addr_str = NULL;
    }
    /* If this stream owns the parent session (outbound single-stream
     * dial), tear it down as well. Allow a tiny grace period so peers can
     * drain any in-flight data before the session disappears. */
    if (st->owns_parent && st->parent_conn)
        libp2p_conn_close(st->parent_conn);
    st->closed = 1;
    return rc;
}

int libp2p_stream_reset(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    if (st->closed)
        return 0;
    if (st->host)
    {
        pthread_mutex_lock(&st->host->mtx);
        stream_entry_t **pp = &st->host->active_streams;
        while (*pp)
        {
            if ((*pp)->s == s)
            {
                stream_entry_t *victim = *pp;
                *pp = victim->next;
                free(victim);
                break;
            }
            pp = &(*pp)->next;
        }
        pthread_mutex_unlock(&st->host->mtx);
    }
    /* Resource manager removed: no release accounting */
    int rc = 0;
    if (st->has_ops && st->ops.reset)
        rc = st->ops.reset(st->io_ctx);
    else if (st->has_ops && st->ops.close)
        rc = st->ops.close(st->io_ctx);
    else if (st->c)
        rc = libp2p_conn_close(st->c);
    if (st->host)
    {
        libp2p_event_t evt1 = {0};
        evt1.kind = LIBP2P_EVT_STREAM_CLOSED;
        evt1.u.stream_closed.reason = LIBP2P_ERR_RESET;
        libp2p_event_publish(st->host, &evt1);
        libp2p_event_t evt2 = {0};
        evt2.kind = LIBP2P_EVT_CONN_CLOSED;
        evt2.u.conn_closed.peer = st->peer;
        evt2.u.conn_closed.reason = LIBP2P_ERR_RESET;
        libp2p_event_publish(st->host, &evt2);
    }
    if (st->peer)
    {
        peer_id_destroy(st->peer);
        free(st->peer);
        st->peer = NULL;
    }
    if (st->remote_addr_str)
    {
        free(st->remote_addr_str);
        st->remote_addr_str = NULL;
    }
    if (st->owns_parent && st->parent_conn)
        libp2p_conn_close(st->parent_conn);
    st->closed = 1;
    return rc == 0 ? LIBP2P_ERR_RESET : rc;
}

void libp2p_stream_free(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st || atomic_load_explicit(&st->freed, memory_order_acquire))
        return;
    int deferred = atomic_load_explicit(&st->defer_destroy, memory_order_acquire);
    if (deferred > 0)
    {
        atomic_store_explicit(&st->defer_destroy, 2, memory_order_release);
        return;
    }
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&st->destroy_state, &expected, 1, memory_order_acq_rel, memory_order_acquire))
        return;
    if (atomic_load_explicit(&st->pending_async, memory_order_acquire) > 0)
        return;
    atomic_store_explicit(&st->destroy_state, 2, memory_order_release);
    libp2p__stream_destroy(s);
}

ssize_t libp2p_stream_read(libp2p_stream_t *s, void *buf, size_t len)
{
    stream_stub_t *st = S(s);
    if (!st || atomic_load_explicit(&st->freed, memory_order_acquire))
        return LIBP2P_ERR_NULL_PTR;
    if (st->closed)
        return LIBP2P_ERR_CLOSED;
    if (st->has_ops && st->ops.read)
    {
        ssize_t n = st->ops.read(st->io_ctx, buf, len);
        if (n > 0 && st->host && st->host->metrics)
        {
            const char *pid = st->proto ? st->proto : "unknown";
            char labels[256];
            int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\"}", pid);
            (void)l;
            libp2p_metrics_inc_counter(st->host->metrics, "libp2p_bytes_received", labels, (double)n);
            libp2p_metrics_observe_histogram(st->host->metrics, "libp2p_stream_read_bytes", labels, (double)n);
        }
        return n;
    }
    if (!st->c)
        return LIBP2P_ERR_NULL_PTR;
    {
        ssize_t n = libp2p_conn_read(st->c, buf, len);
        if (n > 0 && st->host && st->host->metrics)
        {
            const char *pid = st->proto ? st->proto : "unknown";
            char labels[256];
            int l = snprintf(labels, sizeof(labels), "{\"protocol\":\"%s\"}", pid);
            (void)l;
            libp2p_metrics_inc_counter(st->host->metrics, "libp2p_bytes_received", labels, (double)n);
            libp2p_metrics_observe_histogram(st->host->metrics, "libp2p_stream_read_bytes", labels, (double)n);
        }
        return n;
    }
}

int libp2p_stream_set_read_interest(libp2p_stream_t *s, bool enable)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    st->read_interest = enable ? 1 : 0;
    return 0;
}

int libp2p_stream_on_writable(libp2p_stream_t *s, libp2p_on_writable_fn cb, void *user_data)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    st->on_writable = cb;
    st->on_writable_ud = user_data;
    return 0;
}

int libp2p_stream_on_readable(libp2p_stream_t *s, libp2p_on_readable_fn cb, void *user_data)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    st->on_readable = cb;
    st->on_readable_ud = user_data;
    return 0;
}

int libp2p_stream_set_deadline(libp2p_stream_t *s, uint64_t ms)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;
    if (st->has_ops && st->ops.set_deadline)
        return st->ops.set_deadline(st->io_ctx, ms);
    if (!st->c)
        return LIBP2P_ERR_NULL_PTR;
    return libp2p_conn_set_deadline(st->c, ms);
}

bool libp2p_stream_is_initiator(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    return st ? st->initiator != 0 : false;
}

void libp2p_stream_set_user_data(libp2p_stream_t *s, void *user_data)
{
    stream_stub_t *st = S(s);
    if (!st)
        return;
    st->ud = user_data;
}

void *libp2p_stream_get_user_data(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    return st ? st->ud : NULL;
}

const char *libp2p_stream_protocol_id(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    return st ? st->proto : NULL;
}

const multiaddr_t *libp2p_stream_local_addr(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    if (!st)
        return NULL;
    if (st->has_ops && st->ops.local_addr)
        return st->ops.local_addr(st->io_ctx);
    if (!st->c)
        return NULL;
    return libp2p_conn_local_addr(st->c);
}

const multiaddr_t *libp2p_stream_remote_addr(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    if (!st)
        return NULL;
    if (st->has_ops && st->ops.remote_addr)
        return st->ops.remote_addr(st->io_ctx);
    if (!st->c)
        return NULL;
    return libp2p_conn_remote_addr(st->c);
}

const char *libp2p_stream_remote_addr_str(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    return st ? st->remote_addr_str : NULL;
}

const peer_id_t *libp2p_stream_remote_peer(const libp2p_stream_t *s)
{
    const stream_stub_t *st = SC(s);
    return st ? st->peer : NULL;
}

libp2p_stream_t *libp2p_stream_from_conn(struct libp2p_host *host, libp2p_conn_t *c, const char *protocol_id, int initiator, peer_id_t *remote_peer)
{
    if (!c)
        return NULL;
    stream_stub_t *ss = (stream_stub_t *)calloc(1, sizeof(*ss));
    if (!ss)
        return NULL;
    ss->initiator = initiator ? 1 : 0;
    ss->c = c;
    ss->host = host;
    ss->proto = protocol_id ? strdup(protocol_id) : NULL;
    ss->peer = remote_peer; /* take ownership */
    ss->read_interest = 0;
    ss->parent_conn = NULL;
    ss->parent_mx = NULL;
    ss->owns_parent = 0;
    ss->closed = 0;
    ss->remote_addr_str = NULL;
    ss->io_ctx = NULL;
    memset(&ss->ops, 0, sizeof(ss->ops));
    ss->has_ops = 0;
    atomic_init(&ss->defer_destroy, 0);
    atomic_init(&ss->pending_async, 0);
    atomic_init(&ss->destroy_state, 0);
    atomic_init(&ss->freed, false);

    /* Cache remote address string for reuse and register in host list */
    if (host)
    {
        const multiaddr_t *raddr = libp2p_conn_remote_addr(c);
        if (raddr)
        {
            int serr = 0;
            char *saddr = multiaddr_to_str(raddr, &serr);
            if (saddr)
                ss->remote_addr_str = saddr;
        }
        stream_entry_t *ent = (stream_entry_t *)calloc(1, sizeof(*ent));
        if (ent)
        {
            ent->s = (libp2p_stream_t *)ss;
            ent->protocol_id = ss->proto;
            ent->remote_addr = ss->remote_addr_str;
            ent->initiator = ss->initiator;
            pthread_mutex_lock(&host->mtx);
            ent->next = host->active_streams;
            host->active_streams = ent;
            pthread_mutex_unlock(&host->mtx);
        }
    }
    return (libp2p_stream_t *)ss;
}

void libp2p_stream_set_parent(libp2p_stream_t *s, libp2p_conn_t *parent_conn, struct libp2p_muxer *mx, int take_ownership)
{
    stream_stub_t *st = S(s);
    if (!st)
        return;
    st->parent_conn = parent_conn;
    st->parent_mx = mx;
    st->owns_parent = take_ownership ? 1 : 0;
}

int libp2p_stream_set_protocol_id(libp2p_stream_t *s, const char *protocol_id)
{
    stream_stub_t *st = S(s);
    if (!st)
        return LIBP2P_ERR_NULL_PTR;

    char *dup = NULL;
    if (protocol_id)
    {
        dup = strdup(protocol_id);
        if (!dup)
            return LIBP2P_ERR_INTERNAL;
    }

    free(st->proto);
    st->proto = dup;

    if (st->host)
    {
        pthread_mutex_lock(&st->host->mtx);
        stream_entry_t *ent = st->host->active_streams;
        while (ent)
        {
            if (ent->s == s)
            {
                ent->protocol_id = st->proto;
                break;
            }
            ent = ent->next;
        }
        pthread_mutex_unlock(&st->host->mtx);
    }
    return 0;
}

int libp2p_stream_set_remote_peer(libp2p_stream_t *s, peer_id_t *peer)
{
    stream_stub_t *st = S(s);
    if (!st)
    {
        if (peer)
        {
            peer_id_destroy(peer);
            free(peer);
        }
        return LIBP2P_ERR_NULL_PTR;
    }

    if (st->peer)
    {
        peer_id_destroy(st->peer);
        free(st->peer);
    }
    st->peer = peer;
    return 0;
}

int libp2p__stream_consume_on_writable(libp2p_stream_t *s, libp2p_on_writable_fn *out_cb, void **out_ud)
{
    stream_stub_t *st = S(s);
    if (!st)
        return 0;
    libp2p_on_writable_fn cb = st->on_writable;
    void *ud = st->on_writable_ud;
    st->on_writable = NULL;
    st->on_writable_ud = NULL;
    if (cb)
    {
        if (out_cb)
            *out_cb = cb;
        if (out_ud)
            *out_ud = ud;
        return 1;
    }
    return 0;
}

int libp2p__stream_consume_on_readable(libp2p_stream_t *s, libp2p_on_readable_fn *out_cb, void **out_ud)
{
    stream_stub_t *st = S(s);
    if (!st)
        return 0;
    libp2p_on_readable_fn cb = st->on_readable;
    void *ud = st->on_readable_ud;
    st->on_readable = NULL;
    st->on_readable_ud = NULL;
    if (cb)
    {
        if (out_cb)
            *out_cb = cb;
        if (out_ud)
            *out_ud = ud;
        return 1;
    }
    return 0;
}

libp2p_conn_t *libp2p__stream_raw_conn(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    return st ? st->c : NULL;
}

struct libp2p_host *libp2p__stream_host(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    return st ? st->host : NULL;
}

void libp2p__stream_set_cleanup(libp2p_stream_t *s, libp2p_stream_cleanup_fn fn, void *ctx)
{
    stream_stub_t *st = S(s);
    if (!st)
        return;
    st->cleanup = fn;
    st->cleanup_ctx = ctx;
}

void libp2p__stream_mark_deferred(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st)
        return;
    int expected = 0;
    while (!atomic_compare_exchange_weak_explicit(&st->defer_destroy, &expected, 1, memory_order_release, memory_order_acquire))
    {
        if (expected != 0)
            return;
    }
}

int libp2p__stream_retain_async(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st || atomic_load_explicit(&st->freed, memory_order_acquire))
        return 0;
    atomic_fetch_add_explicit(&st->pending_async, 1, memory_order_acq_rel);
    int state = atomic_load_explicit(&st->destroy_state, memory_order_acquire);
    if (state != 0)
    {
        int prev = atomic_fetch_sub_explicit(&st->pending_async, 1, memory_order_acq_rel);
        if (prev == 1 && state == 1)
        {
            int expected = 1;
            if (atomic_compare_exchange_strong_explicit(&st->destroy_state, &expected, 2, memory_order_acq_rel, memory_order_acquire))
            {
                libp2p__stream_destroy(s);
            }
        }
        return 0;
    }
    return 1;
}

int libp2p__stream_release_async(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st)
        return 0;
    if (atomic_load_explicit(&st->freed, memory_order_acquire))
        return 0;
    int prev = atomic_fetch_sub_explicit(&st->pending_async, 1, memory_order_acq_rel);
    if (prev <= 0)
        return 0;
    if (prev == 1)
    {
        int expected = 1;
        if (atomic_compare_exchange_strong_explicit(&st->destroy_state, &expected, 2, memory_order_acq_rel, memory_order_acquire))
        {
            libp2p__stream_destroy(s);
            return 1;
        }
        if (expected == 2)
            return 1;
    }
    return 0;
}

libp2p_stream_t *libp2p_stream_from_ops(struct libp2p_host *host, void *io_ctx, const libp2p_stream_backend_ops_t *ops, const char *protocol_id,
                                        int initiator, peer_id_t *remote_peer)
{
    if (!ops)
        return NULL;
    stream_stub_t *ss = (stream_stub_t *)calloc(1, sizeof(*ss));
    if (!ss)
        return NULL;
    ss->initiator = initiator ? 1 : 0;
    ss->c = NULL;
    ss->host = host;
    ss->proto = protocol_id ? strdup(protocol_id) : NULL;
    ss->peer = remote_peer;
    ss->read_interest = 0;
    ss->parent_conn = NULL;
    ss->parent_mx = NULL;
    ss->owns_parent = 0;
    ss->remote_addr_str = NULL;
    ss->io_ctx = io_ctx;
    if (ops)
        ss->ops = *ops;
    ss->has_ops = 1;
    ss->closed = 0;
    atomic_init(&ss->defer_destroy, 0);
    atomic_init(&ss->pending_async, 0);
    atomic_init(&ss->destroy_state, 0);
    atomic_init(&ss->freed, false);

    if (host)
    {
        const multiaddr_t *raddr = ss->ops.remote_addr ? ss->ops.remote_addr(io_ctx) : NULL;
        if (raddr)
        {
            int serr = 0;
            char *saddr = multiaddr_to_str(raddr, &serr);
            if (saddr)
                ss->remote_addr_str = saddr;
        }
        stream_entry_t *ent = (stream_entry_t *)calloc(1, sizeof(*ent));
        if (ent)
        {
            ent->s = (libp2p_stream_t *)ss;
            ent->protocol_id = ss->proto;
            ent->remote_addr = ss->remote_addr_str;
            ent->initiator = ss->initiator;
            pthread_mutex_lock(&host->mtx);
            ent->next = host->active_streams;
            host->active_streams = ent;
            pthread_mutex_unlock(&host->mtx);
        }
    }
    return (libp2p_stream_t *)ss;
}

void libp2p__stream_destroy(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st)
        return;
    /* idempotent: if already freed, bail */
    bool was_freed = atomic_exchange_explicit(&st->freed, true, memory_order_acq_rel);
    if (was_freed)
        return;
    if (!st->closed)
        (void)libp2p_stream_close(s);
    if (st->cleanup)
    {
        st->cleanup(st->cleanup_ctx, s);
        st->cleanup = NULL;
        st->cleanup_ctx = NULL;
    }
    if (st->has_ops && st->ops.free_ctx && st->io_ctx)
        st->ops.free_ctx(st->io_ctx);
    st->io_ctx = NULL;
    st->has_ops = 0;
    if (st->owns_parent)
    {
        if (st->parent_mx)
        {
            libp2p_muxer_free(st->parent_mx);
            st->parent_mx = NULL;
        }
        if (st->parent_conn)
        {
            libp2p_conn_free(st->parent_conn);
            st->parent_conn = NULL;
        }
    }
    if (st->proto)
    {
        free(st->proto);
        st->proto = NULL;
    }
    if (st->peer)
    {
        peer_id_destroy(st->peer);
        free(st->peer);
        st->peer = NULL;
    }
    if (st->remote_addr_str)
    {
        free(st->remote_addr_str);
        st->remote_addr_str = NULL;
    }
    free(st);
}

int libp2p__stream_is_writable(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st || !st->has_ops || !st->ops.is_writable)
        return -1;
    return st->ops.is_writable(st->io_ctx);
}

int libp2p__stream_has_readable(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st || !st->has_ops || !st->ops.has_readable)
        return -1;
    return st->ops.has_readable(st->io_ctx);
}

int libp2p__stream_has_read_interest(libp2p_stream_t *s)
{
    stream_stub_t *st = S(s);
    if (!st)
        return 0;
    return st->read_interest ? 1 : 0;
}
