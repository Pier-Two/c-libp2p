#ifndef LIBP2P_STREAM_INTERNAL_H
#define LIBP2P_STREAM_INTERNAL_H

#include "libp2p/runtime.h"
#include "libp2p/stream.h"
#include "peer_id/peer_id.h"
#include "transport/connection.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Internal constructor used by host/negotiation to build a stream backed by a connection.
 * Ownership: takes ownership of remote_peer (may be NULL). Duplicates protocol_id string.
 */
struct libp2p_host; /* fwd */
libp2p_stream_t *libp2p_stream_from_conn(struct libp2p_host *host, libp2p_conn_t *c, const char *protocol_id, int initiator, peer_id_t *remote_peer);

/* Internal backend ops for building streams over non-conn backends (e.g. yamux). */
typedef struct libp2p_stream_backend_ops
{
    ssize_t (*read)(void *io_ctx, void *buf, size_t len);
    ssize_t (*write)(void *io_ctx, const void *buf, size_t len);
    int (*close)(void *io_ctx);
    int (*reset)(void *io_ctx);
    int (*set_deadline)(void *io_ctx, uint64_t ms);
    const multiaddr_t *(*local_addr)(void *io_ctx);
    const multiaddr_t *(*remote_addr)(void *io_ctx);
    /* Optional readiness helpers; return 1 (ready), 0 (not ready), -1 (unknown). */
    int (*is_writable)(void *io_ctx);
    int (*has_readable)(void *io_ctx);
    /* Optional destructor to free io_ctx when stream struct is freed (not close). */
    void (*free_ctx)(void *io_ctx);
} libp2p_stream_backend_ops_t;

/* Build a stream from custom backend ops. Ownership: takes ownership of
 * remote_peer and protocol_id copy as usual; does NOT take ownership of
 * io_ctx unless ops.free_ctx provided. */
libp2p_stream_t *libp2p_stream_from_ops(struct libp2p_host *host, void *io_ctx, const libp2p_stream_backend_ops_t *ops, const char *protocol_id,
                                        int initiator, peer_id_t *remote_peer);

/* Internal: attach parent connection/muxer ownership so closing the stream can
 * optionally tear down the underlying session (used for single-stream dials).
 * take_ownership != 0 transfers ownership of parent_conn and mx to the stream. */
struct libp2p_muxer; /* fwd */
void libp2p_stream_set_parent(libp2p_stream_t *s, libp2p_conn_t *parent_conn, struct libp2p_muxer *mx, int take_ownership);

/* Destroy a stream stub after it has been closed; pointer becomes invalid. */
void libp2p__stream_destroy(libp2p_stream_t *s);

/* Retain/release helpers for async callbacks executed off-thread. */
int libp2p__stream_retain_async(libp2p_stream_t *s);
int libp2p__stream_release_async(libp2p_stream_t *s);

/* Optional callback invoked just before the stream storage is released. */
typedef void (*libp2p_stream_cleanup_fn)(void *ctx, libp2p_stream_t *s);
void libp2p__stream_set_cleanup(libp2p_stream_t *s, libp2p_stream_cleanup_fn fn, void *ctx);
void libp2p__stream_mark_deferred(libp2p_stream_t *s);

#include <stddef.h>

/* Internal helpers for runtime-driven readiness integration. */
/* Consume and clear a pending one-shot on_writable callback. Returns 1 if a
 * callback was present and outputs cb/ud, otherwise returns 0. */
int libp2p__stream_consume_on_writable(libp2p_stream_t *s, libp2p_on_writable_fn *out_cb, void **out_ud);
/* Consume and clear a pending one-shot on_readable callback. Returns 1 if a
 * callback was present and outputs cb/ud, otherwise returns 0. */
int libp2p__stream_consume_on_readable(libp2p_stream_t *s, libp2p_on_readable_fn *out_cb, void **out_ud);

/* Access underlying raw connection for internal muxer checks. */
libp2p_conn_t *libp2p__stream_raw_conn(libp2p_stream_t *s);

/* Generic readiness helpers if backend supports them; otherwise return -1. */
int libp2p__stream_is_writable(libp2p_stream_t *s);
int libp2p__stream_has_readable(libp2p_stream_t *s);

/* Query whether read interest is enabled on the stream (pull mode). */
int libp2p__stream_has_read_interest(libp2p_stream_t *s);

/* Internal: obtain owning host pointer from a stream. */
struct libp2p_host;
struct libp2p_host *libp2p__stream_host(libp2p_stream_t *s);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_STREAM_INTERNAL_H */
