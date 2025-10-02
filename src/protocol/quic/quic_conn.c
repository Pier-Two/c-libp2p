#include "transport/connection.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "libp2p/errors.h"
#include "libp2p/log.h"
#include "peer_id/peer_id.h"
#include "protocol/quic/protocol_quic.h"
#include "quic_internal.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* ssize_t */
#include <stddef.h>    /* size_t */
#include <stdint.h>    /* uint64_t */

typedef struct quic_conn_ctx {
    _Atomic bool closed;
    multiaddr_t *local;
    multiaddr_t *remote;
    libp2p_quic_session_t *session;
    void (*session_close)(libp2p_quic_session_t *);
   void (*session_free)(libp2p_quic_session_t *);
    peer_id_t *verified_peer;
    _Atomic uint64_t deadline_ms;
    void *verify_ctx;
    void (*verify_ctx_free)(void *);
} quic_conn_ctx_t;

static ssize_t qconn_read(libp2p_conn_t *self, void *buf, size_t len)
{
    (void)self; (void)buf; (void)len;
    return LIBP2P_CONN_ERR_INTERNAL;
}

static ssize_t qconn_write(libp2p_conn_t *self, const void *buf, size_t len)
{
    (void)self; (void)buf; (void)len;
    return LIBP2P_CONN_ERR_INTERNAL;
}

static libp2p_conn_err_t qconn_set_deadline(libp2p_conn_t *self, uint64_t ms)
{
    if (!self || !self->ctx)
        return LIBP2P_CONN_ERR_NULL_PTR;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)self->ctx;
    atomic_store_explicit(&ctx->deadline_ms, ms, memory_order_release);
    return LIBP2P_CONN_OK;
}

static const multiaddr_t *qconn_local(libp2p_conn_t *self)
{
    if (!self || !self->ctx) return NULL;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)self->ctx;
    return ctx->local;
}

static const multiaddr_t *qconn_remote(libp2p_conn_t *self)
{
    if (!self || !self->ctx) return NULL;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)self->ctx;
    return ctx->remote;
}

static libp2p_conn_err_t qconn_close(libp2p_conn_t *self)
{
    if (!self || !self->ctx)
        return LIBP2P_CONN_ERR_NULL_PTR;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)self->ctx;
    bool expected = false;
    if (atomic_compare_exchange_strong(&ctx->closed, &expected, true))
    {
        if (ctx->session_close && ctx->session)
            ctx->session_close(ctx->session);
    }
    return LIBP2P_CONN_OK;
}

static void qconn_free(libp2p_conn_t *self)
{
    if (!self)
        return;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)self->ctx;
    if (ctx)
    {
        if (ctx->verify_ctx && ctx->verify_ctx_free)
        {
            ctx->verify_ctx_free(ctx->verify_ctx);
            ctx->verify_ctx = NULL;
        }
        if (ctx->session_free && ctx->session)
            ctx->session_free(ctx->session);
        multiaddr_free(ctx->local);
        multiaddr_free(ctx->remote);
        if (ctx->verified_peer)
        {
            peer_id_destroy(ctx->verified_peer);
            free(ctx->verified_peer);
        }
        free(ctx);
    }
    free(self);
}

static int qconn_get_fd(libp2p_conn_t *self)
{
    (void)self;
    return -1; /* QUIC session is not an fd */
}

static const libp2p_conn_vtbl_t QUIC_CONN_VTBL = {
    .read = qconn_read,
    .write = qconn_write,
    .set_deadline = qconn_set_deadline,
    .local_addr = qconn_local,
    .remote_addr = qconn_remote,
    .close = qconn_close,
    .free = qconn_free,
    .get_fd = qconn_get_fd,
};

static peer_id_t *peer_id_clone(const peer_id_t *src)
{
    if (!src)
        return NULL;

    peer_id_t *dup = (peer_id_t *)calloc(1, sizeof(*dup));
    if (!dup)
        return NULL;

    if (src->size > 0 && src->bytes)
    {
        dup->bytes = (uint8_t *)malloc(src->size);
        if (!dup->bytes)
        {
            free(dup);
            return NULL;
        }
        memcpy(dup->bytes, src->bytes, src->size);
        dup->size = src->size;
    }

    return dup;
}

libp2p_conn_t *libp2p_quic_conn_new(
    const multiaddr_t *local,
    const multiaddr_t *remote,
    libp2p_quic_session_t *session,
    void (*session_close)(libp2p_quic_session_t *),
    void (*session_free)(libp2p_quic_session_t *),
    peer_id_t *verified_peer)
{
    libp2p_conn_t *c = (libp2p_conn_t *)calloc(1, sizeof(*c));
    if (!c)
    {
        if (verified_peer)
        {
            peer_id_destroy(verified_peer);
            free(verified_peer);
        }
        return NULL;
    }

    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        if (verified_peer)
        {
            peer_id_destroy(verified_peer);
            free(verified_peer);
        }
        free(c);
        return NULL;
    }

    ctx->verified_peer = verified_peer;

    int err = 0;
    ctx->local = local ? multiaddr_copy(local, &err) : NULL;
    if (local && (!ctx->local || err != 0))
        goto fail;

    err = 0;
    ctx->remote = remote ? multiaddr_copy(remote, &err) : NULL;
    if (remote && (!ctx->remote || err != 0))
        goto fail;

    ctx->session = session;
    ctx->session_close = session_close;
    ctx->session_free = session_free;
    atomic_store(&ctx->closed, false);
    atomic_store(&ctx->deadline_ms, 0);
    ctx->verify_ctx = NULL;
    ctx->verify_ctx_free = NULL;

    c->vt = &QUIC_CONN_VTBL;
    c->ctx = ctx;
    return c;

fail:
    if (ctx)
    {
        multiaddr_free(ctx->local);
        multiaddr_free(ctx->remote);
        if (ctx->verified_peer)
        {
            peer_id_destroy(ctx->verified_peer);
            free(ctx->verified_peer);
            ctx->verified_peer = NULL;
        }
        free(ctx);
    }
    free(c);
    return NULL;
}

libp2p_quic_session_t *libp2p_quic_conn_session(libp2p_conn_t *conn)
{
    if (!conn)
        return NULL;

    /* Only QUIC connections use the QUIC vtable; guard against miscasts (e.g. TCP). */
    if (conn->vt != &QUIC_CONN_VTBL || !conn->ctx)
        return NULL;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)conn->ctx;
    return ctx->session;
}

void libp2p_quic_conn_detach_session(libp2p_conn_t *conn)
{
    if (!conn || !conn->ctx)
        return;
    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)conn->ctx;
    if (ctx->session)
    {
        libp2p__quic_session_release(ctx->session);
        ctx->session = NULL;
    }
    ctx->session_close = NULL;
    ctx->session_free = NULL;
}

int libp2p_quic_conn_set_verified_peer(libp2p_conn_t *conn, peer_id_t *peer)
{
    if (!conn || !conn->ctx)
    {
        if (peer)
        {
            peer_id_destroy(peer);
            free(peer);
        }
        return LIBP2P_ERR_NULL_PTR;
    }

    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)conn->ctx;
    if (ctx->verified_peer)
    {
        peer_id_destroy(ctx->verified_peer);
        free(ctx->verified_peer);
        ctx->verified_peer = NULL;
    }

    ctx->verified_peer = peer;
    return 0;
}

int libp2p_quic_conn_copy_verified_peer(const libp2p_conn_t *conn, peer_id_t **out_peer)
{
    if (!out_peer)
        return LIBP2P_ERR_NULL_PTR;
    *out_peer = NULL;

    if (!conn || !conn->ctx)
        return LIBP2P_ERR_NULL_PTR;

    const quic_conn_ctx_t *ctx = (const quic_conn_ctx_t *)conn->ctx;
    if (!ctx->verified_peer)
        return 0;

    peer_id_t *dup = peer_id_clone(ctx->verified_peer);
    if (!dup)
        return LIBP2P_ERR_INTERNAL;

    *out_peer = dup;
    return 0;
}

int libp2p_quic_conn_set_local(libp2p_conn_t *conn, const multiaddr_t *local)
{
    if (!conn || !conn->ctx)
        return LIBP2P_ERR_NULL_PTR;

    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)conn->ctx;
    multiaddr_t *dup = NULL;
    if (local)
    {
        int err = 0;
        dup = multiaddr_copy(local, &err);
        if (!dup || err != 0)
        {
            if (dup)
                multiaddr_free(dup);
            return LIBP2P_ERR_INTERNAL;
        }
    }

    multiaddr_free(ctx->local);
    ctx->local = dup;
    return 0;
}

int libp2p_quic_conn_set_verify_ctx(libp2p_conn_t *conn, void *verify_ctx, void (*verify_ctx_free)(void *))
{
    if (!conn || !conn->ctx)
    {
        if (verify_ctx && verify_ctx_free)
            verify_ctx_free(verify_ctx);
        return LIBP2P_ERR_NULL_PTR;
    }

    quic_conn_ctx_t *ctx = (quic_conn_ctx_t *)conn->ctx;
    if (ctx->verify_ctx && ctx->verify_ctx_free)
        ctx->verify_ctx_free(ctx->verify_ctx);
    ctx->verify_ctx = verify_ctx;
    ctx->verify_ctx_free = verify_ctx_free;
    return 0;
}
