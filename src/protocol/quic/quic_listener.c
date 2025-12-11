#include "transport/listener.h"
#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif
#include "libp2p/log.h"

#include "quic_listener.h"
#include "quic_internal.h"

#include "libp2p/errors.h"

#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include "picotls.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_crypto_provider_api.h"
#include "picoquic_set_textlog.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#include "picoquic_packet_loop.h"

static ptls_t *quic_listener_tls_handle(picoquic_cnx_t *cnx)
{
    if (!cnx || !cnx->tls_ctx)
        return NULL;
    picoquic_tls_ctx_t *tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;
    return tls_ctx ? tls_ctx->tls : NULL;
}

typedef struct quic_listener_conn_node
{
    libp2p_conn_t *conn;
    struct quic_listener_conn_node *next;
} quic_listener_conn_node_t;

typedef struct quic_listener_peer_entry
{
    void *tls;
    peer_id_t *peer;
    struct quic_listener_peer_entry *next;
} quic_listener_peer_entry_t;

struct quic_listener_ctx
{
    libp2p_transport_t *transport;
    quic_transport_ctx_t *transport_ctx;
    picoquic_quic_t *quic;
    picoquic_network_thread_ctx_t *net_thread;
    picoquic_packet_loop_param_t loop_param;
    pthread_mutex_t lock;        /* protects queue, bound_addr, port_ready */
    pthread_mutex_t peers_lock;  /* protects verified_peers (separate to avoid deadlock with socket loop) */
    pthread_mutex_t quic_mtx;    /* protects all picoquic context access (wake tree, streams, etc.) */
    pthread_cond_t cond;
    quic_listener_conn_node_t *queue_head;
    quic_listener_conn_node_t *queue_tail;
    quic_listener_peer_entry_t *verified_peers;
    multiaddr_t *requested_addr; /* original listen address */
    multiaddr_t *bound_addr;     /* resolved local address (without /quic) */
    int port_ready;
    _Atomic int closing;
    _Atomic int loop_stop;
};

static bool multiaddr_is_unspecified(const multiaddr_t *addr)
{
    if (!addr)
        return false;
    uint64_t proto = 0;
    if (multiaddr_get_protocol_code(addr, 0, &proto) != MULTIADDR_SUCCESS)
        return false;
    if (proto == MULTICODEC_IP4)
    {
        uint8_t bytes[4] = {0};
        size_t len = sizeof(bytes);
        if (multiaddr_get_address_bytes(addr, 0, bytes, &len) != MULTIADDR_SUCCESS || len != sizeof(bytes))
            return false;
        return bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0;
    }
    else if (proto == MULTICODEC_IP6)
    {
        uint8_t bytes[16] = {0};
        size_t len = sizeof(bytes);
        if (multiaddr_get_address_bytes(addr, 0, bytes, &len) != MULTIADDR_SUCCESS || len != sizeof(bytes))
            return false;
        for (size_t i = 0; i < len; i++)
        {
            if (bytes[i] != 0)
                return false;
        }
        return true;
    }
    return false;
}

static multiaddr_t *multiaddr_copy_without_quic(const multiaddr_t *addr)
{
    if (!addr)
        return NULL;
    int err = MULTIADDR_SUCCESS;
    multiaddr_t *copy = multiaddr_copy(addr, &err);
    if (!copy || err != MULTIADDR_SUCCESS)
    {
        if (copy)
            multiaddr_free(copy);
        return NULL;
    }

    size_t protocols = multiaddr_nprotocols(copy);
    if (protocols == 0)
        return copy;

    uint64_t last_code = 0;
    if (multiaddr_get_protocol_code(copy, protocols - 1, &last_code) != MULTIADDR_SUCCESS)
        return copy;

    if (last_code == MULTICODEC_QUIC || last_code == MULTICODEC_QUIC_V1)
    {
        const char *suffix = (last_code == MULTICODEC_QUIC) ? "/quic" : "/quic-v1";
        int dec_err = MULTIADDR_SUCCESS;
        multiaddr_t *suffix_ma = multiaddr_new_from_str(suffix, &dec_err);
        if (!suffix_ma || dec_err != MULTIADDR_SUCCESS)
        {
            if (suffix_ma)
                multiaddr_free(suffix_ma);
            multiaddr_free(copy);
            return NULL;
        }
        multiaddr_t *decapped = multiaddr_decapsulate(copy, suffix_ma, &dec_err);
        multiaddr_free(suffix_ma);
        multiaddr_free(copy);
        if (!decapped || dec_err != MULTIADDR_SUCCESS)
        {
            if (decapped)
                multiaddr_free(decapped);
            return NULL;
        }
        copy = decapped;
    }

    return copy;
}

static void quic_listener_wake(quic_listener_ctx_t *ctx)
{
    if (!ctx || !ctx->net_thread)
        return;
    picoquic_wake_up_network_thread(ctx->net_thread);
}

static void quic_listener_queue_push_locked(quic_listener_ctx_t *ctx, libp2p_conn_t *conn)
{
    quic_listener_conn_node_t *node = (quic_listener_conn_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        if (conn)
        {
            libp2p_conn_close(conn);
            libp2p_conn_free(conn);
        }
        return;
    }
    node->conn = conn;
    if (!ctx->queue_tail)
        ctx->queue_head = ctx->queue_tail = node;
    else
    {
        ctx->queue_tail->next = node;
        ctx->queue_tail = node;
    }
    pthread_cond_broadcast(&ctx->cond);
}

static libp2p_conn_t *quic_listener_queue_pop(quic_listener_ctx_t *ctx)
{
    pthread_mutex_lock(&ctx->lock);
    quic_listener_conn_node_t *node = ctx->queue_head;
    if (!node)
    {
        pthread_mutex_unlock(&ctx->lock);
        return NULL;
    }
    ctx->queue_head = node->next;
    if (!ctx->queue_head)
        ctx->queue_tail = NULL;
    pthread_mutex_unlock(&ctx->lock);

    libp2p_conn_t *conn = node->conn;
    free(node);
    return conn;
}

static void quic_listener_queue_clear(quic_listener_ctx_t *ctx)
{
    pthread_mutex_lock(&ctx->lock);
    quic_listener_conn_node_t *cur = ctx->queue_head;
    ctx->queue_head = ctx->queue_tail = NULL;
    pthread_mutex_unlock(&ctx->lock);

    while (cur)
    {
        quic_listener_conn_node_t *next = cur->next;
        if (cur->conn)
        {
            libp2p_conn_close(cur->conn);
            libp2p_conn_free(cur->conn);
        }
        free(cur);
        cur = next;
    }
}

static void quic_listener_bound_addr_update(quic_listener_ctx_t *ctx, const struct sockaddr *sa, socklen_t len)
{
    if (!ctx || !sa)
        return;
    multiaddr_t *ma = libp2p__quic_multiaddr_from_sockaddr(sa, len);
    if (!ma)
        return;
    pthread_mutex_lock(&ctx->lock);
    multiaddr_free(ctx->bound_addr);
    ctx->bound_addr = ma;
    ctx->port_ready = 1;
    pthread_cond_broadcast(&ctx->cond);
    pthread_mutex_unlock(&ctx->lock);
}

static void quic_listener_free_peers(quic_listener_ctx_t *ctx)
{
    pthread_mutex_lock(&ctx->peers_lock);
    quic_listener_peer_entry_t *cur = ctx->verified_peers;
    ctx->verified_peers = NULL;
    pthread_mutex_unlock(&ctx->peers_lock);

    while (cur)
    {
        quic_listener_peer_entry_t *next = cur->next;
        if (cur->peer)
        {
            peer_id_destroy(cur->peer);
            free(cur->peer);
        }
        free(cur);
        cur = next;
    }
}

void quic_listener_store_verified_peer(quic_listener_ctx_t *ctx, void *tls_ctx, peer_id_t *peer)
{
    if (!ctx || !tls_ctx)
    {
        if (peer)
        {
            peer_id_destroy(peer);
            free(peer);
        }
        return;
    }

    pthread_mutex_lock(&ctx->peers_lock);
    quic_listener_peer_entry_t *cur = ctx->verified_peers;
    quic_listener_peer_entry_t *prev = NULL;
    while (cur)
    {
        if (cur->tls == tls_ctx)
            break;
        prev = cur;
        cur = cur->next;
    }
    if (!cur)
    {
        cur = (quic_listener_peer_entry_t *)calloc(1, sizeof(*cur));
        if (!cur)
        {
            pthread_mutex_unlock(&ctx->peers_lock);
            if (peer)
            {
                peer_id_destroy(peer);
                free(peer);
            }
            return;
        }
        cur->tls = tls_ctx;
        cur->next = ctx->verified_peers;
        ctx->verified_peers = cur;
    }
    if (cur->peer)
    {
        peer_id_destroy(cur->peer);
        free(cur->peer);
        cur->peer = NULL;
    }
    cur->peer = peer;
    pthread_mutex_unlock(&ctx->peers_lock);
}

peer_id_t *quic_listener_take_verified_peer(quic_listener_ctx_t *ctx, void *tls_ctx)
{
    if (!ctx || !tls_ctx)
        return NULL;

    pthread_mutex_lock(&ctx->peers_lock);

    quic_listener_peer_entry_t *cur = ctx->verified_peers;
    quic_listener_peer_entry_t *prev = NULL;
    while (cur)
    {
        if (cur->tls == tls_ctx)
            break;
        prev = cur;
        cur = cur->next;
    }
    if (!cur)
    {
        pthread_mutex_unlock(&ctx->peers_lock);
        return NULL;
    }
    if (prev)
        prev->next = cur->next;
    else
        ctx->verified_peers = cur->next;
    pthread_mutex_unlock(&ctx->peers_lock);

    peer_id_t *peer = cur->peer;
    free(cur);
    return peer;
}

void quic_listener_remove_verified_peer(quic_listener_ctx_t *ctx, void *tls_ctx)
{
    if (!ctx || !tls_ctx)
        return;
    pthread_mutex_lock(&ctx->peers_lock);
    quic_listener_peer_entry_t *cur = ctx->verified_peers;
    quic_listener_peer_entry_t *prev = NULL;
    while (cur)
    {
        if (cur->tls == tls_ctx)
            break;
        prev = cur;
        cur = cur->next;
    }
    if (!cur)
    {
        pthread_mutex_unlock(&ctx->peers_lock);
        return;
    }
    if (prev)
        prev->next = cur->next;
    else
        ctx->verified_peers = cur->next;
    pthread_mutex_unlock(&ctx->peers_lock);

    if (cur->peer)
    {
        peer_id_destroy(cur->peer);
        free(cur->peer);
    }
    free(cur);
}

static libp2p_listener_err_t quic_listener_accept(libp2p_listener_t *l, libp2p_conn_t **out_conn)
{
    if (!l || !out_conn)
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)atomic_load_explicit(&l->ctx, memory_order_acquire);
    if (!ctx)
        return LIBP2P_LISTENER_ERR_INTERNAL;

    libp2p_conn_t *conn = quic_listener_queue_pop(ctx);
    if (!conn)
    {
        if (atomic_load_explicit(&ctx->closing, memory_order_acquire))
            return LIBP2P_LISTENER_ERR_CLOSED;
        return LIBP2P_LISTENER_ERR_AGAIN;
    }

    *out_conn = conn;
    return LIBP2P_LISTENER_OK;
}

static libp2p_listener_err_t quic_listener_local_addr(libp2p_listener_t *l, multiaddr_t **out)
{
    if (!l || !out)
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)atomic_load_explicit(&l->ctx, memory_order_acquire);
    if (!ctx)
        return LIBP2P_LISTENER_ERR_INTERNAL;

    pthread_mutex_lock(&ctx->lock);
    multiaddr_t *base = ctx->bound_addr ? multiaddr_copy(ctx->bound_addr, NULL) : NULL;
    pthread_mutex_unlock(&ctx->lock);

    if ((!base || multiaddr_is_unspecified(base)) && ctx->requested_addr)
    {
        if (base)
            multiaddr_free(base);
        base = multiaddr_copy_without_quic(ctx->requested_addr);
    }

    if (!base)
        return LIBP2P_LISTENER_ERR_INTERNAL;

    int err = 0;
    multiaddr_t *quic_proto = multiaddr_new_from_str("/quic-v1", &err);
    if (!quic_proto || err != 0)
    {
        multiaddr_free(base);
        if (quic_proto)
            multiaddr_free(quic_proto);
        return LIBP2P_LISTENER_ERR_INTERNAL;
    }

    multiaddr_t *full = multiaddr_encapsulate(base, quic_proto, &err);
    multiaddr_free(base);
    multiaddr_free(quic_proto);
    if (!full || err != 0)
    {
        if (full)
            multiaddr_free(full);
        return LIBP2P_LISTENER_ERR_INTERNAL;
    }
    *out = full;
    return LIBP2P_LISTENER_OK;
}

static void quic_listener_free_ctx(quic_listener_ctx_t *ctx)
{
    if (!ctx)
        return;
    quic_listener_queue_clear(ctx);
    quic_listener_free_peers(ctx);
    multiaddr_free(ctx->requested_addr);
    multiaddr_free(ctx->bound_addr);
    pthread_mutex_destroy(&ctx->lock);
    pthread_mutex_destroy(&ctx->peers_lock);
    pthread_mutex_destroy(&ctx->quic_mtx);
    pthread_cond_destroy(&ctx->cond);
    free(ctx);
}

static libp2p_listener_err_t quic_listener_close(libp2p_listener_t *l)
{
    if (!l)
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)atomic_load_explicit(&l->ctx, memory_order_acquire);
    if (!ctx)
        return LIBP2P_LISTENER_ERR_INTERNAL;

    int expected = 0;
    if (!atomic_compare_exchange_strong(&ctx->closing, &expected, 1))
        return LIBP2P_LISTENER_ERR_CLOSED;

    atomic_store(&ctx->loop_stop, 1);

    if (ctx->quic)
    {
        picoquic_set_verify_certificate_callback(ctx->quic, NULL, NULL);
        /* Acquire quic_mtx to synchronize with the socket loop thread.
         * picoquic_close and iteration over connections modify internal data structures. */
        pthread_mutex_lock(&ctx->quic_mtx);
        picoquic_cnx_t *cnx = picoquic_get_first_cnx(ctx->quic);
        while (cnx)
        {
            picoquic_close(cnx, 0);
            cnx = picoquic_get_next_cnx(cnx);
        }
        pthread_mutex_unlock(&ctx->quic_mtx);
    }

    quic_listener_wake(ctx);

    if (ctx->net_thread)
    {
        picoquic_delete_network_thread(ctx->net_thread);
        ctx->net_thread = NULL;
    }

    if (ctx->quic)
    {
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
    }

    quic_listener_queue_clear(ctx);
    return LIBP2P_LISTENER_OK;
}

static void quic_listener_free(libp2p_listener_t *l)
{
    if (!l)
        return;
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)atomic_load_explicit(&l->ctx, memory_order_acquire);
    quic_listener_free_ctx(ctx);
    free(l);
}

static const libp2p_listener_vtbl_t QUIC_LISTENER_VTBL = {
    .accept = quic_listener_accept,
    .local_addr = quic_listener_local_addr,
    .close = quic_listener_close,
    .free = quic_listener_free,
};

static void quic_listener_prepare_listener(libp2p_listener_t *listener, quic_listener_ctx_t *ctx)
{
    atomic_store(&listener->ctx, ctx);
    listener->vt = &QUIC_LISTENER_VTBL;
    atomic_store(&listener->refcount, 1);
    pthread_mutex_init(&listener->mutex, NULL);
}

static void quic_listener_destroy_connection(libp2p_conn_t *conn)
{
    if (!conn)
        return;
    libp2p_conn_close(conn);
    libp2p_conn_free(conn);
}

static void quic_listener_session_close(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    picoquic_cnx_t *cnx = libp2p__quic_session_native(session);
    if (cnx)
    {
        /* NOTE: Do NOT acquire quic_mtx here - the socket loop already holds it via lock_fn
         * callback. Trying to lock here causes a deadlock. */
        (void)picoquic_close(cnx, 0);
    }
}

static void quic_listener_session_free(libp2p_quic_session_t *session)
{
    if (!session)
        return;
    picoquic_cnx_t *cnx = libp2p__quic_session_native(session);
    if (cnx)
    {
        /* Acquire quic_mtx to synchronize with the socket loop thread.
         * picoquic_delete_cnx removes from wake list (splay tree) which is not thread-safe. */
        pthread_mutex_t *mtx = libp2p__quic_session_get_quic_mtx(session);
        if (mtx)
            pthread_mutex_lock(mtx);
        picoquic_delete_cnx(cnx);
        if (mtx)
            pthread_mutex_unlock(mtx);
    }
    libp2p__quic_session_release(session);
}

static int quic_listener_make_conn(quic_listener_ctx_t *ctx,
                                   picoquic_cnx_t *cnx,
                                   libp2p_conn_t **out_conn)
{
    if (!ctx || !cnx || !out_conn)
        return -1;

    struct sockaddr *peer_sa = NULL;
    picoquic_get_peer_addr(cnx, &peer_sa);
    struct sockaddr_storage peer_copy = {0};
    socklen_t peer_len = 0;
    if (peer_sa)
    {
        if (peer_sa->sa_family == AF_INET)
        {
            peer_len = sizeof(struct sockaddr_in);
            memcpy(&peer_copy, peer_sa, peer_len);
        }
#ifdef AF_INET6
        else if (peer_sa->sa_family == AF_INET6)
        {
            peer_len = sizeof(struct sockaddr_in6);
            memcpy(&peer_copy, peer_sa, peer_len);
        }
#endif
    }
    multiaddr_t *remote_base = peer_len ? libp2p__quic_multiaddr_from_sockaddr((struct sockaddr *)&peer_copy, peer_len) : NULL;
    if (!remote_base)
        return -1;

    int err = 0;
    multiaddr_t *quic_proto = multiaddr_new_from_str("/quic-v1", &err);
    if (!quic_proto || err != 0)
    {
        multiaddr_free(remote_base);
        if (quic_proto)
            multiaddr_free(quic_proto);
        return -1;
    }
    multiaddr_t *remote = multiaddr_encapsulate(remote_base, quic_proto, &err);
    multiaddr_free(remote_base);
    multiaddr_free(quic_proto);
    if (!remote || err != 0)
    {
        if (remote)
            multiaddr_free(remote);
        return -1;
    }

    struct sockaddr *local_sa = NULL;
    picoquic_get_local_addr(cnx, &local_sa);
    struct sockaddr_storage local_copy = {0};
    socklen_t local_len = 0;
    if (local_sa)
    {
        if (local_sa->sa_family == AF_INET)
        {
            local_len = sizeof(struct sockaddr_in);
            memcpy(&local_copy, local_sa, local_len);
        }
#ifdef AF_INET6
        else if (local_sa->sa_family == AF_INET6)
        {
            local_len = sizeof(struct sockaddr_in6);
            memcpy(&local_copy, local_sa, local_len);
        }
#endif
    }
    multiaddr_t *local_base = local_len ? libp2p__quic_multiaddr_from_sockaddr((struct sockaddr *)&local_copy, local_len) : NULL;
    if (!local_base)
    {
        multiaddr_free(remote);
        return -1;
    }
    quic_proto = multiaddr_new_from_str("/quic-v1", &err);
    if (!quic_proto || err != 0)
    {
        multiaddr_free(local_base);
        multiaddr_free(remote);
        if (quic_proto)
            multiaddr_free(quic_proto);
        return -1;
    }
    multiaddr_t *local = multiaddr_encapsulate(local_base, quic_proto, &err);
    multiaddr_free(local_base);
    multiaddr_free(quic_proto);
    if (!local || err != 0)
    {
        if (local)
            multiaddr_free(local);
        multiaddr_free(remote);
        return -1;
    }

    libp2p_quic_session_t *session = libp2p__quic_session_wrap(ctx->quic, cnx);
    if (!session)
    {
        multiaddr_free(local);
        multiaddr_free(remote);
        return -1;
    }

    /* Use the listener's quic mutex for this session since they share the same
     * picoquic context. This ensures proper synchronization between the socket
     * loop thread and worker threads (e.g., ping handler) when accessing
     * picoquic's internal data structures. */
    libp2p__quic_session_set_quic_mtx(session, &ctx->quic_mtx);

    libp2p__quic_session_attach_thread(session, ctx->net_thread);

    picoquic_cnx_t *native = libp2p__quic_session_native(session);
    if (native)
        picoquic_cnx_set_padding_policy(native, 0, 1200);
    peer_id_t *peer = quic_listener_take_verified_peer(ctx, quic_listener_tls_handle(native));

    libp2p_conn_t *conn = libp2p_quic_conn_new(local, remote, session,
                                               quic_listener_session_close,
                                               quic_listener_session_free,
                                               peer);

    multiaddr_free(local);
    multiaddr_free(remote);

    if (!conn)
    {
        if (peer)
        {
            peer_id_destroy(peer);
            free(peer);
        }
        libp2p__quic_session_release(session);
        return -1;
    }

    *out_conn = conn;
    return 0;
}

static int quic_listener_conn_cb(picoquic_cnx_t *cnx,
                                 uint64_t stream_id,
                                 uint8_t *bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void *callback_ctx,
                                 void *stream_ctx)
{
    (void)stream_id;
    (void)bytes;
    (void)length;
    (void)stream_ctx;

    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)callback_ctx;
    if (!ctx || !cnx)
        return 0;

    switch (event)
    {
        case picoquic_callback_ready:
        {
            /* Enable keep-alive pings to prevent idle timeout disconnections.
             * Passing 0 sets the interval to idle_timeout/2 automatically. */
            picoquic_enable_keep_alive(cnx, 0);

            libp2p_conn_t *conn = NULL;
            if (quic_listener_make_conn(ctx, cnx, &conn) == 0 && conn)
            {
                pthread_mutex_lock(&ctx->lock);
                quic_listener_queue_push_locked(ctx, conn);
                pthread_mutex_unlock(&ctx->lock);
            }
            else if (conn)
            {
                quic_listener_destroy_connection(conn);
            }
            break;
        }
        case picoquic_callback_close:
        case picoquic_callback_application_close:
        case picoquic_callback_stateless_reset:
            quic_listener_remove_verified_peer(ctx, quic_listener_tls_handle(cnx));
            break;
        default:
            break;
    }
    return 0;
}

static int quic_listener_loop_cb(picoquic_quic_t *quic,
                                 picoquic_packet_loop_cb_enum cb_mode,
                                 void *callback_ctx,
                                 void *callback_arg)
{
    (void)quic;
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)callback_ctx;

    if (!ctx)
        return 0;

    if (cb_mode == picoquic_packet_loop_ready && callback_arg)
    {
        picoquic_packet_loop_options_t *opts = (picoquic_packet_loop_options_t *)callback_arg;
        opts->do_time_check = 1;
    }
    else if (cb_mode == picoquic_packet_loop_port_update && callback_arg)
    {
        const struct sockaddr *addr = (const struct sockaddr *)callback_arg;
        socklen_t len = 0;
        if (addr->sa_family == AF_INET)
            len = sizeof(struct sockaddr_in);
#ifdef AF_INET6
        else if (addr->sa_family == AF_INET6)
            len = sizeof(struct sockaddr_in6);
#endif
        if (len)
            quic_listener_bound_addr_update(ctx, addr, len);
    }

    if (atomic_load(&ctx->loop_stop))
        return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;

    return 0;
}

void quic_listener_handle_connection_closed(quic_listener_ctx_t *ctx, picoquic_cnx_t *cnx)
{
    if (!ctx || !cnx)
        return;
    quic_listener_remove_verified_peer(ctx, quic_listener_tls_handle(cnx));
}

picoquic_quic_t *quic_listener_get_quic(quic_listener_ctx_t *ctx)
{
    return ctx ? ctx->quic : NULL;
}

/* Lock/unlock callbacks for socket loop thread synchronization.
 * These are called by the socket loop to serialize access to picoquic's
 * internal data structures (especially the cnx_wake_tree splay tree). */
static void quic_listener_lock_cb(void *ctx_ptr)
{
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)ctx_ptr;
    if (ctx)
        pthread_mutex_lock(&ctx->quic_mtx);
}

static void quic_listener_unlock_cb(void *ctx_ptr)
{
    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)ctx_ptr;
    if (ctx)
        pthread_mutex_unlock(&ctx->quic_mtx);
}

int quic_listener_start(quic_listener_ctx_t *ctx)
{
    if (!ctx)
        return -1;
    if (ctx->net_thread)
        return 0;

    int loop_ret = 0;
    picoquic_network_thread_ctx_t *net_thread = picoquic_start_network_thread(ctx->quic,
                                                                              &ctx->loop_param,
                                                                              quic_listener_loop_cb,
                                                                              ctx,
                                                                              &loop_ret);
    if (!net_thread || loop_ret != 0)
        return -1;

    /* Set up thread synchronization callbacks to protect picoquic's internal
     * data structures (especially the cnx_wake_tree splay tree) from concurrent
     * access by the socket loop thread and worker threads (e.g., ping handler). */
    net_thread->lock_fn = quic_listener_lock_cb;
    net_thread->unlock_fn = quic_listener_unlock_cb;
    net_thread->lock_ctx = ctx;

    ctx->net_thread = net_thread;

    uint64_t deadline = picoquic_current_time() + 2000000ULL; /* 2 seconds */
    for (;;)
    {
        int thread_ready = net_thread->thread_is_ready;
        int port_ready = 0;
        pthread_mutex_lock(&ctx->lock);
        port_ready = ctx->port_ready;
        pthread_mutex_unlock(&ctx->lock);

        if (thread_ready && port_ready)
            break;

        if (picoquic_current_time() > deadline)
        {
            picoquic_delete_network_thread(net_thread);
            ctx->net_thread = NULL;
            return -1;
        }
        usleep(1000);
    }
    return 0;
}

libp2p_transport_err_t quic_listener_create(libp2p_transport_t *transport,
                                            quic_transport_ctx_t *transport_ctx,
                                            const multiaddr_t *addr,
                                            libp2p_listener_t **out)
{
    if (!transport || !transport_ctx || !addr || !out)
        return LIBP2P_TRANSPORT_ERR_NULL_PTR;

    struct sockaddr_storage listen_ss;
    socklen_t listen_len = 0;
    if (libp2p__quic_multiaddr_to_sockaddr_udp(addr, &listen_ss, &listen_len) != 0)
        return LIBP2P_TRANSPORT_ERR_INVALID_ARG;

    uint8_t *identity_key = NULL;
    size_t identity_len = 0;
    uint64_t identity_type = 0;
    if (libp2p__quic_transport_copy_identity(transport_ctx, &identity_key, &identity_len, &identity_type) != 0)
        return LIBP2P_TRANSPORT_ERR_INTERNAL;

    libp2p_quic_tls_cert_options_t cert_opts = libp2p_quic_tls_cert_options_default();
    cert_opts.identity_key = identity_key;
    cert_opts.identity_key_len = identity_len;
    cert_opts.identity_key_type = identity_type;

    libp2p_quic_tls_certificate_t cert = {0};
    if (libp2p_quic_tls_generate_certificate(&cert_opts, &cert) != 0)
    {
        libp2p__quic_transport_clear_buffer(identity_key, identity_len);
        free(identity_key);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p__quic_transport_clear_buffer(identity_key, identity_len);
    free(identity_key);

    quic_listener_ctx_t *ctx = (quic_listener_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    ctx->transport = transport;
    ctx->transport_ctx = transport_ctx;
    pthread_mutex_init(&ctx->lock, NULL);
    pthread_mutex_init(&ctx->peers_lock, NULL);
    pthread_mutex_init(&ctx->quic_mtx, NULL);
    pthread_cond_init(&ctx->cond, NULL);
    ctx->port_ready = 0;
    atomic_store(&ctx->closing, 0);
    atomic_store(&ctx->loop_stop, 0);
    ctx->requested_addr = multiaddr_copy(addr, NULL);

    libp2p_quic_config_t cfg = libp2p__quic_transport_get_config(transport_ctx);

    picoquic_quic_t *quic = picoquic_create(16,
                                            NULL,
                                            NULL,
                                            NULL,
                                            cfg.alpn ? cfg.alpn : LIBP2P_QUIC_TLS_ALPN,
                                            quic_listener_conn_cb,
                                            ctx,
                                            NULL,
                                            NULL,
                                            NULL,
                                            picoquic_current_time(),
                                            NULL,
                                            NULL,
                                            NULL,
                                            0);
    if (!quic)
    {
        quic_listener_free_ctx(ctx);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    picoquic_set_default_lossbit_policy(quic, picoquic_lossbit_none);

    picoquic_tp_t listener_tp = *picoquic_get_default_tp(quic);
    listener_tp.enable_loss_bit = 0;
    listener_tp.min_ack_delay = 0;
    /* Set max_idle_timeout to 60 seconds (in milliseconds).
     * This ensures keep-alive pings (at idle_timeout/2 = 30s) are sent before timeout.
     * 60s matches rust-libp2p's default to prevent premature timeout disconnections. */
    listener_tp.max_idle_timeout = 60000;
    if (picoquic_set_default_tp(quic, &listener_tp) != 0)
    {
        picoquic_free(quic);
        quic_listener_free_ctx(ctx);
        libp2p_quic_tls_certificate_clear(&cert);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    LP_LOGD("QUIC",
            "listener transport params configured loss_bit=%d min_ack_delay=%" PRIu64 " max_idle_timeout=%" PRIu64 "ms",
            listener_tp.enable_loss_bit,
            listener_tp.min_ack_delay,
            listener_tp.max_idle_timeout);

    ptls_iovec_t *chain = (ptls_iovec_t *)calloc(1, sizeof(*chain));
    if (!chain)
    {
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        quic_listener_free_ctx(ctx);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }
    chain[0].base = cert.cert_der;
    chain[0].len = cert.cert_len;
    picoquic_set_tls_certificate_chain(quic, chain, 1);
    cert.cert_der = NULL;
    cert.cert_len = 0;

    if (libp2p__quic_apply_tls_key(quic, cert.key_der, cert.key_len) != 0)
    {
        picoquic_free(quic);
        libp2p_quic_tls_certificate_clear(&cert);
        quic_listener_free_ctx(ctx);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    libp2p_quic_tls_certificate_clear(&cert);

    /* Ensure the context accepts inbound connections now that TLS material is installed. */
    picoquic_enforce_client_only(quic, 0);
    picoquic_set_client_authentication(quic, 1);
    libp2p__quic_configure_textlog(quic);
    picoquic_set_default_padding(quic, 0, 1200);
    quic->dont_coalesce_init = 1; /* keep Initial datagrams padded instead of relying on coalescing */

    ctx->quic = quic;

    memset(&ctx->loop_param, 0, sizeof(ctx->loop_param));
    ctx->loop_param.local_af = listen_ss.ss_family;
    if (listen_ss.ss_family == AF_INET)
        ctx->loop_param.local_port = ntohs(((struct sockaddr_in *)&listen_ss)->sin_port);
#ifdef AF_INET6
    else if (listen_ss.ss_family == AF_INET6)
        ctx->loop_param.local_port = ntohs(((struct sockaddr_in6 *)&listen_ss)->sin6_port);
#endif
    else
        ctx->loop_param.local_port = 0;

    ctx->bound_addr = libp2p__quic_multiaddr_from_sockaddr((struct sockaddr *)&listen_ss, listen_len);
    if (!ctx->bound_addr)
    {
        int serr = 0;
        multiaddr_t *base = multiaddr_copy(addr, &serr);
        if (base && serr == 0)
        {
            int derr = 0;
            multiaddr_t *decap = NULL;
            multiaddr_t *proto = multiaddr_new_from_str("/quic-v1", &derr);
            if (proto && derr == 0)
            {
                decap = multiaddr_decapsulate(base, proto, &derr);
                multiaddr_free(proto);
            }
            if ((!decap || derr != 0))
            {
                if (decap)
                    multiaddr_free(decap);
                derr = 0;
                proto = multiaddr_new_from_str("/quic", &derr);
                if (proto && derr == 0)
                {
                    decap = multiaddr_decapsulate(base, proto, &derr);
                }
                if (proto)
                    multiaddr_free(proto);
            }
            if (decap && derr == 0)
            {
                ctx->bound_addr = decap;
                multiaddr_free(base);
            }
            else
            {
                ctx->bound_addr = base;
            }
        }
        else if (base)
        {
            ctx->bound_addr = base;
        }
    }

    libp2p_listener_t *listener = (libp2p_listener_t *)calloc(1, sizeof(*listener));
    if (!listener)
    {
        picoquic_free(quic);
        quic_listener_free_ctx(ctx);
        return LIBP2P_TRANSPORT_ERR_INTERNAL;
    }

    quic_listener_prepare_listener(listener, ctx);

    *out = listener;
    return LIBP2P_TRANSPORT_OK;
}
