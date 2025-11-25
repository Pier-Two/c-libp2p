#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "host_internal.h"
#include "conn_pool.h"
#include "libp2p/component_registry.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/quic/protocol_quic.h"
/* For push publisher */
#include "libp2p/debug_trace.h"
#include "libp2p/events.h"
#include "libp2p/log.h"
#include "libp2p/lpmsg.h"
#include "libp2p/transport.h"
#include "libp2p/protocol_dial.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "transport/connection.h"

/* Identify minimal service is provided in protocol_identify module;
 * host does not auto-start it to avoid link cycles. */

static void free_const_string_array(const char *const **array_ptr, size_t *count)
{
    if (!array_ptr || !*array_ptr)
        return;
    const char *const *arr = *array_ptr;
    const size_t limit = count ? *count : 0;
    for (size_t i = 0; i < limit; i++)
        free((void *)arr[i]);
    free((void *)arr);
    *array_ptr = NULL;
    if (count)
        *count = 0;
}

static int duplicate_const_string_array(const char *const *src, size_t count, const char *const **dst_out)
{
    if (!dst_out)
        return LIBP2P_ERR_NULL_PTR;
    *dst_out = NULL;
    if (!src || count == 0)
        return 0;

    const char **copy = (const char **)calloc(count, sizeof(*copy));
    if (!copy)
        return LIBP2P_ERR_INTERNAL;

    for (size_t i = 0; i < count; i++)
    {
        if (src[i])
        {
            copy[i] = strdup(src[i]);
            if (!copy[i])
            {
                for (size_t j = 0; j < i; j++)
                    free((void *)copy[j]);
                free(copy);
                return LIBP2P_ERR_INTERNAL;
            }
        }
        else
        {
            copy[i] = NULL;
        }
    }

    *dst_out = (const char *const *)copy;
    return 0;
}

static int dup_opts(const libp2p_host_options_t *in, libp2p_host_options_t *out)
{
    if (!in || !out)
        return LIBP2P_ERR_NULL_PTR;

    memset(out, 0, sizeof(*out));

    libp2p_host_options_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp = *in;
    tmp.listen_addrs = NULL;
    tmp.security_proposals = NULL;
    tmp.muxer_proposals = NULL;
    tmp.transport_names = NULL;

    int rc = duplicate_const_string_array(in->listen_addrs, in->num_listen_addrs, &tmp.listen_addrs);
    if (rc != 0)
        goto fail;
    rc = duplicate_const_string_array(in->security_proposals, in->num_security_proposals, &tmp.security_proposals);
    if (rc != 0)
        goto fail;
    rc = duplicate_const_string_array(in->muxer_proposals, in->num_muxer_proposals, &tmp.muxer_proposals);
    if (rc != 0)
        goto fail;
    rc = duplicate_const_string_array(in->transport_names, in->num_transport_names, &tmp.transport_names);
    if (rc != 0)
        goto fail;

    *out = tmp;
    return 0;

fail:
    free_const_string_array(&tmp.listen_addrs, &tmp.num_listen_addrs);
    free_const_string_array(&tmp.security_proposals, &tmp.num_security_proposals);
    free_const_string_array(&tmp.muxer_proposals, &tmp.num_muxer_proposals);
    free_const_string_array(&tmp.transport_names, &tmp.num_transport_names);
    return rc;
}

/* Select first transport that can_handle(addr). */
libp2p_transport_t *libp2p__host_select_transport(const libp2p_host_t *host, const multiaddr_t *addr)
{
    if (!host || !addr || !host->transports || host->num_transports == 0)
        return NULL;
    for (size_t i = 0; i < host->num_transports; i++)
    {
        libp2p_transport_t *t = host->transports[i];
        if (t && libp2p_transport_can_handle(t, addr))
            return t;
    }
    return NULL;
}

int libp2p_host_options_default(libp2p_host_options_t *out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    /* Allow more headroom under parallel load to reduce spurious timeouts */
    out->multiselect_handshake_timeout_ms = 15000;
    out->num_runtime_threads = 1;
    out->dial_timeout_ms = 10000;
    out->handshake_timeout_ms = 5000;
    out->multiselect_enable_ls = false;
    out->max_inbound_conns = 0;
    out->max_outbound_conns = 0;
    out->per_conn_max_inbound_streams = 0;
    out->per_conn_max_outbound_streams = 0;
    out->flags = LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND; /* default: outbound auto-identify only */
    return 0;
}

/* Lightweight helpers to track detached workers and signal waiters */
void libp2p__worker_inc(libp2p_host_t *host)
{
    if (!host)
        return;
    atomic_fetch_add(&host->worker_count, 1);
}

void libp2p__worker_dec(libp2p_host_t *host)
{
    if (!host)
        return;
    int newv = atomic_fetch_sub(&host->worker_count, 1) - 1;
    if (newv <= 0)
    {
        pthread_mutex_lock(&host->mtx);
        pthread_cond_broadcast(&host->worker_cv);
        pthread_mutex_unlock(&host->mtx);
    }
}

int libp2p_host_new(const libp2p_host_options_t *opts, libp2p_host_t **out)
{
    if (!opts || !out)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_component_registry_ensure_defaults();
    int component_err = 0;
    libp2p_host_t *h = (libp2p_host_t *)calloc(1, sizeof(*h));
    if (!h)
        return LIBP2P_ERR_INTERNAL;
    if (pthread_mutex_init(&h->mtx, NULL) != 0)
    {
        free(h);
        return LIBP2P_ERR_INTERNAL;
    }
    if (dup_opts(opts, &h->opts) != 0)
    {
        pthread_mutex_destroy(&h->mtx);
        free(h);
        return LIBP2P_ERR_INTERNAL;
    }

    if (pthread_cond_init(&h->evt_cv, NULL) != 0)
    {
        pthread_mutex_destroy(&h->mtx);
        free(h);
        return LIBP2P_ERR_INTERNAL;
    }
    if (pthread_cond_init(&h->worker_cv, NULL) != 0)
    {
        pthread_cond_destroy(&h->evt_cv);
        pthread_mutex_destroy(&h->mtx);
        free(h);
        return LIBP2P_ERR_INTERNAL;
    }
    atomic_init(&h->worker_count, 0);
    h->metrics = NULL;

    /* Start async event dispatcher */
    if (libp2p__event_dispatcher_start(h) != 0)
    {
        pthread_cond_destroy(&h->worker_cv);
        pthread_cond_destroy(&h->evt_cv);
        pthread_mutex_destroy(&h->mtx);
        free(h);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Start application callback executor (single-thread) */
    if (libp2p__cbexec_start(h) != 0)
    {
        libp2p__event_dispatcher_stop(h);
        pthread_cond_destroy(&h->worker_cv);
        pthread_cond_destroy(&h->evt_cv);
        pthread_mutex_destroy(&h->mtx);
        free(h);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Build transports list */
    {
        libp2p_transport_t **arr = NULL;
        size_t n = 0;
        int trans_rc = 0;
        if (h->opts.num_transport_names && h->opts.transport_names)
        {
            for (size_t i = 0; i < h->opts.num_transport_names; i++)
            {
                const char *name = h->opts.transport_names[i];
                if (!name)
                    continue;
                libp2p_transport_factory_fn factory = libp2p_component_lookup_transport(name);
                if (!factory)
                {
                    trans_rc = LIBP2P_ERR_UNSUPPORTED;
                    break;
                }
                libp2p_transport_t *t = NULL;
                trans_rc = factory(&h->opts, &t);
                if (trans_rc != 0 || !t)
                {
                    if (t)
                        libp2p_transport_free(t);
                    if (trans_rc == 0)
                        trans_rc = LIBP2P_ERR_INTERNAL;
                    break;
                }
                libp2p_transport_t **nb = realloc(arr, (n + 1) * sizeof(*arr));
                if (!nb)
                {
                    libp2p_transport_free(t);
                    trans_rc = LIBP2P_ERR_INTERNAL;
                    break;
                }
                arr = nb;
                arr[n++] = t;
            }
        }
        if (trans_rc == 0 && n == 0)
        {
            libp2p_transport_factory_fn factory = libp2p_component_lookup_transport("tcp");
            if (!factory)
                factory = libp2p_component_first_transport();
            if (factory)
            {
                libp2p_transport_t *t = NULL;
                trans_rc = factory(&h->opts, &t);
                if (trans_rc == 0 && t)
                {
                    arr = (libp2p_transport_t **)calloc(1, sizeof(*arr));
                    if (!arr)
                    {
                        libp2p_transport_free(t);
                        trans_rc = LIBP2P_ERR_INTERNAL;
                    }
                    else
                    {
                        arr[0] = t;
                        n = 1;
                    }
                }
                else if (trans_rc == 0)
                {
                    trans_rc = LIBP2P_ERR_INTERNAL;
                }
            }
            else
            {
                trans_rc = LIBP2P_ERR_UNSUPPORTED;
            }
        }
        if (trans_rc != 0)
        {
            if (arr)
            {
                for (size_t i = 0; i < n; i++)
                    libp2p_transport_free(arr[i]);
                free(arr);
            }
            component_err = trans_rc;
            goto components_fail;
        }
        h->transports = arr;
        h->num_transports = n;
    }

    /* Select security proposal */
    {
        libp2p_security_t *sec = NULL;
        int sec_rc = 0;
        if (h->opts.num_security_proposals && h->opts.security_proposals)
        {
            for (size_t i = 0; i < h->opts.num_security_proposals; i++)
            {
                const char *name = h->opts.security_proposals[i];
                if (!name)
                    continue;
                libp2p_security_factory_fn factory = libp2p_component_lookup_security(name);
                if (!factory)
                {
                    sec_rc = LIBP2P_ERR_UNSUPPORTED;
                    break;
                }
                sec_rc = factory(&h->opts, &sec);
                if (sec_rc == 0 && sec)
                    break;
                if (sec)
                {
                    libp2p_security_free(sec);
                    sec = NULL;
                }
                if (sec_rc != 0)
                    break;
            }
        }
        if (!sec && sec_rc == 0)
        {
            libp2p_security_factory_fn factory = libp2p_component_lookup_security("noise");
            if (!factory)
                factory = libp2p_component_first_security();
            if (factory)
                sec_rc = factory(&h->opts, &sec);
            else
                sec_rc = LIBP2P_ERR_UNSUPPORTED;
        }
        if (sec_rc != 0 || !sec)
        {
            if (sec)
                libp2p_security_free(sec);
            component_err = sec_rc != 0 ? sec_rc : LIBP2P_ERR_INTERNAL;
            goto components_fail;
        }
        h->noise = sec;
    }

    /* Select muxer */
    {
        libp2p_muxer_t *mx = NULL;
        int mx_rc = 0;
        if (h->opts.num_muxer_proposals && h->opts.muxer_proposals)
        {
            for (size_t i = 0; i < h->opts.num_muxer_proposals; i++)
            {
                const char *name = h->opts.muxer_proposals[i];
                if (!name)
                    continue;
                libp2p_muxer_factory_fn factory = libp2p_component_lookup_muxer(name);
                if (!factory)
                {
                    mx_rc = LIBP2P_ERR_UNSUPPORTED;
                    break;
                }
                mx_rc = factory(&h->opts, &mx);
                if (mx_rc == 0 && mx)
                    break;
                if (mx)
                {
                    libp2p_muxer_free(mx);
                    mx = NULL;
                }
                if (mx_rc != 0)
                    break;
            }
        }
        if (!mx && mx_rc == 0)
        {
            libp2p_muxer_factory_fn factory = libp2p_component_lookup_muxer("yamux");
            if (!factory)
                factory = libp2p_component_first_muxer();
            if (factory)
                mx_rc = factory(&h->opts, &mx);
            else
                mx_rc = LIBP2P_ERR_UNSUPPORTED;
        }
        if (mx_rc != 0 || !mx)
        {
            if (mx)
                libp2p_muxer_free(mx);
            component_err = mx_rc != 0 ? mx_rc : LIBP2P_ERR_INTERNAL;
            goto components_fail;
        }
        h->yamux = mx;
    }

    /* Resource manager removed for rust-libp2p parity */

    /* Default Peerstore */
    if (!h->peerstore)
    {
        h->peerstore = libp2p_peerstore_new();
    }

    /* Connection pool for QUIC session reuse (0 = unlimited, 300s idle timeout) */
    h->conn_pool = libp2p_conn_pool_new(0, 300);
    if (!h->conn_pool)
    {
        component_err = LIBP2P_ERR_INTERNAL;
        goto components_fail;
    }

    *out = h;
    /* Start Identify responder (/ipfs/id/1.0.0) and Push listener */
    (void)libp2p_identify_service_start(h, &h->identify_server);
    (void)libp2p_identify_push_service_start(h, &h->identify_push_server);
    /* Start lightweight publish service (Identify Push triggers) */
    (void)libp2p_publish_service_start(h);
    return 0;

components_fail:
    if (h->conn_pool)
        libp2p_conn_pool_free(h->conn_pool);
    if (h->yamux)
        libp2p_muxer_free(h->yamux);
    if (h->noise)
        libp2p_security_free(h->noise);
    if (h->transports)
    {
        for (size_t i = 0; i < h->num_transports; i++)
            libp2p_transport_free(h->transports[i]);
        free(h->transports);
        h->transports = NULL;
        h->num_transports = 0;
    }
    libp2p__cbexec_stop(h);
    libp2p__event_dispatcher_stop(h);
    pthread_cond_destroy(&h->worker_cv);
    pthread_cond_destroy(&h->evt_cv);
    pthread_mutex_destroy(&h->mtx);
    free(h);
    return component_err != 0 ? component_err : LIBP2P_ERR_INTERNAL;
}

int libp2p_host_new_default(const char *const *listen_addrs, size_t num_listen_addrs, libp2p_host_t **out)
{
    libp2p_host_options_t o;
    libp2p_host_options_default(&o);
    o.listen_addrs = listen_addrs;
    o.num_listen_addrs = num_listen_addrs;
    return libp2p_host_new(&o, out);
}

void libp2p_host_free(libp2p_host_t *host)
{
    if (!host)
        return;
    LP_LOGD("HOST_FREE", "begin host=%p", (void *)host);
    /* Wait for any detached workers to finish without polling. */
    pthread_mutex_lock(&host->mtx);
    while (atomic_load(&host->worker_count) > 0)
    {
        pthread_cond_wait(&host->worker_cv, &host->mtx);
    }
    pthread_mutex_unlock(&host->mtx);
    /* Stop async event dispatcher before freeing subscriptions/queues */
    libp2p__event_dispatcher_stop(host);
    /* Stop callback executor before tearing down */
    libp2p__cbexec_stop(host);
    /* Unregister Identify service before freeing protocol entries */
    if (host->identify_server)
    {
        (void)libp2p_identify_service_stop(host, host->identify_server);
        host->identify_server = NULL;
    }
    if (host->identify_push_server)
    {
        (void)libp2p_identify_push_service_stop(host, host->identify_push_server);
        host->identify_push_server = NULL;
    }
    /* Stop publish service */
    libp2p_publish_service_stop(host);
    /* Identify service is owned by protocol_identify module if started. */
    /* no ping counters to free */
    LP_LOGD("HOST_FREE", "freeing protocols");
    protocol_entry_t *it = host->protocols;
    while (it)
    {
        protocol_entry_t *nxt = it->next;
        free(it);
        it = nxt;
    }

    LP_LOGD("HOST_FREE", "freeing matchers");
    protocol_match_entry_t *mit = host->matchers;
    while (mit)
    {
        protocol_match_entry_t *nxt = mit->next;
        free(mit);
        mit = nxt;
    }

    LP_LOGD("HOST_FREE", "freeing subscriptions");
    /* Detach subscription list under lock to avoid races with subscribe/unsubscribe */
    pthread_mutex_lock(&host->mtx);
    struct libp2p_subscription *sub = host->subs;
    host->subs = NULL;
    pthread_mutex_unlock(&host->mtx);
    while (sub)
    {
        struct libp2p_subscription *next = sub->next;
        free(sub);
        sub = next;
    }

    LP_LOGD("HOST_FREE", "freeing event queue");
    /* Detach pending event queue under lock; free outside the lock */
    pthread_mutex_lock(&host->mtx);
    event_node_t *en = host->evt_head;
    host->evt_head = NULL;
    host->evt_tail = NULL;
    pthread_mutex_unlock(&host->mtx);
    while (en)
    {
        event_node_t *next = en->next;
        /* Free any deep-copied fields */
        libp2p_event_free(&en->evt);
        free(en);
        en = next;
    }
    LP_LOGD("HOST_FREE", "freeing yamux muxer");
    if (host->yamux)
        libp2p_muxer_free(host->yamux);
    LP_LOGD("HOST_FREE", "freeing noise security");
    if (host->noise)
        libp2p_security_free(host->noise);
    LP_LOGD("HOST_FREE", "freeing peerstore");
    if (host->peerstore)
        libp2p_peerstore_free(host->peerstore);
    /* free any remaining active stream entries */
    LP_LOGD("HOST_FREE", "freeing active_streams list");
    stream_entry_t *se = host->active_streams;
    while (se)
    {
        stream_entry_t *next = se->next;
        free(se);
        se = next;
    }
    /* no resource manager to free */
    if (host->conn_mgr)
        libp2p_conn_mgr_free(host->conn_mgr);
    /* Free connection pool */
    if (host->conn_pool)
    {
        libp2p_conn_pool_free(host->conn_pool);
        host->conn_pool = NULL;
    }
    /* free per-protocol server configs */
    LP_LOGD("HOST_FREE", "freeing proto_cfgs");
    proto_server_cfg_t *pc = host->proto_cfgs;
    while (pc)
    {
        proto_server_cfg_t *next = pc->next;
        if (pc->proto)
            free(pc->proto);
        free(pc);
        pc = next;
    }
    LP_LOGD("HOST_FREE", "freeing identity key");
    if (host->identity_key)
    {
        memset(host->identity_key, 0, host->identity_key_len);
        free(host->identity_key);
        host->identity_key = NULL;
        host->identity_key_len = 0;
    }
    if (host->have_identity && host->local_peer.bytes)
    {
        peer_id_destroy(&host->local_peer);
    }
    LP_LOGD("HOST_FREE", "freeing opts arrays");
    free_const_string_array(&host->opts.listen_addrs, &host->opts.num_listen_addrs);
    free_const_string_array(&host->opts.security_proposals, &host->opts.num_security_proposals);
    free_const_string_array(&host->opts.muxer_proposals, &host->opts.num_muxer_proposals);
    free_const_string_array(&host->opts.transport_names, &host->opts.num_transport_names);
    if (host->transports)
    {
        for (size_t i = 0; i < host->num_transports; i++)
            libp2p_transport_free(host->transports[i]);
        free(host->transports);
        host->transports = NULL;
        host->num_transports = 0;
    }
    LP_LOGD("HOST_FREE", "destroying sync primitives");
    pthread_cond_destroy(&host->evt_cv);
    pthread_cond_destroy(&host->worker_cv);
    /* disp_cv is destroyed in dispatcher_stop */
    pthread_mutex_destroy(&host->mtx);
    free(host);
    LP_LOGD("HOST_FREE", "end");
}

int libp2p_host_set_peerstore(libp2p_host_t *host, libp2p_peerstore_t *ps)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    host->peerstore = ps;
    return 0;
}

int libp2p_host_add_peer_addr(libp2p_host_t *host, const peer_id_t *peer, const multiaddr_t *addr, int ttl_ms)
{
    if (!host || !peer || !addr)
        return LIBP2P_ERR_NULL_PTR;
    if (!host->peerstore)
        host->peerstore = libp2p_peerstore_new();
    if (!host->peerstore)
        return LIBP2P_ERR_INTERNAL;
    return libp2p_peerstore_add_addr(host->peerstore, peer, addr, ttl_ms);
}

int libp2p_host_add_peer_addr_str(libp2p_host_t *host, const peer_id_t *peer, const char *multiaddr_str, int ttl_ms)
{
    if (!host || !peer || !multiaddr_str)
        return LIBP2P_ERR_NULL_PTR;
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str(multiaddr_str, &err);
    if (!ma)
        return LIBP2P_ERR_INTERNAL;
    int rc = libp2p_host_add_peer_addr(host, peer, ma, ttl_ms);
    multiaddr_free(ma);
    return rc;
}

int libp2p_host_set_conn_gater(libp2p_host_t *host, libp2p_conn_gater_fn fn, void *user_data)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    host->gater_fn = fn;
    host->gater_ud = user_data;
    return 0;
}

/* resource manager removed */

int libp2p_host_set_conn_manager(libp2p_host_t *host, libp2p_conn_mgr_t *cm)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    host->conn_mgr = cm;
    return 0;
}

int libp2p_host_set_metrics(libp2p_host_t *host, struct libp2p_metrics *m)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    host->metrics = (libp2p_metrics_t *)m;
    return 0;
}

int libp2p_host_set_private_key(libp2p_host_t *host, const uint8_t *privkey_pb, size_t privkey_len)
{
    if (!host || !privkey_pb || privkey_len == 0)
        return LIBP2P_ERR_NULL_PTR;

    uint64_t key_type = 0;
    const uint8_t *key_data = NULL;
    size_t key_data_len = 0;
    if (parse_private_key_proto(privkey_pb, privkey_len, &key_type, &key_data, &key_data_len) < 0)
        return LIBP2P_ERR_INTERNAL;

    pthread_mutex_lock(&host->mtx);

    if (host->identity_key)
    {
        memset(host->identity_key, 0, host->identity_key_len);
        free(host->identity_key);
        host->identity_key = NULL;
        host->identity_key_len = 0;
    }
    host->identity_key = (uint8_t *)malloc(key_data_len);
    if (!host->identity_key)
    {
        pthread_mutex_unlock(&host->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(host->identity_key, key_data, key_data_len);
    host->identity_key_len = key_data_len;
    host->identity_type = (int)key_type;

    if (host->have_identity && host->local_peer.bytes)
    {
        peer_id_destroy(&host->local_peer);
        host->local_peer.bytes = NULL;
        host->local_peer.size = 0;
    }
    peer_id_error_t perr = peer_id_create_from_private_key(privkey_pb, privkey_len, &host->local_peer);
    if (perr != PEER_ID_SUCCESS)
    {
        memset(host->identity_key, 0, host->identity_key_len);
        free(host->identity_key);
        host->identity_key = NULL;
        host->identity_key_len = 0;
        pthread_mutex_unlock(&host->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    host->have_identity = 1;

    if (host->noise)
    {
        libp2p_security_free(host->noise);
        host->noise = NULL;
    }
    libp2p_noise_config_t cfg = libp2p_noise_config_default();
    cfg.identity_private_key = host->identity_key;
   cfg.identity_private_key_len = host->identity_key_len;
   cfg.identity_key_type = host->identity_type;
   host->noise = libp2p_noise_security_new(&cfg);
   if (!host->noise)
   {
       pthread_mutex_unlock(&host->mtx);
       return LIBP2P_ERR_INTERNAL;
   }

    if (host->transports && host->num_transports > 0)
    {
        libp2p_quic_tls_cert_options_t qopts = libp2p_quic_tls_cert_options_default();
        qopts.identity_key_type = (uint64_t)host->identity_type;
        qopts.identity_key = host->identity_key;
        qopts.identity_key_len = host->identity_key_len;
        for (size_t i = 0; i < host->num_transports; i++)
        {
            if (libp2p_quic_transport_is(host->transports[i]))
                (void)libp2p_quic_transport_set_identity(host->transports[i], &qopts);
        }
    }

    pthread_mutex_unlock(&host->mtx);
    return 0;
}

int libp2p_host_get_peer_id(const libp2p_host_t *host, peer_id_t **out)
{
    if (!host || !out)
        return LIBP2P_ERR_NULL_PTR;
    if (!host->have_identity || !host->local_peer.bytes || host->local_peer.size == 0)
        return LIBP2P_ERR_INTERNAL;
    peer_id_t *dup = (peer_id_t *)calloc(1, sizeof(*dup));
    if (!dup)
        return LIBP2P_ERR_INTERNAL;
    dup->bytes = (uint8_t *)malloc(host->local_peer.size);
    if (!dup->bytes)
    {
        free(dup);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(dup->bytes, host->local_peer.bytes, host->local_peer.size);
    dup->size = host->local_peer.size;
    char pid_buf[128];
    if (peer_id_to_string(dup, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
        snprintf(pid_buf, sizeof(pid_buf), "<unknown>");
    LIBP2P_TRACE("idpush", "local peer id=%s", pid_buf);
    *out = dup;
    return 0;
}

int libp2p_host_peer_protocols(const libp2p_host_t *host, const peer_id_t *peer, const char ***out_protocols, size_t *out_len)
{
    if (!host || !out_protocols || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_protocols = NULL;
    *out_len = 0;

    if (!peer)
        return LIBP2P_ERR_NULL_PTR;
    if (!host->peerstore)
        return LIBP2P_ERR_INTERNAL;

    char pid_buf[128];
    if (peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
        strcpy(pid_buf, "<unknown>");

    int rc = libp2p_peerstore_get_protocols(host->peerstore, peer, out_protocols, out_len);
    if (rc != 0)
    {
        LIBP2P_TRACE("idpush", "peer_protocols query peer=%s rc=%d (error)", pid_buf, rc);
        return rc;
    }

    if (!out_len || *out_len == 0)
    {
        LIBP2P_TRACE("idpush", "peer_protocols query peer=%s rc=%d count=0 (defer)", pid_buf, LIBP2P_ERR_AGAIN);
        return LIBP2P_ERR_AGAIN;
    }

    LIBP2P_TRACE("idpush", "peer_protocols query peer=%s rc=0 count=%zu", pid_buf, *out_len);
    return 0;
}

void libp2p_host_free_peer_protocols(const char **protocols, size_t len) { libp2p_peerstore_free_protocols(protocols, len); }
/* One-shot timer thread: waits briefly, then runs async publisher inline */
static void *__libp2p__publisher_timer(void *arg) { (void)arg; return NULL; }
