#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "host_internal.h"
#include <stdio.h>
#include "libp2p/lpmsg.h"
#include "libp2p/protocol_listen.h"
#include "protocol/identify/protocol_identify.h"

static void publish_local_protocols_updated(libp2p_host_t *host, bool schedule_push)
{
    if (!host)
        return;
    libp2p_event_t evt = {0};
    evt.kind = LIBP2P_EVT_LOCAL_PROTOCOLS_UPDATED;
    libp2p_event_publish(host, &evt);
    if (schedule_push)
    {
        /* Proactively schedule async publisher for resilience */
        libp2p__schedule_identify_push(host);
    }
}

int libp2p_register_protocol(struct libp2p_host *host, const libp2p_protocol_def_t *def)
{
    if (!host || !def || !def->protocol_id)
        return LIBP2P_ERR_NULL_PTR;
    protocol_entry_t *e = (protocol_entry_t *)calloc(1, sizeof(*e));
    if (!e)
        return LIBP2P_ERR_INTERNAL;
    e->def = *def;
    pthread_mutex_lock(&host->mtx);
    e->next = host->protocols;
    host->protocols = e;
    pthread_mutex_unlock(&host->mtx);
    publish_local_protocols_updated(host, true);
    return 0;
}

int libp2p_unregister_protocol(struct libp2p_host *host, const char *protocol_id)
{
    if (!host || !protocol_id)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&host->mtx);
    protocol_entry_t **pp = &host->protocols;
    while (*pp)
    {
        if ((*pp)->def.protocol_id && strcmp((*pp)->def.protocol_id, protocol_id) == 0)
        {
            protocol_entry_t *victim = *pp;
            *pp = victim->next;
            free(victim);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&host->mtx);
    publish_local_protocols_updated(host, false);
    return 0;
}

int libp2p_register_protocol_match(struct libp2p_host *host, const libp2p_protocol_matcher_t *matcher, const libp2p_protocol_def_t *def)
{
    if (!host || !matcher || !def)
        return LIBP2P_ERR_NULL_PTR;
    protocol_match_entry_t *e = (protocol_match_entry_t *)calloc(1, sizeof(*e));
    if (!e)
        return LIBP2P_ERR_INTERNAL;
    e->matcher = *matcher;
    e->def = *def;
    pthread_mutex_lock(&host->mtx);
    e->next = host->matchers;
    host->matchers = e;
    pthread_mutex_unlock(&host->mtx);
    return 0;
}

static protocol_entry_t *register_entry_node(libp2p_host_t *host, const libp2p_protocol_def_t *def)
{
    protocol_entry_t *e = (protocol_entry_t *)calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->def = *def;
    pthread_mutex_lock(&host->mtx);
    e->next = host->protocols;
    host->protocols = e;
    pthread_mutex_unlock(&host->mtx);
    return e;
}

static void remove_entry_node(libp2p_host_t *host, protocol_entry_t *node)
{
    if (!host || !node)
        return;
    pthread_mutex_lock(&host->mtx);
    protocol_entry_t **pp = &host->protocols;
    while (*pp)
    {
        if (*pp == node)
        {
            protocol_entry_t *victim = *pp;
            *pp = victim->next;
            free(victim);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&host->mtx);
}

static void remove_match_entry_node(libp2p_host_t *host, protocol_match_entry_t *node)
{
    if (!host || !node)
        return;
    pthread_mutex_lock(&host->mtx);
    protocol_match_entry_t **pp = &host->matchers;
    while (*pp)
    {
        if (*pp == node)
        {
            protocol_match_entry_t *victim = *pp;
            *pp = victim->next;
            free(victim);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&host->mtx);
}

struct libp2p_protocol_server
{
    protocol_entry_t **entries;
    size_t num_entries;
    protocol_match_entry_t **match_entries;
    size_t num_match_entries;
};

/* Internal helpers to manage per-protocol server option overrides */
static proto_server_cfg_t *find_proto_cfg(libp2p_host_t *host, const char *proto)
{
    if (!host || !proto)
        return NULL;
    for (proto_server_cfg_t *it = host->proto_cfgs; it; it = it->next)
        if (it->proto && strcmp(it->proto, proto) == 0)
            return it;
    return NULL;
}

static int set_proto_cfg(libp2p_host_t *host, const char *proto, const libp2p_protocol_server_opts_t *opts)
{
    if (!host || !proto || !opts || opts->struct_size != sizeof(libp2p_protocol_server_opts_t))
        return 0; /* nothing to set */
    proto_server_cfg_t *cfg = find_proto_cfg(host, proto);
    if (!cfg)
    {
        cfg = (proto_server_cfg_t *)calloc(1, sizeof(*cfg));
        if (!cfg)
            return -1;
        cfg->proto = strdup(proto);
        if (!cfg->proto)
        {
            free(cfg);
            return -1;
        }
        cfg->next = host->proto_cfgs;
        host->proto_cfgs = cfg;
    }
    cfg->handshake_timeout_ms = opts->handshake_timeout_ms;
    cfg->max_inflight_application_bytes = opts->max_inflight_application_bytes;
    cfg->require_identified_peer = opts->require_identified_peer ? 1 : 0;
    return 0;
}

static void remove_proto_cfg(libp2p_host_t *host, const char *proto)
{
    if (!host || !proto)
        return;
    proto_server_cfg_t **pp = &host->proto_cfgs;
    while (*pp)
    {
        if ((*pp)->proto && strcmp((*pp)->proto, proto) == 0)
        {
            proto_server_cfg_t *victim = *pp;
            *pp = victim->next;
            free(victim->proto);
            free(victim);
            break;
        }
        pp = &(*pp)->next;
    }
}

int libp2p_host_listen_selected(struct libp2p_host *host, const libp2p_proto_listener_t *listener, const libp2p_protocol_def_t *def,
                                const libp2p_protocol_server_opts_t *opts, libp2p_protocol_server_t **out_server)
{
    if (!host || !listener || !def || !out_server)
        return LIBP2P_ERR_NULL_PTR;

    /* Strict validation: if options are provided, the caller must set
     * opts->struct_size to exactly sizeof(libp2p_protocol_server_opts_t).
     * This prevents accidental partial overrides when the struct grows. */
    if (opts && opts->struct_size != sizeof(libp2p_protocol_server_opts_t))
        return LIBP2P_ERR_UNSUPPORTED;

    libp2p_protocol_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv)
        return LIBP2P_ERR_INTERNAL;

    switch (listener->kind)
    {
        case LIBP2P_PROTO_LISTEN_EXACT:
        {
            if (!listener->exact_id)
            {
                free(srv);
                return LIBP2P_ERR_NULL_PTR;
            }
            libp2p_protocol_def_t d = *def;
            if (opts && opts->struct_size == sizeof(libp2p_protocol_server_opts_t))
                d.read_mode = opts->read_mode;
            d.protocol_id = listener->exact_id;
            protocol_entry_t *e = register_entry_node(host, &d);
            if (!e)
            {
                free(srv);
                return LIBP2P_ERR_INTERNAL;
            }
            /* Track server option overrides (resource manager removed) */
            if (opts && opts->struct_size == sizeof(libp2p_protocol_server_opts_t))
                (void)set_proto_cfg(host, listener->exact_id, opts);
            srv->entries = calloc(1, sizeof(*srv->entries));
            if (!srv->entries)
            {
                remove_entry_node(host, e);
                free(srv);
                return LIBP2P_ERR_INTERNAL;
            }
            srv->entries[0] = e;
            srv->num_entries = 1;
            break;
        }
        case LIBP2P_PROTO_LISTEN_LIST:
        {
            if (!listener->id_list || listener->id_list_len == 0)
            {
                free(srv);
                return LIBP2P_ERR_NULL_PTR;
            }
            srv->entries = calloc(listener->id_list_len, sizeof(*srv->entries));
            if (!srv->entries)
            {
                free(srv);
                return LIBP2P_ERR_INTERNAL;
            }
            for (size_t i = 0; i < listener->id_list_len; i++)
            {
                libp2p_protocol_def_t d = *def;
                if (opts && opts->struct_size == sizeof(libp2p_protocol_server_opts_t))
                    d.read_mode = opts->read_mode;
                d.protocol_id = listener->id_list[i];
                protocol_entry_t *e = register_entry_node(host, &d);
                if (!e)
                {
                    for (size_t j = 0; j < i; j++)
                        remove_entry_node(host, srv->entries[j]);
                    free(srv->entries);
                    free(srv);
                    return LIBP2P_ERR_INTERNAL;
                }
                srv->entries[i] = e;
                /* Track per-protocol options (resource manager removed) */
                if (opts && opts->struct_size == sizeof(libp2p_protocol_server_opts_t))
                    (void)set_proto_cfg(host, listener->id_list[i], opts);
            }
            srv->num_entries = listener->id_list_len;
            break;
        }
        case LIBP2P_PROTO_LISTEN_PREFIX:
        {
            if (!listener->prefix)
            {
                free(srv);
                return LIBP2P_ERR_NULL_PTR;
            }
            libp2p_protocol_matcher_t m = {
                .kind = LIBP2P_PROTO_MATCH_PREFIX,
                .pattern = listener->prefix,
            };
            srv->match_entries = calloc(1, sizeof(*srv->match_entries));
            if (!srv->match_entries)
            {
                free(srv);
                return LIBP2P_ERR_INTERNAL;
            }
            libp2p_protocol_def_t d = *def;
            if (opts && opts->struct_size == sizeof(libp2p_protocol_server_opts_t))
                d.read_mode = opts->read_mode;
            int rc = libp2p_register_protocol_match(host, &m, &d);
            if (rc != 0)
            {
                free(srv->match_entries);
                free(srv);
                return rc;
            }
            srv->match_entries[0] = host->matchers;
            srv->num_match_entries = 1;
            break;
        }
        case LIBP2P_PROTO_LISTEN_SEMVER:
        {
            if (!listener->base_path || !listener->semver_range)
            {
                free(srv);
                return LIBP2P_ERR_NULL_PTR;
            }
            libp2p_protocol_matcher_t m = {
                .kind = LIBP2P_PROTO_MATCH_SEMVER,
                .pattern = listener->semver_range,
                .base_path = listener->base_path,
            };
            srv->match_entries = calloc(1, sizeof(*srv->match_entries));
            if (!srv->match_entries)
            {
                free(srv);
                return LIBP2P_ERR_INTERNAL;
            }
            libp2p_protocol_def_t d = *def;
            if (opts && opts->struct_size == sizeof(libp2p_protocol_server_opts_t))
                d.read_mode = opts->read_mode;
            int rc = libp2p_register_protocol_match(host, &m, &d);
            if (rc != 0)
            {
                free(srv->match_entries);
                free(srv);
                return rc;
            }
            srv->match_entries[0] = host->matchers;
            srv->num_match_entries = 1;
            break;
        }
        default:
            free(srv);
            return LIBP2P_ERR_UNSUPPORTED;
    }

    /* Notify that local protocols have changed so Identify can update peers */
    publish_local_protocols_updated(host, true);

    *out_server = srv;
    return 0;
}

void libp2p_protocol_server_free(libp2p_protocol_server_t *s)
{
    if (!s)
        return;
    free(s->entries);
    free(s->match_entries);
    free(s);
}

int libp2p_host_unlisten(struct libp2p_host *host, libp2p_protocol_server_t *s)
{
    if (!host || !s)
        return LIBP2P_ERR_NULL_PTR;
    for (size_t i = 0; i < s->num_entries; i++)
    {
        /* Remove registered per-protocol overrides */
        if (s->entries[i] && s->entries[i]->def.protocol_id)
            remove_proto_cfg(host, s->entries[i]->def.protocol_id);
        remove_entry_node(host, s->entries[i]);
    }
    for (size_t i = 0; i < s->num_match_entries; i++)
        remove_match_entry_node(host, s->match_entries[i]);
    libp2p_protocol_server_free(s);
    /* Notify that local protocols have changed (protocol removed) */
    publish_local_protocols_updated(host, false);
    return 0;
}

int libp2p_host_listen_protocol(struct libp2p_host *host, const libp2p_protocol_def_t *def, libp2p_protocol_server_t **out_server)
{
    if (!host || !def || !out_server)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_proto_listener_t l = {
        .kind = LIBP2P_PROTO_LISTEN_EXACT,
        .exact_id = def->protocol_id,
        .id_list = NULL,
        .id_list_len = 0,
        .prefix = NULL,
        .base_path = NULL,
        .semver_range = NULL,
    };
    return libp2p_host_listen_selected(host, &l, def, NULL, out_server);
}
