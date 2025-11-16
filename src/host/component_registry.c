#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libp2p/component_registry.h"
#include "libp2p/muxer_mplex.h"
#include "libp2p/muxer_yamux.h"
#include "libp2p/security_noise.h"
#include "protocol/quic/protocol_quic.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/tcp/protocol_tcp_poller.h"

typedef struct component_entry
{
    char *name;
    void *factory;
    struct component_entry *next;
} component_entry_t;

typedef struct component_registry
{
    component_entry_t *head;
    pthread_mutex_t lock;
} component_registry_t;

static component_registry_t g_transport_registry = {NULL, PTHREAD_MUTEX_INITIALIZER};
static component_registry_t g_security_registry = {NULL, PTHREAD_MUTEX_INITIALIZER};
static component_registry_t g_muxer_registry = {NULL, PTHREAD_MUTEX_INITIALIZER};

static int registry_upsert(component_registry_t *registry, const char *name, void *factory)
{
    if (!registry || !name || !factory)
        return LIBP2P_ERR_NULL_PTR;
    component_entry_t *entry = NULL;
    pthread_mutex_lock(&registry->lock);
    for (component_entry_t *it = registry->head; it; it = it->next)
    {
        if (strcmp(it->name, name) == 0)
        {
            entry = it;
            break;
        }
    }
    if (entry)
    {
        entry->factory = factory;
        pthread_mutex_unlock(&registry->lock);
        return 0;
    }
    entry = (component_entry_t *)calloc(1, sizeof(*entry));
    if (!entry)
    {
        pthread_mutex_unlock(&registry->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->name = strdup(name);
    if (!entry->name)
    {
        free(entry);
        pthread_mutex_unlock(&registry->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    entry->factory = factory;
    entry->next = registry->head;
    registry->head = entry;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

static void *registry_lookup(component_registry_t *registry, const char *name)
{
    if (!registry || !name)
        return NULL;
    void *factory = NULL;
    pthread_mutex_lock(&registry->lock);
    for (component_entry_t *it = registry->head; it; it = it->next)
    {
        if (strcmp(it->name, name) == 0)
        {
            factory = it->factory;
            break;
        }
    }
    pthread_mutex_unlock(&registry->lock);
    return factory;
}

static void *registry_first(component_registry_t *registry)
{
    if (!registry)
        return NULL;
    void *factory = NULL;
    pthread_mutex_lock(&registry->lock);
    if (registry->head)
        factory = registry->head->factory;
    pthread_mutex_unlock(&registry->lock);
    return factory;
}

int libp2p_component_register_transport(const char *name, libp2p_transport_factory_fn fn)
{
    return registry_upsert(&g_transport_registry, name, (void *)fn);
}

int libp2p_component_register_security(const char *name, libp2p_security_factory_fn fn)
{
    return registry_upsert(&g_security_registry, name, (void *)fn);
}

int libp2p_component_register_muxer(const char *name, libp2p_muxer_factory_fn fn)
{
    return registry_upsert(&g_muxer_registry, name, (void *)fn);
}

libp2p_transport_factory_fn libp2p_component_lookup_transport(const char *name)
{
    libp2p_component_registry_ensure_defaults();
    return (libp2p_transport_factory_fn)registry_lookup(&g_transport_registry, name);
}

libp2p_security_factory_fn libp2p_component_lookup_security(const char *name)
{
    libp2p_component_registry_ensure_defaults();
    return (libp2p_security_factory_fn)registry_lookup(&g_security_registry, name);
}

libp2p_muxer_factory_fn libp2p_component_lookup_muxer(const char *name)
{
    libp2p_component_registry_ensure_defaults();
    return (libp2p_muxer_factory_fn)registry_lookup(&g_muxer_registry, name);
}

libp2p_transport_factory_fn libp2p_component_first_transport(void)
{
    libp2p_component_registry_ensure_defaults();
    return (libp2p_transport_factory_fn)registry_first(&g_transport_registry);
}

libp2p_security_factory_fn libp2p_component_first_security(void)
{
    libp2p_component_registry_ensure_defaults();
    return (libp2p_security_factory_fn)registry_first(&g_security_registry);
}

libp2p_muxer_factory_fn libp2p_component_first_muxer(void)
{
    libp2p_component_registry_ensure_defaults();
    return (libp2p_muxer_factory_fn)registry_first(&g_muxer_registry);
}

/* --- Built-in component registration ------------------------------------ */

static int tcp_transport_factory(const libp2p_host_options_t *opts, libp2p_transport_t **out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    if (libp2p_transport_tcp(out) != 0 || !*out)
        return LIBP2P_ERR_INTERNAL;
    if (!opts || !*out || !(*out)->ctx)
        return 0;
    tcp_transport_ctx_t *tcpctx = (tcp_transport_ctx_t *)(*out)->ctx;
    if (opts->dial_timeout_ms > 0)
        tcpctx->cfg.connect_timeout_ms = (uint32_t)opts->dial_timeout_ms;
    return 0;
}

static int quic_transport_factory(const libp2p_host_options_t *opts, libp2p_transport_t **out)
{
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    if (libp2p_transport_quic(out) != 0 || !*out)
        return LIBP2P_ERR_INTERNAL;
    if (opts && opts->dial_timeout_ms > 0)
        (void)libp2p_quic_transport_set_dial_timeout(*out, (uint32_t)opts->dial_timeout_ms);
    return 0;
}

static int noise_security_factory(const libp2p_host_options_t *opts, libp2p_security_t **out)
{
    (void)opts;
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    if (libp2p_security_noise(out) != 0 || !*out)
        return LIBP2P_ERR_INTERNAL;
    return 0;
}

static int yamux_muxer_factory(const libp2p_host_options_t *opts, libp2p_muxer_t **out)
{
    (void)opts;
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    if (libp2p_muxer_yamux(out) != 0 || !*out)
        return LIBP2P_ERR_INTERNAL;
    return 0;
}

static int mplex_muxer_factory(const libp2p_host_options_t *opts, libp2p_muxer_t **out)
{
    (void)opts;
    if (!out)
        return LIBP2P_ERR_NULL_PTR;
    if (libp2p_muxer_mplex(out) != 0 || !*out)
        return LIBP2P_ERR_INTERNAL;
    return 0;
}

static pthread_once_t g_registry_once = PTHREAD_ONCE_INIT;

static void register_builtin_components(void)
{
    (void)libp2p_component_register_transport("tcp", tcp_transport_factory);
    (void)libp2p_component_register_transport("quic", quic_transport_factory);
    (void)libp2p_component_register_security("noise", noise_security_factory);
    (void)libp2p_component_register_muxer("yamux", yamux_muxer_factory);
    (void)libp2p_component_register_muxer("mplex", mplex_muxer_factory);
}

void libp2p_component_registry_ensure_defaults(void)
{
    pthread_once(&g_registry_once, register_builtin_components);
}
