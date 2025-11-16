#ifndef LIBP2P_COMPONENT_REGISTRY_H
#define LIBP2P_COMPONENT_REGISTRY_H

#include <stddef.h>

#include "libp2p/errors.h"
#include "libp2p/host.h"
#include "libp2p/muxer.h"
#include "libp2p/security.h"
#include "libp2p/transport.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef int (*libp2p_transport_factory_fn)(const libp2p_host_options_t *opts, libp2p_transport_t **out);
typedef int (*libp2p_security_factory_fn)(const libp2p_host_options_t *opts, libp2p_security_t **out);
typedef int (*libp2p_muxer_factory_fn)(const libp2p_host_options_t *opts, libp2p_muxer_t **out);

int libp2p_component_register_transport(const char *name, libp2p_transport_factory_fn fn);
int libp2p_component_register_security(const char *name, libp2p_security_factory_fn fn);
int libp2p_component_register_muxer(const char *name, libp2p_muxer_factory_fn fn);

libp2p_transport_factory_fn libp2p_component_lookup_transport(const char *name);
libp2p_security_factory_fn libp2p_component_lookup_security(const char *name);
libp2p_muxer_factory_fn libp2p_component_lookup_muxer(const char *name);

libp2p_transport_factory_fn libp2p_component_first_transport(void);
libp2p_security_factory_fn libp2p_component_first_security(void);
libp2p_muxer_factory_fn libp2p_component_first_muxer(void);

void libp2p_component_registry_ensure_defaults(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_COMPONENT_REGISTRY_H */
