#ifndef LIBP2P_HOST_BUILDER_H
#define LIBP2P_HOST_BUILDER_H

#include "libp2p/host.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_host_builder libp2p_host_builder_t;

libp2p_host_builder_t *libp2p_host_builder_new(void);
void libp2p_host_builder_free(libp2p_host_builder_t *b);

int libp2p_host_builder_listen_addr(libp2p_host_builder_t *b, const char *maddr);
int libp2p_host_builder_transport(libp2p_host_builder_t *b, const char *name);
int libp2p_host_builder_security(libp2p_host_builder_t *b, const char *name);
int libp2p_host_builder_muxer(libp2p_host_builder_t *b, const char *name);
int libp2p_host_builder_threads(libp2p_host_builder_t *b, int num_threads);
int libp2p_host_builder_multistream(libp2p_host_builder_t *b, int handshake_timeout_ms, bool enable_ls);
int libp2p_host_builder_flags(libp2p_host_builder_t *b, uint32_t flags);

/* Limits & policies (optional) */
int libp2p_host_builder_max_conns(libp2p_host_builder_t *b, int inbound, int outbound);
int libp2p_host_builder_per_conn_stream_caps(libp2p_host_builder_t *b, int inbound, int outbound);
int libp2p_host_builder_conn_manager(libp2p_host_builder_t *b, int low_water, int high_water, int grace_ms);

int libp2p_host_builder_build(const libp2p_host_builder_t *b, libp2p_host_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_HOST_BUILDER_H */
