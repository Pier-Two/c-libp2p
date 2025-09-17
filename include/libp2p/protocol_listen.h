#ifndef LIBP2P_PROTOCOL_LISTEN_H
#define LIBP2P_PROTOCOL_LISTEN_H

#include <stdbool.h>
#include <stddef.h>

#include "libp2p/protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_protocol_server libp2p_protocol_server_t;

typedef enum
{
    LIBP2P_PROTO_LISTEN_EXACT,
    LIBP2P_PROTO_LISTEN_LIST,
    LIBP2P_PROTO_LISTEN_PREFIX,
    LIBP2P_PROTO_LISTEN_SEMVER
} libp2p_proto_listen_kind_t;

typedef struct
{
    libp2p_proto_listen_kind_t kind;
    const char *exact_id;
    const char *const *id_list;
    size_t id_list_len;
    const char *prefix;
    const char *base_path;
    const char *semver_range;
} libp2p_proto_listener_t;

typedef struct
{
    size_t struct_size;
    libp2p_read_mode_t read_mode;
    int max_concurrent_streams_total;
    int max_concurrent_streams_per_peer;
    size_t max_inflight_application_bytes;
    int handshake_timeout_ms;
    bool require_identified_peer;
} libp2p_protocol_server_opts_t;

int libp2p_host_listen_selected(struct libp2p_host *host, const libp2p_proto_listener_t *listener, const libp2p_protocol_def_t *def,
                                const libp2p_protocol_server_opts_t *opts, libp2p_protocol_server_t **out_server);

void libp2p_protocol_server_free(libp2p_protocol_server_t *s);
int libp2p_host_unlisten(struct libp2p_host *host, libp2p_protocol_server_t *s);
int libp2p_host_listen_protocol(struct libp2p_host *host, const libp2p_protocol_def_t *def, libp2p_protocol_server_t **out_server);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_LISTEN_H */
