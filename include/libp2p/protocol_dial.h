#ifndef LIBP2P_PROTOCOL_DIAL_H
#define LIBP2P_PROTOCOL_DIAL_H

#include <stdbool.h>
#include <stddef.h>

#include "libp2p/host.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    LIBP2P_PROTO_SELECT_EXACT,
    LIBP2P_PROTO_SELECT_LIST,
    LIBP2P_PROTO_SELECT_PREFIX,
    LIBP2P_PROTO_SELECT_SEMVER
} libp2p_proto_select_kind_t;

typedef struct
{
    libp2p_proto_select_kind_t kind;
    const char *exact_id;
    const char *const *id_list;
    size_t id_list_len;
    const char *prefix;
    const char *base_path;
    const char *semver_range;
} libp2p_proto_selector_t;

typedef struct
{
    size_t struct_size;
    int handshake_timeout_ms;
    bool prefer_ls_probe;
    int max_attempts;
    bool allow_reuse_existing_stream;
} libp2p_proto_dial_opts_t;

int libp2p_host_dial_selected(libp2p_host_t *host, const char *remote_multiaddr, const libp2p_proto_selector_t *selector,
                              const libp2p_proto_dial_opts_t *opts, libp2p_on_stream_open_fn on_open, void *user_data);

int libp2p_host_dial_selected_blocking(libp2p_host_t *host, const char *remote_multiaddr, const libp2p_proto_selector_t *selector, int timeout_ms,
                                       libp2p_stream_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_DIAL_H */
