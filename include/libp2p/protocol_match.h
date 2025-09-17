#ifndef LIBP2P_PROTOCOL_MATCH_H
#define LIBP2P_PROTOCOL_MATCH_H

#include <stddef.h>

#include "libp2p/protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    LIBP2P_PROTO_MATCH_EXACT,
    LIBP2P_PROTO_MATCH_PREFIX,
    LIBP2P_PROTO_MATCH_SEMVER
} libp2p_proto_match_kind_t;

typedef struct
{
    libp2p_proto_match_kind_t kind;
    const char *pattern;
    /* For LIBP2P_PROTO_MATCH_SEMVER, constrain matches to this base path.
       Example: base_path = "/mystuff/" and pattern = "^1" */
    const char *base_path;
} libp2p_protocol_matcher_t;

int libp2p_register_protocol_match(struct libp2p_host *host, const libp2p_protocol_matcher_t *matcher, const libp2p_protocol_def_t *def);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_MATCH_H */
