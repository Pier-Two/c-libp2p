#ifndef LIBP2P_PROTO_SELECT_INTERNAL_H
#define LIBP2P_PROTO_SELECT_INTERNAL_H

#include <stddef.h>

#include "host_internal.h"
#include "libp2p/protocol_dial.h"

typedef struct version_triplet
{
    int major;
    int minor;
    int patch;
} version_triplet_t;

typedef struct semver_range
{
    int has_low;
    version_triplet_t low; /* inclusive */
    int has_high;
    version_triplet_t high; /* exclusive */
    int exact;
    version_triplet_t exact_v;
} semver_range_t;

int parse_version_triplet(const char *s, version_triplet_t *out);
int extract_version_from_id(const char *protocol_id, const char *base_path, version_triplet_t *out);
int parse_semver_range(const char *pattern, semver_range_t *out);
int semver_in_range(const version_triplet_t *v, const semver_range_t *r);

int build_prefix_candidates(libp2p_host_t *host, const char *prefix, const char ***out_list, size_t *out_len);
int build_semver_candidates(libp2p_host_t *host, const char *base_path, const char *range_pattern, const char ***out_list, size_t *out_len);

int build_proposals_from_selector(libp2p_host_t *host, const libp2p_proto_selector_t *sel, const char ***out_list, size_t *out_len, int *out_dynamic);

#endif /* LIBP2P_PROTO_SELECT_INTERNAL_H */
