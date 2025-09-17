#ifndef LIBP2P_IDENTIFY_PUBLIC_H
#define LIBP2P_IDENTIFY_PUBLIC_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/host.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Opaque Identify service/controller handle */
typedef struct libp2p_identify_service libp2p_identify_service_t;

typedef struct
{
    size_t struct_size;
    int push_enabled;             /* reserved; push is auto-wired by host */
    uint64_t refresh_interval_ms; /* reserved */
} libp2p_identify_opts_t;

/* Create a new Identify controller bound to `host`. Options are currently
 * advisory; push publication is managed by the host. */
int libp2p_identify_new(libp2p_host_t *host, const libp2p_identify_opts_t *opts, libp2p_identify_service_t **out);

/* Free the Identify controller. */
void libp2p_identify_ctrl_free(libp2p_identify_service_t *id);

/* Send an Identify request to `peer` using addresses from the host peerstore.
 * On success, updates the peerstore entries for public key, listen addrs and
 * supported protocols. Returns 0 on success, negative error otherwise. */
int libp2p_identify_request(libp2p_identify_service_t *id, const peer_id_t *peer);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_IDENTIFY_PUBLIC_H */
