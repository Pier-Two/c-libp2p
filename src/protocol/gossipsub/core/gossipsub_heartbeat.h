#ifndef LIBP2P_GOSSIPSUB_HEARTBEAT_H
#define LIBP2P_GOSSIPSUB_HEARTBEAT_H

#include "gossipsub_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

void gossipsub_heartbeat_run(libp2p_gossipsub_t *gs);
void gossipsub_heartbeat_tick(libp2p_gossipsub_t *gs, uint64_t now_ms);
void gossipsub_opportunistic_run(libp2p_gossipsub_t *gs);
void gossipsub_opportunistic_tick(libp2p_gossipsub_t *gs, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_HEARTBEAT_H */
