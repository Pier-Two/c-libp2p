#ifndef LIBP2P_GOSSIPSUB_PROPAGATION_H
#define LIBP2P_GOSSIPSUB_PROPAGATION_H

#include "gossipsub_internal.h"
#include "gossipsub_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

void gossipsub_propagation_propagate_frame(libp2p_gossipsub_t *gs,
                                           gossipsub_topic_state_t *topic,
                                           const peer_id_t *exclude_peer,
                                           const uint8_t *frame,
                                           size_t frame_len);

libp2p_err_t gossipsub_propagation_handle_inbound_publish(libp2p_gossipsub_t *gs,
                                                          gossipsub_peer_entry_t *entry,
                                                          libp2p_gossipsub_Message *proto_msg,
                                                          const uint8_t *frame,
                                                          size_t frame_len);

void gossipsub_propagation_emit_gossip_locked(libp2p_gossipsub_t *gs,
                                              gossipsub_topic_state_t *topic,
                                              uint64_t gossip_round);

void gossipsub_propagation_try_connect_px(libp2p_gossipsub_t *gs,
                                          gossipsub_peer_entry_t *entry);

void gossipsub_propagation_try_connect_peer(libp2p_gossipsub_t *gs,
                                            const peer_id_t *peer);

uint64_t gossipsub_propagation_backoff_seconds(const libp2p_gossipsub_t *gs);

uint64_t gossipsub_propagation_compute_backoff_expiry(uint64_t now_ms, uint64_t backoff_ms);

void gossipsub_prune_target_free(gossipsub_prune_target_t *target);

libp2p_err_t gossipsub_propagation_handle_subscriptions(libp2p_gossipsub_t *gs,
                                                         gossipsub_peer_entry_t *entry,
                                                         gossipsub_rpc_subscription_t *subs,
                                                         size_t count);

libp2p_err_t gossipsub_propagation_handle_control_ihave(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_ihave_t *ihaves,
                                                        size_t count);

libp2p_err_t gossipsub_propagation_handle_control_iwant(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_iwant_t *iwants,
                                                        size_t count);

libp2p_err_t gossipsub_propagation_handle_control_graft(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_graft_t *grafts,
                                                        size_t count);

libp2p_err_t gossipsub_propagation_handle_control_prune(libp2p_gossipsub_t *gs,
                                                        gossipsub_peer_entry_t *entry,
                                                        const gossipsub_rpc_control_prune_t *prunes,
                                                        size_t count);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_PROPAGATION_H */
