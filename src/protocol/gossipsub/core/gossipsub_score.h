#ifndef LIBP2P_GOSSIPSUB_SCORE_H
#define LIBP2P_GOSSIPSUB_SCORE_H

#include "gossipsub_internal.h"

void gossipsub_score_init(libp2p_gossipsub_t *gs);
void gossipsub_score_deinit(libp2p_gossipsub_t *gs);
void gossipsub_score_on_mesh_join_locked(libp2p_gossipsub_t *gs,
                                         gossipsub_topic_state_t *topic,
                                         gossipsub_peer_entry_t *entry,
                                         uint64_t now_ms);
void gossipsub_score_on_mesh_leave_locked(libp2p_gossipsub_t *gs,
                                          gossipsub_topic_state_t *topic,
                                          const peer_id_t *peer,
                                          uint64_t now_ms);
void gossipsub_score_on_prune_negative_locked(libp2p_gossipsub_t *gs,
                                              gossipsub_topic_state_t *topic,
                                              gossipsub_peer_entry_t *entry,
                                              uint64_t now_ms);
void gossipsub_score_on_peer_removed_locked(libp2p_gossipsub_t *gs,
                                            gossipsub_peer_entry_t *entry);
void gossipsub_score_on_topic_unsubscribe_locked(libp2p_gossipsub_t *gs,
                                                 gossipsub_peer_entry_t *entry,
                                                 const char *topic_name);
void gossipsub_score_on_heartbeat_locked(libp2p_gossipsub_t *gs,
                                         uint64_t now_ms);
void gossipsub_score_on_first_delivery_locked(libp2p_gossipsub_t *gs,
                                              gossipsub_topic_state_t *topic,
                                              gossipsub_peer_entry_t *entry,
                                              int mesh_delivery,
                                              uint64_t now_ms);
void gossipsub_score_on_invalid_message_locked(libp2p_gossipsub_t *gs,
                                               gossipsub_topic_state_t *topic,
                                               gossipsub_peer_entry_t *entry,
                                               uint64_t now_ms);
void gossipsub_score_start_timer(libp2p_gossipsub_t *gs);
void gossipsub_score_stop_timer(libp2p_gossipsub_t *gs);
void gossipsub_score_recompute_peer_locked(libp2p_gossipsub_t *gs,
                                           gossipsub_peer_entry_t *entry,
                                           uint64_t now_ms);
void gossipsub_score_emit_update_locked(libp2p_gossipsub_t *gs,
                                        gossipsub_peer_entry_t *entry);

#endif /* LIBP2P_GOSSIPSUB_SCORE_H */
