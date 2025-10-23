#ifndef LIBP2P_GOSSIPSUB_TOPIC_H
#define LIBP2P_GOSSIPSUB_TOPIC_H

#include "gossipsub_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gossipsub_topic_mesh_params
{
    size_t d_lo;
    size_t d;
    size_t d_hi;
} gossipsub_topic_mesh_params_t;

gossipsub_topic_state_t *gossipsub_topic_find(gossipsub_topic_state_t *head, const char *topic);
libp2p_err_t gossipsub_topic_ensure(libp2p_gossipsub_t *gs,
                                    const libp2p_gossipsub_topic_config_t *topic_cfg,
                                    gossipsub_topic_state_t **out_topic);
void gossipsub_topics_remove_peer_locked(libp2p_gossipsub_t *gs, const peer_id_t *peer);
void gossipsub_topics_clear(gossipsub_topic_state_t *head);

gossipsub_mesh_member_t *gossipsub_mesh_member_find(gossipsub_mesh_member_t *head, const peer_id_t *peer);
gossipsub_mesh_member_t *gossipsub_mesh_member_insert(gossipsub_topic_state_t *topic,
                                                      gossipsub_peer_entry_t *entry,
                                                      int outbound,
                                                      uint64_t now_ms);
int gossipsub_mesh_member_remove(gossipsub_topic_state_t *topic, const peer_id_t *peer);
void gossipsub_mesh_member_touch(gossipsub_mesh_member_t *member, uint64_t now_ms);

gossipsub_fanout_peer_t *gossipsub_fanout_find(gossipsub_fanout_peer_t *head, const peer_id_t *peer);
gossipsub_fanout_peer_t *gossipsub_fanout_add(gossipsub_topic_state_t *topic,
                                              gossipsub_peer_entry_t *entry,
                                              int outbound,
                                              uint64_t now_ms);
int gossipsub_fanout_remove(gossipsub_topic_state_t *topic, const peer_id_t *peer);
void gossipsub_fanout_clear(gossipsub_fanout_peer_t **head_ptr);

void gossipsub_topic_remove_peer(libp2p_gossipsub_t *gs,
                                 gossipsub_topic_state_t *topic,
                                 const peer_id_t *peer);

void gossipsub_backoff_gc_locked(gossipsub_topic_state_t *topic, uint64_t now_ms);
int gossipsub_backoff_add(gossipsub_topic_state_t *topic, const peer_id_t *peer, uint64_t expire_ms);
void gossipsub_backoff_remove(gossipsub_topic_state_t *topic, const peer_id_t *peer);
int gossipsub_backoff_contains(gossipsub_topic_state_t *topic, const peer_id_t *peer, uint64_t now_ms);

void gossipsub_topic_heartbeat_mesh_locked(gossipsub_topic_state_t *topic, uint64_t now_ms);
void gossipsub_topic_heartbeat_fanout_locked(gossipsub_topic_state_t *topic, uint64_t now_ms);

peer_id_t **gossipsub_topic_collect_px_locked(gossipsub_topic_state_t *topic,
                                              const peer_id_t *exclude_peer,
                                              size_t limit,
                                              size_t *out_len);
void gossipsub_px_list_free(peer_id_t **list, size_t len);

void gossipsub_topic_compute_mesh_params(const libp2p_gossipsub_config_t *cfg,
                                         const gossipsub_topic_state_t *topic,
                                         gossipsub_topic_mesh_params_t *out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_TOPIC_H */
