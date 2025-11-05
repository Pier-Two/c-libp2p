#ifndef LIBP2P_GOSSIPSUB_PEER_H
#define LIBP2P_GOSSIPSUB_PEER_H

#include "gossipsub_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

gossipsub_peer_entry_t *gossipsub_peer_find(gossipsub_peer_entry_t *head, const peer_id_t *peer);
gossipsub_peer_entry_t *gossipsub_peer_find_or_add_locked(libp2p_gossipsub_t *gs, const peer_id_t *peer);
void gossipsub_peer_detach_stream_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry, libp2p_stream_t *s);
void gossipsub_peer_attach_stream_locked(libp2p_gossipsub_t *gs, gossipsub_peer_entry_t *entry, libp2p_stream_t *s);
libp2p_err_t gossipsub_peer_enqueue_frame_locked(libp2p_gossipsub_t *gs,
                                                 gossipsub_peer_entry_t *entry,
                                                 const uint8_t *frame,
                                                 size_t frame_len);
libp2p_err_t gossipsub_peer_send_subscription_locked(libp2p_gossipsub_t *gs,
                                                     gossipsub_peer_entry_t *entry,
                                                     const char *topic,
                                                     int subscribe);
void gossipsub_peer_topics_clear(gossipsub_peer_entry_t *entry);
gossipsub_peer_topic_t *gossipsub_peer_topic_find(gossipsub_peer_topic_t *head, const char *topic);
libp2p_err_t gossipsub_peer_topic_subscribe(libp2p_gossipsub_t *gs,
                                            gossipsub_peer_entry_t *entry,
                                            char **topic_ptr);
void gossipsub_peer_topic_unsubscribe(libp2p_gossipsub_t *gs,
                                      gossipsub_peer_entry_t *entry,
                                      const char *topic_name);
void gossipsub_peer_sendq_clear(gossipsub_peer_entry_t *entry);
libp2p_err_t gossipsub_peer_sendq_pop_locked(gossipsub_peer_entry_t *entry,
                                             uint8_t **out_buf,
                                             size_t *out_len);
void gossipsub_peers_clear(libp2p_gossipsub_t *gs);
void gossipsub_peer_explicit_cancel_timer_locked(libp2p_gossipsub_t *gs,
                                                 gossipsub_peer_entry_t *entry);
void gossipsub_peer_explicit_schedule_dial_locked(libp2p_gossipsub_t *gs,
                                                  gossipsub_peer_entry_t *entry,
                                                  uint64_t delay_ms);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_PEER_H */
