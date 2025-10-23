#ifndef LIBP2P_GOSSIPSUB_PROMISES_H
#define LIBP2P_GOSSIPSUB_PROMISES_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"

typedef struct gossipsub_promise_peer
{
    peer_id_t *peer;
    uint64_t expire_ms;
    struct gossipsub_promise_peer *next;
} gossipsub_promise_peer_t;

typedef struct gossipsub_promise_entry
{
    uint8_t *message_id;
    size_t message_id_len;
    gossipsub_promise_peer_t *peers;
    struct gossipsub_promise_entry *next;
} gossipsub_promise_entry_t;

typedef struct gossipsub_promises
{
    gossipsub_promise_entry_t *head;
} gossipsub_promises_t;

struct libp2p_gossipsub;

void gossipsub_promises_init(gossipsub_promises_t *promises);
void gossipsub_promises_clear(gossipsub_promises_t *promises);
void gossipsub_promises_track(gossipsub_promises_t *promises,
                              const peer_id_t *peer,
                              const uint8_t *const *ids,
                              const size_t *lens,
                              size_t count,
                              uint64_t expire_ms);
void gossipsub_promises_message_delivered(gossipsub_promises_t *promises,
                                          const uint8_t *id,
                                          size_t id_len);
void gossipsub_promises_apply_penalties(struct libp2p_gossipsub *gs,
                                        uint64_t now_ms);

#endif /* LIBP2P_GOSSIPSUB_PROMISES_H */
