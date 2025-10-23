#ifndef LIBP2P_GOSSIPSUB_VALIDATION_H
#define LIBP2P_GOSSIPSUB_VALIDATION_H

#include "gossipsub_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

libp2p_err_t gossipsub_validation_collect(libp2p_gossipsub_t *gs,
                                          const char *topic_name,
                                          gossipsub_topic_state_t **out_topic,
                                          libp2p_gossipsub_validator_handle_t ***out_handles,
                                          size_t *out_len);

libp2p_err_t gossipsub_validation_schedule(libp2p_gossipsub_t *gs,
                                           gossipsub_topic_state_t *topic,
                                           libp2p_gossipsub_validator_handle_t **validators,
                                           size_t validator_count,
                                           const libp2p_gossipsub_message_t *msg,
                                           int propagate_on_accept);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_VALIDATION_H */
