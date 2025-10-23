#ifndef LIBP2P_GOSSIPSUB_MESSAGE_H
#define LIBP2P_GOSSIPSUB_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/errors.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Topic descriptor used when interacting with the gossipsub service.
 * Applications normally only need to provide the topic name, but the
 * struct leaves room for optional future fields (mesh parameters, score
 * overrides, signing policies).
 */
typedef struct
{
    size_t struct_size;
    const char *topic;
} libp2p_gossipsub_topic_descriptor_t;

typedef struct libp2p_gossipsub_message libp2p_gossipsub_message_t;

typedef libp2p_err_t (*libp2p_gossipsub_message_id_fn)(const libp2p_gossipsub_message_t *msg,
                                                       uint8_t **out_id,
                                                       size_t *out_len,
                                                       void *user_data);

/**
 * View of a pubsub message passed to validators and application hooks.
 * The underlying buffers are owned by the gossipsub service unless
 * documented otherwise.
 */
struct libp2p_gossipsub_message
{
    libp2p_gossipsub_topic_descriptor_t topic;
    const uint8_t *data;
    size_t data_len;
    const peer_id_t *from;
    const uint8_t *seqno;
    size_t seqno_len;
    const uint8_t *raw_message;
    size_t raw_message_len;
};

/**
 * Result of a validator. The enum mirrors the behaviour specified in
 * gossipsub v1.1: reject drops the message and applies penalties, ignore
 * suppresses propagation without scoring impact, defer allows asynchronous
 * validators to continue processing.
 */
typedef enum
{
    LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT = 0,
    LIBP2P_GOSSIPSUB_VALIDATION_REJECT,
    LIBP2P_GOSSIPSUB_VALIDATION_IGNORE,
    LIBP2P_GOSSIPSUB_VALIDATION_DEFER
} libp2p_gossipsub_validation_result_t;

typedef libp2p_gossipsub_validation_result_t (*libp2p_gossipsub_validator_fn)(const libp2p_gossipsub_message_t *msg, void *user_data);

typedef void (*libp2p_gossipsub_validator_done_fn)(libp2p_gossipsub_validation_result_t result, void *user_data);

typedef void (*libp2p_gossipsub_async_validator_fn)(const libp2p_gossipsub_message_t *msg,
                                                    libp2p_gossipsub_validator_done_fn done,
                                                    void *user_data,
                                                    void *done_user_data);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_MESSAGE_H */
