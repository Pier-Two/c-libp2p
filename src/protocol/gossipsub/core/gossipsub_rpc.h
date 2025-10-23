#ifndef LIBP2P_GOSSIPSUB_RPC_H
#define LIBP2P_GOSSIPSUB_RPC_H

#include "gossipsub_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gossipsub_rpc_out
{
    uint8_t *frame;
    size_t frame_len;
} gossipsub_rpc_out_t;

typedef struct gossipsub_rpc_subscription
{
    char *topic;
    int subscribe;
} gossipsub_rpc_subscription_t;

typedef struct gossipsub_rpc_control_iwant
{
    uint8_t **ids;
    size_t *lengths;
    size_t count;
} gossipsub_rpc_control_iwant_t;

typedef struct gossipsub_rpc_control_ihave
{
    char *topic;
    uint8_t **ids;
    size_t *lengths;
    size_t count;
} gossipsub_rpc_control_ihave_t;

typedef struct gossipsub_rpc_control_graft
{
    char *topic;
} gossipsub_rpc_control_graft_t;

typedef struct gossipsub_rpc_px_record
{
    peer_id_t *peer;
    uint8_t *signed_peer_record;
    size_t signed_peer_record_len;
} gossipsub_rpc_px_record_t;

typedef struct gossipsub_rpc_control_prune
{
    char *topic;
    uint64_t backoff;
    gossipsub_rpc_px_record_t *px;
    size_t px_count;
} gossipsub_rpc_control_prune_t;

typedef struct gossipsub_rpc_parsed
{
    gossipsub_rpc_subscription_t *subscriptions;
    size_t subscriptions_len;

    gossipsub_rpc_control_iwant_t *iwants;
    size_t iwant_len;

    gossipsub_rpc_control_ihave_t *ihaves;
    size_t ihave_len;

    gossipsub_rpc_control_graft_t *grafts;
    size_t graft_len;

    gossipsub_rpc_control_prune_t *prunes;
    size_t prune_len;
} gossipsub_rpc_parsed_t;

void gossipsub_rpc_out_init(gossipsub_rpc_out_t *out);
void gossipsub_rpc_out_clear(gossipsub_rpc_out_t *out);

libp2p_err_t gossipsub_rpc_encode_control_iwant(uint8_t **ids,
                                                const size_t *id_lengths,
                                                size_t count,
                                                gossipsub_rpc_out_t *out);

libp2p_err_t gossipsub_rpc_encode_control_prune(const gossipsub_prune_target_t *const *targets,
                                                size_t count,
                                                uint64_t backoff_seconds,
                                                gossipsub_rpc_out_t *out);

libp2p_err_t gossipsub_rpc_encode_control_graft(const char *const *topics,
                                                size_t count,
                                                gossipsub_rpc_out_t *out);

libp2p_err_t gossipsub_rpc_encode_control_ihave(const char *topic,
                                                uint8_t **ids,
                                                const size_t *id_lengths,
                                                size_t count,
                                                gossipsub_rpc_out_t *out);

void gossipsub_rpc_parsed_init(gossipsub_rpc_parsed_t *parsed);
void gossipsub_rpc_parsed_clear(gossipsub_rpc_parsed_t *parsed);
libp2p_err_t gossipsub_rpc_parse(const libp2p_gossipsub_RPC *rpc, gossipsub_rpc_parsed_t *out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_RPC_H */
