#ifndef LIBP2P_GOSSIPSUB_H
#define LIBP2P_GOSSIPSUB_H

#include <stdbool.h>
#include <stddef.h>

#include "libp2p/errors.h"
#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/runtime.h"
#include "protocol/gossipsub/message.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_gossipsub libp2p_gossipsub_t;
typedef struct libp2p_gossipsub_validator_handle libp2p_gossipsub_validator_handle_t;

typedef enum
{
    LIBP2P_GOSSIPSUB_VALIDATOR_SYNC,
    LIBP2P_GOSSIPSUB_VALIDATOR_ASYNC
} libp2p_gossipsub_validator_type_t;

typedef struct
{
    size_t struct_size;
    libp2p_gossipsub_validator_type_t type;
    libp2p_gossipsub_validator_fn sync_fn;
    libp2p_gossipsub_async_validator_fn async_fn;
    void *user_data;
} libp2p_gossipsub_validator_def_t;

typedef struct
{
    size_t struct_size;
    double topic_weight;
    double time_in_mesh_weight;
    double time_in_mesh_cap;
    double first_message_deliveries_weight;
    double first_message_deliveries_decay;
    double first_message_deliveries_cap;
    double mesh_message_deliveries_weight;
    double mesh_message_deliveries_decay;
    double mesh_message_delivery_threshold;
    double mesh_message_deliveries_cap;
    double mesh_failure_penalty_weight;
    double mesh_failure_penalty_decay;
    double invalid_message_deliveries_weight;
    double invalid_message_deliveries_decay;
    double behavioural_penalty_weight;
} libp2p_gossipsub_topic_score_params_t;

typedef struct
{
    size_t struct_size;
    const peer_id_t *peer;
    double score;
    int score_override;
} libp2p_gossipsub_score_update_t;

typedef void (*libp2p_gossipsub_score_update_cb)(libp2p_gossipsub_t *gs,
                                                 const libp2p_gossipsub_score_update_t *update,
                                                 void *user_data);

typedef struct
{
    size_t struct_size;
    libp2p_gossipsub_topic_descriptor_t descriptor;
    const libp2p_gossipsub_topic_score_params_t *score_params;
    double publish_threshold;
    libp2p_gossipsub_message_id_fn message_id_fn;
    void *message_id_user_data;
} libp2p_gossipsub_topic_config_t;

typedef struct
{
    size_t struct_size;
    const peer_id_t *peer;
    const char *const *addresses;
    size_t address_count;
} libp2p_gossipsub_explicit_peer_t;

typedef struct
{
    size_t struct_size;
    int heartbeat_interval_ms;
    int opportunistic_graft_interval_ms;
    int score_decay_interval_ms;
    int prune_backoff_ms;
    int graft_flood_threshold_ms;
    int iwant_followup_time_ms;
    int d;
    int d_lo;
    int d_hi;
    int d_out;
    int d_lazy;
    int gossip_factor_percent;
    int d_score;
    bool enable_px;
    bool enable_flood_publish;
    bool enable_opportunistic_graft;
    double opportunistic_graft_threshold;
    int opportunistic_graft_peers;
    double publish_threshold;
    double gossip_threshold;
    double graylist_threshold;
    double accept_px_threshold;
    double score_time_in_mesh_cap;
    size_t seen_cache_capacity;
    int seen_cache_ttl_ms;
    const libp2p_gossipsub_explicit_peer_t *explicit_peers;
    size_t num_explicit_peers;
    libp2p_runtime_t *runtime;
    size_t message_cache_length;
    size_t message_cache_gossip;
    size_t px_peer_target;
    size_t max_ihave_messages;
    size_t max_ihave_length;
    double ihave_spam_penalty;
    libp2p_gossipsub_score_update_cb on_score_update;
    void *score_update_user_data;
    double app_specific_weight;
    double ip_colocation_weight;
    int ip_colocation_threshold;
    double behaviour_penalty_weight;
    double behaviour_penalty_decay;
    uint64_t fanout_ttl_ms;
    const char *const *protocol_ids;
    size_t protocol_id_count;
} libp2p_gossipsub_config_t;

libp2p_err_t libp2p_gossipsub_config_default(libp2p_gossipsub_config_t *cfg);

libp2p_err_t libp2p_gossipsub_new(libp2p_host_t *host, const libp2p_gossipsub_config_t *cfg, libp2p_gossipsub_t **out);
void libp2p_gossipsub_free(libp2p_gossipsub_t *gs);

libp2p_err_t libp2p_gossipsub_start(libp2p_gossipsub_t *gs);
void libp2p_gossipsub_stop(libp2p_gossipsub_t *gs);

libp2p_err_t libp2p_gossipsub_subscribe(libp2p_gossipsub_t *gs, const libp2p_gossipsub_topic_config_t *topic_cfg);
libp2p_err_t libp2p_gossipsub_unsubscribe(libp2p_gossipsub_t *gs, const char *topic);
libp2p_err_t libp2p_gossipsub_update_topic(libp2p_gossipsub_t *gs,
                                           const libp2p_gossipsub_topic_config_t *topic_cfg);

libp2p_err_t libp2p_gossipsub_publish(libp2p_gossipsub_t *gs, const libp2p_gossipsub_message_t *msg);

libp2p_err_t libp2p_gossipsub_add_validator(libp2p_gossipsub_t *gs,
                                            const char *topic,
                                            const libp2p_gossipsub_validator_def_t *def,
                                            libp2p_gossipsub_validator_handle_t **out_handle);
libp2p_err_t libp2p_gossipsub_remove_validator(libp2p_gossipsub_t *gs, libp2p_gossipsub_validator_handle_t *handle);

libp2p_err_t libp2p_gossipsub_peering_add(libp2p_gossipsub_t *gs, const peer_id_t *peer);
libp2p_err_t libp2p_gossipsub_peering_remove(libp2p_gossipsub_t *gs, const peer_id_t *peer);
libp2p_err_t libp2p_gossipsub_set_peer_application_score(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer,
                                                         double score);
libp2p_err_t libp2p_gossipsub_set_peer_behaviour_penalty(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer,
                                                         double penalty);
libp2p_err_t libp2p_gossipsub_add_peer_behaviour_penalty(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer,
                                                         double delta);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_H */
