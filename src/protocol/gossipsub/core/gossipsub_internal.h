#ifndef LIBP2P_GOSSIPSUB_INTERNAL_H
#define LIBP2P_GOSSIPSUB_INTERNAL_H

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol/gossipsub/gossipsub.h"
#include "libp2p/protocol.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "peer_id/peer_id.h"

#define GOSSIPSUB_PRIMARY_PROTOCOL "/meshsub/1.1.0"

#include "../proto/gossipsub_proto.h"
#include "gossipsub_cache.h"
#include "gossipsub_promises.h"

typedef struct gossipsub_validator_node
{
    libp2p_gossipsub_validator_handle_t *handle;
    struct gossipsub_validator_node *next;
} gossipsub_validator_node_t;

typedef struct gossipsub_mesh_member
{
    peer_id_t *peer;
    struct gossipsub_peer_entry *peer_entry;
    int outbound;
    uint64_t last_heartbeat_ms;
    struct gossipsub_mesh_member *next;
} gossipsub_mesh_member_t;

typedef struct gossipsub_fanout_peer
{
    peer_id_t *peer;
    struct gossipsub_peer_entry *peer_entry;
    int outbound;
    uint64_t last_publish_ms;
    struct gossipsub_fanout_peer *next;
} gossipsub_fanout_peer_t;

typedef struct gossipsub_peer_topic
{
    char *name;
    uint64_t mesh_join_time_ms;
    uint64_t mesh_time_accum_ms;
    uint64_t last_mesh_update_ms;
    double first_message_deliveries;
    double mesh_message_deliveries;
    double mesh_failure_penalty;
    double invalid_message_deliveries;
    double topic_score;
    int in_mesh;
    struct gossipsub_peer_topic *next;
} gossipsub_peer_topic_t;

typedef struct gossipsub_sendq_item
{
    uint8_t *payload;
    size_t payload_len;
    size_t payload_sent;
    uint8_t header[10];
    size_t header_len;
    size_t header_sent;
    struct gossipsub_sendq_item *next;
} gossipsub_sendq_item_t;

typedef struct gossipsub_backoff_entry
{
    peer_id_t *peer;
    uint64_t expire_ms;
    struct gossipsub_backoff_entry *next;
} gossipsub_backoff_entry_t;

typedef struct gossipsub_topic_state
{
    char *name;
    int subscribed;
    gossipsub_mesh_member_t *mesh;
   size_t mesh_size;
   gossipsub_fanout_peer_t *fanout;
   size_t fanout_size;
   uint64_t fanout_expire_ms;
    uint64_t last_opportunistic_graft_ms;
   gossipsub_backoff_entry_t *backoff;
    size_t backoff_size;
    libp2p_gossipsub_topic_score_params_t score_params;
    int has_score_params;
    double publish_threshold;
    int has_publish_threshold;
    libp2p_gossipsub_message_id_fn message_id_fn;
    void *message_id_user_data;
    gossipsub_validator_node_t *validators;
    struct gossipsub_topic_state *next;
} gossipsub_topic_state_t;

typedef struct gossipsub_peer_entry
{
    peer_id_t *peer;
    int explicit_peering;
    int connected;
    int explicit_dial_timer_id;
    libp2p_stream_t *stream;
    int outbound_stream;
    uint64_t last_stream_dir_update_ms;
    gossipsub_sendq_item_t *sendq_head;
    gossipsub_sendq_item_t *sendq_tail;
    double score;
    double behaviour_penalty;
    double application_score;
    int score_override;
    size_t ihave_advertisements;
    size_t ihave_ids_asked;
    char *remote_ip;
    int write_backpressure;
    int flush_scheduled;
    libp2p_gossipsub_rpc_decoder_t decoder;
    gossipsub_peer_topic_t *topics;
    size_t topics_count;
    struct gossipsub_peer_entry *next;
} gossipsub_peer_entry_t;

typedef struct gossipsub_prune_target
{
    char *topic;
    peer_id_t **px_peers;
    size_t px_len;
} gossipsub_prune_target_t;

typedef struct gossipsub_px_dial_ctx
{
    libp2p_gossipsub_t *gs;
    peer_id_t *peer;
} gossipsub_px_dial_ctx_t;

struct libp2p_gossipsub_validator_handle
{
    libp2p_gossipsub_validator_type_t type;
    libp2p_gossipsub_validator_fn sync_fn;
    libp2p_gossipsub_async_validator_fn async_fn;
    void *user_data;
    gossipsub_topic_state_t *topic;
    atomic_int refcount;
};

struct libp2p_gossipsub
{
    libp2p_host_t *host;
    libp2p_runtime_t *runtime;
    int owns_runtime;
    libp2p_subscription_t *subscription;
    libp2p_gossipsub_config_t cfg;
    pthread_mutex_t lock;
    int started;
    libp2p_protocol_def_t protocol_defs[3];
    size_t num_protocol_defs;
   pthread_t runtime_thread;
  int runtime_thread_started;
  int heartbeat_timer_id;
    int opportunistic_timer_id;
    gossipsub_topic_state_t *topics;
    gossipsub_peer_entry_t *peers;
    gossipsub_seen_cache_t seen_cache;
    gossipsub_message_cache_t message_cache;
    gossipsub_promises_t promises;
    atomic_uint_fast64_t seqno_counter;
    uint64_t gossip_round;
    uint64_t last_opportunistic_graft_ms;
    int score_timer_id;
    uint64_t last_score_tick_ms;
};

typedef struct gossipsub_flush_task
{
    libp2p_gossipsub_t *gs;
    peer_id_t *peer;
} gossipsub_flush_task_t;

peer_id_t *gossipsub_peer_clone(const peer_id_t *src);
void gossipsub_peer_free(peer_id_t *pid);
int gossipsub_peer_equals(const peer_id_t *a, const peer_id_t *b);
uint64_t gossipsub_now_ms(void);
uint64_t gossipsub_random_u64(void);
void gossipsub_validator_handle_retain(libp2p_gossipsub_validator_handle_t *handle);
void gossipsub_validator_handle_release(libp2p_gossipsub_validator_handle_t *handle);

#endif /* LIBP2P_GOSSIPSUB_INTERNAL_H */
