#pragma once

#include "protocol/gossipsub/gossipsub.h"
#include "../../src/host/host_internal.h"
#include "../../src/protocol/gossipsub/proto/gen/gossipsub_rpc.pb.h"
#include "libp2p/peerstore.h"
#include "peer_id/peer_id.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "../../../lib/noise-c/src/crypto/ed25519/ed25519.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_ed25519.h"

#include "noise/protobufs.h"
#include "noise/protocol/constants.h"
#include "libp2p/events.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct multiaddr_s
{
    size_t size;
    uint8_t *bytes;
};

extern libp2p_err_t libp2p_gossipsub__inject_frame(libp2p_gossipsub_t *gs,
                                                   const peer_id_t *peer,
                                                   const uint8_t *frame,
                                                   size_t frame_len);
libp2p_err_t libp2p_gossipsub_rpc_encode_publish(const libp2p_gossipsub_message_t *msg,
                                                 uint8_t **out_buf,
                                                 size_t *out_len);
size_t libp2p_gossipsub__topic_mesh_size(libp2p_gossipsub_t *gs, const char *topic);
int libp2p_gossipsub__topic_mesh_contains(libp2p_gossipsub_t *gs,
                                          const char *topic,
                                          const peer_id_t *peer,
                                          int *out_outbound,
                                          uint64_t *out_last_heartbeat_ms);
libp2p_err_t libp2p_gossipsub__topic_mesh_add_peer(libp2p_gossipsub_t *gs,
                                                   const char *topic,
                                                   const peer_id_t *peer,
                                                   int outbound_hint);
libp2p_err_t libp2p_gossipsub__topic_mesh_remove_peer(libp2p_gossipsub_t *gs,
                                                      const char *topic,
                                                      const peer_id_t *peer);
size_t libp2p_gossipsub__topic_fanout_size(libp2p_gossipsub_t *gs, const char *topic);
uint64_t libp2p_gossipsub__topic_fanout_expire_ms(libp2p_gossipsub_t *gs, const char *topic);
int libp2p_gossipsub__topic_fanout_contains(libp2p_gossipsub_t *gs,
                                            const char *topic,
                                            const peer_id_t *peer,
                                            int *out_outbound,
                                            uint64_t *out_last_publish_ms);
libp2p_err_t libp2p_gossipsub__topic_fanout_add_peer(libp2p_gossipsub_t *gs,
                                                     const char *topic,
                                                     const peer_id_t *peer,
                                                     int outbound_hint,
                                                     uint64_t ttl_ms);
libp2p_err_t libp2p_gossipsub__topic_fanout_remove_peer(libp2p_gossipsub_t *gs,
                                                        const char *topic,
                                                        const peer_id_t *peer);
size_t libp2p_gossipsub__peer_sendq_len(libp2p_gossipsub_t *gs, const peer_id_t *peer);
int libp2p_gossipsub__message_in_cache(libp2p_gossipsub_t *gs,
                                       const uint8_t *message_id,
                                       size_t message_id_len);
libp2p_err_t libp2p_gossipsub__peer_set_connected(libp2p_gossipsub_t *gs,
                                                  const peer_id_t *peer,
                                                  int connected);
libp2p_err_t libp2p_gossipsub__peer_clear_sendq(libp2p_gossipsub_t *gs, const peer_id_t *peer);
libp2p_err_t libp2p_gossipsub__peer_pop_sendq(libp2p_gossipsub_t *gs,
                                              const peer_id_t *peer,
                                              uint8_t **out_buf,
                                              size_t *out_len);
libp2p_err_t libp2p_gossipsub__heartbeat(libp2p_gossipsub_t *gs);
libp2p_err_t libp2p_gossipsub__opportunistic(libp2p_gossipsub_t *gs);
libp2p_err_t libp2p_gossipsub__peer_set_score(libp2p_gossipsub_t *gs,
                                              const peer_id_t *peer,
                                              double score);
libp2p_err_t libp2p_gossipsub__peer_clear_score_override(libp2p_gossipsub_t *gs,
                                                         const peer_id_t *peer);
double libp2p_gossipsub__peer_get_score(libp2p_gossipsub_t *gs,
                                        const peer_id_t *peer,
                                        int *out_override);
libp2p_err_t libp2p_gossipsub__peer_set_remote_ip(libp2p_gossipsub_t *gs,
                                                  const peer_id_t *peer,
                                                  const char *ip);
void libp2p_gossipsub__set_flood_publish(libp2p_gossipsub_t *gs, int enable);
void libp2p_gossipsub__set_publish_threshold(libp2p_gossipsub_t *gs, double threshold);
void libp2p_gossipsub__set_gossip_threshold(libp2p_gossipsub_t *gs, double threshold);
void libp2p_gossipsub__set_graylist_threshold(libp2p_gossipsub_t *gs, double threshold);
libp2p_err_t libp2p_gossipsub__topic_set_publish_threshold(libp2p_gossipsub_t *gs,
                                                           const char *topic,
                                                           double threshold);
int libp2p_gossipsub__peer_has_subscription(libp2p_gossipsub_t *gs,
                                            const peer_id_t *peer,
                                            const char *topic);
int libp2p_gossipsub__topic_backoff_contains(libp2p_gossipsub_t *gs,
                                             const char *topic,
                                             const peer_id_t *peer);
int libp2p_gossipsub__peer_explicit_timer_id(libp2p_gossipsub_t *gs,
                                             const peer_id_t *peer);
void gossipsub_host_events_on_host_event(const libp2p_event_t *evt, void *user_data);
libp2p_err_t libp2p_gossipsub_rpc_decode_frame(const uint8_t *frame,
                                               size_t frame_len,
                                               libp2p_gossipsub_RPC **out_rpc);

extern size_t gossipsub_debug_last_eligible;
extern size_t gossipsub_debug_last_limit;

extern const uint8_t kTestPxSecretKey[32];
extern atomic_int g_sync_called;
extern atomic_int g_async_called;

typedef struct gossipsub_service_test_env_s
{
    libp2p_host_t *host;
    libp2p_gossipsub_t *gs;
    libp2p_gossipsub_validator_handle_t *sync_handle;
    libp2p_gossipsub_validator_handle_t *async_handle;
    libp2p_gossipsub_config_t cfg;
    int cfg_initialized;
    const char *config_addrs[1];
    libp2p_gossipsub_explicit_peer_t cfg_explicit_peer;
    peer_id_t config_peer;
    int config_peer_ok;
    int fatal_failure;
    int score_update_count;
    double score_update_last_value;
    int score_update_last_override;
} gossipsub_service_test_env_t;

void print_result(const char *name, int ok);
libp2p_err_t encode_subscription_rpc(const char *topic,
                                     int subscribe,
                                     uint8_t **out_buf,
                                     size_t *out_len);
size_t compute_expected_gossip_targets(size_t eligible, int gossip_percent, int d_lazy);
int decode_prune_px_count(const uint8_t *frame,
                          size_t frame_len,
                          const char *topic,
                          size_t *out_px_count);
int setup_gossip_peer(libp2p_gossipsub_t *gs,
                      const char *topic,
                      const char *peer_str,
                      peer_id_t *out_peer);
int run_gossip_factor_scenario(libp2p_gossipsub_t *gs,
                               const char *topic,
                               peer_id_t *peers,
                               size_t count,
                               const uint8_t *payload,
                               size_t payload_len,
                               size_t expected,
                               size_t *out_selected,
                               size_t *out_limit);
libp2p_err_t encode_control_ihave_rpc(const char *topic,
                                      const uint8_t *msg_id,
                                      size_t msg_id_len,
                                      uint8_t **out_buf,
                                      size_t *out_len);
int gossipsub_wait_for_peer_frame(libp2p_gossipsub_t *gs,
                                  const peer_id_t *peer,
                                  uint64_t timeout_ms,
                                  size_t *out_frame_len);
int gossipsub_wait_for_peer_idle(libp2p_gossipsub_t *gs,
                                 const peer_id_t *peer,
                                 uint64_t duration_ms,
                                 size_t *out_queue_len);
libp2p_err_t encode_graft_rpc(const char *topic,
                              uint8_t **out_buf,
                              size_t *out_len);
libp2p_err_t encode_peer_record_proto(const peer_id_t *peer,
                                      const multiaddr_t *const *addrs,
                                      size_t addr_count,
                                      uint8_t **out_buf,
                                      size_t *out_len);
libp2p_err_t encode_signed_peer_record(const peer_id_t *peer,
                                       const multiaddr_t *const *addrs,
                                       size_t addr_count,
                                       const uint8_t *secret_key,
                                       size_t secret_key_len,
                                       uint8_t **out_buf,
                                       size_t *out_len);
libp2p_err_t encode_prune_px_rpc(const char *topic,
                                 const peer_id_t *px_peer,
                                 const uint8_t *signed_record,
                                 size_t signed_record_len,
                                 uint8_t **out_buf,
                                 size_t *out_len);
libp2p_err_t encode_prune_rpc(const char *topic,
                              int include_px,
                              uint8_t **out_buf,
                              size_t *out_len);
libp2p_err_t encode_control_iwant_rpc(const uint8_t *msg_id,
                                      size_t msg_id_len,
                                      uint8_t **out_buf,
                                      size_t *out_len);
libp2p_err_t first_byte_message_id_fn(const libp2p_gossipsub_message_t *msg,
                                      uint8_t **out_id,
                                      size_t *out_len,
                                      void *user_data);
void gossipsub_service_free_env(gossipsub_service_test_env_t *env);
void gossipsub_test_score_update_cb(libp2p_gossipsub_t *gs,
                                    const libp2p_gossipsub_score_update_t *update,
                                    void *user_data);

int gossipsub_service_run_setup(gossipsub_service_test_env_t *env);
int gossipsub_service_run_subscription_mesh_tests(gossipsub_service_test_env_t *env);
int gossipsub_service_run_heartbeat_and_gossip_tests(gossipsub_service_test_env_t *env);
int gossipsub_service_run_px_and_opportunistic_tests(gossipsub_service_test_env_t *env);
int gossipsub_service_run_scoring_tests(gossipsub_service_test_env_t *env);
int gossipsub_service_run_explicit_peer_tests(gossipsub_service_test_env_t *env);
int gossipsub_service_run_cleanup_tests(gossipsub_service_test_env_t *env);
