#ifndef __gossipsub_rpc_pb_h__
#define __gossipsub_rpc_pb_h__

#include <noise/protobufs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _libp2p_gossipsub_RPC libp2p_gossipsub_RPC;
typedef struct _libp2p_gossipsub_RPC_SubOpts libp2p_gossipsub_RPC_SubOpts;
typedef struct _libp2p_gossipsub_Message libp2p_gossipsub_Message;
typedef struct _libp2p_gossipsub_ControlMessage libp2p_gossipsub_ControlMessage;
typedef struct _libp2p_gossipsub_ControlIHave libp2p_gossipsub_ControlIHave;
typedef struct _libp2p_gossipsub_ControlIWant libp2p_gossipsub_ControlIWant;
typedef struct _libp2p_gossipsub_ControlGraft libp2p_gossipsub_ControlGraft;
typedef struct _libp2p_gossipsub_ControlPrune libp2p_gossipsub_ControlPrune;
typedef struct _libp2p_gossipsub_ControlIDontWant libp2p_gossipsub_ControlIDontWant;
typedef struct _libp2p_gossipsub_ControlExtensions libp2p_gossipsub_ControlExtensions;
typedef struct _libp2p_gossipsub_PeerInfo libp2p_gossipsub_PeerInfo;

int libp2p_gossipsub_RPC_new(libp2p_gossipsub_RPC **obj);
int libp2p_gossipsub_RPC_free(libp2p_gossipsub_RPC *obj);
int libp2p_gossipsub_RPC_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_RPC *obj);
int libp2p_gossipsub_RPC_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_RPC **obj);
int libp2p_gossipsub_RPC_clear_subscriptions(libp2p_gossipsub_RPC *obj);
int libp2p_gossipsub_RPC_has_subscriptions(const libp2p_gossipsub_RPC *obj);
size_t libp2p_gossipsub_RPC_count_subscriptions(const libp2p_gossipsub_RPC *obj);
libp2p_gossipsub_RPC_SubOpts *libp2p_gossipsub_RPC_get_at_subscriptions(const libp2p_gossipsub_RPC *obj, size_t index);
int libp2p_gossipsub_RPC_add_subscriptions(libp2p_gossipsub_RPC *obj, libp2p_gossipsub_RPC_SubOpts **value);
int libp2p_gossipsub_RPC_insert_subscriptions(libp2p_gossipsub_RPC *obj, size_t index, libp2p_gossipsub_RPC_SubOpts *value);
int libp2p_gossipsub_RPC_clear_publish(libp2p_gossipsub_RPC *obj);
int libp2p_gossipsub_RPC_has_publish(const libp2p_gossipsub_RPC *obj);
size_t libp2p_gossipsub_RPC_count_publish(const libp2p_gossipsub_RPC *obj);
libp2p_gossipsub_Message *libp2p_gossipsub_RPC_get_at_publish(const libp2p_gossipsub_RPC *obj, size_t index);
int libp2p_gossipsub_RPC_add_publish(libp2p_gossipsub_RPC *obj, libp2p_gossipsub_Message **value);
int libp2p_gossipsub_RPC_insert_publish(libp2p_gossipsub_RPC *obj, size_t index, libp2p_gossipsub_Message *value);
int libp2p_gossipsub_RPC_clear_control(libp2p_gossipsub_RPC *obj);
int libp2p_gossipsub_RPC_has_control(const libp2p_gossipsub_RPC *obj);
libp2p_gossipsub_ControlMessage *libp2p_gossipsub_RPC_get_control(const libp2p_gossipsub_RPC *obj);
int libp2p_gossipsub_RPC_get_new_control(libp2p_gossipsub_RPC *obj, libp2p_gossipsub_ControlMessage **value);

int libp2p_gossipsub_RPC_SubOpts_new(libp2p_gossipsub_RPC_SubOpts **obj);
int libp2p_gossipsub_RPC_SubOpts_free(libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_RPC_SubOpts **obj);
int libp2p_gossipsub_RPC_SubOpts_clear_subscribe(libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_has_subscribe(const libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_get_subscribe(const libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_set_subscribe(libp2p_gossipsub_RPC_SubOpts *obj, int value);
int libp2p_gossipsub_RPC_SubOpts_clear_topic(libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_has_topic(const libp2p_gossipsub_RPC_SubOpts *obj);
const char *libp2p_gossipsub_RPC_SubOpts_get_topic(const libp2p_gossipsub_RPC_SubOpts *obj);
size_t libp2p_gossipsub_RPC_SubOpts_get_size_topic(const libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_set_topic(libp2p_gossipsub_RPC_SubOpts *obj, const char *value, size_t size);
int libp2p_gossipsub_RPC_SubOpts_clear_topic_id(libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_has_topic_id(const libp2p_gossipsub_RPC_SubOpts *obj);
const char *libp2p_gossipsub_RPC_SubOpts_get_topic_id(const libp2p_gossipsub_RPC_SubOpts *obj);
size_t libp2p_gossipsub_RPC_SubOpts_get_size_topic_id(const libp2p_gossipsub_RPC_SubOpts *obj);
int libp2p_gossipsub_RPC_SubOpts_set_topic_id(libp2p_gossipsub_RPC_SubOpts *obj, const char *value, size_t size);

int libp2p_gossipsub_Message_new(libp2p_gossipsub_Message **obj);
int libp2p_gossipsub_Message_free(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_Message **obj);
int libp2p_gossipsub_Message_clear_from(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_from(const libp2p_gossipsub_Message *obj);
const void *libp2p_gossipsub_Message_get_from(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_get_size_from(const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_set_from(libp2p_gossipsub_Message *obj, const void *value, size_t size);
int libp2p_gossipsub_Message_clear_data(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_data(const libp2p_gossipsub_Message *obj);
const void *libp2p_gossipsub_Message_get_data(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_get_size_data(const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_set_data(libp2p_gossipsub_Message *obj, const void *value, size_t size);
int libp2p_gossipsub_Message_clear_seqno(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_seqno(const libp2p_gossipsub_Message *obj);
const void *libp2p_gossipsub_Message_get_seqno(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_get_size_seqno(const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_set_seqno(libp2p_gossipsub_Message *obj, const void *value, size_t size);
int libp2p_gossipsub_Message_clear_topic(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_topic(const libp2p_gossipsub_Message *obj);
const char *libp2p_gossipsub_Message_get_topic(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_get_size_topic(const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_set_topic(libp2p_gossipsub_Message *obj, const char *value, size_t size);
int libp2p_gossipsub_Message_clear_signature(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_signature(const libp2p_gossipsub_Message *obj);
const void *libp2p_gossipsub_Message_get_signature(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_get_size_signature(const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_set_signature(libp2p_gossipsub_Message *obj, const void *value, size_t size);
int libp2p_gossipsub_Message_clear_key(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_key(const libp2p_gossipsub_Message *obj);
const void *libp2p_gossipsub_Message_get_key(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_get_size_key(const libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_set_key(libp2p_gossipsub_Message *obj, const void *value, size_t size);
int libp2p_gossipsub_Message_clear_topic_ids(libp2p_gossipsub_Message *obj);
int libp2p_gossipsub_Message_has_topic_ids(const libp2p_gossipsub_Message *obj);
size_t libp2p_gossipsub_Message_count_topic_ids(const libp2p_gossipsub_Message *obj);
const char *libp2p_gossipsub_Message_get_at_topic_ids(const libp2p_gossipsub_Message *obj, size_t index);
size_t libp2p_gossipsub_Message_get_size_at_topic_ids(const libp2p_gossipsub_Message *obj, size_t index);
int libp2p_gossipsub_Message_add_topic_ids(libp2p_gossipsub_Message *obj, const char *value, size_t size);

int libp2p_gossipsub_ControlMessage_new(libp2p_gossipsub_ControlMessage **obj);
int libp2p_gossipsub_ControlMessage_free(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlMessage **obj);
int libp2p_gossipsub_ControlMessage_clear_ihave(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_has_ihave(const libp2p_gossipsub_ControlMessage *obj);
size_t libp2p_gossipsub_ControlMessage_count_ihave(const libp2p_gossipsub_ControlMessage *obj);
libp2p_gossipsub_ControlIHave *libp2p_gossipsub_ControlMessage_get_at_ihave(const libp2p_gossipsub_ControlMessage *obj, size_t index);
int libp2p_gossipsub_ControlMessage_add_ihave(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlIHave **value);
int libp2p_gossipsub_ControlMessage_insert_ihave(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlIHave *value);
int libp2p_gossipsub_ControlMessage_clear_iwant(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_has_iwant(const libp2p_gossipsub_ControlMessage *obj);
size_t libp2p_gossipsub_ControlMessage_count_iwant(const libp2p_gossipsub_ControlMessage *obj);
libp2p_gossipsub_ControlIWant *libp2p_gossipsub_ControlMessage_get_at_iwant(const libp2p_gossipsub_ControlMessage *obj, size_t index);
int libp2p_gossipsub_ControlMessage_add_iwant(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlIWant **value);
int libp2p_gossipsub_ControlMessage_insert_iwant(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlIWant *value);
int libp2p_gossipsub_ControlMessage_clear_graft(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_has_graft(const libp2p_gossipsub_ControlMessage *obj);
size_t libp2p_gossipsub_ControlMessage_count_graft(const libp2p_gossipsub_ControlMessage *obj);
libp2p_gossipsub_ControlGraft *libp2p_gossipsub_ControlMessage_get_at_graft(const libp2p_gossipsub_ControlMessage *obj, size_t index);
int libp2p_gossipsub_ControlMessage_add_graft(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlGraft **value);
int libp2p_gossipsub_ControlMessage_insert_graft(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlGraft *value);
int libp2p_gossipsub_ControlMessage_clear_prune(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_has_prune(const libp2p_gossipsub_ControlMessage *obj);
size_t libp2p_gossipsub_ControlMessage_count_prune(const libp2p_gossipsub_ControlMessage *obj);
libp2p_gossipsub_ControlPrune *libp2p_gossipsub_ControlMessage_get_at_prune(const libp2p_gossipsub_ControlMessage *obj, size_t index);
int libp2p_gossipsub_ControlMessage_add_prune(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlPrune **value);
int libp2p_gossipsub_ControlMessage_insert_prune(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlPrune *value);
int libp2p_gossipsub_ControlMessage_clear_idontwant(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_has_idontwant(const libp2p_gossipsub_ControlMessage *obj);
size_t libp2p_gossipsub_ControlMessage_count_idontwant(const libp2p_gossipsub_ControlMessage *obj);
libp2p_gossipsub_ControlIDontWant *libp2p_gossipsub_ControlMessage_get_at_idontwant(const libp2p_gossipsub_ControlMessage *obj, size_t index);
int libp2p_gossipsub_ControlMessage_add_idontwant(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlIDontWant **value);
int libp2p_gossipsub_ControlMessage_insert_idontwant(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlIDontWant *value);
int libp2p_gossipsub_ControlMessage_clear_extensions(libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_has_extensions(const libp2p_gossipsub_ControlMessage *obj);
libp2p_gossipsub_ControlExtensions *libp2p_gossipsub_ControlMessage_get_extensions(const libp2p_gossipsub_ControlMessage *obj);
int libp2p_gossipsub_ControlMessage_get_new_extensions(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlExtensions **value);

int libp2p_gossipsub_ControlIHave_new(libp2p_gossipsub_ControlIHave **obj);
int libp2p_gossipsub_ControlIHave_free(libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlIHave **obj);
int libp2p_gossipsub_ControlIHave_clear_topic(libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_has_topic(const libp2p_gossipsub_ControlIHave *obj);
const char *libp2p_gossipsub_ControlIHave_get_topic(const libp2p_gossipsub_ControlIHave *obj);
size_t libp2p_gossipsub_ControlIHave_get_size_topic(const libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_set_topic(libp2p_gossipsub_ControlIHave *obj, const char *value, size_t size);
int libp2p_gossipsub_ControlIHave_clear_message_ids(libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_has_message_ids(const libp2p_gossipsub_ControlIHave *obj);
size_t libp2p_gossipsub_ControlIHave_count_message_ids(const libp2p_gossipsub_ControlIHave *obj);
const void *libp2p_gossipsub_ControlIHave_get_at_message_ids(const libp2p_gossipsub_ControlIHave *obj, size_t index);
size_t libp2p_gossipsub_ControlIHave_get_size_at_message_ids(const libp2p_gossipsub_ControlIHave *obj, size_t index);
int libp2p_gossipsub_ControlIHave_add_message_ids(libp2p_gossipsub_ControlIHave *obj, const void *value, size_t size);
int libp2p_gossipsub_ControlIHave_clear_topic_id(libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_has_topic_id(const libp2p_gossipsub_ControlIHave *obj);
const char *libp2p_gossipsub_ControlIHave_get_topic_id(const libp2p_gossipsub_ControlIHave *obj);
size_t libp2p_gossipsub_ControlIHave_get_size_topic_id(const libp2p_gossipsub_ControlIHave *obj);
int libp2p_gossipsub_ControlIHave_set_topic_id(libp2p_gossipsub_ControlIHave *obj, const char *value, size_t size);

int libp2p_gossipsub_ControlIWant_new(libp2p_gossipsub_ControlIWant **obj);
int libp2p_gossipsub_ControlIWant_free(libp2p_gossipsub_ControlIWant *obj);
int libp2p_gossipsub_ControlIWant_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlIWant *obj);
int libp2p_gossipsub_ControlIWant_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlIWant **obj);
int libp2p_gossipsub_ControlIWant_clear_message_ids(libp2p_gossipsub_ControlIWant *obj);
int libp2p_gossipsub_ControlIWant_has_message_ids(const libp2p_gossipsub_ControlIWant *obj);
size_t libp2p_gossipsub_ControlIWant_count_message_ids(const libp2p_gossipsub_ControlIWant *obj);
const void *libp2p_gossipsub_ControlIWant_get_at_message_ids(const libp2p_gossipsub_ControlIWant *obj, size_t index);
size_t libp2p_gossipsub_ControlIWant_get_size_at_message_ids(const libp2p_gossipsub_ControlIWant *obj, size_t index);
int libp2p_gossipsub_ControlIWant_add_message_ids(libp2p_gossipsub_ControlIWant *obj, const void *value, size_t size);

int libp2p_gossipsub_ControlGraft_new(libp2p_gossipsub_ControlGraft **obj);
int libp2p_gossipsub_ControlGraft_free(libp2p_gossipsub_ControlGraft *obj);
int libp2p_gossipsub_ControlGraft_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlGraft *obj);
int libp2p_gossipsub_ControlGraft_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlGraft **obj);
int libp2p_gossipsub_ControlGraft_clear_topic(libp2p_gossipsub_ControlGraft *obj);
int libp2p_gossipsub_ControlGraft_has_topic(const libp2p_gossipsub_ControlGraft *obj);
const char *libp2p_gossipsub_ControlGraft_get_topic(const libp2p_gossipsub_ControlGraft *obj);
size_t libp2p_gossipsub_ControlGraft_get_size_topic(const libp2p_gossipsub_ControlGraft *obj);
int libp2p_gossipsub_ControlGraft_set_topic(libp2p_gossipsub_ControlGraft *obj, const char *value, size_t size);
int libp2p_gossipsub_ControlGraft_clear_topic_id(libp2p_gossipsub_ControlGraft *obj);
int libp2p_gossipsub_ControlGraft_has_topic_id(const libp2p_gossipsub_ControlGraft *obj);
const char *libp2p_gossipsub_ControlGraft_get_topic_id(const libp2p_gossipsub_ControlGraft *obj);
size_t libp2p_gossipsub_ControlGraft_get_size_topic_id(const libp2p_gossipsub_ControlGraft *obj);
int libp2p_gossipsub_ControlGraft_set_topic_id(libp2p_gossipsub_ControlGraft *obj, const char *value, size_t size);

int libp2p_gossipsub_ControlPrune_new(libp2p_gossipsub_ControlPrune **obj);
int libp2p_gossipsub_ControlPrune_free(libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlPrune **obj);
int libp2p_gossipsub_ControlPrune_clear_topic(libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_has_topic(const libp2p_gossipsub_ControlPrune *obj);
const char *libp2p_gossipsub_ControlPrune_get_topic(const libp2p_gossipsub_ControlPrune *obj);
size_t libp2p_gossipsub_ControlPrune_get_size_topic(const libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_set_topic(libp2p_gossipsub_ControlPrune *obj, const char *value, size_t size);
int libp2p_gossipsub_ControlPrune_clear_peers(libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_has_peers(const libp2p_gossipsub_ControlPrune *obj);
size_t libp2p_gossipsub_ControlPrune_count_peers(const libp2p_gossipsub_ControlPrune *obj);
libp2p_gossipsub_PeerInfo *libp2p_gossipsub_ControlPrune_get_at_peers(const libp2p_gossipsub_ControlPrune *obj, size_t index);
int libp2p_gossipsub_ControlPrune_add_peers(libp2p_gossipsub_ControlPrune *obj, libp2p_gossipsub_PeerInfo **value);
int libp2p_gossipsub_ControlPrune_insert_peers(libp2p_gossipsub_ControlPrune *obj, size_t index, libp2p_gossipsub_PeerInfo *value);
int libp2p_gossipsub_ControlPrune_clear_backoff(libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_has_backoff(const libp2p_gossipsub_ControlPrune *obj);
uint64_t libp2p_gossipsub_ControlPrune_get_backoff(const libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_set_backoff(libp2p_gossipsub_ControlPrune *obj, uint64_t value);
int libp2p_gossipsub_ControlPrune_clear_topic_id(libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_has_topic_id(const libp2p_gossipsub_ControlPrune *obj);
const char *libp2p_gossipsub_ControlPrune_get_topic_id(const libp2p_gossipsub_ControlPrune *obj);
size_t libp2p_gossipsub_ControlPrune_get_size_topic_id(const libp2p_gossipsub_ControlPrune *obj);
int libp2p_gossipsub_ControlPrune_set_topic_id(libp2p_gossipsub_ControlPrune *obj, const char *value, size_t size);

int libp2p_gossipsub_ControlIDontWant_new(libp2p_gossipsub_ControlIDontWant **obj);
int libp2p_gossipsub_ControlIDontWant_free(libp2p_gossipsub_ControlIDontWant *obj);
int libp2p_gossipsub_ControlIDontWant_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlIDontWant *obj);
int libp2p_gossipsub_ControlIDontWant_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlIDontWant **obj);
int libp2p_gossipsub_ControlIDontWant_clear_message_ids(libp2p_gossipsub_ControlIDontWant *obj);
int libp2p_gossipsub_ControlIDontWant_has_message_ids(const libp2p_gossipsub_ControlIDontWant *obj);
size_t libp2p_gossipsub_ControlIDontWant_count_message_ids(const libp2p_gossipsub_ControlIDontWant *obj);
const void *libp2p_gossipsub_ControlIDontWant_get_at_message_ids(const libp2p_gossipsub_ControlIDontWant *obj, size_t index);
size_t libp2p_gossipsub_ControlIDontWant_get_size_at_message_ids(const libp2p_gossipsub_ControlIDontWant *obj, size_t index);
int libp2p_gossipsub_ControlIDontWant_add_message_ids(libp2p_gossipsub_ControlIDontWant *obj, const void *value, size_t size);

int libp2p_gossipsub_ControlExtensions_new(libp2p_gossipsub_ControlExtensions **obj);
int libp2p_gossipsub_ControlExtensions_free(libp2p_gossipsub_ControlExtensions *obj);
int libp2p_gossipsub_ControlExtensions_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlExtensions *obj);
int libp2p_gossipsub_ControlExtensions_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlExtensions **obj);
int libp2p_gossipsub_ControlExtensions_clear_placeholder(libp2p_gossipsub_ControlExtensions *obj);
int libp2p_gossipsub_ControlExtensions_has_placeholder(const libp2p_gossipsub_ControlExtensions *obj);
int libp2p_gossipsub_ControlExtensions_get_placeholder(const libp2p_gossipsub_ControlExtensions *obj);
int libp2p_gossipsub_ControlExtensions_set_placeholder(libp2p_gossipsub_ControlExtensions *obj, int value);

int libp2p_gossipsub_PeerInfo_new(libp2p_gossipsub_PeerInfo **obj);
int libp2p_gossipsub_PeerInfo_free(libp2p_gossipsub_PeerInfo *obj);
int libp2p_gossipsub_PeerInfo_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_PeerInfo *obj);
int libp2p_gossipsub_PeerInfo_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_PeerInfo **obj);
int libp2p_gossipsub_PeerInfo_clear_peer_id(libp2p_gossipsub_PeerInfo *obj);
int libp2p_gossipsub_PeerInfo_has_peer_id(const libp2p_gossipsub_PeerInfo *obj);
const void *libp2p_gossipsub_PeerInfo_get_peer_id(const libp2p_gossipsub_PeerInfo *obj);
size_t libp2p_gossipsub_PeerInfo_get_size_peer_id(const libp2p_gossipsub_PeerInfo *obj);
int libp2p_gossipsub_PeerInfo_set_peer_id(libp2p_gossipsub_PeerInfo *obj, const void *value, size_t size);
int libp2p_gossipsub_PeerInfo_clear_signed_peer_record(libp2p_gossipsub_PeerInfo *obj);
int libp2p_gossipsub_PeerInfo_has_signed_peer_record(const libp2p_gossipsub_PeerInfo *obj);
const void *libp2p_gossipsub_PeerInfo_get_signed_peer_record(const libp2p_gossipsub_PeerInfo *obj);
size_t libp2p_gossipsub_PeerInfo_get_size_signed_peer_record(const libp2p_gossipsub_PeerInfo *obj);
int libp2p_gossipsub_PeerInfo_set_signed_peer_record(libp2p_gossipsub_PeerInfo *obj, const void *value, size_t size);

#ifdef __cplusplus
};
#endif

#endif
