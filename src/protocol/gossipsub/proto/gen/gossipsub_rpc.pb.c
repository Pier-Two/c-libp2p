#include "gossipsub_rpc.pb.h"
#include <stdlib.h>
#include <string.h>

struct _libp2p_gossipsub_RPC {
    libp2p_gossipsub_RPC_SubOpts **subscriptions;
    size_t subscriptions_count_;
    size_t subscriptions_max_;
    libp2p_gossipsub_Message **publish;
    size_t publish_count_;
    size_t publish_max_;
    libp2p_gossipsub_ControlMessage *control;
};

struct _libp2p_gossipsub_RPC_SubOpts {
    int subscribe;
    char *topic;
    size_t topic_size_;
    char *topic_id;
    size_t topic_id_size_;
};

struct _libp2p_gossipsub_Message {
    void *from;
    size_t from_size_;
    void *data;
    size_t data_size_;
    void *seqno;
    size_t seqno_size_;
    char *topic;
    size_t topic_size_;
    char **topic_ids;
    size_t *topic_ids_size_;
    size_t topic_ids_count_;
    size_t topic_ids_max_;
    void *signature;
    size_t signature_size_;
    void *key;
    size_t key_size_;
};

struct _libp2p_gossipsub_ControlMessage {
    libp2p_gossipsub_ControlIHave **ihave;
    size_t ihave_count_;
    size_t ihave_max_;
    libp2p_gossipsub_ControlIWant **iwant;
    size_t iwant_count_;
    size_t iwant_max_;
    libp2p_gossipsub_ControlGraft **graft;
    size_t graft_count_;
    size_t graft_max_;
    libp2p_gossipsub_ControlPrune **prune;
    size_t prune_count_;
    size_t prune_max_;
    libp2p_gossipsub_ControlIDontWant **idontwant;
    size_t idontwant_count_;
    size_t idontwant_max_;
    libp2p_gossipsub_ControlExtensions *extensions;
};

struct _libp2p_gossipsub_ControlIHave {
    char *topic;
    size_t topic_size_;
    char *topic_id;
    size_t topic_id_size_;
    void **message_ids;
    size_t *message_ids_size_;
    size_t message_ids_count_;
    size_t message_ids_max_;
};

struct _libp2p_gossipsub_ControlIWant {
    void **message_ids;
    size_t *message_ids_size_;
    size_t message_ids_count_;
    size_t message_ids_max_;
};

struct _libp2p_gossipsub_ControlGraft {
    char *topic;
    size_t topic_size_;
    char *topic_id;
    size_t topic_id_size_;
};

struct _libp2p_gossipsub_ControlPrune {
    char *topic;
    size_t topic_size_;
    char *topic_id;
    size_t topic_id_size_;
    libp2p_gossipsub_PeerInfo **peers;
    size_t peers_count_;
    size_t peers_max_;
    uint64_t backoff;
};

struct _libp2p_gossipsub_ControlIDontWant {
    void **message_ids;
    size_t *message_ids_size_;
    size_t message_ids_count_;
    size_t message_ids_max_;
};

struct _libp2p_gossipsub_ControlExtensions {
    int placeholder;
};

struct _libp2p_gossipsub_PeerInfo {
    void *peer_id;
    size_t peer_id_size_;
    void *signed_peer_record;
    size_t signed_peer_record_size_;
};

int libp2p_gossipsub_RPC_new(libp2p_gossipsub_RPC **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_RPC *)calloc(1, sizeof(libp2p_gossipsub_RPC));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_free(libp2p_gossipsub_RPC *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    for (index = 0; index < obj->subscriptions_count_; ++index)
        libp2p_gossipsub_RPC_SubOpts_free(obj->subscriptions[index]);
    noise_protobuf_free_memory(obj->subscriptions, obj->subscriptions_max_ * sizeof(libp2p_gossipsub_RPC_SubOpts *));
    for (index = 0; index < obj->publish_count_; ++index)
        libp2p_gossipsub_Message_free(obj->publish[index]);
    noise_protobuf_free_memory(obj->publish, obj->publish_max_ * sizeof(libp2p_gossipsub_Message *));
    libp2p_gossipsub_ControlMessage_free(obj->control);
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_RPC));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_RPC *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->control)
        libp2p_gossipsub_ControlMessage_write(pbuf, 3, obj->control);
    for (index = obj->publish_count_; index > 0; --index)
        libp2p_gossipsub_Message_write(pbuf, 2, obj->publish[index - 1]);
    for (index = obj->subscriptions_count_; index > 0; --index)
        libp2p_gossipsub_RPC_SubOpts_write(pbuf, 1, obj->subscriptions[index - 1]);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_RPC_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_RPC **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_RPC_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                libp2p_gossipsub_RPC_SubOpts *value = 0;
                int err;
                libp2p_gossipsub_RPC_SubOpts_read(pbuf, 1, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->subscriptions), &((*obj)->subscriptions_count_), &((*obj)->subscriptions_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 2: {
                libp2p_gossipsub_Message *value = 0;
                int err;
                libp2p_gossipsub_Message_read(pbuf, 2, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->publish), &((*obj)->publish_count_), &((*obj)->publish_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 3: {
                libp2p_gossipsub_ControlMessage_free((*obj)->control);
                (*obj)->control = 0;
                libp2p_gossipsub_ControlMessage_read(pbuf, 3, &((*obj)->control));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_RPC_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_RPC_clear_subscriptions(libp2p_gossipsub_RPC *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->subscriptions_count_; ++index)
            libp2p_gossipsub_RPC_SubOpts_free(obj->subscriptions[index]);
        noise_protobuf_free_memory(obj->subscriptions, obj->subscriptions_max_ * sizeof(libp2p_gossipsub_RPC_SubOpts *));
        obj->subscriptions = 0;
        obj->subscriptions_count_ = 0;
        obj->subscriptions_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_has_subscriptions(const libp2p_gossipsub_RPC *obj)
{
    return obj ? (obj->subscriptions_count_ != 0) : 0;
}

size_t libp2p_gossipsub_RPC_count_subscriptions(const libp2p_gossipsub_RPC *obj)
{
    return obj ? obj->subscriptions_count_ : 0;
}

libp2p_gossipsub_RPC_SubOpts *libp2p_gossipsub_RPC_get_at_subscriptions(const libp2p_gossipsub_RPC *obj, size_t index)
{
    if (obj && index < obj->subscriptions_count_)
        return obj->subscriptions[index];
    else
        return 0;
}

int libp2p_gossipsub_RPC_add_subscriptions(libp2p_gossipsub_RPC *obj, libp2p_gossipsub_RPC_SubOpts **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_RPC_SubOpts_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->subscriptions), &(obj->subscriptions_count_), &(obj->subscriptions_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_RPC_SubOpts_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_insert_subscriptions(libp2p_gossipsub_RPC *obj, size_t index, libp2p_gossipsub_RPC_SubOpts *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->subscriptions), &(obj->subscriptions_count_), &(obj->subscriptions_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_RPC_clear_publish(libp2p_gossipsub_RPC *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->publish_count_; ++index)
            libp2p_gossipsub_Message_free(obj->publish[index]);
        noise_protobuf_free_memory(obj->publish, obj->publish_max_ * sizeof(libp2p_gossipsub_Message *));
        obj->publish = 0;
        obj->publish_count_ = 0;
        obj->publish_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_has_publish(const libp2p_gossipsub_RPC *obj)
{
    return obj ? (obj->publish_count_ != 0) : 0;
}

size_t libp2p_gossipsub_RPC_count_publish(const libp2p_gossipsub_RPC *obj)
{
    return obj ? obj->publish_count_ : 0;
}

libp2p_gossipsub_Message *libp2p_gossipsub_RPC_get_at_publish(const libp2p_gossipsub_RPC *obj, size_t index)
{
    if (obj && index < obj->publish_count_)
        return obj->publish[index];
    else
        return 0;
}

int libp2p_gossipsub_RPC_add_publish(libp2p_gossipsub_RPC *obj, libp2p_gossipsub_Message **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_Message_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->publish), &(obj->publish_count_), &(obj->publish_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_Message_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_insert_publish(libp2p_gossipsub_RPC *obj, size_t index, libp2p_gossipsub_Message *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->publish), &(obj->publish_count_), &(obj->publish_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_RPC_clear_control(libp2p_gossipsub_RPC *obj)
{
    if (obj) {
        libp2p_gossipsub_ControlMessage_free(obj->control);
        obj->control = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_has_control(const libp2p_gossipsub_RPC *obj)
{
    return obj ? (obj->control != 0) : 0;
}

libp2p_gossipsub_ControlMessage *libp2p_gossipsub_RPC_get_control(const libp2p_gossipsub_RPC *obj)
{
    return obj ? obj->control : 0;
}

int libp2p_gossipsub_RPC_get_new_control(libp2p_gossipsub_RPC *obj, libp2p_gossipsub_ControlMessage **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlMessage_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    libp2p_gossipsub_ControlMessage_free(obj->control);
    obj->control = *value;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_SubOpts_new(libp2p_gossipsub_RPC_SubOpts **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_RPC_SubOpts *)calloc(1, sizeof(libp2p_gossipsub_RPC_SubOpts));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_SubOpts_free(libp2p_gossipsub_RPC_SubOpts *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->topic, obj->topic_size_);
    noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_RPC_SubOpts));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_RPC_SubOpts_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_RPC_SubOpts *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->topic)
        noise_protobuf_write_string(pbuf, 2, obj->topic, obj->topic_size_);
    if (obj->topic_id)
        noise_protobuf_write_string(pbuf, 3, obj->topic_id, obj->topic_id_size_);
    if (obj->subscribe)
        noise_protobuf_write_bool(pbuf, 1, obj->subscribe);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_RPC_SubOpts_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_RPC_SubOpts **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_RPC_SubOpts_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_read_bool(pbuf, 1, &((*obj)->subscribe));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->topic, (*obj)->topic_size_);
                (*obj)->topic = 0;
                (*obj)->topic_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->topic), 0, &((*obj)->topic_size_));
            } break;
            case 3: {
                noise_protobuf_free_memory((*obj)->topic_id, (*obj)->topic_id_size_);
                (*obj)->topic_id = 0;
                (*obj)->topic_id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 3, &((*obj)->topic_id), 0, &((*obj)->topic_id_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_RPC_SubOpts_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_RPC_SubOpts_clear_subscribe(libp2p_gossipsub_RPC_SubOpts *obj)
{
    if (obj) {
        obj->subscribe = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_SubOpts_has_subscribe(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? (obj->subscribe != 0) : 0;
}

int libp2p_gossipsub_RPC_SubOpts_get_subscribe(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? obj->subscribe : 0;
}

int libp2p_gossipsub_RPC_SubOpts_set_subscribe(libp2p_gossipsub_RPC_SubOpts *obj, int value)
{
    if (obj) {
        obj->subscribe = value;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_SubOpts_clear_topic(libp2p_gossipsub_RPC_SubOpts *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = 0;
        obj->topic_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_SubOpts_has_topic(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? (obj->topic != 0) : 0;
}

const char *libp2p_gossipsub_RPC_SubOpts_get_topic(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? obj->topic : 0;
}

size_t libp2p_gossipsub_RPC_SubOpts_get_size_topic(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? obj->topic_size_ : 0;
}

int libp2p_gossipsub_RPC_SubOpts_set_topic(libp2p_gossipsub_RPC_SubOpts *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = (char *)malloc(size + 1);
        if (obj->topic) {
            memcpy(obj->topic, value, size);
            obj->topic[size] = 0;
            obj->topic_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_SubOpts_clear_topic_id(libp2p_gossipsub_RPC_SubOpts *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = 0;
        obj->topic_id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_RPC_SubOpts_has_topic_id(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? (obj->topic_id != 0) : 0;
}

const char *libp2p_gossipsub_RPC_SubOpts_get_topic_id(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? obj->topic_id : 0;
}

size_t libp2p_gossipsub_RPC_SubOpts_get_size_topic_id(const libp2p_gossipsub_RPC_SubOpts *obj)
{
    return obj ? obj->topic_id_size_ : 0;
}

int libp2p_gossipsub_RPC_SubOpts_set_topic_id(libp2p_gossipsub_RPC_SubOpts *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = (char *)malloc(size + 1);
        if (obj->topic_id) {
            memcpy(obj->topic_id, value, size);
            obj->topic_id[size] = 0;
            obj->topic_id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_new(libp2p_gossipsub_Message **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_Message *)calloc(1, sizeof(libp2p_gossipsub_Message));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_Message_free(libp2p_gossipsub_Message *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->from, obj->from_size_);
    noise_protobuf_free_memory(obj->data, obj->data_size_);
    noise_protobuf_free_memory(obj->seqno, obj->seqno_size_);
    noise_protobuf_free_memory(obj->topic, obj->topic_size_);
    for (index = 0; index < obj->topic_ids_count_; ++index)
        noise_protobuf_free_memory(obj->topic_ids[index], obj->topic_ids_size_[index]);
    noise_protobuf_free_memory(obj->topic_ids, obj->topic_ids_max_ * sizeof(char *));
    noise_protobuf_free_memory(obj->topic_ids_size_, obj->topic_ids_max_ * sizeof(size_t));
    noise_protobuf_free_memory(obj->signature, obj->signature_size_);
    noise_protobuf_free_memory(obj->key, obj->key_size_);
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_Message));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_Message_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_Message *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->topic_ids_count_; index > 0; --index)
        noise_protobuf_write_string(pbuf, 7, obj->topic_ids[index - 1], obj->topic_ids_size_[index - 1]);
    if (obj->key)
        noise_protobuf_write_bytes(pbuf, 6, obj->key, obj->key_size_);
    if (obj->signature)
        noise_protobuf_write_bytes(pbuf, 5, obj->signature, obj->signature_size_);
    if (obj->topic)
        noise_protobuf_write_string(pbuf, 4, obj->topic, obj->topic_size_);
    if (obj->seqno)
        noise_protobuf_write_bytes(pbuf, 3, obj->seqno, obj->seqno_size_);
    if (obj->data)
        noise_protobuf_write_bytes(pbuf, 2, obj->data, obj->data_size_);
    if (obj->from)
        noise_protobuf_write_bytes(pbuf, 1, obj->from, obj->from_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_Message_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_Message **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_Message_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->from, (*obj)->from_size_);
                (*obj)->from = 0;
                (*obj)->from_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 1, &((*obj)->from), 0, &((*obj)->from_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->data, (*obj)->data_size_);
                (*obj)->data = 0;
                (*obj)->data_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 2, &((*obj)->data), 0, &((*obj)->data_size_));
            } break;
            case 3: {
                noise_protobuf_free_memory((*obj)->seqno, (*obj)->seqno_size_);
                (*obj)->seqno = 0;
                (*obj)->seqno_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 3, &((*obj)->seqno), 0, &((*obj)->seqno_size_));
            } break;
            case 4: {
                noise_protobuf_free_memory((*obj)->topic, (*obj)->topic_size_);
                (*obj)->topic = 0;
                (*obj)->topic_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 4, &((*obj)->topic), 0, &((*obj)->topic_size_));
            } break;
            case 5: {
                noise_protobuf_free_memory((*obj)->signature, (*obj)->signature_size_);
                (*obj)->signature = 0;
                (*obj)->signature_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 5, &((*obj)->signature), 0, &((*obj)->signature_size_));
            } break;
            case 6: {
                noise_protobuf_free_memory((*obj)->key, (*obj)->key_size_);
                (*obj)->key = 0;
                (*obj)->key_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 6, &((*obj)->key), 0, &((*obj)->key_size_));
            } break;
            case 7: {
                char *value = 0;
                size_t len = 0;
                noise_protobuf_read_alloc_string(pbuf, 7, &value, 0, &len);
                libp2p_gossipsub_Message_add_topic_ids(*obj, value, len);
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_Message_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_Message_clear_from(libp2p_gossipsub_Message *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->from, obj->from_size_);
        obj->from = 0;
        obj->from_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_from(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->from != 0) : 0;
}

const void *libp2p_gossipsub_Message_get_from(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->from : 0;
}

size_t libp2p_gossipsub_Message_get_size_from(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->from_size_ : 0;
}

int libp2p_gossipsub_Message_set_from(libp2p_gossipsub_Message *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->from, obj->from_size_);
        obj->from = (void *)malloc(size ? size : 1);
        if (obj->from) {
            memcpy(obj->from, value, size);
            obj->from_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->from_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_clear_data(libp2p_gossipsub_Message *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->data, obj->data_size_);
        obj->data = 0;
        obj->data_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_data(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->data != 0) : 0;
}

const void *libp2p_gossipsub_Message_get_data(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->data : 0;
}

size_t libp2p_gossipsub_Message_get_size_data(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->data_size_ : 0;
}

int libp2p_gossipsub_Message_set_data(libp2p_gossipsub_Message *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->data, obj->data_size_);
        obj->data = (void *)malloc(size ? size : 1);
        if (obj->data) {
            memcpy(obj->data, value, size);
            obj->data_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->data_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_clear_seqno(libp2p_gossipsub_Message *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->seqno, obj->seqno_size_);
        obj->seqno = 0;
        obj->seqno_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_seqno(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->seqno != 0) : 0;
}

const void *libp2p_gossipsub_Message_get_seqno(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->seqno : 0;
}

size_t libp2p_gossipsub_Message_get_size_seqno(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->seqno_size_ : 0;
}

int libp2p_gossipsub_Message_set_seqno(libp2p_gossipsub_Message *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->seqno, obj->seqno_size_);
        obj->seqno = (void *)malloc(size ? size : 1);
        if (obj->seqno) {
            memcpy(obj->seqno, value, size);
            obj->seqno_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->seqno_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_clear_topic(libp2p_gossipsub_Message *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = 0;
        obj->topic_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_topic(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->topic != 0) : 0;
}

const char *libp2p_gossipsub_Message_get_topic(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->topic : 0;
}

size_t libp2p_gossipsub_Message_get_size_topic(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->topic_size_ : 0;
}

int libp2p_gossipsub_Message_set_topic(libp2p_gossipsub_Message *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = (char *)malloc(size + 1);
        if (obj->topic) {
            memcpy(obj->topic, value, size);
            obj->topic[size] = 0;
            obj->topic_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_clear_topic_ids(libp2p_gossipsub_Message *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->topic_ids_count_; ++index)
            noise_protobuf_free_memory(obj->topic_ids[index], obj->topic_ids_size_[index]);
        noise_protobuf_free_memory(obj->topic_ids, obj->topic_ids_max_ * sizeof(char *));
        noise_protobuf_free_memory(obj->topic_ids_size_, obj->topic_ids_max_ * sizeof(size_t));
        obj->topic_ids = 0;
        obj->topic_ids_count_ = 0;
        obj->topic_ids_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_topic_ids(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->topic_ids_count_ != 0) : 0;
}

size_t libp2p_gossipsub_Message_count_topic_ids(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->topic_ids_count_ : 0;
}

const char *libp2p_gossipsub_Message_get_at_topic_ids(const libp2p_gossipsub_Message *obj, size_t index)
{
    if (obj && index < obj->topic_ids_count_)
        return obj->topic_ids[index];
    else
        return 0;
}

size_t libp2p_gossipsub_Message_get_size_at_topic_ids(const libp2p_gossipsub_Message *obj, size_t index)
{
    if (obj && index < obj->topic_ids_count_)
        return obj->topic_ids_size_[index];
    else
        return 0;
}

int libp2p_gossipsub_Message_add_topic_ids(libp2p_gossipsub_Message *obj, const char *value, size_t size)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_add_to_string_array(&(obj->topic_ids), &(obj->topic_ids_size_), &(obj->topic_ids_count_), &(obj->topic_ids_max_), value, size);
}

int libp2p_gossipsub_Message_clear_signature(libp2p_gossipsub_Message *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->signature, obj->signature_size_);
        obj->signature = 0;
        obj->signature_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_signature(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->signature != 0) : 0;
}

const void *libp2p_gossipsub_Message_get_signature(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->signature : 0;
}

size_t libp2p_gossipsub_Message_get_size_signature(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->signature_size_ : 0;
}

int libp2p_gossipsub_Message_set_signature(libp2p_gossipsub_Message *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->signature, obj->signature_size_);
        obj->signature = (void *)malloc(size ? size : 1);
        if (obj->signature) {
            memcpy(obj->signature, value, size);
            obj->signature_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->signature_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_clear_key(libp2p_gossipsub_Message *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->key, obj->key_size_);
        obj->key = 0;
        obj->key_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_Message_has_key(const libp2p_gossipsub_Message *obj)
{
    return obj ? (obj->key != 0) : 0;
}

const void *libp2p_gossipsub_Message_get_key(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->key : 0;
}

size_t libp2p_gossipsub_Message_get_size_key(const libp2p_gossipsub_Message *obj)
{
    return obj ? obj->key_size_ : 0;
}

int libp2p_gossipsub_Message_set_key(libp2p_gossipsub_Message *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->key, obj->key_size_);
        obj->key = (void *)malloc(size ? size : 1);
        if (obj->key) {
            memcpy(obj->key, value, size);
            obj->key_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->key_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_new(libp2p_gossipsub_ControlMessage **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlMessage *)calloc(1, sizeof(libp2p_gossipsub_ControlMessage));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_free(libp2p_gossipsub_ControlMessage *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    for (index = 0; index < obj->ihave_count_; ++index)
        libp2p_gossipsub_ControlIHave_free(obj->ihave[index]);
    noise_protobuf_free_memory(obj->ihave, obj->ihave_max_ * sizeof(libp2p_gossipsub_ControlIHave *));
    for (index = 0; index < obj->iwant_count_; ++index)
        libp2p_gossipsub_ControlIWant_free(obj->iwant[index]);
    noise_protobuf_free_memory(obj->iwant, obj->iwant_max_ * sizeof(libp2p_gossipsub_ControlIWant *));
    for (index = 0; index < obj->graft_count_; ++index)
        libp2p_gossipsub_ControlGraft_free(obj->graft[index]);
    noise_protobuf_free_memory(obj->graft, obj->graft_max_ * sizeof(libp2p_gossipsub_ControlGraft *));
    for (index = 0; index < obj->prune_count_; ++index)
        libp2p_gossipsub_ControlPrune_free(obj->prune[index]);
    noise_protobuf_free_memory(obj->prune, obj->prune_max_ * sizeof(libp2p_gossipsub_ControlPrune *));
    for (index = 0; index < obj->idontwant_count_; ++index)
        libp2p_gossipsub_ControlIDontWant_free(obj->idontwant[index]);
    noise_protobuf_free_memory(obj->idontwant, obj->idontwant_max_ * sizeof(libp2p_gossipsub_ControlIDontWant *));
    libp2p_gossipsub_ControlExtensions_free(obj->extensions);
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlMessage));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlMessage *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->extensions)
        libp2p_gossipsub_ControlExtensions_write(pbuf, 6, obj->extensions);
    for (index = obj->idontwant_count_; index > 0; --index)
        libp2p_gossipsub_ControlIDontWant_write(pbuf, 5, obj->idontwant[index - 1]);
    for (index = obj->prune_count_; index > 0; --index)
        libp2p_gossipsub_ControlPrune_write(pbuf, 4, obj->prune[index - 1]);
    for (index = obj->graft_count_; index > 0; --index)
        libp2p_gossipsub_ControlGraft_write(pbuf, 3, obj->graft[index - 1]);
    for (index = obj->iwant_count_; index > 0; --index)
        libp2p_gossipsub_ControlIWant_write(pbuf, 2, obj->iwant[index - 1]);
    for (index = obj->ihave_count_; index > 0; --index)
        libp2p_gossipsub_ControlIHave_write(pbuf, 1, obj->ihave[index - 1]);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlMessage_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlMessage **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlMessage_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                libp2p_gossipsub_ControlIHave *value = 0;
                int err;
                libp2p_gossipsub_ControlIHave_read(pbuf, 1, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->ihave), &((*obj)->ihave_count_), &((*obj)->ihave_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 2: {
                libp2p_gossipsub_ControlIWant *value = 0;
                int err;
                libp2p_gossipsub_ControlIWant_read(pbuf, 2, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->iwant), &((*obj)->iwant_count_), &((*obj)->iwant_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 3: {
                libp2p_gossipsub_ControlGraft *value = 0;
                int err;
                libp2p_gossipsub_ControlGraft_read(pbuf, 3, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->graft), &((*obj)->graft_count_), &((*obj)->graft_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 4: {
                libp2p_gossipsub_ControlPrune *value = 0;
                int err;
                libp2p_gossipsub_ControlPrune_read(pbuf, 4, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->prune), &((*obj)->prune_count_), &((*obj)->prune_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 5: {
                libp2p_gossipsub_ControlIDontWant *value = 0;
                int err;
                libp2p_gossipsub_ControlIDontWant_read(pbuf, 5, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->idontwant), &((*obj)->idontwant_count_), &((*obj)->idontwant_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 6: {
                libp2p_gossipsub_ControlExtensions_free((*obj)->extensions);
                (*obj)->extensions = 0;
                libp2p_gossipsub_ControlExtensions_read(pbuf, 6, &((*obj)->extensions));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlMessage_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlMessage_clear_ihave(libp2p_gossipsub_ControlMessage *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->ihave_count_; ++index)
            libp2p_gossipsub_ControlIHave_free(obj->ihave[index]);
        noise_protobuf_free_memory(obj->ihave, obj->ihave_max_ * sizeof(libp2p_gossipsub_ControlIHave *));
        obj->ihave = 0;
        obj->ihave_count_ = 0;
        obj->ihave_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_has_ihave(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? (obj->ihave_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlMessage_count_ihave(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? obj->ihave_count_ : 0;
}

libp2p_gossipsub_ControlIHave *libp2p_gossipsub_ControlMessage_get_at_ihave(const libp2p_gossipsub_ControlMessage *obj, size_t index)
{
    if (obj && index < obj->ihave_count_)
        return obj->ihave[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlMessage_add_ihave(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlIHave **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlIHave_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->ihave), &(obj->ihave_count_), &(obj->ihave_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlIHave_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_insert_ihave(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlIHave *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->ihave), &(obj->ihave_count_), &(obj->ihave_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_ControlMessage_clear_iwant(libp2p_gossipsub_ControlMessage *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->iwant_count_; ++index)
            libp2p_gossipsub_ControlIWant_free(obj->iwant[index]);
        noise_protobuf_free_memory(obj->iwant, obj->iwant_max_ * sizeof(libp2p_gossipsub_ControlIWant *));
        obj->iwant = 0;
        obj->iwant_count_ = 0;
        obj->iwant_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_has_iwant(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? (obj->iwant_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlMessage_count_iwant(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? obj->iwant_count_ : 0;
}

libp2p_gossipsub_ControlIWant *libp2p_gossipsub_ControlMessage_get_at_iwant(const libp2p_gossipsub_ControlMessage *obj, size_t index)
{
    if (obj && index < obj->iwant_count_)
        return obj->iwant[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlMessage_add_iwant(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlIWant **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlIWant_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->iwant), &(obj->iwant_count_), &(obj->iwant_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlIWant_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_insert_iwant(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlIWant *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->iwant), &(obj->iwant_count_), &(obj->iwant_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_ControlMessage_clear_graft(libp2p_gossipsub_ControlMessage *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->graft_count_; ++index)
            libp2p_gossipsub_ControlGraft_free(obj->graft[index]);
        noise_protobuf_free_memory(obj->graft, obj->graft_max_ * sizeof(libp2p_gossipsub_ControlGraft *));
        obj->graft = 0;
        obj->graft_count_ = 0;
        obj->graft_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_has_graft(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? (obj->graft_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlMessage_count_graft(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? obj->graft_count_ : 0;
}

libp2p_gossipsub_ControlGraft *libp2p_gossipsub_ControlMessage_get_at_graft(const libp2p_gossipsub_ControlMessage *obj, size_t index)
{
    if (obj && index < obj->graft_count_)
        return obj->graft[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlMessage_add_graft(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlGraft **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlGraft_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->graft), &(obj->graft_count_), &(obj->graft_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlGraft_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_insert_graft(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlGraft *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->graft), &(obj->graft_count_), &(obj->graft_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_ControlMessage_clear_prune(libp2p_gossipsub_ControlMessage *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->prune_count_; ++index)
            libp2p_gossipsub_ControlPrune_free(obj->prune[index]);
        noise_protobuf_free_memory(obj->prune, obj->prune_max_ * sizeof(libp2p_gossipsub_ControlPrune *));
        obj->prune = 0;
        obj->prune_count_ = 0;
        obj->prune_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_has_prune(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? (obj->prune_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlMessage_count_prune(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? obj->prune_count_ : 0;
}

libp2p_gossipsub_ControlPrune *libp2p_gossipsub_ControlMessage_get_at_prune(const libp2p_gossipsub_ControlMessage *obj, size_t index)
{
    if (obj && index < obj->prune_count_)
        return obj->prune[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlMessage_add_prune(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlPrune **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlPrune_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->prune), &(obj->prune_count_), &(obj->prune_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlPrune_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_insert_prune(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlPrune *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->prune), &(obj->prune_count_), &(obj->prune_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_ControlMessage_clear_idontwant(libp2p_gossipsub_ControlMessage *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->idontwant_count_; ++index)
            libp2p_gossipsub_ControlIDontWant_free(obj->idontwant[index]);
        noise_protobuf_free_memory(obj->idontwant, obj->idontwant_max_ * sizeof(libp2p_gossipsub_ControlIDontWant *));
        obj->idontwant = 0;
        obj->idontwant_count_ = 0;
        obj->idontwant_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_has_idontwant(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? (obj->idontwant_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlMessage_count_idontwant(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? obj->idontwant_count_ : 0;
}

libp2p_gossipsub_ControlIDontWant *libp2p_gossipsub_ControlMessage_get_at_idontwant(const libp2p_gossipsub_ControlMessage *obj, size_t index)
{
    if (obj && index < obj->idontwant_count_)
        return obj->idontwant[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlMessage_add_idontwant(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlIDontWant **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlIDontWant_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->idontwant), &(obj->idontwant_count_), &(obj->idontwant_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlIDontWant_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlMessage_insert_idontwant(libp2p_gossipsub_ControlMessage *obj, size_t index, libp2p_gossipsub_ControlIDontWant *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->idontwant), &(obj->idontwant_count_), &(obj->idontwant_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_ControlMessage_clear_extensions(libp2p_gossipsub_ControlMessage *obj)
{
    if (obj) {
        libp2p_gossipsub_ControlExtensions_free(obj->extensions);
        obj->extensions = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlMessage_has_extensions(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? (obj->extensions != 0) : 0;
}

libp2p_gossipsub_ControlExtensions *libp2p_gossipsub_ControlMessage_get_extensions(const libp2p_gossipsub_ControlMessage *obj)
{
    return obj ? obj->extensions : 0;
}

int libp2p_gossipsub_ControlMessage_get_new_extensions(libp2p_gossipsub_ControlMessage *obj, libp2p_gossipsub_ControlExtensions **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlExtensions_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    libp2p_gossipsub_ControlExtensions_free(obj->extensions);
    obj->extensions = *value;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIHave_new(libp2p_gossipsub_ControlIHave **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlIHave *)calloc(1, sizeof(libp2p_gossipsub_ControlIHave));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIHave_free(libp2p_gossipsub_ControlIHave *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->topic, obj->topic_size_);
    noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
    for (index = 0; index < obj->message_ids_count_; ++index)
        noise_protobuf_free_memory(obj->message_ids[index], obj->message_ids_size_[index]);
    noise_protobuf_free_memory(obj->message_ids, obj->message_ids_max_ * sizeof(void *));
    noise_protobuf_free_memory(obj->message_ids_size_, obj->message_ids_max_ * sizeof(size_t));
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlIHave));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIHave_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlIHave *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->topic_id)
        noise_protobuf_write_string(pbuf, 3, obj->topic_id, obj->topic_id_size_);
    for (index = obj->message_ids_count_; index > 0; --index)
        noise_protobuf_write_bytes(pbuf, 2, obj->message_ids[index - 1], obj->message_ids_size_[index - 1]);
    if (obj->topic)
        noise_protobuf_write_string(pbuf, 1, obj->topic, obj->topic_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlIHave_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlIHave **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlIHave_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->topic, (*obj)->topic_size_);
                (*obj)->topic = 0;
                (*obj)->topic_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->topic), 0, &((*obj)->topic_size_));
            } break;
            case 2: {
                void *value = 0;
                size_t len = 0;
noise_protobuf_read_alloc_bytes(pbuf, 2, &value, 0, &len);
                libp2p_gossipsub_ControlIHave_add_message_ids(*obj, value, len);
            } break;
            case 3: {
                noise_protobuf_free_memory((*obj)->topic_id, (*obj)->topic_id_size_);
                (*obj)->topic_id = 0;
                (*obj)->topic_id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 3, &((*obj)->topic_id), 0, &((*obj)->topic_id_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlIHave_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlIHave_clear_topic(libp2p_gossipsub_ControlIHave *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = 0;
        obj->topic_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIHave_has_topic(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? (obj->topic != 0) : 0;
}

const char *libp2p_gossipsub_ControlIHave_get_topic(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? obj->topic : 0;
}

size_t libp2p_gossipsub_ControlIHave_get_size_topic(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? obj->topic_size_ : 0;
}

int libp2p_gossipsub_ControlIHave_set_topic(libp2p_gossipsub_ControlIHave *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = (char *)malloc(size + 1);
        if (obj->topic) {
            memcpy(obj->topic, value, size);
            obj->topic[size] = 0;
            obj->topic_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIHave_clear_topic_id(libp2p_gossipsub_ControlIHave *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = 0;
        obj->topic_id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIHave_has_topic_id(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? (obj->topic_id != 0) : 0;
}

const char *libp2p_gossipsub_ControlIHave_get_topic_id(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? obj->topic_id : 0;
}

size_t libp2p_gossipsub_ControlIHave_get_size_topic_id(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? obj->topic_id_size_ : 0;
}

int libp2p_gossipsub_ControlIHave_set_topic_id(libp2p_gossipsub_ControlIHave *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = (char *)malloc(size + 1);
        if (obj->topic_id) {
            memcpy(obj->topic_id, value, size);
            obj->topic_id[size] = 0;
            obj->topic_id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIHave_clear_message_ids(libp2p_gossipsub_ControlIHave *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->message_ids_count_; ++index)
            noise_protobuf_free_memory(obj->message_ids[index], obj->message_ids_size_[index]);
        noise_protobuf_free_memory(obj->message_ids, obj->message_ids_max_ * sizeof(void *));
        noise_protobuf_free_memory(obj->message_ids_size_, obj->message_ids_max_ * sizeof(size_t));
        obj->message_ids = 0;
        obj->message_ids_count_ = 0;
        obj->message_ids_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIHave_has_message_ids(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? (obj->message_ids_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlIHave_count_message_ids(const libp2p_gossipsub_ControlIHave *obj)
{
    return obj ? obj->message_ids_count_ : 0;
}

const void *libp2p_gossipsub_ControlIHave_get_at_message_ids(const libp2p_gossipsub_ControlIHave *obj, size_t index)
{
    if (obj && index < obj->message_ids_count_)
        return obj->message_ids[index];
    else
        return 0;
}

size_t libp2p_gossipsub_ControlIHave_get_size_at_message_ids(const libp2p_gossipsub_ControlIHave *obj, size_t index)
{
    if (obj && index < obj->message_ids_count_)
        return obj->message_ids_size_[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlIHave_add_message_ids(libp2p_gossipsub_ControlIHave *obj, const void *value, size_t size)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_add_to_bytes_array(&(obj->message_ids), &(obj->message_ids_size_), &(obj->message_ids_count_), &(obj->message_ids_max_), value, size);
}

int libp2p_gossipsub_ControlIWant_new(libp2p_gossipsub_ControlIWant **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlIWant *)calloc(1, sizeof(libp2p_gossipsub_ControlIWant));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIWant_free(libp2p_gossipsub_ControlIWant *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    for (index = 0; index < obj->message_ids_count_; ++index)
        noise_protobuf_free_memory(obj->message_ids[index], obj->message_ids_size_[index]);
    noise_protobuf_free_memory(obj->message_ids, obj->message_ids_max_ * sizeof(void *));
    noise_protobuf_free_memory(obj->message_ids_size_, obj->message_ids_max_ * sizeof(size_t));
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlIWant));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIWant_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlIWant *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->message_ids_count_; index > 0; --index)
        noise_protobuf_write_bytes(pbuf, 1, obj->message_ids[index - 1], obj->message_ids_size_[index - 1]);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlIWant_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlIWant **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlIWant_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                void *value = 0;
                size_t len = 0;
noise_protobuf_read_alloc_bytes(pbuf, 1, &value, 0, &len);
                libp2p_gossipsub_ControlIWant_add_message_ids(*obj, value, len);
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlIWant_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlIWant_clear_message_ids(libp2p_gossipsub_ControlIWant *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->message_ids_count_; ++index)
            noise_protobuf_free_memory(obj->message_ids[index], obj->message_ids_size_[index]);
        noise_protobuf_free_memory(obj->message_ids, obj->message_ids_max_ * sizeof(void *));
        noise_protobuf_free_memory(obj->message_ids_size_, obj->message_ids_max_ * sizeof(size_t));
        obj->message_ids = 0;
        obj->message_ids_count_ = 0;
        obj->message_ids_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIWant_has_message_ids(const libp2p_gossipsub_ControlIWant *obj)
{
    return obj ? (obj->message_ids_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlIWant_count_message_ids(const libp2p_gossipsub_ControlIWant *obj)
{
    return obj ? obj->message_ids_count_ : 0;
}

const void *libp2p_gossipsub_ControlIWant_get_at_message_ids(const libp2p_gossipsub_ControlIWant *obj, size_t index)
{
    if (obj && index < obj->message_ids_count_)
        return obj->message_ids[index];
    else
        return 0;
}

size_t libp2p_gossipsub_ControlIWant_get_size_at_message_ids(const libp2p_gossipsub_ControlIWant *obj, size_t index)
{
    if (obj && index < obj->message_ids_count_)
        return obj->message_ids_size_[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlIWant_add_message_ids(libp2p_gossipsub_ControlIWant *obj, const void *value, size_t size)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_add_to_bytes_array(&(obj->message_ids), &(obj->message_ids_size_), &(obj->message_ids_count_), &(obj->message_ids_max_), value, size);
}

int libp2p_gossipsub_ControlGraft_new(libp2p_gossipsub_ControlGraft **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlGraft *)calloc(1, sizeof(libp2p_gossipsub_ControlGraft));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlGraft_free(libp2p_gossipsub_ControlGraft *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->topic, obj->topic_size_);
    noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlGraft));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlGraft_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlGraft *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->topic_id)
        noise_protobuf_write_string(pbuf, 2, obj->topic_id, obj->topic_id_size_);
    if (obj->topic)
        noise_protobuf_write_string(pbuf, 1, obj->topic, obj->topic_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlGraft_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlGraft **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlGraft_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->topic, (*obj)->topic_size_);
                (*obj)->topic = 0;
                (*obj)->topic_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->topic), 0, &((*obj)->topic_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->topic_id, (*obj)->topic_id_size_);
                (*obj)->topic_id = 0;
                (*obj)->topic_id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->topic_id), 0, &((*obj)->topic_id_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlGraft_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlGraft_clear_topic(libp2p_gossipsub_ControlGraft *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = 0;
        obj->topic_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlGraft_has_topic(const libp2p_gossipsub_ControlGraft *obj)
{
    return obj ? (obj->topic != 0) : 0;
}

const char *libp2p_gossipsub_ControlGraft_get_topic(const libp2p_gossipsub_ControlGraft *obj)
{
    return obj ? obj->topic : 0;
}

size_t libp2p_gossipsub_ControlGraft_get_size_topic(const libp2p_gossipsub_ControlGraft *obj)
{
    return obj ? obj->topic_size_ : 0;
}

int libp2p_gossipsub_ControlGraft_set_topic(libp2p_gossipsub_ControlGraft *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = (char *)malloc(size + 1);
        if (obj->topic) {
            memcpy(obj->topic, value, size);
            obj->topic[size] = 0;
            obj->topic_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlGraft_clear_topic_id(libp2p_gossipsub_ControlGraft *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = 0;
        obj->topic_id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlGraft_has_topic_id(const libp2p_gossipsub_ControlGraft *obj)
{
    return obj ? (obj->topic_id != 0) : 0;
}

const char *libp2p_gossipsub_ControlGraft_get_topic_id(const libp2p_gossipsub_ControlGraft *obj)
{
    return obj ? obj->topic_id : 0;
}

size_t libp2p_gossipsub_ControlGraft_get_size_topic_id(const libp2p_gossipsub_ControlGraft *obj)
{
    return obj ? obj->topic_id_size_ : 0;
}

int libp2p_gossipsub_ControlGraft_set_topic_id(libp2p_gossipsub_ControlGraft *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = (char *)malloc(size + 1);
        if (obj->topic_id) {
            memcpy(obj->topic_id, value, size);
            obj->topic_id[size] = 0;
            obj->topic_id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_new(libp2p_gossipsub_ControlPrune **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlPrune *)calloc(1, sizeof(libp2p_gossipsub_ControlPrune));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlPrune_free(libp2p_gossipsub_ControlPrune *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->topic, obj->topic_size_);
    noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
    for (index = 0; index < obj->peers_count_; ++index)
        libp2p_gossipsub_PeerInfo_free(obj->peers[index]);
    noise_protobuf_free_memory(obj->peers, obj->peers_max_ * sizeof(libp2p_gossipsub_PeerInfo *));
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlPrune));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlPrune_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlPrune *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->topic_id)
        noise_protobuf_write_string(pbuf, 4, obj->topic_id, obj->topic_id_size_);
    if (obj->backoff)
        noise_protobuf_write_uint64(pbuf, 3, obj->backoff);
    for (index = obj->peers_count_; index > 0; --index)
        libp2p_gossipsub_PeerInfo_write(pbuf, 2, obj->peers[index - 1]);
    if (obj->topic)
        noise_protobuf_write_string(pbuf, 1, obj->topic, obj->topic_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlPrune_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlPrune **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlPrune_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->topic, (*obj)->topic_size_);
                (*obj)->topic = 0;
                (*obj)->topic_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->topic), 0, &((*obj)->topic_size_));
            } break;
            case 2: {
                libp2p_gossipsub_PeerInfo *value = 0;
                int err;
                libp2p_gossipsub_PeerInfo_read(pbuf, 2, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->peers), &((*obj)->peers_count_), &((*obj)->peers_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 3: {
                noise_protobuf_read_uint64(pbuf, 3, &((*obj)->backoff));
            } break;
            case 4: {
                noise_protobuf_free_memory((*obj)->topic_id, (*obj)->topic_id_size_);
                (*obj)->topic_id = 0;
                (*obj)->topic_id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 4, &((*obj)->topic_id), 0, &((*obj)->topic_id_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlPrune_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlPrune_clear_topic(libp2p_gossipsub_ControlPrune *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = 0;
        obj->topic_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_has_topic(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? (obj->topic != 0) : 0;
}

const char *libp2p_gossipsub_ControlPrune_get_topic(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? obj->topic : 0;
}

size_t libp2p_gossipsub_ControlPrune_get_size_topic(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? obj->topic_size_ : 0;
}

int libp2p_gossipsub_ControlPrune_set_topic(libp2p_gossipsub_ControlPrune *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic, obj->topic_size_);
        obj->topic = (char *)malloc(size + 1);
        if (obj->topic) {
            memcpy(obj->topic, value, size);
            obj->topic[size] = 0;
            obj->topic_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_clear_topic_id(libp2p_gossipsub_ControlPrune *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = 0;
        obj->topic_id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_has_topic_id(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? (obj->topic_id != 0) : 0;
}

const char *libp2p_gossipsub_ControlPrune_get_topic_id(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? obj->topic_id : 0;
}

size_t libp2p_gossipsub_ControlPrune_get_size_topic_id(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? obj->topic_id_size_ : 0;
}

int libp2p_gossipsub_ControlPrune_set_topic_id(libp2p_gossipsub_ControlPrune *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->topic_id, obj->topic_id_size_);
        obj->topic_id = (char *)malloc(size + 1);
        if (obj->topic_id) {
            memcpy(obj->topic_id, value, size);
            obj->topic_id[size] = 0;
            obj->topic_id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->topic_id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_clear_peers(libp2p_gossipsub_ControlPrune *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->peers_count_; ++index)
            libp2p_gossipsub_PeerInfo_free(obj->peers[index]);
        noise_protobuf_free_memory(obj->peers, obj->peers_max_ * sizeof(libp2p_gossipsub_PeerInfo *));
        obj->peers = 0;
        obj->peers_count_ = 0;
        obj->peers_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_has_peers(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? (obj->peers_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlPrune_count_peers(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? obj->peers_count_ : 0;
}

libp2p_gossipsub_PeerInfo *libp2p_gossipsub_ControlPrune_get_at_peers(const libp2p_gossipsub_ControlPrune *obj, size_t index)
{
    if (obj && index < obj->peers_count_)
        return obj->peers[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlPrune_add_peers(libp2p_gossipsub_ControlPrune *obj, libp2p_gossipsub_PeerInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_PeerInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->peers), &(obj->peers_count_), &(obj->peers_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_PeerInfo_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlPrune_insert_peers(libp2p_gossipsub_ControlPrune *obj, size_t index, libp2p_gossipsub_PeerInfo *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->peers), &(obj->peers_count_), &(obj->peers_max_), index, &value, sizeof(value));
}

int libp2p_gossipsub_ControlPrune_clear_backoff(libp2p_gossipsub_ControlPrune *obj)
{
    if (obj) {
        obj->backoff = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlPrune_has_backoff(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? (obj->backoff != 0) : 0;
}

uint64_t libp2p_gossipsub_ControlPrune_get_backoff(const libp2p_gossipsub_ControlPrune *obj)
{
    return obj ? obj->backoff : 0;
}

int libp2p_gossipsub_ControlPrune_set_backoff(libp2p_gossipsub_ControlPrune *obj, uint64_t value)
{
    if (obj) {
        obj->backoff = value;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIDontWant_new(libp2p_gossipsub_ControlIDontWant **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlIDontWant *)calloc(1, sizeof(libp2p_gossipsub_ControlIDontWant));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIDontWant_free(libp2p_gossipsub_ControlIDontWant *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    for (index = 0; index < obj->message_ids_count_; ++index)
        noise_protobuf_free_memory(obj->message_ids[index], obj->message_ids_size_[index]);
    noise_protobuf_free_memory(obj->message_ids, obj->message_ids_max_ * sizeof(void *));
    noise_protobuf_free_memory(obj->message_ids_size_, obj->message_ids_max_ * sizeof(size_t));
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlIDontWant));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlIDontWant_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlIDontWant *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->message_ids_count_; index > 0; --index)
        noise_protobuf_write_bytes(pbuf, 1, obj->message_ids[index - 1], obj->message_ids_size_[index - 1]);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlIDontWant_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlIDontWant **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlIDontWant_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                void *value = 0;
                size_t len = 0;
noise_protobuf_read_alloc_bytes(pbuf, 1, &value, 0, &len);
                libp2p_gossipsub_ControlIDontWant_add_message_ids(*obj, value, len);
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlIDontWant_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlIDontWant_clear_message_ids(libp2p_gossipsub_ControlIDontWant *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->message_ids_count_; ++index)
            noise_protobuf_free_memory(obj->message_ids[index], obj->message_ids_size_[index]);
        noise_protobuf_free_memory(obj->message_ids, obj->message_ids_max_ * sizeof(void *));
        noise_protobuf_free_memory(obj->message_ids_size_, obj->message_ids_max_ * sizeof(size_t));
        obj->message_ids = 0;
        obj->message_ids_count_ = 0;
        obj->message_ids_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlIDontWant_has_message_ids(const libp2p_gossipsub_ControlIDontWant *obj)
{
    return obj ? (obj->message_ids_count_ != 0) : 0;
}

size_t libp2p_gossipsub_ControlIDontWant_count_message_ids(const libp2p_gossipsub_ControlIDontWant *obj)
{
    return obj ? obj->message_ids_count_ : 0;
}

const void *libp2p_gossipsub_ControlIDontWant_get_at_message_ids(const libp2p_gossipsub_ControlIDontWant *obj, size_t index)
{
    if (obj && index < obj->message_ids_count_)
        return obj->message_ids[index];
    else
        return 0;
}

size_t libp2p_gossipsub_ControlIDontWant_get_size_at_message_ids(const libp2p_gossipsub_ControlIDontWant *obj, size_t index)
{
    if (obj && index < obj->message_ids_count_)
        return obj->message_ids_size_[index];
    else
        return 0;
}

int libp2p_gossipsub_ControlIDontWant_add_message_ids(libp2p_gossipsub_ControlIDontWant *obj, const void *value, size_t size)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_add_to_bytes_array(&(obj->message_ids), &(obj->message_ids_size_), &(obj->message_ids_count_), &(obj->message_ids_max_), value, size);
}

int libp2p_gossipsub_ControlExtensions_new(libp2p_gossipsub_ControlExtensions **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_ControlExtensions *)calloc(1, sizeof(libp2p_gossipsub_ControlExtensions));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlExtensions_free(libp2p_gossipsub_ControlExtensions *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_ControlExtensions));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_ControlExtensions_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_ControlExtensions *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->placeholder)
        noise_protobuf_write_bool(pbuf, 1, obj->placeholder);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_ControlExtensions_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_ControlExtensions **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_ControlExtensions_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_read_bool(pbuf, 1, &((*obj)->placeholder));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_ControlExtensions_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_ControlExtensions_clear_placeholder(libp2p_gossipsub_ControlExtensions *obj)
{
    if (obj) {
        obj->placeholder = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_ControlExtensions_has_placeholder(const libp2p_gossipsub_ControlExtensions *obj)
{
    return obj ? (obj->placeholder != 0) : 0;
}

int libp2p_gossipsub_ControlExtensions_get_placeholder(const libp2p_gossipsub_ControlExtensions *obj)
{
    return obj ? obj->placeholder : 0;
}

int libp2p_gossipsub_ControlExtensions_set_placeholder(libp2p_gossipsub_ControlExtensions *obj, int value)
{
    if (obj) {
        obj->placeholder = value;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_PeerInfo_new(libp2p_gossipsub_PeerInfo **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (libp2p_gossipsub_PeerInfo *)calloc(1, sizeof(libp2p_gossipsub_PeerInfo));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_PeerInfo_free(libp2p_gossipsub_PeerInfo *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->peer_id, obj->peer_id_size_);
    noise_protobuf_free_memory(obj->signed_peer_record, obj->signed_peer_record_size_);
    noise_protobuf_free_memory(obj, sizeof(libp2p_gossipsub_PeerInfo));
    return NOISE_ERROR_NONE;
}

int libp2p_gossipsub_PeerInfo_write(NoiseProtobuf *pbuf, int tag, const libp2p_gossipsub_PeerInfo *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->signed_peer_record)
        noise_protobuf_write_bytes(pbuf, 2, obj->signed_peer_record, obj->signed_peer_record_size_);
    if (obj->peer_id)
        noise_protobuf_write_bytes(pbuf, 1, obj->peer_id, obj->peer_id_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int libp2p_gossipsub_PeerInfo_read(NoiseProtobuf *pbuf, int tag, libp2p_gossipsub_PeerInfo **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = libp2p_gossipsub_PeerInfo_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->peer_id, (*obj)->peer_id_size_);
                (*obj)->peer_id = 0;
                (*obj)->peer_id_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 1, &((*obj)->peer_id), 0, &((*obj)->peer_id_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->signed_peer_record, (*obj)->signed_peer_record_size_);
                (*obj)->signed_peer_record = 0;
                (*obj)->signed_peer_record_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 2, &((*obj)->signed_peer_record), 0, &((*obj)->signed_peer_record_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        libp2p_gossipsub_PeerInfo_free(*obj);
        *obj = 0;
    }
    return err;
}

int libp2p_gossipsub_PeerInfo_clear_peer_id(libp2p_gossipsub_PeerInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->peer_id, obj->peer_id_size_);
        obj->peer_id = 0;
        obj->peer_id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_PeerInfo_has_peer_id(const libp2p_gossipsub_PeerInfo *obj)
{
    return obj ? (obj->peer_id != 0) : 0;
}

const void *libp2p_gossipsub_PeerInfo_get_peer_id(const libp2p_gossipsub_PeerInfo *obj)
{
    return obj ? obj->peer_id : 0;
}

size_t libp2p_gossipsub_PeerInfo_get_size_peer_id(const libp2p_gossipsub_PeerInfo *obj)
{
    return obj ? obj->peer_id_size_ : 0;
}

int libp2p_gossipsub_PeerInfo_set_peer_id(libp2p_gossipsub_PeerInfo *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->peer_id, obj->peer_id_size_);
        obj->peer_id = (void *)malloc(size ? size : 1);
        if (obj->peer_id) {
            memcpy(obj->peer_id, value, size);
            obj->peer_id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->peer_id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_PeerInfo_clear_signed_peer_record(libp2p_gossipsub_PeerInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->signed_peer_record, obj->signed_peer_record_size_);
        obj->signed_peer_record = 0;
        obj->signed_peer_record_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int libp2p_gossipsub_PeerInfo_has_signed_peer_record(const libp2p_gossipsub_PeerInfo *obj)
{
    return obj ? (obj->signed_peer_record != 0) : 0;
}

const void *libp2p_gossipsub_PeerInfo_get_signed_peer_record(const libp2p_gossipsub_PeerInfo *obj)
{
    return obj ? obj->signed_peer_record : 0;
}

size_t libp2p_gossipsub_PeerInfo_get_size_signed_peer_record(const libp2p_gossipsub_PeerInfo *obj)
{
    return obj ? obj->signed_peer_record_size_ : 0;
}

int libp2p_gossipsub_PeerInfo_set_signed_peer_record(libp2p_gossipsub_PeerInfo *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->signed_peer_record, obj->signed_peer_record_size_);
        obj->signed_peer_record = (void *)malloc(size ? size : 1);
        if (obj->signed_peer_record) {
            memcpy(obj->signed_peer_record, value, size);
            obj->signed_peer_record_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->signed_peer_record_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}
