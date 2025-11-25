#include "gossipsub_validation.h"

#include "gossipsub_cache.h"
#include "gossipsub_peer.h"
#include "gossipsub_propagation.h"
#include "gossipsub_score.h"
#include "gossipsub_topic.h"

#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../external/wjcryptlib/lib/WjCryptLib_Sha256.h"

#ifndef LIBP2P_LOGGING_FORCE
#define LIBP2P_LOGGING_FORCE 1
#endif

#include "libp2p/log.h"
#include "libp2p/runtime.h"
#include "../../../host/host_internal.h"
#include "../proto/gossipsub_proto.h"

#define GOSSIPSUB_MODULE "gossipsub"

#if LIBP2P_LOGGING_ENABLED
static void gossipsub_trace_publish_frame(const libp2p_gossipsub_message_t *msg,
                                          const uint8_t *frame,
                                          size_t frame_len,
                                          const uint8_t *message_id,
                                          size_t message_id_len)
{
    if (!frame || frame_len == 0)
        return;

    libp2p_log_level_t log_level = LIBP2P_LOG_TRACE;
    if (libp2p_log_is_enabled(LIBP2P_LOG_TRACE))
    {
        log_level = LIBP2P_LOG_TRACE;
    }
    else if (libp2p_log_is_enabled(LIBP2P_LOG_DEBUG))
    {
        log_level = LIBP2P_LOG_DEBUG;
    }
    else if (libp2p_log_is_enabled(LIBP2P_LOG_INFO))
    {
        log_level = LIBP2P_LOG_INFO;
    }
    else if (libp2p_log_is_enabled(LIBP2P_LOG_WARN))
    {
        log_level = LIBP2P_LOG_WARN;
    }
    else
    {
        return;
    }

    static const char hex_digits[] = "0123456789abcdef";
    const size_t preview_cap = 48;
    char preview[(preview_cap * 2) + 4];
    size_t preview_len = frame_len < preview_cap ? frame_len : preview_cap;
    for (size_t i = 0; i < preview_len; ++i)
    {
        preview[(i * 2) + 0] = hex_digits[(frame[i] >> 4) & 0xF];
        preview[(i * 2) + 1] = hex_digits[frame[i] & 0xF];
    }
    size_t preview_idx = preview_len * 2;
    preview[preview_idx] = '\0';
    if (frame_len > preview_cap)
    {
        preview[preview_idx++] = '.';
        preview[preview_idx++] = '.';
        preview[preview_idx++] = '.';
        preview[preview_idx] = '\0';
    }

    char msg_id_hex[65];
    const int has_msg_id = (message_id && message_id_len && message_id_len <= 32);
    if (has_msg_id)
    {
        for (size_t i = 0; i < message_id_len; ++i)
        {
            msg_id_hex[(i * 2) + 0] = hex_digits[(message_id[i] >> 4) & 0xF];
            msg_id_hex[(i * 2) + 1] = hex_digits[message_id[i] & 0xF];
        }
        msg_id_hex[message_id_len * 2] = '\0';
    }

    const char *topic = (msg && msg->topic.topic) ? msg->topic.topic : "(null)";
    size_t data_len = msg ? msg->data_len : 0;
    size_t seqno_len = msg ? msg->seqno_len : 0;

    size_t publish_count = 0;
    size_t encoded_data_len = 0;
    const char *encoded_topic = NULL;
    libp2p_gossipsub_RPC *decoded = NULL;
    libp2p_err_t decode_rc = libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &decoded);
    if (decode_rc == LIBP2P_ERR_OK && decoded)
    {
        publish_count = libp2p_gossipsub_RPC_count_publish(decoded);
        if (publish_count > 0)
        {
            libp2p_gossipsub_Message *first = libp2p_gossipsub_RPC_get_at_publish(decoded, 0);
            if (first)
            {
                encoded_data_len = libp2p_gossipsub_Message_get_size_data(first);
                encoded_topic = libp2p_gossipsub_Message_get_topic(first);
            }
        }
    }

    LP_LOGF(log_level,
            GOSSIPSUB_MODULE,
            "publish frame topic=%s encoded_topic=%s frame_len=%zu publish_count=%zu data_len=%zu seqno_len=%zu "
            "msg_id=%s preview=%s decode_rc=%d encoded_data_len=%zu",
            topic,
            encoded_topic ? encoded_topic : "(null)",
            frame_len,
            publish_count,
            data_len,
            seqno_len,
            has_msg_id ? msg_id_hex : "(none)",
            preview,
            decode_rc,
            encoded_data_len);

    if (decoded)
        libp2p_gossipsub_RPC_free(decoded);
}
#else
static void gossipsub_trace_publish_frame(const libp2p_gossipsub_message_t *msg,
                                          const uint8_t *frame,
                                          size_t frame_len,
                                          const uint8_t *message_id,
                                          size_t message_id_len)
{
    (void)msg;
    (void)frame;
    (void)frame_len;
    (void)message_id;
    (void)message_id_len;
}
#endif

typedef struct gossipsub_async_task
{
    libp2p_gossipsub_t *gs;
    struct gossipsub_validation_ctx *ctx;
    libp2p_gossipsub_validator_handle_t *handle;
} gossipsub_async_task_t;

typedef struct gossipsub_async_done_ctx
{
    struct gossipsub_validation_ctx *ctx;
} gossipsub_async_done_ctx_t;

typedef struct gossipsub_validation_ctx
{
    libp2p_gossipsub_t *gs;
    gossipsub_topic_state_t *topic;
    libp2p_gossipsub_message_t message;
    char *topic_str;
    uint8_t *data_buf;
    uint8_t *seqno_buf;
    uint8_t *raw_buf;
    peer_id_t *from_copy;
    libp2p_gossipsub_validator_handle_t **validators;
    size_t validators_len;
    size_t pending_async;
    int propagate_on_accept;
    libp2p_gossipsub_validation_result_t final_result;
    int completed;
    pthread_mutex_t mtx;
} gossipsub_validation_ctx_t;

static void gossipsub_validator_array_release(libp2p_gossipsub_validator_handle_t **handles, size_t count)
{
    if (!handles)
        return;
    for (size_t i = 0; i < count; ++i)
    {
        if (handles[i])
            gossipsub_validator_handle_release(handles[i]);
    }
    free(handles);
}

static void gossipsub_validation_ctx_free(gossipsub_validation_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->validators)
    {
        for (size_t i = 0; i < ctx->validators_len; ++i)
            gossipsub_validator_handle_release(ctx->validators[i]);
        free(ctx->validators);
    }
    if (ctx->topic_str)
        free(ctx->topic_str);
    if (ctx->data_buf)
        free(ctx->data_buf);
    if (ctx->seqno_buf)
        free(ctx->seqno_buf);
    if (ctx->raw_buf)
        free(ctx->raw_buf);
    if (ctx->from_copy)
        gossipsub_peer_free(ctx->from_copy);
    pthread_mutex_destroy(&ctx->mtx);
    free(ctx);
}

static libp2p_err_t gossipsub_message_clone_into_ctx(gossipsub_validation_ctx_t *ctx,
                                                     const libp2p_gossipsub_message_t *msg)
{
    if (!ctx || !msg)
        return LIBP2P_ERR_NULL_PTR;

    memset(&ctx->message, 0, sizeof(ctx->message));
    ctx->message.topic.struct_size = sizeof(ctx->message.topic);
    if (msg->topic.topic)
    {
        ctx->topic_str = strdup(msg->topic.topic);
        if (!ctx->topic_str)
            return LIBP2P_ERR_INTERNAL;
        ctx->message.topic.topic = ctx->topic_str;
    }

    if (msg->data && msg->data_len)
    {
        ctx->data_buf = (uint8_t *)malloc(msg->data_len);
        if (!ctx->data_buf)
            return LIBP2P_ERR_INTERNAL;
        memcpy(ctx->data_buf, msg->data, msg->data_len);
        ctx->message.data = ctx->data_buf;
        ctx->message.data_len = msg->data_len;
    }

    if (msg->seqno && msg->seqno_len)
    {
        ctx->seqno_buf = (uint8_t *)malloc(msg->seqno_len);
        if (!ctx->seqno_buf)
            return LIBP2P_ERR_INTERNAL;
        memcpy(ctx->seqno_buf, msg->seqno, msg->seqno_len);
        ctx->message.seqno = ctx->seqno_buf;
        ctx->message.seqno_len = msg->seqno_len;
    }

    if (msg->raw_message && msg->raw_message_len)
    {
        ctx->raw_buf = (uint8_t *)malloc(msg->raw_message_len);
        if (!ctx->raw_buf)
            return LIBP2P_ERR_INTERNAL;
        memcpy(ctx->raw_buf, msg->raw_message, msg->raw_message_len);
        ctx->message.raw_message = ctx->raw_buf;
        ctx->message.raw_message_len = msg->raw_message_len;
    }

    if (msg->from)
    {
        ctx->from_copy = gossipsub_peer_clone(msg->from);
        if (!ctx->from_copy)
            return LIBP2P_ERR_INTERNAL;
        ctx->message.from = ctx->from_copy;
    }

    return LIBP2P_ERR_OK;
}

static void gossipsub_validation_finish_exec(void *user_data);
static void gossipsub_validation_launch_async(gossipsub_validation_ctx_t *ctx, size_t start_index);

static void gossipsub_validation_schedule_finish(gossipsub_validation_ctx_t *ctx,
                                                 libp2p_gossipsub_validation_result_t result)
{
    if (!ctx)
        return;
    int should_schedule = 0;
    pthread_mutex_lock(&ctx->mtx);
    if (!ctx->completed)
    {
        ctx->completed = 1;
        ctx->final_result = result;
        should_schedule = 1;
    }
    pthread_mutex_unlock(&ctx->mtx);
    if (should_schedule)
        libp2p__exec_on_cb_thread(ctx->gs->host, gossipsub_validation_finish_exec, ctx);
}

static libp2p_gossipsub_validation_result_t gossipsub_run_sync_validators(gossipsub_validation_ctx_t *ctx,
                                                                          size_t *async_start)
{
    if (!ctx || !async_start)
        return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;

    *async_start = ctx->validators_len;
    for (size_t i = 0; i < ctx->validators_len; ++i)
    {
        libp2p_gossipsub_validator_handle_t *handle = ctx->validators[i];
        if (!handle)
            continue;
        if (handle->type == LIBP2P_GOSSIPSUB_VALIDATOR_ASYNC)
        {
            *async_start = i;
            return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
        }
        if (!handle->sync_fn)
            continue;
        libp2p_gossipsub_validation_result_t res = handle->sync_fn(&ctx->message, handle->user_data);
        if (res == LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT || res == LIBP2P_GOSSIPSUB_VALIDATION_DEFER)
            continue;
        *async_start = ctx->validators_len;
        return res;
    }
    *async_start = ctx->validators_len;
    return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
}

static void gossipsub_validation_mark_async_result(gossipsub_validation_ctx_t *ctx,
                                                   libp2p_gossipsub_validation_result_t result)
{
    if (!ctx)
        return;

    libp2p_gossipsub_validation_result_t final = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    pthread_mutex_lock(&ctx->mtx);

    if (result == LIBP2P_GOSSIPSUB_VALIDATION_REJECT)
        ctx->final_result = LIBP2P_GOSSIPSUB_VALIDATION_REJECT;
    else if (result == LIBP2P_GOSSIPSUB_VALIDATION_IGNORE && ctx->final_result == LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT)
        ctx->final_result = LIBP2P_GOSSIPSUB_VALIDATION_IGNORE;

    if (ctx->pending_async > 0)
        ctx->pending_async--;

    final = ctx->final_result;
    int should_finish = (ctx->pending_async == 0);
    pthread_mutex_unlock(&ctx->mtx);

    if (should_finish)
        gossipsub_validation_schedule_finish(ctx, final);
}

static void gossipsub_async_done_trampoline(libp2p_gossipsub_validation_result_t result, void *user_data)
{
    gossipsub_async_done_ctx_t *done_ctx = (gossipsub_async_done_ctx_t *)user_data;
    if (!done_ctx)
        return;
    gossipsub_validation_ctx_t *ctx = done_ctx->ctx;
    free(done_ctx);
    gossipsub_validation_mark_async_result(ctx, result);
}

static void gossipsub_async_timer_cb(void *user_data)
{
    gossipsub_async_task_t *task = (gossipsub_async_task_t *)user_data;
    if (!task)
        return;

    gossipsub_validation_ctx_t *ctx = task->ctx;
    libp2p_gossipsub_validator_handle_t *handle = task->handle;

    if (!ctx || !handle || !handle->async_fn)
    {
        gossipsub_validation_mark_async_result(ctx, LIBP2P_GOSSIPSUB_VALIDATION_IGNORE);
        free(task);
        return;
    }

    gossipsub_async_done_ctx_t *done_ctx = (gossipsub_async_done_ctx_t *)calloc(1, sizeof(*done_ctx));
    if (!done_ctx)
    {
        gossipsub_validation_mark_async_result(ctx, LIBP2P_GOSSIPSUB_VALIDATION_IGNORE);
        free(task);
        return;
    }
    done_ctx->ctx = ctx;
    handle->async_fn(&ctx->message, gossipsub_async_done_trampoline, handle->user_data, done_ctx);
    free(task);
}

static int gossipsub_runtime_dispatch(libp2p_gossipsub_t *gs, gossipsub_async_task_t *task)
{
    if (!gs || !gs->runtime || !task)
        return -1;
    int tid = libp2p_runtime_add_timer(gs->runtime, 0, 0, gossipsub_async_timer_cb, task);
    if (tid < 0)
        return -1;
    return 0;
}

static void gossipsub_validation_launch_async(gossipsub_validation_ctx_t *ctx, size_t start_index)
{
    if (!ctx)
        return;
    if (start_index >= ctx->validators_len)
    {
        gossipsub_validation_schedule_finish(ctx, ctx->final_result);
        return;
    }

    size_t launched = 0;
    for (size_t i = start_index; i < ctx->validators_len; ++i)
    {
        libp2p_gossipsub_validator_handle_t *handle = ctx->validators[i];
        if (!handle || handle->type != LIBP2P_GOSSIPSUB_VALIDATOR_ASYNC)
            continue;

        gossipsub_async_task_t *task = (gossipsub_async_task_t *)calloc(1, sizeof(*task));
        pthread_mutex_lock(&ctx->mtx);
        ctx->pending_async++;
        pthread_mutex_unlock(&ctx->mtx);

        if (!task)
        {
            gossipsub_validation_mark_async_result(ctx, LIBP2P_GOSSIPSUB_VALIDATION_IGNORE);
            continue;
        }

        task->gs = ctx->gs;
        task->ctx = ctx;
        task->handle = handle;
        if (gossipsub_runtime_dispatch(ctx->gs, task) != 0)
        {
            free(task);
            gossipsub_validation_mark_async_result(ctx, LIBP2P_GOSSIPSUB_VALIDATION_IGNORE);
            continue;
        }
        launched++;
    }

    if (launched == 0)
        gossipsub_validation_schedule_finish(ctx, ctx->final_result);
}

static void gossipsub_write_u64_be(uint64_t value, uint8_t out[8])
{
    for (int i = 0; i < 8; ++i)
        out[7 - i] = (uint8_t)((value >> (i * 8)) & 0xFFU);
}

static libp2p_err_t gossipsub_message_compute_id(const libp2p_gossipsub_message_t *msg,
                                                 const gossipsub_topic_state_t *topic,
                                                 uint8_t **out_id,
                                                 size_t *out_len)
{
    if (!msg || !out_id || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_id = NULL;
    *out_len = 0;

    if (topic && topic->message_id_fn)
    {
        libp2p_err_t custom_rc = topic->message_id_fn(msg, out_id, out_len, topic->message_id_user_data);
        if (custom_rc == LIBP2P_ERR_OK)
        {
            if (*out_id && *out_len > 0)
                return LIBP2P_ERR_OK;
            if (*out_id)
            {
                free(*out_id);
                *out_id = NULL;
            }
            *out_len = 0;
            return LIBP2P_ERR_INTERNAL;
        }
        if (custom_rc != LIBP2P_ERR_UNSUPPORTED)
            return custom_rc;
    }

    if (msg->seqno && msg->seqno_len > 0 && msg->from && msg->from->bytes && msg->from->size > 0)
    {
        size_t id_len = msg->from->size + msg->seqno_len;
        uint8_t *buf = (uint8_t *)malloc(id_len);
        if (!buf)
            return LIBP2P_ERR_INTERNAL;
        memcpy(buf, msg->from->bytes, msg->from->size);
        memcpy(buf + msg->from->size, msg->seqno, msg->seqno_len);
        *out_id = buf;
        *out_len = id_len;
        return LIBP2P_ERR_OK;
    }

    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (msg->data && msg->data_len > 0)
    {
        payload = msg->data;
        payload_len = msg->data_len;
    }
    else if (msg->raw_message && msg->raw_message_len > 0)
    {
        payload = msg->raw_message;
        payload_len = msg->raw_message_len;
    }

    if (!payload || payload_len == 0 || payload_len > UINT32_MAX)
        return LIBP2P_ERR_UNSUPPORTED;

    uint8_t *buf = (uint8_t *)malloc(SHA256_HASH_SIZE);
    if (!buf)
        return LIBP2P_ERR_INTERNAL;

    SHA256_HASH hash;
    Sha256Calculate(payload, (uint32_t)payload_len, &hash);
    memcpy(buf, hash.bytes, SHA256_HASH_SIZE);
    *out_id = buf;
    *out_len = SHA256_HASH_SIZE;
    return LIBP2P_ERR_OK;
}

static void gossipsub_validation_finalize(gossipsub_validation_ctx_t *ctx)
{
    if (!ctx)
        return;

    libp2p_gossipsub_t *gs = ctx->gs;
    if (!gs)
    {
        gossipsub_validation_ctx_free(ctx);
        return;
    }

    if (ctx->final_result != LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT)
    {
        if (ctx->final_result == LIBP2P_GOSSIPSUB_VALIDATION_REJECT && ctx->topic && ctx->message.from)
        {
            uint8_t *message_id = NULL;
            size_t message_id_len = 0;
            libp2p_err_t mid_rc = gossipsub_message_compute_id(&ctx->message, ctx->topic, &message_id, &message_id_len);
            uint64_t now_ms = gossipsub_now_ms();
            pthread_mutex_lock(&gs->lock);
            if (mid_rc == LIBP2P_ERR_OK && message_id && message_id_len)
                gossipsub_promises_message_delivered(&gs->promises, message_id, message_id_len);
            gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, ctx->message.from);
            if (entry)
                gossipsub_score_on_invalid_message_locked(gs, ctx->topic, entry, now_ms);
            pthread_mutex_unlock(&gs->lock);
            if (message_id)
                free(message_id);
        }
        gossipsub_validation_ctx_free(ctx);
        return;
    }

    /* In anonymous mode, skip adding from/seqno fields to be compatible with
       rust-libp2p ValidationMode::Anonymous which rejects messages with these fields */
    if (ctx->propagate_on_accept && !gs->cfg.anonymous_mode && !ctx->message.from && gs->host)
    {
        peer_id_t *self = NULL;
        if (libp2p_host_get_peer_id(gs->host, &self) == LIBP2P_ERR_OK && self)
        {
            if (ctx->from_copy)
                gossipsub_peer_free(ctx->from_copy);
            ctx->from_copy = self;
            ctx->message.from = self;
        }
        else if (self)
        {
            gossipsub_peer_free(self);
        }
    }

    if (ctx->propagate_on_accept && !gs->cfg.anonymous_mode && ctx->message.seqno_len == 0)
    {
        uint8_t seqno_bytes[8];
        uint64_t seq = atomic_fetch_add_explicit(&gs->seqno_counter, 1, memory_order_relaxed);
        gossipsub_write_u64_be(seq, seqno_bytes);
        uint8_t *buf = (uint8_t *)malloc(sizeof(seqno_bytes));
        if (buf)
        {
            memcpy(buf, seqno_bytes, sizeof(seqno_bytes));
            if (ctx->seqno_buf)
                free(ctx->seqno_buf);
            ctx->seqno_buf = buf;
            ctx->message.seqno = ctx->seqno_buf;
            ctx->message.seqno_len = sizeof(seqno_bytes);
        }
    }

    uint8_t *message_id = NULL;
    size_t message_id_len = 0;
    libp2p_err_t id_rc = gossipsub_message_compute_id(&ctx->message, ctx->topic, &message_id, &message_id_len);
    if (id_rc != LIBP2P_ERR_OK)
    {
        LP_LOGD(GOSSIPSUB_MODULE, "unable to derive message id for topic %s (rc=%d)",
                ctx->message.topic.topic ? ctx->message.topic.topic : "(unknown)", id_rc);
    }

    const uint8_t *frame = ctx->message.raw_message;
    size_t frame_len = ctx->message.raw_message_len;
    uint8_t *encoded_frame = NULL;
    if (!frame || frame_len == 0)
    {
        libp2p_err_t enc_rc = libp2p_gossipsub_rpc_encode_publish(&ctx->message, &encoded_frame, &frame_len);
        if (enc_rc != LIBP2P_ERR_OK || !encoded_frame || frame_len == 0)
        {
            LP_LOGW(GOSSIPSUB_MODULE, "failed to encode publish RPC (rc=%d)", enc_rc);
            if (encoded_frame)
                free(encoded_frame);
            if (message_id)
                free(message_id);
            gossipsub_validation_ctx_free(ctx);
            return;
        }
        frame = encoded_frame;
    }

    gossipsub_trace_publish_frame(&ctx->message, frame, frame_len, message_id, message_id_len);

    int duplicate = 0;
    if (message_id && message_id_len)
    {
        uint64_t now_ms = gossipsub_now_ms();
        int was_present = 0;
        pthread_mutex_lock(&gs->lock);
        libp2p_err_t seen_rc = gossipsub_seen_cache_check_and_add(&gs->seen_cache,
                                                                  message_id,
                                                                  message_id_len,
                                                                  now_ms,
                                                                  &was_present);
        (void)gossipsub_message_cache_put(&gs->message_cache,
                                          message_id,
                                          message_id_len,
                                          ctx->message.topic.topic,
                                          frame,
                                          frame_len);
        gossipsub_promises_message_delivered(&gs->promises, message_id, message_id_len);
        if (seen_rc == LIBP2P_ERR_OK && !was_present && ctx->topic && ctx->message.from)
        {
            gossipsub_peer_entry_t *entry = gossipsub_peer_find(gs->peers, ctx->message.from);
            if (entry)
            {
                gossipsub_mesh_member_t *member = gossipsub_mesh_member_find(ctx->topic->mesh, ctx->message.from);
                int in_mesh = (member != NULL) ? 1 : 0;
                gossipsub_score_on_first_delivery_locked(gs, ctx->topic, entry, in_mesh, now_ms);
            }
        }
        pthread_mutex_unlock(&gs->lock);
        if (seen_rc != LIBP2P_ERR_OK)
            LP_LOGW(GOSSIPSUB_MODULE, "failed to update seen cache (rc=%d)", seen_rc);
        else
            duplicate = was_present;
    }

    if (ctx->propagate_on_accept)
        duplicate = 0;

    if (!duplicate)
    {
        gossipsub_propagation_propagate_frame(gs, ctx->topic, ctx->message.from, frame, frame_len);
    }

    if (encoded_frame)
        free(encoded_frame);
    if (message_id)
        free(message_id);
    gossipsub_validation_ctx_free(ctx);
}

static void gossipsub_validation_finish_exec(void *user_data)
{
    gossipsub_validation_ctx_t *ctx = (gossipsub_validation_ctx_t *)user_data;
    gossipsub_validation_finalize(ctx);
}

static void gossipsub_validation_begin_exec(void *user_data)
{
    gossipsub_validation_ctx_t *ctx = (gossipsub_validation_ctx_t *)user_data;
    if (!ctx)
        return;

    size_t async_start = ctx->validators_len;
    libp2p_gossipsub_validation_result_t res = gossipsub_run_sync_validators(ctx, &async_start);
    if (res != LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT)
    {
        gossipsub_validation_schedule_finish(ctx, res);
        return;
    }

    pthread_mutex_lock(&ctx->mtx);
    if (ctx->pending_async == 0)
        ctx->final_result = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    pthread_mutex_unlock(&ctx->mtx);

    if (async_start >= ctx->validators_len)
    {
        gossipsub_validation_schedule_finish(ctx, ctx->final_result);
    }
    else
    {
        gossipsub_validation_launch_async(ctx, async_start);
    }
}

libp2p_err_t gossipsub_validation_collect(libp2p_gossipsub_t *gs,
                                          const char *topic_name,
                                          gossipsub_topic_state_t **out_topic,
                                          libp2p_gossipsub_validator_handle_t ***out_handles,
                                          size_t *out_len)
{
    if (!gs || !topic_name || !out_handles || !out_len)
        return LIBP2P_ERR_NULL_PTR;

    *out_handles = NULL;
    *out_len = 0;
    if (out_topic)
        *out_topic = NULL;

    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic || !topic->subscribed)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_UNSUPPORTED;
    }

    size_t validator_count = 0;
    for (gossipsub_validator_node_t *node = topic->validators; node; node = node->next)
        validator_count++;

    libp2p_gossipsub_validator_handle_t **validators = NULL;
    if (validator_count)
    {
        validators = (libp2p_gossipsub_validator_handle_t **)calloc(validator_count, sizeof(*validators));
        if (!validators)
        {
            pthread_mutex_unlock(&gs->lock);
            return LIBP2P_ERR_INTERNAL;
        }
        size_t idx = validator_count;
        for (gossipsub_validator_node_t *node = topic->validators; node; node = node->next)
        {
            validators[--idx] = node->handle;
            gossipsub_validator_handle_retain(node->handle);
        }
    }
    pthread_mutex_unlock(&gs->lock);

    if (out_topic)
        *out_topic = topic;
    *out_handles = validators;
    *out_len = validator_count;
    return LIBP2P_ERR_OK;
}

libp2p_err_t gossipsub_validation_schedule(libp2p_gossipsub_t *gs,
                                           gossipsub_topic_state_t *topic,
                                           libp2p_gossipsub_validator_handle_t **validators,
                                           size_t validator_count,
                                           const libp2p_gossipsub_message_t *msg,
                                           int propagate_on_accept)
{
    gossipsub_validation_ctx_t *ctx = (gossipsub_validation_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        gossipsub_validator_array_release(validators, validator_count);
        return LIBP2P_ERR_INTERNAL;
    }

    ctx->gs = gs;
    ctx->topic = topic;
    ctx->validators = validators;
    ctx->validators_len = validator_count;
    ctx->propagate_on_accept = propagate_on_accept ? 1 : 0;
    ctx->final_result = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    ctx->pending_async = 0;
    ctx->completed = 0;

    if (pthread_mutex_init(&ctx->mtx, NULL) != 0)
    {
        gossipsub_validator_array_release(validators, validator_count);
        free(ctx);
        return LIBP2P_ERR_INTERNAL;
    }

    libp2p_err_t clone_rc = gossipsub_message_clone_into_ctx(ctx, msg);
    if (clone_rc != LIBP2P_ERR_OK)
    {
        gossipsub_validation_ctx_free(ctx);
        return clone_rc;
    }

    const char *topic_label = msg->topic.topic ? msg->topic.topic : "(null)";
    LP_LOGD(GOSSIPSUB_MODULE,
            "queueing %s message on topic %s (%zu bytes)",
            propagate_on_accept ? "publish" : "inbound",
            topic_label,
            msg->data_len);
    libp2p__exec_on_cb_thread(gs->host, gossipsub_validation_begin_exec, ctx);
    return LIBP2P_ERR_OK;
}

void gossipsub_validator_handle_retain(libp2p_gossipsub_validator_handle_t *handle)
{
    if (!handle)
        return;
    atomic_fetch_add_explicit(&handle->refcount, 1, memory_order_relaxed);
}

void gossipsub_validator_handle_release(libp2p_gossipsub_validator_handle_t *handle)
{
    if (!handle)
        return;
    if (atomic_fetch_sub_explicit(&handle->refcount, 1, memory_order_acq_rel) == 1)
        free(handle);
}

libp2p_err_t libp2p_gossipsub_add_validator(libp2p_gossipsub_t *gs,
                                            const char *topic_name,
                                            const libp2p_gossipsub_validator_def_t *def,
                                            libp2p_gossipsub_validator_handle_t **out_handle)
{
    if (!gs || !topic_name || !def)
        return LIBP2P_ERR_NULL_PTR;
    if (def->type == LIBP2P_GOSSIPSUB_VALIDATOR_SYNC && !def->sync_fn)
        return LIBP2P_ERR_NULL_PTR;
    if (def->type == LIBP2P_GOSSIPSUB_VALIDATOR_ASYNC && !def->async_fn)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = gossipsub_topic_find(gs->topics, topic_name);
    if (!topic)
    {
        libp2p_gossipsub_topic_config_t cfg = {
            .struct_size = sizeof(cfg),
            .descriptor = {
                .struct_size = sizeof(cfg.descriptor),
                .topic = topic_name
            },
            .score_params = NULL
        };
        libp2p_err_t rc = gossipsub_topic_ensure(gs, &cfg, &topic);
        if (rc != LIBP2P_ERR_OK)
        {
            pthread_mutex_unlock(&gs->lock);
            return rc;
        }
    }

    libp2p_gossipsub_validator_handle_t *handle = (libp2p_gossipsub_validator_handle_t *)calloc(1, sizeof(*handle));
    if (!handle)
    {
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    handle->type = def->type;
    handle->sync_fn = def->sync_fn;
    handle->async_fn = def->async_fn;
    handle->user_data = def->user_data;
    handle->topic = topic;
    atomic_init(&handle->refcount, 1);

    gossipsub_validator_node_t *node = (gossipsub_validator_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        gossipsub_validator_handle_release(handle);
        pthread_mutex_unlock(&gs->lock);
        return LIBP2P_ERR_INTERNAL;
    }
    node->handle = handle;
    node->next = topic->validators;
    topic->validators = node;
    pthread_mutex_unlock(&gs->lock);

    if (out_handle)
        *out_handle = handle;

    LP_LOGD(GOSSIPSUB_MODULE,
            "added %s validator for topic %s",
            def->type == LIBP2P_GOSSIPSUB_VALIDATOR_SYNC ? "sync" : "async",
            topic_name);
    return LIBP2P_ERR_OK;
}

libp2p_err_t libp2p_gossipsub_remove_validator(libp2p_gossipsub_t *gs,
                                               libp2p_gossipsub_validator_handle_t *handle)
{
    if (!gs || !handle || !handle->topic)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&gs->lock);
    gossipsub_topic_state_t *topic = handle->topic;
    gossipsub_validator_node_t **pp = &topic->validators;
    while (*pp)
    {
        if ((*pp)->handle == handle)
        {
            gossipsub_validator_node_t *victim = *pp;
            *pp = victim->next;
            gossipsub_validator_handle_release(victim->handle);
            free(victim);
            pthread_mutex_unlock(&gs->lock);
            LP_LOGD(GOSSIPSUB_MODULE, "removed validator from topic %s", topic->name);
            return LIBP2P_ERR_OK;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&gs->lock);
    return LIBP2P_ERR_INTERNAL;
}
