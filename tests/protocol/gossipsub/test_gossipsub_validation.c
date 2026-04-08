#include "protocol/gossipsub/gossipsub.h"
#include "gossipsub_validation.h"
#include "gossipsub_rpc.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_int g_sync_called;
static atomic_int g_async_called;
static atomic_int g_delivery_called;
static uint8_t g_last_message_id[128];
static size_t g_last_message_id_len;
static char g_last_source_text[128];

libp2p_err_t libp2p_gossipsub__inject_frame(libp2p_gossipsub_t *gs, const peer_id_t *peer, const uint8_t *frame,
                                            size_t frame_len);
size_t libp2p_gossipsub__peer_sendq_len(libp2p_gossipsub_t *gs, const peer_id_t *peer);
libp2p_err_t libp2p_gossipsub__peer_set_connected(libp2p_gossipsub_t *gs, const peer_id_t *peer, int connected);
libp2p_err_t libp2p_gossipsub__peer_pop_sendq(libp2p_gossipsub_t *gs, const peer_id_t *peer, uint8_t **out_buf,
                                              size_t *out_len);
libp2p_err_t libp2p_gossipsub__heartbeat(libp2p_gossipsub_t *gs);

static libp2p_gossipsub_validation_result_t counting_sync_validator(const libp2p_gossipsub_message_t *msg,
                                                                    void *user_data)
{
    (void)msg;
    atomic_fetch_add_explicit((atomic_int *)user_data, 1, memory_order_relaxed);
    return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
}

static void counting_async_validator(const libp2p_gossipsub_message_t *msg,
                                     libp2p_gossipsub_validator_done_fn done,
                                     void *user_data,
                                     void *done_user_data)
{
    (void)msg;
    atomic_fetch_add_explicit((atomic_int *)user_data, 1, memory_order_relaxed);
    if (done)
        done(LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT, done_user_data);
}

static void counting_message_delivery(libp2p_gossipsub_t *gs,
                                      const libp2p_gossipsub_message_t *msg,
                                      const uint8_t *message_id,
                                      size_t message_id_len,
                                      const peer_id_t *propagation_source,
                                      void *user_data)
{
    (void)gs;
    (void)msg;
    (void)user_data;

    atomic_fetch_add_explicit(&g_delivery_called, 1, memory_order_relaxed);
    g_last_message_id_len = 0;
    if (message_id && message_id_len > 0 && message_id_len <= sizeof(g_last_message_id))
    {
        memcpy(g_last_message_id, message_id, message_id_len);
        g_last_message_id_len = message_id_len;
    }

    memset(g_last_source_text, 0, sizeof(g_last_source_text));
    if (propagation_source)
    {
        size_t written = 0;
        if (peer_id_text_write(propagation_source,
                               PEER_ID_TEXT_LEGACY_BASE58,
                               g_last_source_text,
                               sizeof(g_last_source_text),
                               &written) != PEER_ID_OK)
            g_last_source_text[0] = '\0';
    }
}

static void print_result(const char *name, int ok)
{
    printf("TEST: %-45s | %s\n", name, ok ? "PASS" : "FAIL");
}

static int setup_subscribed_peer(libp2p_gossipsub_t *gs, const char *topic, const char *peer_str, peer_id_t **out_peer)
{
    if (!gs || !topic || !peer_str || !out_peer) {
        return 0;
    }

    *out_peer = NULL;
    peer_id_t *peer = NULL;
    if (peer_id_new_from_text(peer_str, &peer) != PEER_ID_OK || !peer) {
        return 0;
    }

    gossipsub_rpc_out_t out;
    gossipsub_rpc_out_init(&out);
    if (gossipsub_rpc_encode_subscription(topic, 1, &out) != LIBP2P_ERR_OK || !out.frame || out.frame_len == 0) {
        if (out.frame) {
            free(out.frame);
        }
        peer_id_free(peer);
        return 0;
    }

    libp2p_err_t inject_rc = libp2p_gossipsub__inject_frame(gs, peer, out.frame, out.frame_len);
    free(out.frame);
    if (inject_rc != LIBP2P_ERR_OK) {
        peer_id_free(peer);
        return 0;
    }

    if (libp2p_gossipsub__peer_set_connected(gs, peer, 1) != LIBP2P_ERR_OK) {
        peer_id_free(peer);
        return 0;
    }

    *out_peer = peer;
    return 1;
}

static int wait_for_peer_frame(libp2p_gossipsub_t *gs, const peer_id_t *peer, uint64_t timeout_ms, size_t *out_frame_len)
{
    if (!gs || !peer) {
        return 0;
    }
    if (out_frame_len) {
        *out_frame_len = 0;
    }

    for (uint64_t elapsed = 0; elapsed < timeout_ms; ++elapsed) {
        uint8_t *frame_buf = NULL;
        size_t frame_len = 0;
        libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, peer, &frame_buf, &frame_len);
        if (pop_rc == LIBP2P_ERR_OK) {
            if (out_frame_len) {
                *out_frame_len = frame_len;
            }
            free(frame_buf);
            return 1;
        }
        if (pop_rc != LIBP2P_ERR_UNSUPPORTED) {
            break;
        }
        usleep(1000);
    }

    return 0;
}

static int wait_for_peer_idle(libp2p_gossipsub_t *gs, const peer_id_t *peer, uint64_t duration_ms)
{
    if (!gs || !peer) {
        return 0;
    }

    for (uint64_t elapsed = 0; elapsed < duration_ms; ++elapsed) {
        if (libp2p_gossipsub__peer_sendq_len(gs, peer) == 0) {
            return 1;
        }
        usleep(1000);
    }
    return libp2p_gossipsub__peer_sendq_len(gs, peer) == 0;
}

static void clear_peer_sendq(libp2p_gossipsub_t *gs, const peer_id_t *peer)
{
    if (!gs || !peer) {
        return;
    }

    for (;;) {
        uint8_t *frame_buf = NULL;
        size_t frame_len = 0;
        if (libp2p_gossipsub__peer_pop_sendq(gs, peer, &frame_buf, &frame_len) != LIBP2P_ERR_OK) {
            break;
        }
        free(frame_buf);
    }
}

static libp2p_err_t make_gossipsub(libp2p_gossipsub_t **out_gs, libp2p_host_t **out_host)
{
    libp2p_host_options_t host_opts;
    if (libp2p_host_options_default(&host_opts) != 0)
        return LIBP2P_ERR_INTERNAL;

    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&host_opts, &host) != 0 || !host)
        return LIBP2P_ERR_INTERNAL;

    libp2p_gossipsub_config_t cfg;
    libp2p_gossipsub_config_default(&cfg);
    cfg.d = 4;
    cfg.d_lo = 2;
    cfg.d_hi = 6;
    cfg.d_lazy = 3;
    cfg.d_out = 1;
    cfg.message_cache_length = 2;
    cfg.message_cache_gossip = 1;

    libp2p_gossipsub_t *gs = NULL;
    libp2p_err_t rc = libp2p_gossipsub_new(host, &cfg, &gs);
    if (rc != LIBP2P_ERR_OK || !gs)
    {
        libp2p_host_free(host);
        return LIBP2P_ERR_INTERNAL;
    }

    rc = libp2p_gossipsub_start(gs);
    if (rc != LIBP2P_ERR_OK)
    {
        libp2p_gossipsub_free(gs);
        libp2p_host_free(host);
        return rc;
    }

    *out_gs = gs;
    *out_host = host;
    return LIBP2P_ERR_OK;
}

int main(void)
{
    int failures = 0;
    libp2p_gossipsub_t *gs = NULL;
    libp2p_host_t *host = NULL;

    if (make_gossipsub(&gs, &host) != LIBP2P_ERR_OK)
    {
        fprintf(stderr, "failed to set up gossipsub under test\n");
        return 1;
    }

    const char *topic_name = "validation/topic";

    gossipsub_topic_state_t *topic_state = NULL;
    libp2p_gossipsub_validator_handle_t **handles = NULL;
    size_t handle_count = 0;

    libp2p_err_t rc = gossipsub_validation_collect(gs, topic_name, &topic_state, &handles, &handle_count);
    int ok = (rc == LIBP2P_ERR_UNSUPPORTED);
    print_result("collect_requires_subscription", ok);
    if (!ok)
        failures++;

    libp2p_gossipsub_topic_config_t cfg = {
        .struct_size = sizeof(cfg),
        .descriptor = {
            .struct_size = sizeof(cfg.descriptor),
            .topic = topic_name
        },
        .score_params = NULL
    };
    rc = libp2p_gossipsub_subscribe(gs, &cfg);
    ok = (rc == LIBP2P_ERR_OK);
    print_result("subscribe_topic_for_validation", ok);
    if (!ok)
        failures++;

    atomic_store(&g_sync_called, 0);
    atomic_store(&g_async_called, 0);

    libp2p_gossipsub_validator_handle_t *sync_handle = NULL;
    libp2p_gossipsub_validator_def_t sync_def = {
        .struct_size = sizeof(sync_def),
        .type = LIBP2P_GOSSIPSUB_VALIDATOR_SYNC,
        .sync_fn = counting_sync_validator,
        .async_fn = NULL,
        .user_data = &g_sync_called
    };
    rc = libp2p_gossipsub_add_validator(gs, topic_name, &sync_def, &sync_handle);
    ok = (rc == LIBP2P_ERR_OK && sync_handle);
    print_result("add_sync_validator", ok);
    if (!ok)
        failures++;

    libp2p_gossipsub_validator_handle_t *async_handle = NULL;
    libp2p_gossipsub_validator_def_t async_def = {
        .struct_size = sizeof(async_def),
        .type = LIBP2P_GOSSIPSUB_VALIDATOR_ASYNC,
        .sync_fn = NULL,
        .async_fn = counting_async_validator,
        .user_data = &g_async_called
    };
    rc = libp2p_gossipsub_add_validator(gs, topic_name, &async_def, &async_handle);
    ok = (rc == LIBP2P_ERR_OK && async_handle);
    print_result("add_async_validator", ok);
    if (!ok)
        failures++;

    handles = NULL;
    handle_count = 0;
    topic_state = NULL;
    rc = gossipsub_validation_collect(gs, topic_name, &topic_state, &handles, &handle_count);
    ok = (rc == LIBP2P_ERR_OK && topic_state && handle_count == 2 && handles);
    print_result("collect_returns_registered_handles", ok);
    if (!ok)
        failures++;
    if (handles)
    {
        for (size_t i = 0; i < handle_count; ++i)
        {
            if (handles[i])
                gossipsub_validator_handle_release(handles[i]);
        }
        free(handles);
    }

    uint8_t payload[] = { 0xAA, 0xBB, 0xCC };
    libp2p_gossipsub_message_t msg = {
        .topic = {
            .struct_size = sizeof(msg.topic),
            .topic = topic_name
        },
        .data = payload,
        .data_len = sizeof(payload),
        .from = NULL,
        .seqno = NULL,
        .seqno_len = 0,
        .raw_message = NULL,
        .raw_message_len = 0
    };

    handles = NULL;
    handle_count = 0;
    topic_state = NULL;
    rc = gossipsub_validation_collect(gs, topic_name, &topic_state, &handles, &handle_count);
    ok = (rc == LIBP2P_ERR_OK && handles && handle_count == 2);
    if (!ok)
    {
        print_result("collect_for_schedule", ok);
        failures++;
    }
    else
    {
        rc = gossipsub_validation_schedule(gs, topic_state, handles, handle_count, &msg, 1, NULL);
        ok = (rc == LIBP2P_ERR_OK);
        print_result("schedule_validation_accept", ok);
        if (!ok)
            failures++;
        if (ok)
        {
            for (int i = 0; i < 200; ++i)
            {
                if (atomic_load_explicit(&g_sync_called, memory_order_relaxed) > 0 &&
                    atomic_load_explicit(&g_async_called, memory_order_relaxed) > 0)
                    break;
                usleep(1000);
            }

            int sync_seen = (atomic_load_explicit(&g_sync_called, memory_order_relaxed) > 0);
            int async_seen = (atomic_load_explicit(&g_async_called, memory_order_relaxed) > 0);
            print_result("schedule_sync_validator_invoked", sync_seen);
            if (!sync_seen)
                failures++;
            print_result("schedule_async_validator_invoked", async_seen);
            if (!async_seen)
                failures++;
        }
    }

    if (sync_handle)
        libp2p_gossipsub_remove_validator(gs, sync_handle);
    if (async_handle)
        libp2p_gossipsub_remove_validator(gs, async_handle);

    atomic_store(&g_delivery_called, 0);
    g_last_message_id_len = 0;
    g_last_source_text[0] = '\0';
    rc = libp2p_gossipsub_set_message_delivery_callback(gs, counting_message_delivery, NULL);
    ok = (rc == LIBP2P_ERR_OK);
    print_result("set_external_delivery_callback", ok);
    if (!ok)
        failures++;

    peer_id_t *recipient_peer = NULL;
    int recipient_ok = setup_subscribed_peer(
        gs,
        topic_name,
        "12D3KooWPy9khA5QLm5m8wKtPp1sHwoMvV7bgidhraNEnNh4tW7x",
        &recipient_peer);
    print_result("external_validation_setup_recipient", recipient_ok);
    if (!recipient_ok)
        failures++;
    if (recipient_ok)
        clear_peer_sendq(gs, recipient_peer);

    peer_id_t *source_peer = NULL;
    int source_ok = (peer_id_new_from_text(
                         "12D3KooWMmV2UmyHk4G2MijvSEezwEWj1vDLteA94ppWKqhzyzk5",
                         &source_peer)
                     == PEER_ID_OK);
    print_result("external_validation_setup_source", source_ok);
    if (!source_ok)
        failures++;

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    size_t forwarded_len = 0;
    if (recipient_ok && source_ok)
    {
        const uint8_t external_payload[] = { 0x10, 0x20, 0x30, 0x40 };
        const uint8_t external_seqno[] = { 0xAA, 0xBB, 0xCC };
        libp2p_gossipsub_message_t inbound_msg = {
            .topic = {
                .struct_size = sizeof(inbound_msg.topic),
                .topic = topic_name
            },
            .data = external_payload,
            .data_len = sizeof(external_payload),
            .from = source_peer,
            .seqno = external_seqno,
            .seqno_len = sizeof(external_seqno),
            .raw_message = NULL,
            .raw_message_len = 0
        };

        rc = libp2p_gossipsub_rpc_encode_publish(&inbound_msg, &encoded, &encoded_len);
        ok = (rc == LIBP2P_ERR_OK && encoded != NULL && encoded_len > 0);
        print_result("external_validation_encode_publish", ok);
        if (!ok)
            failures++;

        if (ok)
        {
            rc = libp2p_gossipsub__inject_frame(gs, source_peer, encoded, encoded_len);
            ok = (rc == LIBP2P_ERR_OK);
            print_result("external_validation_inject_first", ok);
            if (!ok)
                failures++;
        }

        if (ok)
        {
            for (int i = 0; i < 200 && atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 0; ++i)
                usleep(1000);
            ok = (atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 1 && g_last_message_id_len > 0
                  && strcmp(g_last_source_text,
                            "12D3KooWMmV2UmyHk4G2MijvSEezwEWj1vDLteA94ppWKqhzyzk5")
                         == 0);
            print_result("external_validation_callback_invoked", ok);
            if (!ok)
                failures++;
        }

        if (ok)
        {
            rc = libp2p_gossipsub__inject_frame(gs, source_peer, encoded, encoded_len);
            ok = (rc == LIBP2P_ERR_OK);
            print_result("external_validation_inject_duplicate", ok);
            if (!ok)
                failures++;
            usleep(10000);
            ok = (atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 1);
            print_result("external_validation_duplicate_suppressed", ok);
            if (!ok)
                failures++;
        }

        if (recipient_ok)
        {
            size_t queue_len = libp2p_gossipsub__peer_sendq_len(gs, recipient_peer);
            ok = (queue_len == 0);
            print_result("external_validation_no_forward_before_report", ok);
            if (!ok)
                failures++;
        }

        if (g_last_message_id_len > 0)
        {
            rc = libp2p_gossipsub_report_message_validation_result(
                gs,
                g_last_message_id,
                g_last_message_id_len,
                LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT);
            ok = (rc == LIBP2P_ERR_OK);
            print_result("external_validation_report_accept", ok);
            if (!ok)
                failures++;
        }

        if (recipient_ok)
        {
            ok = wait_for_peer_frame(gs, recipient_peer, 200, &forwarded_len);
            print_result("external_validation_forward_after_accept", ok);
            if (!ok)
                failures++;
        }

        const uint8_t reject_payload[] = { 0x55, 0x66, 0x77 };
        const uint8_t reject_seqno[] = { 0x01, 0x02, 0x03, 0x04 };
        libp2p_gossipsub_message_t reject_msg = {
            .topic = {
                .struct_size = sizeof(reject_msg.topic),
                .topic = topic_name
            },
            .data = reject_payload,
            .data_len = sizeof(reject_payload),
            .from = source_peer,
            .seqno = reject_seqno,
            .seqno_len = sizeof(reject_seqno),
            .raw_message = NULL,
            .raw_message_len = 0
        };

        free(encoded);
        encoded = NULL;
        encoded_len = 0;
        atomic_store(&g_delivery_called, 0);
        g_last_message_id_len = 0;
        g_last_source_text[0] = '\0';
        if (recipient_ok)
            clear_peer_sendq(gs, recipient_peer);

        rc = libp2p_gossipsub_rpc_encode_publish(&reject_msg, &encoded, &encoded_len);
        ok = (rc == LIBP2P_ERR_OK && encoded != NULL && encoded_len > 0);
        print_result("external_validation_encode_reject", ok);
        if (!ok)
            failures++;

        if (ok)
        {
            rc = libp2p_gossipsub__inject_frame(gs, source_peer, encoded, encoded_len);
            ok = (rc == LIBP2P_ERR_OK);
            print_result("external_validation_inject_reject", ok);
            if (!ok)
                failures++;
        }

        if (ok)
        {
            for (int i = 0; i < 200 && atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 0; ++i)
                usleep(1000);
            ok = (atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 1 && g_last_message_id_len > 0);
            print_result("external_validation_callback_reject_case", ok);
            if (!ok)
                failures++;
        }

        if (g_last_message_id_len > 0)
        {
            rc = libp2p_gossipsub_report_message_validation_result(
                gs,
                g_last_message_id,
                g_last_message_id_len,
                LIBP2P_GOSSIPSUB_VALIDATION_REJECT);
            ok = (rc == LIBP2P_ERR_OK);
            print_result("external_validation_report_reject", ok);
            if (!ok)
                failures++;

            usleep(10000);
            ok = wait_for_peer_idle(gs, recipient_peer, 25);
            print_result("external_validation_reject_not_forwarded", ok);
            if (!ok)
                failures++;

            rc = libp2p_gossipsub_report_message_validation_result(
                gs,
                g_last_message_id,
                g_last_message_id_len,
                LIBP2P_GOSSIPSUB_VALIDATION_REJECT);
            ok = (rc == LIBP2P_ERR_AGAIN);
            print_result("external_validation_second_report_rejected", ok);
            if (!ok)
                failures++;
        }

        const uint8_t expire_payload[] = { 0x90, 0x91 };
        const uint8_t expire_seqno[] = { 0x0A, 0x0B };
        libp2p_gossipsub_message_t expire_msg = {
            .topic = {
                .struct_size = sizeof(expire_msg.topic),
                .topic = topic_name
            },
            .data = expire_payload,
            .data_len = sizeof(expire_payload),
            .from = source_peer,
            .seqno = expire_seqno,
            .seqno_len = sizeof(expire_seqno),
            .raw_message = NULL,
            .raw_message_len = 0
        };

        free(encoded);
        encoded = NULL;
        encoded_len = 0;
        atomic_store(&g_delivery_called, 0);
        g_last_message_id_len = 0;

        rc = libp2p_gossipsub_rpc_encode_publish(&expire_msg, &encoded, &encoded_len);
        ok = (rc == LIBP2P_ERR_OK && encoded != NULL && encoded_len > 0);
        print_result("external_validation_encode_expiry", ok);
        if (!ok)
            failures++;

        if (ok)
        {
            rc = libp2p_gossipsub__inject_frame(gs, source_peer, encoded, encoded_len);
            ok = (rc == LIBP2P_ERR_OK);
            print_result("external_validation_inject_expiry", ok);
            if (!ok)
                failures++;
        }

        if (ok)
        {
            for (int i = 0; i < 200 && atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 0; ++i)
                usleep(1000);
            ok = (atomic_load_explicit(&g_delivery_called, memory_order_relaxed) == 1 && g_last_message_id_len > 0);
            print_result("external_validation_callback_expiry_case", ok);
            if (!ok)
                failures++;
        }

        (void)libp2p_gossipsub__heartbeat(gs);
        (void)libp2p_gossipsub__heartbeat(gs);
        if (g_last_message_id_len > 0)
        {
            rc = libp2p_gossipsub_report_message_validation_result(
                gs,
                g_last_message_id,
                g_last_message_id_len,
                LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT);
            ok = (rc == LIBP2P_ERR_AGAIN);
            print_result("external_validation_report_after_expiry", ok);
            if (!ok)
                failures++;
        }
    }

    if (encoded)
        free(encoded);
    if (recipient_ok)
        peer_id_free(recipient_peer);
    if (source_ok)
        peer_id_free(source_peer);

    libp2p_gossipsub_unsubscribe(gs, topic_name);
    libp2p_gossipsub_stop(gs);
    libp2p_gossipsub_free(gs);
    libp2p_host_free(host);

    return failures ? 1 : 0;
}
