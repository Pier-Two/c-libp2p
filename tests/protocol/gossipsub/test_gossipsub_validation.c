#include "protocol/gossipsub/gossipsub.h"
#include "gossipsub_validation.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_int g_sync_called;
static atomic_int g_async_called;

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

static void print_result(const char *name, int ok)
{
    printf("TEST: %-45s | %s\n", name, ok ? "PASS" : "FAIL");
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
        rc = gossipsub_validation_schedule(gs, topic_state, handles, handle_count, &msg, 1);
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

    libp2p_gossipsub_unsubscribe(gs, topic_name);
    libp2p_gossipsub_stop(gs);
    libp2p_gossipsub_free(gs);
    libp2p_host_free(host);

    return failures ? 1 : 0;
}
