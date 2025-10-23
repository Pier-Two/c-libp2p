#include "test_gossipsub_service_common.h"

#include <errno.h>

static libp2p_gossipsub_validation_result_t counting_sync_validator(const libp2p_gossipsub_message_t *msg,
                                                                    void *user_data)
{
    (void)msg;
    (void)user_data;
    atomic_fetch_add_explicit(&g_sync_called, 1, memory_order_relaxed);
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

int gossipsub_service_run_setup(gossipsub_service_test_env_t *env)
{
    if (!env)
        return 0;

    int failures = 0;
    env->score_update_count = 0;
    env->score_update_last_value = 0.0;
    env->score_update_last_override = 0;
    libp2p_host_options_t host_opts;
    if (libp2p_host_options_default(&host_opts) != 0)
    {
        fprintf(stderr, "opts default failed\n");
        env->fatal_failure = 1;
        return 1;
    }

    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&host_opts, &host) != 0 || !host)
    {
        fprintf(stderr, "host_new failed\n");
        env->fatal_failure = 1;
        return 1;
    }
    env->host = host;

    const char *config_peer_str = "12D3KooWL9qw9QdCsiPUQXGWxZhwivKar35CFYuU9B9kavHuV2XZ";
    peer_id_t config_peer = { 0 };
    int config_peer_ok = (peer_id_create_from_string(config_peer_str, &config_peer) == PEER_ID_SUCCESS);
    print_result("gossipsub_explicit_config_peer_id", config_peer_ok);
    if (!config_peer_ok)
    {
        failures++;
        memset(&env->config_peer, 0, sizeof(env->config_peer));
        env->config_peer_ok = 0;
    }
    else
    {
        env->config_peer = config_peer;
        config_peer.bytes = NULL;
        config_peer.size = 0;
        env->config_peer_ok = 1;
        env->config_addrs[0] = "/ip4/127.0.0.1/tcp/7001";
        env->cfg_explicit_peer.struct_size = sizeof(env->cfg_explicit_peer);
        env->cfg_explicit_peer.peer = &env->config_peer;
        env->cfg_explicit_peer.addresses = env->config_addrs;
        env->cfg_explicit_peer.address_count = 1;
    }

    libp2p_gossipsub_config_t default_cfg;
    libp2p_err_t default_rc = libp2p_gossipsub_config_default(&default_cfg);
    int default_ok = (default_rc == LIBP2P_ERR_OK);
    print_result("gossipsub_config_default_ok", default_ok);
    if (!default_ok)
        failures++;

    int overlay_defaults_ok = default_ok &&
                              default_cfg.d == 6 &&
                              default_cfg.d_lo == 5 &&
                              default_cfg.d_hi == 12 &&
                              default_cfg.d_lazy == 6 &&
                              default_cfg.d_out == 2 &&
                              default_cfg.d_score == 4 &&
                              default_cfg.gossip_factor_percent == 25;
    print_result("gossipsub_config_default_overlay", overlay_defaults_ok);
    if (!overlay_defaults_ok)
    {
        failures++;
        if (default_ok)
        {
            printf("expected overlay defaults d=6 d_lo=5 d_hi=12 d_lazy=6 d_out=2 d_score=4 gossip_factor=25,"
                   " got d=%d d_lo=%d d_hi=%d d_lazy=%d d_out=%d d_score=%d gossip_factor=%d\n",
                   default_cfg.d,
                   default_cfg.d_lo,
                   default_cfg.d_hi,
                   default_cfg.d_lazy,
                   default_cfg.d_out,
                   default_cfg.d_score,
                   default_cfg.gossip_factor_percent);
        }
    }

    int px_target_ok = default_ok && default_cfg.px_peer_target == 16;
    print_result("gossipsub_config_default_px_target", px_target_ok);
    if (!px_target_ok)
    {
        failures++;
        if (default_ok)
            printf("expected px_peer_target=16, got %zu\n", default_cfg.px_peer_target);
    }

    int ihave_defaults_ok = default_ok &&
                            default_cfg.max_ihave_messages == 10 &&
                            default_cfg.max_ihave_length == 5000;
    print_result("gossipsub_config_default_ihave_limits", ihave_defaults_ok);
    if (!ihave_defaults_ok)
    {
        failures++;
        if (default_ok)
        {
            printf("expected max_ihave_messages=10 max_ihave_length=5000, got %zu and %zu\n",
                   default_cfg.max_ihave_messages,
                   default_cfg.max_ihave_length);
        }
    }
    int ihave_penalty_default_ok = default_ok && default_cfg.ihave_spam_penalty == 0.1;
    print_result("gossipsub_config_default_ihave_penalty", ihave_penalty_default_ok);
    if (!ihave_penalty_default_ok)
    {
        failures++;
        if (default_ok)
            printf("expected ihave_spam_penalty=0.1, got %f\n", default_cfg.ihave_spam_penalty);
    }

    libp2p_gossipsub_config_t invalid_cfg = default_cfg;
    invalid_cfg.d_lo = default_cfg.d + 1;
    libp2p_gossipsub_t *invalid_gs = NULL;
    libp2p_err_t invalid_rc = libp2p_gossipsub_new(host, &invalid_cfg, &invalid_gs);
    int invalid_rejected = (invalid_rc == LIBP2P_ERR_UNSUPPORTED && invalid_gs == NULL);
    print_result("gossipsub_config_invalid_mesh_rejected", invalid_rejected);
    if (!invalid_rejected)
        failures++;

    libp2p_gossipsub_config_default(&env->cfg);
    env->cfg.d = 4;
    env->cfg.d_lo = 2;
    env->cfg.d_hi = 6;
    env->cfg.d_lazy = 3;
    env->cfg.d_score = 2;
    env->cfg.d_out = 1;
    env->cfg.iwant_followup_time_ms = 200;
    env->cfg.opportunistic_graft_threshold = 0.5;
    env->cfg.opportunistic_graft_peers = 2;
    env->cfg.accept_px_threshold = 0.5;
    env->cfg.max_ihave_messages = 2;
    env->cfg.max_ihave_length = 2;
    env->cfg.on_score_update = gossipsub_test_score_update_cb;
    env->cfg.score_update_user_data = env;
    env->cfg.app_specific_weight = 1.0;
    env->cfg.behaviour_penalty_weight = -1.0;
    env->cfg.behaviour_penalty_decay = 0.95;
    env->cfg.ip_colocation_weight = -1.5;
    env->cfg.ip_colocation_threshold = 1;
    if (env->config_peer_ok)
    {
        env->cfg.explicit_peers = &env->cfg_explicit_peer;
        env->cfg.num_explicit_peers = 1;
    }
    else
    {
        env->cfg.explicit_peers = NULL;
        env->cfg.num_explicit_peers = 0;
    }
    env->cfg_initialized = 1;

    libp2p_gossipsub_t *gs = NULL;
    libp2p_err_t err = libp2p_gossipsub_new(host, &env->cfg, &gs);
    int ok = (err == LIBP2P_ERR_OK && gs);
    print_result("gossipsub_new", ok);
    if (!ok)
    {
        env->fatal_failure = 1;
        gossipsub_service_free_env(env);
        return failures ? failures : 1;
    }
    env->gs = gs;

    if (env->config_peer_ok)
    {
        const multiaddr_t **seeded = NULL;
        size_t seeded_len = 0;
        int peerstore_ok = (host->peerstore != NULL);
        if (peerstore_ok)
            peerstore_ok = (libp2p_peerstore_get_addrs(host->peerstore, &env->config_peer, &seeded, &seeded_len) == 0);
        int seeded_available = (peerstore_ok && seeded_len >= 1);
        print_result("gossipsub_explicit_config_seeded_peerstore", seeded_available);
        if (!seeded_available)
            failures++;
        if (seeded)
            libp2p_peerstore_free_addrs(seeded, seeded_len);
    }

    err = libp2p_gossipsub_start(gs);
    ok = (err == LIBP2P_ERR_OK);
    print_result("gossipsub_start", ok);
    if (!ok)
        failures++;

    libp2p_gossipsub_topic_config_t topic_cfg = {
        .struct_size = sizeof(topic_cfg),
        .descriptor = {
            .struct_size = sizeof(topic_cfg.descriptor),
            .topic = "test/topic"
        },
        .score_params = NULL
    };
    err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
    ok = (err == LIBP2P_ERR_OK);
    print_result("gossipsub_subscribe", ok);
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
        .user_data = NULL
    };
    err = libp2p_gossipsub_add_validator(gs, "test/topic", &sync_def, &sync_handle);
    ok = (err == LIBP2P_ERR_OK && sync_handle);
    print_result("gossipsub_add_sync_validator", ok);
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
    err = libp2p_gossipsub_add_validator(gs, "test/topic", &async_def, &async_handle);
    ok = (err == LIBP2P_ERR_OK && async_handle);
    print_result("gossipsub_add_async_validator", ok);
    if (!ok)
        failures++;

    env->sync_handle = sync_handle;
    env->async_handle = async_handle;

    int pub_ok = 0;
    if (ok)
    {
        uint8_t payload[4] = { 0x00, 0x01, 0x02, 0x03 };
        libp2p_gossipsub_message_t msg = {
            .topic = {
                .struct_size = sizeof(msg.topic),
                .topic = "test/topic"
            },
            .data = payload,
            .data_len = sizeof(payload),
            .from = NULL,
            .seqno = NULL,
            .seqno_len = 0,
            .raw_message = NULL,
            .raw_message_len = 0
        };
        err = libp2p_gossipsub_publish(gs, &msg);
        pub_ok = (err == LIBP2P_ERR_OK);
        print_result("gossipsub_publish", pub_ok);
        if (!pub_ok)
            failures++;
    }

    if (pub_ok)
    {
        for (int i = 0; i < 200 && atomic_load_explicit(&g_async_called, memory_order_relaxed) == 0; ++i)
            usleep(1000);
    }

    int sync_seen = (atomic_load_explicit(&g_sync_called, memory_order_relaxed) > 0);
    print_result("gossipsub_sync_validator_invoked", sync_seen);
    if (!sync_seen)
        failures++;

    int async_seen = (atomic_load_explicit(&g_async_called, memory_order_relaxed) > 0);
    print_result("gossipsub_async_validator_invoked", async_seen);
    if (!async_seen)
        failures++;

    if (sync_seen && async_seen)
    {
        atomic_store(&g_sync_called, 0);
        atomic_store(&g_async_called, 0);

        const char *test_peer_str = "12D3KooWQ7W3zfBDSSY5YTbSsfXCMVvjJAnYXhYzu3PV6PvJkU8E";
        peer_id_t self_peer = { 0 };
        int peer_ok = (peer_id_create_from_string(test_peer_str, &self_peer) == PEER_ID_SUCCESS);
        libp2p_err_t enc_err = LIBP2P_ERR_INTERNAL;
        libp2p_err_t inj_err = LIBP2P_ERR_INTERNAL;

        if (peer_ok)
        {
            const uint8_t inbound_payload[] = { 0x10, 0x20, 0x30 };
            const uint8_t inbound_seqno[] = { 0xAA, 0x01, 0x02 };
            libp2p_gossipsub_message_t inbound_msg = {
                .topic = {
                    .struct_size = sizeof(inbound_msg.topic),
                    .topic = "test/topic"
                },
                .data = inbound_payload,
                .data_len = sizeof(inbound_payload),
                .from = &self_peer,
                .seqno = inbound_seqno,
                .seqno_len = sizeof(inbound_seqno),
                .raw_message = NULL,
                .raw_message_len = 0
            };

            uint8_t *encoded = NULL;
            size_t encoded_len = 0;
            enc_err = libp2p_gossipsub_rpc_encode_publish(&inbound_msg, &encoded, &encoded_len);
            if (enc_err == LIBP2P_ERR_OK && encoded && encoded_len)
            {
                inj_err = libp2p_gossipsub__inject_frame(gs, &self_peer, encoded, encoded_len);
                if (inj_err == LIBP2P_ERR_OK)
                {
                    for (int i = 0; i < 200 && atomic_load_explicit(&g_async_called, memory_order_relaxed) == 0; ++i)
                        usleep(1000);
                }
                free(encoded);
            }
        }

        int inbound_sync_seen = (atomic_load_explicit(&g_sync_called, memory_order_relaxed) > 0);
        int inbound_async_seen = (atomic_load_explicit(&g_async_called, memory_order_relaxed) > 0);

        print_result("gossipsub_inbound_peer_available", peer_ok);
        if (!peer_ok)
            failures++;

        print_result("gossipsub_inbound_rpc_encoded", enc_err == LIBP2P_ERR_OK);
        if (enc_err != LIBP2P_ERR_OK)
            failures++;

        print_result("gossipsub_inbound_rpc_injected", inj_err == LIBP2P_ERR_OK);
        if (inj_err != LIBP2P_ERR_OK)
            failures++;

        print_result("gossipsub_inbound_sync_validator", inbound_sync_seen);
        if (!inbound_sync_seen)
            failures++;

        print_result("gossipsub_inbound_async_validator", inbound_async_seen);
        if (!inbound_async_seen)
            failures++;

        if (peer_ok)
            peer_id_destroy(&self_peer);
    }
    else
    {
        print_result("gossipsub_inbound_peer_available", 0);
        print_result("gossipsub_inbound_rpc_encoded", 0);
        print_result("gossipsub_inbound_rpc_injected", 0);
        print_result("gossipsub_inbound_sync_validator", 0);
        print_result("gossipsub_inbound_async_validator", 0);
        failures += 5;
    }

    return failures;
}
