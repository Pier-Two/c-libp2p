#include "test_gossipsub_service_common.h"
#include <math.h>

static libp2p_gossipsub_validation_result_t reject_sync_validator(const libp2p_gossipsub_message_t *msg,
                                                                  void *user_data)
{
    (void)msg;
    (void)user_data;
    return LIBP2P_GOSSIPSUB_VALIDATION_REJECT;
}

static int run_ip_colocation_test(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 1;

    libp2p_gossipsub_t *gs = env->gs;
    int failures = 0;

    const char *topic_name = "score/ip_colocation";
    libp2p_gossipsub_topic_config_t coloc_cfg = {
        .struct_size = sizeof(coloc_cfg),
        .descriptor = {
            .struct_size = sizeof(coloc_cfg.descriptor),
            .topic = topic_name
        },
        .score_params = NULL
    };

    libp2p_err_t err = libp2p_gossipsub_subscribe(gs, &coloc_cfg);
    int subscribe_ok = (err == LIBP2P_ERR_OK);
    print_result("gossipsub_score_ip_colocation_subscribe", subscribe_ok);
    if (!subscribe_ok)
        return failures + 1;

    const char *peer_a_str = "12D3KooWKihXhd6hExP1dcrQom7uxVkxrSF7CXQQqiweRCLFLACn";
    const char *peer_b_str = "12D3KooWPyUCDV3zLh3yfrBh7ku19gt1rjYPdByJ72kX3HY4cGJm";
    peer_id_t peer_a = {0};
    peer_id_t peer_b = {0};
    int peer_a_ok = setup_gossip_peer(gs, topic_name, peer_a_str, &peer_a);
    print_result("gossipsub_score_ip_colocation_peer_a", peer_a_ok);
    if (!peer_a_ok)
        failures++;
    int peer_b_ok = 0;
    if (peer_a_ok)
        peer_b_ok = setup_gossip_peer(gs, topic_name, peer_b_str, &peer_b);
    print_result("gossipsub_score_ip_colocation_peer_b", peer_b_ok);
    if (!peer_b_ok)
        failures++;

    if (peer_a_ok && peer_b_ok)
    {
        libp2p_err_t set_a_rc = libp2p_gossipsub__peer_set_remote_ip(gs, &peer_a, "192.0.2.10");
        libp2p_err_t set_b_rc = libp2p_gossipsub__peer_set_remote_ip(gs, &peer_b, "192.0.2.10");
        int set_a_ok = (set_a_rc == LIBP2P_ERR_OK);
        int set_b_ok = (set_b_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_score_ip_colocation_set_a", set_a_ok);
        if (!set_a_ok)
            failures++;
        print_result("gossipsub_score_ip_colocation_set_b", set_b_ok);
        if (!set_b_ok)
            failures++;

        if (set_a_ok && set_b_ok)
        {
            (void)libp2p_gossipsub__heartbeat(gs);
            double expected_penalty = env->cfg.ip_colocation_weight * 1.0;
            double score_a = libp2p_gossipsub__peer_get_score(gs, &peer_a, NULL);
            double score_b = libp2p_gossipsub__peer_get_score(gs, &peer_b, NULL);
            int penalty_a_ok = (fabs(score_a - expected_penalty) < 1e-6);
            int penalty_b_ok = (fabs(score_b - expected_penalty) < 1e-6);
            print_result("gossipsub_score_ip_colocation_penalty_a", penalty_a_ok);
            if (!penalty_a_ok)
                failures++;
            print_result("gossipsub_score_ip_colocation_penalty_b", penalty_b_ok);
            if (!penalty_b_ok)
                failures++;

            libp2p_err_t reset_b_rc = libp2p_gossipsub__peer_set_remote_ip(gs, &peer_b, "198.51.100.20");
            int reset_b_ok = (reset_b_rc == LIBP2P_ERR_OK);
            print_result("gossipsub_score_ip_colocation_reset_b", reset_b_ok);
            if (!reset_b_ok)
                failures++;

            if (reset_b_ok)
            {
                (void)libp2p_gossipsub__heartbeat(gs);
                double score_a_after = libp2p_gossipsub__peer_get_score(gs, &peer_a, NULL);
                double score_b_after = libp2p_gossipsub__peer_get_score(gs, &peer_b, NULL);
                int cleared_a_ok = (fabs(score_a_after) < 1e-6);
                int cleared_b_ok = (fabs(score_b_after) < 1e-6);
                print_result("gossipsub_score_ip_colocation_clear_a", cleared_a_ok);
                if (!cleared_a_ok)
                    failures++;
                print_result("gossipsub_score_ip_colocation_clear_b", cleared_b_ok);
                if (!cleared_b_ok)
                    failures++;
            }
        }

        (void)libp2p_gossipsub__peer_clear_sendq(gs, &peer_a);
        (void)libp2p_gossipsub__peer_clear_sendq(gs, &peer_b);
        (void)libp2p_gossipsub__peer_set_connected(gs, &peer_a, 0);
        (void)libp2p_gossipsub__peer_set_connected(gs, &peer_b, 0);
    }

    if (subscribe_ok)
    {
        libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
        int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_score_ip_colocation_unsubscribe", unsub_ok);
        if (!unsub_ok)
            failures++;
    }

    if (peer_a_ok)
        peer_id_destroy(&peer_a);
    if (peer_b_ok)
        peer_id_destroy(&peer_b);

    return failures;
}

int gossipsub_service_run_scoring_tests(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 0;

    libp2p_gossipsub_t *gs = env->gs;
    libp2p_err_t err = LIBP2P_ERR_OK;
    int failures = 0;
    {

            const char *topic_name = "score/time_in_mesh_basic";
            libp2p_gossipsub_topic_score_params_t score_params = {
                .struct_size = sizeof(score_params),
                .time_in_mesh_weight = 3.0,
                .first_message_deliveries_weight = 0.0,
                .mesh_message_deliveries_weight = 0.0,
                .invalid_message_deliveries_weight = 0.0,
                .behavioural_penalty_weight = 0.0
            };
            libp2p_gossipsub_topic_config_t score_cfg = {
                .struct_size = sizeof(score_cfg),
                .descriptor = {
                    .struct_size = sizeof(score_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = &score_params
            };
    
            err = libp2p_gossipsub_subscribe(gs, &score_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWRbYFJd8hVZCqxx1Zt9KJ9kzPWxtLs5FoX4iVQQPPrw3Y";
            peer_id_t score_peer;
            memset(&score_peer, 0, sizeof(score_peer));
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &score_peer);
            print_result("gossipsub_score_peer_setup", peer_ok);
            if (!peer_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &score_peer, 1);
                int mesh_ok = (mesh_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_mesh_add", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                double initial_score = libp2p_gossipsub__peer_get_score(gs, &score_peer, NULL);
                int initial_ok = (initial_score >= -1e-6 && initial_score <= 1e-6);
                print_result("gossipsub_score_initial_zero", initial_ok);
                if (!initial_ok)
                    failures++;
    
                usleep(20000);
                libp2p_gossipsub__heartbeat(gs);
                double score_first = libp2p_gossipsub__peer_get_score(gs, &score_peer, NULL);
                int positive_ok = (score_first > 0.0);
                print_result("gossipsub_score_positive", positive_ok);
                if (!positive_ok)
                    failures++;
    
                usleep(20000);
                libp2p_gossipsub__heartbeat(gs);
                double score_second = libp2p_gossipsub__peer_get_score(gs, &score_peer, NULL);
                int increasing_ok = (score_second > score_first);
                print_result("gossipsub_score_increasing", increasing_ok);
                if (!increasing_ok)
                    failures++;
    
                libp2p_err_t remove_rc = libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &score_peer);
                int remove_ok = (remove_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_mesh_remove", remove_ok);
                if (!remove_ok)
                    failures++;
    
                libp2p_gossipsub__heartbeat(gs);
                double score_removed = libp2p_gossipsub__peer_get_score(gs, &score_peer, NULL);
                int reset_ok = (score_removed >= -1e-6 && score_removed <= 0.05);
                print_result("gossipsub_score_reset", reset_ok);
                if (!reset_ok)
                    failures++;
    
                libp2p_err_t override_rc = libp2p_gossipsub__peer_set_score(gs, &score_peer, 5.0);
                int override_set_ok = (override_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_override_set", override_set_ok);
                if (!override_set_ok)
                    failures++;
    
                usleep(10000);
                libp2p_gossipsub__heartbeat(gs);
                int override_flag = 0;
                double override_score = libp2p_gossipsub__peer_get_score(gs, &score_peer, &override_flag);
                int override_ok = (override_flag == 1 && override_score >= 4.9 && override_score <= 5.1);
                print_result("gossipsub_score_override_persist", override_ok);
                if (!override_ok)
                    failures++;
    
                (void)libp2p_gossipsub__peer_set_score(gs, &score_peer, 0.0);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &score_peer);
                libp2p_gossipsub__peer_set_connected(gs, &score_peer, 0);
            }
    
            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_unsubscribe", 0);
                failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&score_peer);
        }
    
        {
            const char *topic_name = "score/operator_controls";
            libp2p_gossipsub_topic_config_t op_cfg = {
                .struct_size = sizeof(op_cfg),
                .descriptor = {
                    .struct_size = sizeof(op_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };

            err = libp2p_gossipsub_subscribe(gs, &op_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_operator_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;

            const char *peer_str = "12D3KooWLL8sR3cQoQ1Mo3eLKP9whXphJEG9wZb5G1fWQYTTK91S";
            peer_id_t op_peer = { 0 };
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &op_peer);
            print_result("gossipsub_score_operator_peer_setup", peer_ok);
            if (!peer_ok)
                failures++;

            if (subscribe_ok && peer_ok)
            {
                int base_updates = env->score_update_count;
                double desired_score = 2.5;
                libp2p_err_t op_rc = libp2p_gossipsub_set_peer_application_score(gs, &op_peer, desired_score);
                int application_set_ok = (op_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_operator_application_set", application_set_ok);
                if (!application_set_ok)
                    failures++;

                double score_after_set = libp2p_gossipsub__peer_get_score(gs, &op_peer, NULL);
                int application_value_ok = (fabs(score_after_set - desired_score) < 1e-6);
                print_result("gossipsub_score_operator_application_value", application_value_ok);
                if (!application_value_ok)
                    failures++;

                int application_callback_ok = (env->score_update_count == base_updates + 1) &&
                                              (env->score_update_last_override == 0);
                print_result("gossipsub_score_operator_application_callback", application_callback_ok);
                if (!application_callback_ok)
                    failures++;

                base_updates = env->score_update_count;
                double penalty_delta = 1.25;
                op_rc = libp2p_gossipsub_add_peer_behaviour_penalty(gs, &op_peer, penalty_delta);
                int penalty_add_ok = (op_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_operator_penalty_add", penalty_add_ok);
                if (!penalty_add_ok)
                    failures++;

                double score_after_penalty = libp2p_gossipsub__peer_get_score(gs, &op_peer, NULL);
                double penalty_weight = env->cfg.behaviour_penalty_weight;
                double expected_penalty_score = desired_score + penalty_weight * (penalty_delta * penalty_delta);
                int penalty_value_ok = (fabs(score_after_penalty - expected_penalty_score) < 1e-6);
                print_result("gossipsub_score_operator_penalty_value", penalty_value_ok);
                if (!penalty_value_ok)
                    failures++;

                int penalty_callback_ok = (env->score_update_count == base_updates + 1) &&
                                          (env->score_update_last_override == 0);
                print_result("gossipsub_score_operator_penalty_callback", penalty_callback_ok);
                if (!penalty_callback_ok)
                    failures++;

                base_updates = env->score_update_count;
                op_rc = libp2p_gossipsub_set_peer_behaviour_penalty(gs, &op_peer, 0.0);
                int penalty_reset_ok = (op_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_operator_penalty_reset", penalty_reset_ok);
                if (!penalty_reset_ok)
                    failures++;

                double score_after_reset = libp2p_gossipsub__peer_get_score(gs, &op_peer, NULL);
                int penalty_reset_value_ok = (fabs(score_after_reset - desired_score) < 1e-6);
                print_result("gossipsub_score_operator_penalty_reset_value", penalty_reset_value_ok);
                if (!penalty_reset_value_ok)
                    failures++;

                int penalty_reset_callback_ok = (env->score_update_count == base_updates + 1) &&
                                                (env->score_update_last_override == 0);
                print_result("gossipsub_score_operator_penalty_reset_callback", penalty_reset_callback_ok);
                if (!penalty_reset_callback_ok)
                    failures++;

                base_updates = env->score_update_count;
                libp2p_err_t override_rc = libp2p_gossipsub__peer_set_score(gs, &op_peer, 4.0);
                int override_ok = (override_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_operator_override_set", override_ok);
                if (!override_ok)
                    failures++;

                int override_callback_ok = (env->score_update_count == base_updates + 1) &&
                                           (env->score_update_last_override == 1) &&
                                           (fabs(env->score_update_last_value - 4.0) < 1e-6);
                print_result("gossipsub_score_operator_override_callback", override_callback_ok);
                if (!override_callback_ok)
                    failures++;

                base_updates = env->score_update_count;
                (void)libp2p_gossipsub__peer_clear_score_override(gs, &op_peer);
                (void)libp2p_gossipsub__heartbeat(gs);
                int override_clear_callback_ok = (env->score_update_count >= base_updates + 1) &&
                                                 (env->score_update_last_override == 0);
                print_result("gossipsub_score_operator_override_clear_callback", override_clear_callback_ok);
                if (!override_clear_callback_ok)
                    failures++;
                double score_post_clear = libp2p_gossipsub__peer_get_score(gs, &op_peer, NULL);
                int override_clear_value_ok = (fabs(score_post_clear - desired_score) < 1e-6);
                print_result("gossipsub_score_operator_override_cleared", override_clear_value_ok);
                if (!override_clear_value_ok)
                    failures++;
            }

            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_operator_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_operator_unsubscribe", 0);
                failures++;
            }

            if (peer_ok)
                peer_id_destroy(&op_peer);
        }

        {
            const char *topic_name = "score/first_delivery";
            libp2p_gossipsub_topic_score_params_t score_params = {
                .struct_size = sizeof(score_params),
                .topic_weight = 1.0,
                .time_in_mesh_weight = 0.0,
                .time_in_mesh_cap = 0.0,
                .first_message_deliveries_weight = 2.5,
                .first_message_deliveries_decay = 1.0,
                .first_message_deliveries_cap = 10.0,
                .mesh_message_deliveries_weight = 0.0,
                .mesh_message_deliveries_decay = 1.0,
                .mesh_message_delivery_threshold = 0.0,
                .mesh_message_deliveries_cap = 0.0,
                .mesh_failure_penalty_weight = 0.0,
                .mesh_failure_penalty_decay = 1.0,
                .invalid_message_deliveries_weight = 0.0,
                .invalid_message_deliveries_decay = 1.0,
                .behavioural_penalty_weight = 0.0
            };
            libp2p_gossipsub_topic_config_t first_cfg = {
                .struct_size = sizeof(first_cfg),
                .descriptor = {
                    .struct_size = sizeof(first_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = &score_params
            };
    
            err = libp2p_gossipsub_subscribe(gs, &first_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_first_delivery_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWNhqcS8N5cCw6mU4esDaS6XdZWQU3oS9LFCH4x4ETyCQT";
            peer_id_t first_peer = { 0 };
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &first_peer);
            print_result("gossipsub_score_first_delivery_peer_setup", peer_ok);
            if (!peer_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &first_peer, 1);
                int mesh_ok = (mesh_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_first_delivery_mesh_add", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                if (mesh_ok)
                {
                    const uint8_t payload[] = { 0x42, 0x42, 0x24 };
                    const uint8_t seqno[] = { 0xAA, 0xBB, 0x01, 0x00 };
                    libp2p_gossipsub_message_t first_msg = {
                        .topic = {
                            .struct_size = sizeof(first_msg.topic),
                            .topic = topic_name
                        },
                        .data = payload,
                        .data_len = sizeof(payload),
                        .from = &first_peer,
                        .seqno = seqno,
                        .seqno_len = sizeof(seqno),
                        .raw_message = NULL,
                        .raw_message_len = 0
                    };
    
                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t enc_rc = libp2p_gossipsub_rpc_encode_publish(&first_msg, &frame, &frame_len);
                    int encode_ok = (enc_rc == LIBP2P_ERR_OK && frame && frame_len > 0);
                    print_result("gossipsub_score_first_delivery_encode", encode_ok);
                    if (!encode_ok)
                        failures++;
    
                    if (encode_ok)
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &first_peer, frame, frame_len);
                        int inject_ok = (inj_rc == LIBP2P_ERR_OK);
                        print_result("gossipsub_score_first_delivery_inject", inject_ok);
                        if (!inject_ok)
                            failures++;
                        else
                        {
                            usleep(10000);
                            double score = libp2p_gossipsub__peer_get_score(gs, &first_peer, NULL);
                            int score_ok = (score > 0.0);
                            print_result("gossipsub_score_first_delivery_positive", score_ok);
                            if (!score_ok)
                                failures++;
                        }
                    }
    
                    if (frame)
                        free(frame);
                }
    
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &first_peer);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &first_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &first_peer, 0);
            }
    
            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_first_delivery_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_first_delivery_unsubscribe", 0);
                failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&first_peer);
        }
    
        {
            const char *topic_name = "score/mesh_delivery_penalty";
            libp2p_gossipsub_topic_score_params_t score_params = {
                .struct_size = sizeof(score_params),
                .topic_weight = 1.0,
                .time_in_mesh_weight = 0.0,
                .time_in_mesh_cap = 0.0,
                .first_message_deliveries_weight = 0.0,
                .first_message_deliveries_decay = 1.0,
                .first_message_deliveries_cap = 0.0,
                .mesh_message_deliveries_weight = -1.0,
                .mesh_message_deliveries_decay = 1.0,
                .mesh_message_delivery_threshold = 1.0,
                .mesh_message_deliveries_cap = 0.0,
                .mesh_failure_penalty_weight = 0.0,
                .mesh_failure_penalty_decay = 1.0,
                .invalid_message_deliveries_weight = 0.0,
                .invalid_message_deliveries_decay = 1.0,
                .behavioural_penalty_weight = 0.0
            };
            libp2p_gossipsub_topic_config_t mesh_cfg = {
                .struct_size = sizeof(mesh_cfg),
                .descriptor = {
                    .struct_size = sizeof(mesh_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = &score_params
            };
    
            err = libp2p_gossipsub_subscribe(gs, &mesh_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_mesh_penalty_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWHZjVdysJ8V5Y2Tyshzw31wY1M2fjTw83YVHC6rU1ttzv";
            peer_id_t mesh_peer = { 0 };
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &mesh_peer);
            print_result("gossipsub_score_mesh_penalty_peer_setup", peer_ok);
            if (!peer_ok && subscribe_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                (void)libp2p_gossipsub__peer_clear_score_override(gs, &mesh_peer);
                libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &mesh_peer, 1);
                int mesh_ok = (mesh_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_mesh_penalty_mesh_add", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                if (mesh_ok)
                {
                    libp2p_gossipsub__heartbeat(gs);
                    double score = libp2p_gossipsub__peer_get_score(gs, &mesh_peer, NULL);
                    int penalty_ok = (score < -0.5);
                    print_result("gossipsub_score_mesh_penalty_negative", penalty_ok);
                    if (!penalty_ok)
                        failures++;
                }
    
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &mesh_peer);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &mesh_peer, 0);
            }
    
            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_mesh_penalty_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_mesh_penalty_unsubscribe", 0);
                failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&mesh_peer);
        }
    
        {
            const char *topic_name = "score/mesh_failure_penalty";
            libp2p_gossipsub_topic_score_params_t score_params = {
                .struct_size = sizeof(score_params),
                .topic_weight = 1.0,
                .time_in_mesh_weight = 0.0,
                .time_in_mesh_cap = 0.0,
                .first_message_deliveries_weight = 0.0,
                .first_message_deliveries_decay = 1.0,
                .first_message_deliveries_cap = 0.0,
                .mesh_message_deliveries_weight = -1.0,
                .mesh_message_deliveries_decay = 1.0,
                .mesh_message_delivery_threshold = 1.5,
                .mesh_message_deliveries_cap = 0.0,
                .mesh_failure_penalty_weight = -0.5,
                .mesh_failure_penalty_decay = 1.0,
                .invalid_message_deliveries_weight = 0.0,
                .invalid_message_deliveries_decay = 1.0,
                .behavioural_penalty_weight = 0.0
            };
            libp2p_gossipsub_topic_config_t failure_cfg = {
                .struct_size = sizeof(failure_cfg),
                .descriptor = {
                    .struct_size = sizeof(failure_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = &score_params
            };
    
            err = libp2p_gossipsub_subscribe(gs, &failure_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_failure_penalty_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWQX1pP6uPQ7RZicMv6z4dGYBHc9B7iKLB9gowgCJFzQEw";
            peer_id_t failure_peer = { 0 };
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &failure_peer);
            print_result("gossipsub_score_failure_penalty_peer_setup", peer_ok);
            if (!peer_ok && subscribe_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                (void)libp2p_gossipsub__peer_clear_score_override(gs, &failure_peer);
                libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &failure_peer, 1);
                int mesh_ok = (mesh_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_failure_penalty_mesh_add", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                if (mesh_ok)
                {
                    libp2p_gossipsub__heartbeat(gs);
                    double score_before = libp2p_gossipsub__peer_get_score(gs, &failure_peer, NULL);
                    int negative_ok = (score_before < -1.0);
                    print_result("gossipsub_score_failure_penalty_negative_before", negative_ok);
                    if (!negative_ok)
                        failures++;
    
                    libp2p_err_t remove_rc = libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &failure_peer);
                    int remove_ok = (remove_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_score_failure_penalty_remove", remove_ok);
                    if (!remove_ok)
                        failures++;
    
                    double score_after = libp2p_gossipsub__peer_get_score(gs, &failure_peer, NULL);
                    int penalty_sticky = (score_after < score_before - 0.4);
                    print_result("gossipsub_score_failure_penalty_sticky", penalty_sticky);
                    if (!penalty_sticky)
                        failures++;
                }
    
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &failure_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &failure_peer, 0);
            }
    
            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_failure_penalty_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_failure_penalty_unsubscribe", 0);
                failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&failure_peer);
        }
    
        {
            const char *topic_name = "score/invalid_penalty";
            libp2p_gossipsub_topic_score_params_t score_params = {
                .struct_size = sizeof(score_params),
                .topic_weight = 1.0,
                .time_in_mesh_weight = 0.0,
                .time_in_mesh_cap = 0.0,
                .first_message_deliveries_weight = 0.0,
                .first_message_deliveries_decay = 1.0,
                .mesh_message_deliveries_weight = 0.0,
                .mesh_message_deliveries_decay = 1.0,
                .mesh_message_delivery_threshold = 0.0,
                .mesh_message_deliveries_cap = 0.0,
                .mesh_failure_penalty_weight = 0.0,
                .mesh_failure_penalty_decay = 1.0,
                .invalid_message_deliveries_weight = -4.0,
                .invalid_message_deliveries_decay = 1.0,
                .behavioural_penalty_weight = 0.0
            };
            libp2p_gossipsub_topic_config_t invalid_cfg = {
                .struct_size = sizeof(invalid_cfg),
                .descriptor = {
                    .struct_size = sizeof(invalid_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = &score_params
            };
    
            err = libp2p_gossipsub_subscribe(gs, &invalid_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_invalid_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            libp2p_gossipsub_validator_handle_t *validator_handle = NULL;
            if (subscribe_ok)
            {
                libp2p_gossipsub_validator_def_t def = {
                    .struct_size = sizeof(def),
                    .type = LIBP2P_GOSSIPSUB_VALIDATOR_SYNC,
                    .sync_fn = reject_sync_validator,
                    .async_fn = NULL,
                    .user_data = NULL
                };
                libp2p_err_t val_rc = libp2p_gossipsub_add_validator(gs, topic_name, &def, &validator_handle);
                int val_ok = (val_rc == LIBP2P_ERR_OK && validator_handle);
                print_result("gossipsub_score_invalid_validator_add", val_ok);
                if (!val_ok)
                {
                    failures++;
                    validator_handle = NULL;
                }
            }
    
            const char *peer_str = "12D3KooWR4hrfaGHadzZmuywckcUPMfELzUhY4JiuYxazJJQdky3";
            peer_id_t invalid_peer = { 0 };
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &invalid_peer);
            print_result("gossipsub_score_invalid_peer_setup", peer_ok);
            if (!peer_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                (void)libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &invalid_peer, 1);
    
                const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
                const uint8_t seqno[] = { 0x11, 0x22, 0x33, 0x44 };
                libp2p_gossipsub_message_t invalid_msg = {
                    .topic = {
                        .struct_size = sizeof(invalid_msg.topic),
                        .topic = topic_name
                    },
                    .data = payload,
                    .data_len = sizeof(payload),
                    .from = &invalid_peer,
                    .seqno = seqno,
                    .seqno_len = sizeof(seqno),
                    .raw_message = NULL,
                    .raw_message_len = 0
                };
    
                uint8_t *frame = NULL;
                size_t frame_len = 0;
                libp2p_err_t enc_rc = libp2p_gossipsub_rpc_encode_publish(&invalid_msg, &frame, &frame_len);
                int encode_ok = (enc_rc == LIBP2P_ERR_OK && frame && frame_len > 0);
                print_result("gossipsub_score_invalid_encode", encode_ok);
                if (!encode_ok)
                    failures++;
    
                if (encode_ok)
                {
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &invalid_peer, frame, frame_len);
                    int inject_ok = (inj_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_score_invalid_inject", inject_ok);
                    if (!inject_ok)
                        failures++;
                    else
                    {
                        usleep(10000);
                        double score = libp2p_gossipsub__peer_get_score(gs, &invalid_peer, NULL);
                        int score_ok = (score < 0.0);
                        print_result("gossipsub_score_invalid_negative", score_ok);
                        if (!score_ok)
                            failures++;
                    }
                }
    
                if (frame)
                    free(frame);
    
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &invalid_peer);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &invalid_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &invalid_peer, 0);
            }
    
            if (validator_handle)
            {
                libp2p_err_t val_rm_rc = libp2p_gossipsub_remove_validator(gs, validator_handle);
                int val_rm_ok = (val_rm_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_invalid_validator_remove", val_rm_ok);
                if (!val_rm_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_invalid_validator_remove", 0);
                failures++;
            }
    
            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_invalid_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_invalid_unsubscribe", 0);
                failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&invalid_peer);
        }
    
        {
            const char *runtime_topic = "config/runtime_update_score";
            const char *runtime_peer_str = "12D3KooWQezYB7Lr9n7xw3v63ogpDkC6BasuCCJJksDkD6ZrB8Sx";
            const size_t minimal_config_size = offsetof(libp2p_gossipsub_topic_config_t, score_params) +
                                               sizeof(((libp2p_gossipsub_topic_config_t *)0)->score_params);
    
            libp2p_gossipsub_topic_config_t missing_cfg = {
                .struct_size = minimal_config_size,
                .descriptor = {
                    .struct_size = sizeof(libp2p_gossipsub_topic_descriptor_t),
                    .topic = runtime_topic
                },
                .score_params = NULL
            };
            libp2p_err_t missing_rc = libp2p_gossipsub_update_topic(gs, &missing_cfg);
            int missing_expected = (missing_rc == LIBP2P_ERR_UNSUPPORTED);
            print_result("gossipsub_runtime_update_missing_topic", missing_expected);
            if (!missing_expected)
                failures++;
    
            libp2p_gossipsub_topic_score_params_t runtime_score_params = {
                .struct_size = sizeof(runtime_score_params),
                .topic_weight = 1.0,
                .time_in_mesh_weight = 1.0,
                .first_message_deliveries_weight = 0.0,
                .mesh_message_deliveries_weight = 0.0,
                .invalid_message_deliveries_weight = 0.0,
                .behavioural_penalty_weight = 0.0
            };
            libp2p_gossipsub_topic_config_t runtime_cfg = {
                .struct_size = sizeof(runtime_cfg),
                .descriptor = {
                    .struct_size = sizeof(libp2p_gossipsub_topic_descriptor_t),
                    .topic = runtime_topic
                },
                .score_params = &runtime_score_params
            };
    
            libp2p_err_t runtime_sub_rc = libp2p_gossipsub_subscribe(gs, &runtime_cfg);
            int runtime_sub_ok = (runtime_sub_rc == LIBP2P_ERR_OK);
            print_result("gossipsub_runtime_update_subscribe", runtime_sub_ok);
            if (!runtime_sub_ok)
                failures++;
    
            peer_id_t runtime_peer = { 0 };
            int runtime_peer_ok = runtime_sub_ok && setup_gossip_peer(gs, runtime_topic, runtime_peer_str, &runtime_peer);
            print_result("gossipsub_runtime_update_peer_setup", runtime_peer_ok);
            if (!runtime_peer_ok)
            {
                failures++;
            }
    
            if (runtime_sub_ok && runtime_peer_ok)
            {
                libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, runtime_topic, &runtime_peer, 1);
                int mesh_ok = (mesh_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_runtime_update_mesh_join", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                if (mesh_ok)
                {
                    (void)libp2p_gossipsub__heartbeat(gs);
                    usleep(20000);
                    (void)libp2p_gossipsub__heartbeat(gs);
                    double initial_score = libp2p_gossipsub__peer_get_score(gs, &runtime_peer, NULL);
                    int initial_positive = (initial_score > 0.0);
                    print_result("gossipsub_runtime_update_initial_score", initial_positive);
                    if (!initial_positive)
                        failures++;
    
                    libp2p_gossipsub_topic_score_params_t boosted_params = runtime_score_params;
                    boosted_params.time_in_mesh_weight = 4.0;
                    libp2p_gossipsub_topic_config_t boosted_cfg = {
                        .struct_size = sizeof(boosted_cfg),
                        .descriptor = {
                            .struct_size = sizeof(libp2p_gossipsub_topic_descriptor_t),
                            .topic = runtime_topic
                        },
                        .score_params = &boosted_params
                    };
    
                    libp2p_err_t boost_rc = libp2p_gossipsub_update_topic(gs, &boosted_cfg);
                    int boost_ok = (boost_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_runtime_update_apply_boost", boost_ok);
                    if (!boost_ok)
                        failures++;
    
                    double boosted_score = libp2p_gossipsub__peer_get_score(gs, &runtime_peer, NULL);
                    int boosted_higher = (boosted_score > initial_score * 1.5);
                    print_result("gossipsub_runtime_update_score_increased", boosted_higher);
                    if (!boosted_higher)
                        failures++;
    
                    libp2p_gossipsub_topic_config_t clear_cfg = {
                        .struct_size = minimal_config_size,
                        .descriptor = {
                            .struct_size = sizeof(libp2p_gossipsub_topic_descriptor_t),
                            .topic = runtime_topic
                        },
                        .score_params = NULL
                    };
                    libp2p_err_t clear_rc = libp2p_gossipsub_update_topic(gs, &clear_cfg);
                    int clear_ok = (clear_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_runtime_update_clear_params", clear_ok);
                    if (!clear_ok)
                        failures++;
    
                    double cleared_score = libp2p_gossipsub__peer_get_score(gs, &runtime_peer, NULL);
                    int cleared_zero = (cleared_score > -1e-6 && cleared_score < 1e-6);
                    print_result("gossipsub_runtime_update_score_cleared", cleared_zero);
                    if (!cleared_zero)
                        failures++;
    
                    (void)libp2p_gossipsub__heartbeat(gs);
                    double cleared_post_tick = libp2p_gossipsub__peer_get_score(gs, &runtime_peer, NULL);
                    int cleared_stable = (cleared_post_tick > -1e-6 && cleared_post_tick < 1e-6);
                    print_result("gossipsub_runtime_update_score_stable", cleared_stable);
                    if (!cleared_stable)
                        failures++;
                }
    
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, runtime_topic, &runtime_peer);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &runtime_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &runtime_peer, 0);
            }
    
            if (runtime_sub_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, runtime_topic);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_runtime_update_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_runtime_update_unsubscribe", 0);
                failures++;
            }
    
            if (runtime_peer_ok)
                peer_id_destroy(&runtime_peer);
        }

        {
            const char *topic_name = "score/ihave_penalty";
            libp2p_gossipsub_topic_config_t spam_cfg = {
                .struct_size = sizeof(spam_cfg),
                .descriptor = {
                    .struct_size = sizeof(spam_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };

            err = libp2p_gossipsub_subscribe(gs, &spam_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_score_ihave_penalty_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;

            const char *peer_str = "12D3KooWJMCZpZGsGWpRieyU7gnaNmJKbnHiKK4xqSSdoRRt9P5r";
            peer_id_t spam_peer = {0};
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &spam_peer);
            print_result("gossipsub_score_ihave_penalty_peer_setup", peer_ok);
            if (!peer_ok)
            {
                failures++;
            }

            if (subscribe_ok && peer_ok)
            {
                libp2p_err_t reset_app_rc = libp2p_gossipsub_set_peer_application_score(gs, &spam_peer, 0.0);
                int reset_app_ok = (reset_app_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_ihave_penalty_reset_app", reset_app_ok);
                if (!reset_app_ok)
                    failures++;

                libp2p_err_t reset_pen_rc = libp2p_gossipsub_set_peer_behaviour_penalty(gs, &spam_peer, 0.0);
                int reset_pen_ok = (reset_pen_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_ihave_penalty_reset_penalty", reset_pen_ok);
                if (!reset_pen_ok)
                    failures++;

                libp2p_err_t override_rc = libp2p_gossipsub__peer_set_score(gs, &spam_peer, 0.0);
                int override_reset_ok = (override_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_ihave_penalty_override_reset", override_reset_ok);
                if (!override_reset_ok)
                    failures++;

                libp2p_err_t clear_override_rc = libp2p_gossipsub__peer_clear_score_override(gs, &spam_peer);
                int override_clear_ok = (clear_override_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_ihave_penalty_override_clear", override_clear_ok);
                if (!override_clear_ok)
                    failures++;

                double expected_penalty = env->cfg.ihave_spam_penalty;
                double initial_score = libp2p_gossipsub__peer_get_score(gs, &spam_peer, NULL);
                int initial_ok = (initial_score > -1e-6 && initial_score < 1e-6);
                print_result("gossipsub_score_ihave_penalty_initial", initial_ok);
                if (!initial_ok)
                    failures++;

                const uint8_t msg1[] = {0xAA, 0x01};
                const uint8_t msg2[] = {0xAA, 0x02};
                const uint8_t msg3[] = {0xAA, 0x03};
                const uint8_t *msgs[] = {msg1, msg2, msg3};
                const size_t msg_lens[] = {sizeof(msg1), sizeof(msg2), sizeof(msg3)};

                for (size_t i = 0; i < 3; ++i)
                {
                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t enc_rc = encode_control_ihave_rpc(topic_name, msgs[i], msg_lens[i], &frame, &frame_len);
                    int enc_ok = (enc_rc == LIBP2P_ERR_OK && frame && frame_len > 0);
                    char enc_name[64];
                    snprintf(enc_name, sizeof(enc_name), "gossipsub_score_ihave_penalty_encode_%zu", i);
                    print_result(enc_name, enc_ok);
                    if (!enc_ok)
                    {
                        failures++;
                        if (frame)
                            free(frame);
                        break;
                    }

                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &spam_peer, frame, frame_len);
                    free(frame);
                    int inj_ok = (inj_rc == LIBP2P_ERR_OK);
                    char inj_name[64];
                    snprintf(inj_name, sizeof(inj_name), "gossipsub_score_ihave_penalty_inject_%zu", i);
                    print_result(inj_name, inj_ok);
                    if (!inj_ok)
                    {
                        failures++;
                        break;
                    }

                    usleep(10000);

                    double score = libp2p_gossipsub__peer_get_score(gs, &spam_peer, NULL);
                    if (i < 2)
                    {
                        int pre_penalty_ok = (score > -1e-6 && score < 1e-6);
                        char name[64];
                        snprintf(name, sizeof(name), "gossipsub_score_ihave_penalty_pre_%zu", i);
                        print_result(name, pre_penalty_ok);
                        if (!pre_penalty_ok)
                            failures++;
                    }
                    else
                    {
                        double penalty_weight = env->cfg.behaviour_penalty_weight;
                        double expected_score = (expected_penalty > 0.0 && penalty_weight != 0.0)
                                                    ? penalty_weight * (expected_penalty * expected_penalty)
                                                    : 0.0;
                        double delta = fabs(score - expected_score);
                        int penalty_ok = (delta < 1e-6);
                        print_result("gossipsub_score_ihave_penalty_triggered", penalty_ok);
                        if (!penalty_ok)
                            failures++;
                    }
                }

                (void)libp2p_gossipsub__peer_clear_sendq(gs, &spam_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &spam_peer, 0);
            }

            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_score_ihave_penalty_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_score_ihave_penalty_unsubscribe", 0);
                failures++;
            }

            if (peer_ok)
                peer_id_destroy(&spam_peer);
        }

        {
            const char *topic_name = "spam/iwant_promises";
            libp2p_gossipsub_topic_config_t promise_cfg = {
                .struct_size = sizeof(promise_cfg),
                .descriptor = {
                    .struct_size = sizeof(promise_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };

            err = libp2p_gossipsub_subscribe(gs, &promise_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_spam_promise_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;

            const char *peer_str = "12D3KooWDGnJ9cYVbS1oFNsM1PYTR1eA6AAquuZqPtSg1xMkFk3d";
            peer_id_t promise_peer = {0};
            int peer_ok = 0;
            if (subscribe_ok)
                peer_ok = setup_gossip_peer(gs, topic_name, peer_str, &promise_peer);
            print_result("gossipsub_spam_promise_peer_setup", peer_ok);
            if (!peer_ok)
                failures++;

            if (subscribe_ok && peer_ok)
            {
                const uint8_t msg_id[] = {0xBA, 0x5E, 0xBA};
                uint8_t *ihave_frame = NULL;
                size_t ihave_len = 0;

                libp2p_err_t enc_rc = encode_control_ihave_rpc(topic_name, msg_id, sizeof(msg_id), &ihave_frame, &ihave_len);
                int enc_ok = (enc_rc == LIBP2P_ERR_OK && ihave_frame && ihave_len > 0);
                print_result("gossipsub_spam_promise_encode", enc_ok);
                if (!enc_ok)
                {
                    failures++;
                }
                else
                {
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &promise_peer, ihave_frame, ihave_len);
                    int inj_ok = (inj_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_spam_promise_inject", inj_ok);
                    if (!inj_ok)
                        failures++;
                    free(ihave_frame);
                }

                size_t queue_len = libp2p_gossipsub__peer_sendq_len(gs, &promise_peer);
                int iwant_sent = (queue_len >= 1);
                print_result("gossipsub_spam_promise_iwant_sent", iwant_sent);
                if (!iwant_sent)
                    failures++;

                uint8_t *send_frame = NULL;
                size_t send_len = 0;
                libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, &promise_peer, &send_frame, &send_len);
                int pop_ok = (pop_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_spam_promise_pop", pop_ok);
                if (!pop_ok)
                    failures++;
                if (send_frame)
                    free(send_frame);

                double initial_score = libp2p_gossipsub__peer_get_score(gs, &promise_peer, NULL);
                int initial_ok = (initial_score > -1e-6 && initial_score < 1e-6);
                print_result("gossipsub_spam_promise_initial_score", initial_ok);
                if (!initial_ok)
                    failures++;

                int followup_ms = env->cfg.iwant_followup_time_ms ? env->cfg.iwant_followup_time_ms : 3000;
                usleep((useconds_t)(followup_ms * 2000));
                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_spam_promise_heartbeat", hb_ok);
                if (!hb_ok)
                    failures++;

                double after_score = libp2p_gossipsub__peer_get_score(gs, &promise_peer, NULL);
                int penalty_applied = (after_score < -0.5);
                print_result("gossipsub_spam_promise_penalty", penalty_applied);
                if (!penalty_applied)
                    failures++;

                (void)libp2p_gossipsub__peer_clear_sendq(gs, &promise_peer);
                (void)libp2p_gossipsub__peer_set_connected(gs, &promise_peer, 0);
            }

            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_spam_promise_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_spam_promise_unsubscribe", 0);
                failures++;
            }

            if (peer_ok)
                peer_id_destroy(&promise_peer);
        }

        {
            const char *explicit_peer_str = "12D3KooWL9qw9QdCsiPUQXGWxZhwivKar35CFYuU9B9kavHuV2XZ";
            const char *mesh_peer_str = "12D3KooWL41axLhXgML3zbxTDkVxFvtz7ZzZWtH1yurVpbkWueMH";
            const char *explicit_topic_name = "explicit/test/topic";
            peer_id_t explicit_peer = { 0 };
            peer_id_t mesh_peer = { 0 };
            int explicit_peer_ok = (peer_id_create_from_string(explicit_peer_str, &explicit_peer) == PEER_ID_SUCCESS);
            int mesh_peer_ok = (peer_id_create_from_string(mesh_peer_str, &mesh_peer) == PEER_ID_SUCCESS);

        }

    failures += run_ip_colocation_test(env);
    return failures;
}
