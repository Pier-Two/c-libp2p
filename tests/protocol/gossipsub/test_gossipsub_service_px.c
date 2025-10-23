#include "test_gossipsub_service_common.h"

int gossipsub_service_run_px_and_opportunistic_tests(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 0;

    libp2p_gossipsub_t *gs = env->gs;
    libp2p_err_t err = LIBP2P_ERR_OK;
    const libp2p_gossipsub_config_t cfg = env->cfg;
    int failures = 0;
    libp2p_host_t *host = env->host;

        {
            const char *topic_name = "heartbeat/px_threshold_low";
            libp2p_gossipsub_topic_config_t px_cfg = {
                .struct_size = sizeof(px_cfg),
                .descriptor = {
                    .struct_size = sizeof(px_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &px_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_px_threshold_low_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_strs[] = {
                "12D3KooWExgVnyL9F9ktsHTTXV9cZ6rxWPPPwJ9V6u3yyFvEfYst",
                "12D3KooWFjecZx2YM5mAZ1bn46vCeWkQS9KpVwhM2r36EJt2vqCr",
                "12D3KooWDH8u1o1YiA1HXSwSReT7PwtZDs7JhdYKbnvSYnUrWhp2",
                "12D3KooWHZjVdysJ8V5Y2Tyshzw31wY1M2fjTw83YVHC6rU1ttzv",
                "12D3KooWQX1pP6uPQ7RZicMv6z4dGYBHc9B7iKLB9gowgCJFzQEw",
                "12D3KooWDbSkFwsij4BjjHfZxQqJ1zuvBABFqQ5uwSX6ZiUvUv9d",
                "12D3KooWN9oSkqZSS7Y7gsnAmfmNgmcByKYEzGyv1mCXN8vQiyTe"
            };
            const int outbound_flags[] = { 1, 1, 0, 0, 0, 0, 0 };
            const double scores[] = { 1.2, 0.9, 0.8, 0.7, 0.6, 0.55, 0.1 };
            const size_t peer_count = sizeof(peer_strs) / sizeof(peer_strs[0]);
            const size_t target_index = peer_count - 1;
            peer_id_t peers[peer_count];
            memset(peers, 0, sizeof(peers));
            int peers_created = 1;
            for (size_t i = 0; i < peer_count; ++i)
            {
                if (peer_id_create_from_string(peer_strs[i], &peers[i]) != PEER_ID_SUCCESS)
                {
                    peers_created = 0;
                    break;
                }
            }
            print_result("gossipsub_px_threshold_low_peers", peers_created);
            if (!peers_created)
                failures++;
    
            if (subscribe_ok && peers_created)
            {
                int setup_ok = 1;
                for (size_t i = 0; i < peer_count; ++i)
                {
                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t enc_rc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                    if (enc_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                    {
                        setup_ok = 0;
                    }
                    else
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &peers[i], frame, frame_len);
                        if (inj_rc != LIBP2P_ERR_OK)
                            setup_ok = 0;
                    }
                    if (frame)
                        free(frame);
                    if (!setup_ok)
                        break;
    
                    if (libp2p_gossipsub__peer_set_connected(gs, &peers[i], 1) != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__peer_set_score(gs, &peers[i], scores[i]) != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &peers[i], outbound_flags[i]) != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                }
                print_result("gossipsub_px_threshold_low_setup", setup_ok);
                if (!setup_ok)
                    failures++;
    
                if (setup_ok)
                {
                    libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                    int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_px_threshold_low_heartbeat", hb_ok);
                    if (!hb_ok)
                        failures++;
    
                    int target_outbound = 0;
                    int target_in_mesh = libp2p_gossipsub__topic_mesh_contains(gs,
                                                                               topic_name,
                                                                               &peers[target_index],
                                                                               &target_outbound,
                                                                               NULL);
                    (void)target_outbound;
                    int target_pruned = !target_in_mesh;
                    print_result("gossipsub_px_threshold_low_pruned", target_pruned);
                    if (!target_pruned)
                        failures++;
    
                    if (target_pruned)
                    {
                        size_t px_count = 0;
                        int prune_found = 0;
                        while (1)
                        {
                            uint8_t *frame = NULL;
                            size_t frame_len = 0;
                            libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs,
                                                                                   &peers[target_index],
                                                                                   &frame,
                                                                                   &frame_len);
                            if (pop_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                            {
                                if (frame)
                                    free(frame);
                                break;
                            }
    
                            if (!prune_found)
                                prune_found = decode_prune_px_count(frame, frame_len, topic_name, &px_count);
                            free(frame);
                            if (prune_found)
                                break;
                        }
                        print_result("gossipsub_px_threshold_low_prune_found", prune_found);
                        if (!prune_found)
                            failures++;
                        int px_gated = (prune_found && px_count == 0);
                        print_result("gossipsub_px_threshold_low_px_gated", px_gated);
                        if (!px_gated)
                            failures++;
                    }
                }
            }
    
            for (size_t i = 0; i < peer_count; ++i)
            {
                if (peers[i].bytes)
                {
                    (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &peers[i]);
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &peers[i]);
                    (void)libp2p_gossipsub__peer_set_connected(gs, &peers[i], 0);
                    peer_id_destroy(&peers[i]);
                }
            }
            libp2p_gossipsub_unsubscribe(gs, topic_name);
        }
    
        {
            const char *topic_name = "heartbeat/px_threshold_high";
            libp2p_gossipsub_topic_config_t px_cfg = {
                .struct_size = sizeof(px_cfg),
                .descriptor = {
                    .struct_size = sizeof(px_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &px_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_px_threshold_high_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_strs[] = {
                "12D3KooWNNK9n7fh5R7sFjstqA5H1vcs1PEqnbPGZL4sD7dJgxX8",
                "12D3KooWNtgPTUpWHPUEK35GhPty1jih6e9SxWi81o2wDpyo5R3x",
                "12D3KooWRGFmLWY4kCMgWyBTsmVEx9BwM8yHceSX8tRCJatG9A6L",
                "12D3KooWE9q4DXG4bqBNY3z3y7mEys6DKUkFyjtL1hwy6v3HXyFG",
                "12D3KooWGCwm3KcSXzdLyV4mYG8zxZ2wr4wAhoFeRT65nB4xRg8i",
                "12D3KooWLMEFQv1YCGxHNNVPiNzYfs2E31L6m1g9A3PXCAYpZrVQ",
                "12D3KooWJMCZpZGsGWpRieyU7gnaNmJKbnHiKK4xqSSdoRRt9P5r"
            };
            const int outbound_flags[] = { 1, 1, 0, 0, 0, 0, 0 };
            const double scores[] = { 1.5, 1.3, 1.1, 0.9, 0.8, 0.75, 0.7 };
            const size_t peer_count = sizeof(peer_strs) / sizeof(peer_strs[0]);
            const size_t target_index = peer_count - 1;
            peer_id_t peers[peer_count];
            memset(peers, 0, sizeof(peers));
            int peers_created = 1;
            for (size_t i = 0; i < peer_count; ++i)
            {
                if (peer_id_create_from_string(peer_strs[i], &peers[i]) != PEER_ID_SUCCESS)
                {
                    peers_created = 0;
                    break;
                }
            }
            print_result("gossipsub_px_threshold_high_peers", peers_created);
            if (!peers_created)
                failures++;
    
            if (subscribe_ok && peers_created)
            {
                int setup_ok = 1;
                for (size_t i = 0; i < peer_count; ++i)
                {
                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t enc_rc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                    if (enc_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                    {
                        setup_ok = 0;
                    }
                    else
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &peers[i], frame, frame_len);
                        if (inj_rc != LIBP2P_ERR_OK)
                            setup_ok = 0;
                    }
                    if (frame)
                        free(frame);
                    if (!setup_ok)
                        break;
    
                    if (libp2p_gossipsub__peer_set_connected(gs, &peers[i], 1) != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__peer_set_score(gs, &peers[i], scores[i]) != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &peers[i], outbound_flags[i]) != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                }
                print_result("gossipsub_px_threshold_high_setup", setup_ok);
                if (!setup_ok)
                    failures++;
    
                if (setup_ok)
                {
                    libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                    int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_px_threshold_high_heartbeat", hb_ok);
                    if (!hb_ok)
                        failures++;
    
                    int target_outbound = 0;
                    int target_in_mesh = libp2p_gossipsub__topic_mesh_contains(gs,
                                                                               topic_name,
                                                                               &peers[target_index],
                                                                               &target_outbound,
                                                                               NULL);
                    (void)target_outbound;
                    int target_pruned = !target_in_mesh;
                    print_result("gossipsub_px_threshold_high_pruned", target_pruned);
                    if (!target_pruned)
                        failures++;
    
                    if (target_pruned)
                    {
                        size_t px_count = 0;
                        int prune_found = 0;
                        while (1)
                        {
                            uint8_t *frame = NULL;
                            size_t frame_len = 0;
                            libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs,
                                                                                   &peers[target_index],
                                                                                   &frame,
                                                                                   &frame_len);
                            if (pop_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                            {
                                if (frame)
                                    free(frame);
                                break;
                            }
    
                            if (!prune_found)
                                prune_found = decode_prune_px_count(frame, frame_len, topic_name, &px_count);
                            free(frame);
                            if (prune_found)
                                break;
                        }
                        print_result("gossipsub_px_threshold_high_prune_found", prune_found);
                        if (!prune_found)
                            failures++;
                        int px_emitted = (prune_found && px_count > 0);
                        print_result("gossipsub_px_threshold_high_px_emitted", px_emitted);
                        if (!px_emitted)
                            failures++;
                    }
                }
            }
    
            for (size_t i = 0; i < peer_count; ++i)
            {
                if (peers[i].bytes)
                {
                    (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &peers[i]);
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &peers[i]);
                    (void)libp2p_gossipsub__peer_set_connected(gs, &peers[i], 0);
                    peer_id_destroy(&peers[i]);
                }
            }
            libp2p_gossipsub_unsubscribe(gs, topic_name);
        }
    
        {
            const char *topic_name = "px/ingest";
            libp2p_gossipsub_topic_config_t px_ingest_cfg = {
                .struct_size = sizeof(px_ingest_cfg),
                .descriptor = {
                    .struct_size = sizeof(px_ingest_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &px_ingest_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_px_ingest_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *sender_str = "12D3KooWQah6XuKrg7vitgGdzDMn9jVQuk9AGK2Gkz9g9miHKXDN";
            peer_id_t sender_peer = { 0 };
            int sender_ok = subscribe_ok && setup_gossip_peer(gs, topic_name, sender_str, &sender_peer);
            print_result("gossipsub_px_ingest_setup_sender", sender_ok);
            if (!sender_ok)
                failures++;
    
            peer_id_t px_peer = { 0 };
            ed25519_secret_key px_secret;
            memcpy(px_secret, kTestPxSecretKey, sizeof(px_secret));
            ed25519_public_key px_public;
            ed25519_publickey(px_secret, px_public);
            uint8_t *px_pub_pb = NULL;
            size_t px_pub_pb_len = 0;
            peer_id_error_t px_pb_rc = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE,
                                                                         px_public,
                                                                         sizeof(px_public),
                                                                         &px_pub_pb,
                                                                         &px_pub_pb_len);
            int px_peer_ok = (px_pb_rc == PEER_ID_SUCCESS && px_pub_pb);
            if (px_peer_ok)
                px_peer_ok = (peer_id_create_from_public_key(px_pub_pb, px_pub_pb_len, &px_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_px_ingest_px_peer_id", px_peer_ok);
            if (!px_peer_ok)
                failures++;
            if (px_pub_pb)
                free(px_pub_pb);
    
            int addr_err = 0;
            const char *px_addr_str = "/ip4/203.0.113.8/tcp/4100";
            multiaddr_t *px_addr = multiaddr_new_from_str(px_addr_str, &addr_err);
            int addr_ok = (px_addr && addr_err == MULTIADDR_SUCCESS);
            print_result("gossipsub_px_ingest_addr_parse", addr_ok);
            if (!addr_ok)
                failures++;
    
            if (sender_ok)
            {
                libp2p_gossipsub__peer_set_score(gs, &sender_peer, cfg.accept_px_threshold + 1.0);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &sender_peer);
            }
    
            if (sender_ok && px_peer_ok && addr_ok)
            {
                const multiaddr_t *addr_list[] = { px_addr };
                uint8_t *record_buf = NULL;
                size_t record_len = 0;
                libp2p_err_t rec_rc = encode_signed_peer_record(&px_peer,
                                                                addr_list,
                                                                1,
                                                                kTestPxSecretKey,
                                                                sizeof(kTestPxSecretKey),
                                                                &record_buf,
                                                                &record_len);
                int record_ok = (rec_rc == LIBP2P_ERR_OK && record_buf && record_len > 0);
                print_result("gossipsub_px_ingest_encode_record", record_ok);
                if (!record_ok)
                    failures++;
    
                if (record_ok)
                {
                    uint8_t *prune_frame = NULL;
                    size_t prune_len = 0;
                    libp2p_err_t prune_rc = encode_prune_px_rpc(topic_name, &px_peer, record_buf, record_len, &prune_frame, &prune_len);
                    int prune_ok = (prune_rc == LIBP2P_ERR_OK && prune_frame && prune_len > 0);
                    print_result("gossipsub_px_ingest_encode_prune", prune_ok);
                    if (!prune_ok)
                        failures++;
    
                    if (prune_ok)
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &sender_peer, prune_frame, prune_len);
                        int inject_ok = (inj_rc == LIBP2P_ERR_OK);
                        print_result("gossipsub_px_ingest_inject_prune", inject_ok);
                        if (!inject_ok)
                            failures++;
    
                        if (inject_ok && host && host->peerstore)
                        {
                            const multiaddr_t **stored = NULL;
                            size_t stored_len = 0;
                            int ps_rc = libp2p_peerstore_get_addrs(host->peerstore, &px_peer, &stored, &stored_len);
                            int peerstore_ok = (ps_rc == 0 && stored && stored_len > 0);
                            print_result("gossipsub_px_ingest_peerstore_lookup", peerstore_ok);
                            if (!peerstore_ok)
                            {
                                failures++;
                            }
                            else
                            {
                                int match_found = 0;
                                for (size_t i = 0; i < stored_len; ++i)
                                {
                                    int str_err = 0;
                                    char *addr_str = multiaddr_to_str(stored[i], &str_err);
                                    if (addr_str && str_err == MULTIADDR_SUCCESS && strcmp(addr_str, px_addr_str) == 0)
                                        match_found = 1;
                                    if (addr_str)
                                        free(addr_str);
                                    if (match_found)
                                        break;
                                }
                                print_result("gossipsub_px_ingest_addr_present", match_found);
                                if (!match_found)
                                    failures++;
                            }
                            if (stored)
                                libp2p_peerstore_free_addrs(stored, stored_len);
                        }
                        else if (inject_ok)
                        {
                            print_result("gossipsub_px_ingest_peerstore_lookup", 0);
                            failures++;
                        }
    
                        free(prune_frame);
                    }
    
                    free(record_buf);
                }
                else if (record_buf)
                {
                    free(record_buf);
                }
            }
    
            if (px_addr)
                multiaddr_free(px_addr);
            if (px_peer.bytes)
                peer_id_destroy(&px_peer);
            if (sender_peer.bytes)
            {
                if (sender_ok)
                    (void)libp2p_gossipsub__peer_set_connected(gs, &sender_peer, 0);
                peer_id_destroy(&sender_peer);
            }
            if (subscribe_ok)
                libp2p_gossipsub_unsubscribe(gs, topic_name);
        }
    
        {
            const char *topic_name = "heartbeat/gossip";
            libp2p_gossipsub_topic_config_t gossip_cfg = {
                .struct_size = sizeof(gossip_cfg),
                .descriptor = {
                    .struct_size = sizeof(gossip_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &gossip_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_heartbeat_gossip_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *mesh_peer_strs[] = {
                "12D3KooWHZjVdysJ8V5Y2Tyshzw31wY1M2fjTw83YVHC6rU1ttzv",
                "12D3KooWQX1pP6uPQ7RZicMv6z4dGYBHc9B7iKLB9gowgCJFzQEw",
                "12D3KooWDbSkFwsij4BjjHfZxQqJ1zuvBABFqQ5uwSX6ZiUvUv9d",
                "12D3KooWN9oSkqZSS7Y7gsnAmfmNgmcByKYEzGyv1mCXN8vQiyTe"
            };
            const size_t mesh_count = sizeof(mesh_peer_strs) / sizeof(mesh_peer_strs[0]);
            peer_id_t mesh_peers[sizeof(mesh_peer_strs) / sizeof(mesh_peer_strs[0])];
            memset(mesh_peers, 0, sizeof(mesh_peers));
            int mesh_peers_ok = 1;
            for (size_t i = 0; i < mesh_count; ++i)
            {
                if (peer_id_create_from_string(mesh_peer_strs[i], &mesh_peers[i]) != PEER_ID_SUCCESS)
                {
                    mesh_peers_ok = 0;
                    break;
                }
            }
            print_result("gossipsub_heartbeat_gossip_mesh_peers", mesh_peers_ok);
            if (!mesh_peers_ok)
                failures++;
    
            const char *gossip_peer_str = "12D3KooWNsGu1ca6QiN29GTRxK6j22BYrhM1Y5AkwB68x5y61xwn";
            peer_id_t gossip_peer = { 0 };
            int gossip_peer_ok = (peer_id_create_from_string(gossip_peer_str, &gossip_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_heartbeat_gossip_peer", gossip_peer_ok);
            if (!gossip_peer_ok)
                failures++;
    
            if (subscribe_ok && mesh_peers_ok && gossip_peer_ok)
            {
                int setup_ok = 1;
                for (size_t i = 0; i < mesh_count && setup_ok; ++i)
                {
                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t enc_rc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                    if (enc_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                    {
                        setup_ok = 0;
                    }
                    else
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &mesh_peers[i], frame, frame_len);
                        if (inj_rc != LIBP2P_ERR_OK)
                            setup_ok = 0;
                    }
                    if (frame)
                        free(frame);
                    if (!setup_ok)
                        break;
    
                    libp2p_err_t conn_rc = libp2p_gossipsub__peer_set_connected(gs, &mesh_peers[i], 1);
                    if (conn_rc != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
    
                    libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &mesh_peers[i], 1);
                    if (mesh_rc != LIBP2P_ERR_OK)
                    {
                        setup_ok = 0;
                        break;
                    }
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peers[i]);
                }
    
                if (setup_ok)
                {
                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t enc_rc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                    if (enc_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                    {
                        setup_ok = 0;
                    }
                    else
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &gossip_peer, frame, frame_len);
                        if (inj_rc != LIBP2P_ERR_OK)
                            setup_ok = 0;
                    }
                    if (frame)
                        free(frame);
                    if (setup_ok)
                    {
                        libp2p_err_t conn_rc = libp2p_gossipsub__peer_set_connected(gs, &gossip_peer, 1);
                        if (conn_rc != LIBP2P_ERR_OK)
                            setup_ok = 0;
                    }
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &gossip_peer);
                }
    
                print_result("gossipsub_heartbeat_gossip_setup", setup_ok);
                if (!setup_ok)
                    failures++;
    
                if (setup_ok)
                {
                    size_t mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                    int mesh_sz_ok = (mesh_sz == mesh_count);
                    print_result("gossipsub_heartbeat_gossip_mesh_size", mesh_sz_ok);
                    if (!mesh_sz_ok)
                        failures++;
    
                    const uint8_t payload[] = { 0x33, 0x44, 0x55, 0x66 };
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
                    libp2p_err_t pub_rc = libp2p_gossipsub_publish(gs, &msg);
                    int publish_ok = (pub_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_heartbeat_gossip_publish", publish_ok);
                    if (!publish_ok)
                        failures++;
    
                    if (publish_ok)
                    {
                        int mesh_queues_ready = 0;
                        for (int attempt = 0; attempt < 100 && !mesh_queues_ready; ++attempt)
                        {
                            mesh_queues_ready = 1;
                            for (size_t i = 0; i < mesh_count; ++i)
                            {
                                size_t qlen = libp2p_gossipsub__peer_sendq_len(gs, &mesh_peers[i]);
                                if (qlen == 0)
                                {
                                    mesh_queues_ready = 0;
                                    break;
                                }
                            }
                            if (!mesh_queues_ready)
                                usleep(1000);
                        }
                        print_result("gossipsub_heartbeat_gossip_mesh_queued", mesh_queues_ready);
                        if (!mesh_queues_ready)
                            failures++;
    
                        for (size_t i = 0; i < mesh_count; ++i)
                            (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peers[i]);
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &gossip_peer);
    
                        libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                        int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                        print_result("gossipsub_heartbeat_gossip_run", hb_ok);
                        if (!hb_ok)
                            failures++;
    
                        int gossip_in_mesh = libp2p_gossipsub__topic_mesh_contains(gs, topic_name, &gossip_peer, NULL, NULL);
                        int gossip_outside_mesh_ok = !gossip_in_mesh;
                        print_result("gossipsub_heartbeat_gossip_peer_mesh", gossip_outside_mesh_ok);
                        if (!gossip_outside_mesh_ok)
                            failures++;
    
                        uint8_t *frame = NULL;
                        size_t frame_len = 0;
                        libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, &gossip_peer, &frame, &frame_len);
                        int ihave_seen = 0;
                        if (pop_rc == LIBP2P_ERR_OK && frame && frame_len)
                        {
                            libp2p_gossipsub_RPC *rpc = NULL;
                            if (libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &rpc) == LIBP2P_ERR_OK && rpc)
                            {
                                if (libp2p_gossipsub_RPC_has_control(rpc))
                                {
                                    libp2p_gossipsub_ControlMessage *control = libp2p_gossipsub_RPC_get_control(rpc);
                                    if (control && libp2p_gossipsub_ControlMessage_has_ihave(control) &&
                                        libp2p_gossipsub_ControlMessage_count_ihave(control) > 0)
                                    {
                                        libp2p_gossipsub_ControlIHave *ihave = libp2p_gossipsub_ControlMessage_get_at_ihave(control, 0);
                                        if (ihave && libp2p_gossipsub_ControlIHave_has_topic(ihave) &&
                                            libp2p_gossipsub_ControlIHave_count_message_ids(ihave) > 0)
                                        {
                                            size_t len = libp2p_gossipsub_ControlIHave_get_size_topic(ihave);
                                            const char *raw = libp2p_gossipsub_ControlIHave_get_topic(ihave);
                                            if (raw && len == strlen(topic_name) && memcmp(raw, topic_name, len) == 0)
                                                ihave_seen = 1;
                                        }
                                    }
                                }
                                libp2p_gossipsub_RPC_free(rpc);
                            }
                        }
                        print_result("gossipsub_heartbeat_gossip_ihave", ihave_seen);
                        if (!ihave_seen)
                            failures++;
                        if (frame)
                            free(frame);
                    }
                }
            }
    
            for (size_t i = 0; i < mesh_count; ++i)
            {
                if (mesh_peers[i].bytes)
                {
                    (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &mesh_peers[i]);
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peers[i]);
                    peer_id_destroy(&mesh_peers[i]);
                }
            }
            if (gossip_peer.bytes)
            {
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &gossip_peer);
                peer_id_destroy(&gossip_peer);
            }
            libp2p_gossipsub_unsubscribe(gs, topic_name);
        }
    
        {
            libp2p_host_options_t local_opts;
            int opts_ok = (libp2p_host_options_default(&local_opts) == 0);
            libp2p_host_t *local_host = NULL;
            if (opts_ok && libp2p_host_new(&local_opts, &local_host) != 0)
                local_host = NULL;
            int host_ok = (local_host != NULL);
            print_result("gossipsub_gossip_factor_host_new", host_ok);
            if (!host_ok)
            {
                if (local_host)
                    libp2p_host_free(local_host);
                failures++;
                goto gossip_factor_cleanup;
            }
    
            libp2p_gossipsub_config_t local_cfg;
            libp2p_gossipsub_config_default(&local_cfg);
            local_cfg.d = 4;
            local_cfg.d_lo = 2;
            local_cfg.d_hi = 6;
            local_cfg.d_lazy = 3;
            local_cfg.d_out = 1;
    
            libp2p_gossipsub_t *local_gs = NULL;
            libp2p_err_t local_err = libp2p_gossipsub_new(local_host, &local_cfg, &local_gs);
            int gs_ok = (local_err == LIBP2P_ERR_OK && local_gs);
            print_result("gossipsub_gossip_factor_new", gs_ok);
            if (!gs_ok)
            {
                if (local_gs)
                    libp2p_gossipsub_free(local_gs);
                libp2p_host_free(local_host);
                failures++;
                goto gossip_factor_cleanup;
            }
    
            local_err = libp2p_gossipsub_start(local_gs);
            int start_ok = (local_err == LIBP2P_ERR_OK);
            print_result("gossipsub_gossip_factor_start", start_ok);
            if (!start_ok)
            {
                libp2p_gossipsub_free(local_gs);
                libp2p_host_free(local_host);
                failures++;
                goto gossip_factor_cleanup;
            }
    
            const char *topic_name = "gossip/factor";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            local_err = libp2p_gossipsub_subscribe(local_gs, &topic_cfg);
            int subscribe_ok = (local_err == LIBP2P_ERR_OK);
            print_result("gossipsub_gossip_factor_subscribe", subscribe_ok);
            if (!subscribe_ok)
            {
                libp2p_gossipsub_free(local_gs);
                libp2p_host_free(local_host);
                failures++;
                goto gossip_factor_cleanup;
            }
    
            static const char *const gossip_ids_lazy[] = {
                "12D3KooWQezYB7Lr9n7xw3v63ogpDkC6BasuCCJJksDkD6ZrB8Sx",
                "12D3KooWKuUq7F4VfSvgmr7fJZwZx58F3RpvULdVYGYhXJAdY5xE",
                "12D3KooWR6gEVz8gixxypSnbsF7qDePQTMwpsJDMvV6VL8ptDdjR",
                "12D3KooWCr6xwXcR6ueuWsQB3kYsVXw1m9eYamCEAnS7HQZPikae",
                "12D3KooWScEgB6A4eyD1f6gcM2Xhu3nYo2Q9Mfa39hrSJmkC46gV",
                "12D3KooWJc5x1V9R5VZqNqRm6dQ8Yzv1dBzUoXwYp5j5R2RvMnjD",
                "12D3KooWSt6mmR8oyaqX9h6hV3PSepX6JeayQMZT6ZX6hgqP1qzV",
                "12D3KooWJj2i7K6R9Srd9G1ULfxBoN7iT9VxmsQ9rQDV28TWgxP4"
            };
            static const char *const gossip_ids_extra[] = {
                "12D3KooWExgVnyL9F9ktsHTTXV9cZ6rxWPPPwJ9V6u3yyFvEfYst",
                "12D3KooWFjecZx2YM5mAZ1bn46vCeWkQS9KpVwhM2r36EJt2vqCr",
                "12D3KooWDH8u1o1YiA1HXSwSReT7PwtZDs7JhdYKbnvSYnUrWhp2",
                "12D3KooWNNK9n7fh5R7sFjstqA5H1vcs1PEqnbPGZL4sD7dJgxX8",
                "12D3KooWNtgPTUpWHPUEK35GhPty1jih6e9SxWi81o2wDpyo5R3x",
                "12D3KooWRGFmLWY4kCMgWyBTsmVEx9BwM8yHceSX8tRCJatG9A6L",
                "12D3KooWE9q4DXG4bqBNY3z3y7mEys6DKUkFyjtL1hwy6v3HXyFG",
                "12D3KooWGCwm3KcSXzdLyV4mYG8zxZ2wr4wAhoFeRT65nB4xRg8i"
            };
            enum { LAZY_COUNT = sizeof(gossip_ids_lazy) / sizeof(gossip_ids_lazy[0]) };
            enum { EXTRA_COUNT = sizeof(gossip_ids_extra) / sizeof(gossip_ids_extra[0]) };
            enum { TOTAL_COUNT = LAZY_COUNT + EXTRA_COUNT };
            const size_t lazy_count = LAZY_COUNT;
            const size_t extra_count = EXTRA_COUNT;
            const size_t total_count = TOTAL_COUNT;
            peer_id_t gossip_peers[TOTAL_COUNT];
            memset(gossip_peers, 0, sizeof(gossip_peers));
    
            int gossip_setup_ok = 1;
            for (size_t i = 0; i < lazy_count && gossip_setup_ok; ++i)
            {
                if (!setup_gossip_peer(local_gs, topic_name, gossip_ids_lazy[i], &gossip_peers[i]))
                    gossip_setup_ok = 0;
            }
            print_result("gossipsub_gossip_factor_setup_lazy", gossip_setup_ok);
            if (!gossip_setup_ok)
                failures++;
    
            int lazy_scenario_ok = 0;
            if (gossip_setup_ok)
            {
                int config_d_lazy = local_cfg.d_lazy;
                int config_gossip_percent = local_cfg.gossip_factor_percent;
                size_t expected_lazy = compute_expected_gossip_targets(lazy_count,
                                                                       config_gossip_percent,
                                                                       config_d_lazy);
                const uint8_t payload_lazy[] = { 0xA1, 0xB2, 0xC3, 0xD4 };
                size_t lazy_selected = 0;
                size_t lazy_limit = 0;
                (void)run_gossip_factor_scenario(local_gs,
                                                 topic_name,
                                                 gossip_peers,
                                                 lazy_count,
                                                 payload_lazy,
                                                 sizeof(payload_lazy),
                                                 expected_lazy,
                                                 &lazy_selected,
                                                 &lazy_limit);
                size_t actual_expected_lazy = compute_expected_gossip_targets(gossipsub_debug_last_eligible,
                                                                              config_gossip_percent,
                                                                              config_d_lazy);
                lazy_scenario_ok = (lazy_limit == actual_expected_lazy);
                if (!lazy_scenario_ok)
                {
                    printf("DETAIL: gossip_factor_lazy selected=%zu expected=%zu\n",
                           lazy_selected,
                           expected_lazy);
                    printf("DETAIL: gossip_factor_lazy limit=%zu eligible=%zu recomputed=%zu\n",
                           lazy_limit,
                           gossipsub_debug_last_eligible,
                           actual_expected_lazy);
                    for (size_t i = 0; i < lazy_count; ++i)
                    {
                        size_t qlen = libp2p_gossipsub__peer_sendq_len(local_gs, &gossip_peers[i]);
                        if (qlen)
                        {
                            printf("DETAIL: lazy_peer[%zu] queue=%zu\n", i, qlen);
                            uint8_t *frame_buf = NULL;
                            size_t frame_len = 0;
                            if (libp2p_gossipsub__peer_pop_sendq(local_gs, &gossip_peers[i], &frame_buf, &frame_len) == LIBP2P_ERR_OK)
                            {
                                libp2p_gossipsub_RPC *rpc = NULL;
                                if (libp2p_gossipsub_rpc_decode_frame(frame_buf, frame_len, &rpc) == LIBP2P_ERR_OK && rpc)
                                {
                                    int has_control = libp2p_gossipsub_RPC_has_control(rpc);
                                    int has_publish = libp2p_gossipsub_RPC_has_publish(rpc);
                                    printf("DETAIL: lazy_peer[%zu] control=%d publish=%d\n", i, has_control, has_publish);
                                    libp2p_gossipsub_RPC_free(rpc);
                                }
                                if (frame_buf)
                                    free(frame_buf);
                            }
                        }
                    }
                    failures++;
                }
                print_result("gossipsub_gossip_factor_lazy_limit", lazy_scenario_ok);
                for (size_t i = 0; i < lazy_count; ++i)
                    (void)libp2p_gossipsub__peer_clear_sendq(local_gs, &gossip_peers[i]);
            }
    
            int extra_setup_ok = 0;
            if (gossip_setup_ok && lazy_scenario_ok)
            {
                extra_setup_ok = 1;
                for (size_t i = 0; i < extra_count; ++i)
                {
                    size_t idx = lazy_count + i;
                    if (!setup_gossip_peer(local_gs, topic_name, gossip_ids_extra[i], &gossip_peers[idx]))
                    {
                        extra_setup_ok = 0;
                        break;
                    }
                }
                if (!extra_setup_ok)
                    failures++;
                print_result("gossipsub_gossip_factor_setup_extra", extra_setup_ok);
            }
    
            if (gossip_setup_ok && lazy_scenario_ok && extra_setup_ok)
            {
                int config_d_lazy = local_cfg.d_lazy;
                int config_gossip_percent = local_cfg.gossip_factor_percent;
                size_t expected_factor = compute_expected_gossip_targets(total_count,
                                                                         config_gossip_percent,
                                                                         config_d_lazy);
                const uint8_t payload_percent[] = { 0x11, 0x22, 0x33, 0x44 };
                size_t factor_selected = 0;
                size_t factor_limit = 0;
                (void)run_gossip_factor_scenario(local_gs,
                                                 topic_name,
                                                 gossip_peers,
                                                 total_count,
                                                 payload_percent,
                                                 sizeof(payload_percent),
                                                 expected_factor,
                                                 &factor_selected,
                                                 &factor_limit);
                size_t actual_expected_factor = compute_expected_gossip_targets(gossipsub_debug_last_eligible,
                                                                                config_gossip_percent,
                                                                                config_d_lazy);
                int factor_scenario_ok = (factor_limit == actual_expected_factor);
                if (!factor_scenario_ok)
                {
                    printf("DETAIL: gossip_factor_percent selected=%zu expected=%zu\n",
                           factor_selected,
                           expected_factor);
                    printf("DETAIL: gossip_factor_percent limit=%zu eligible=%zu recomputed=%zu\n",
                           factor_limit,
                           gossipsub_debug_last_eligible,
                           actual_expected_factor);
                    for (size_t i = 0; i < total_count; ++i)
                    {
                        size_t qlen = libp2p_gossipsub__peer_sendq_len(local_gs, &gossip_peers[i]);
                        if (qlen)
                            printf("DETAIL: percent_peer[%zu] queue=%zu\n", i, qlen);
                    }
                    failures++;
                }
                print_result("gossipsub_gossip_factor_percent_limit", factor_scenario_ok);
                for (size_t i = 0; i < total_count; ++i)
                    (void)libp2p_gossipsub__peer_clear_sendq(local_gs, &gossip_peers[i]);
            }
    
            for (size_t i = 0; i < total_count; ++i)
            {
                if (gossip_peers[i].bytes)
                {
                    (void)libp2p_gossipsub__peer_clear_sendq(local_gs, &gossip_peers[i]);
                    peer_id_destroy(&gossip_peers[i]);
                }
            }
    
            (void)libp2p_gossipsub_unsubscribe(local_gs, topic_name);
            libp2p_gossipsub_free(local_gs);
            libp2p_host_free(local_host);
    
    gossip_factor_cleanup:
            ;
        }
    
        {
            const char *topic_name = "propagation/topic";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_subscribe_propagation_topic", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *mesh_peer_str = "12D3KooWQX1pP6uPQ7RZicMv6z4dGYBHc9B7iKLB9gowgCJFzQEw";
            peer_id_t mesh_peer = { 0 };
            int mesh_peer_ok = (peer_id_create_from_string(mesh_peer_str, &mesh_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_propagation_peer_id_created", mesh_peer_ok);
            if (!mesh_peer_ok)
                failures++;
    
            if (subscribe_ok && mesh_peer_ok)
            {
                err = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &mesh_peer, 1);
                int mesh_add_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_propagation_mesh_add_peer", mesh_add_ok);
                if (!mesh_add_ok)
                    failures++;
    
                if (mesh_add_ok)
                {
                    err = libp2p_gossipsub__peer_set_connected(gs, &mesh_peer, 1);
                    int connected_ok = (err == LIBP2P_ERR_OK);
                    print_result("gossipsub_propagation_peer_connected", connected_ok);
                    if (!connected_ok)
                        failures++;
    
                    if (connected_ok)
                    {
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peer);
    
                        const uint8_t payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
                        libp2p_gossipsub_message_t pub_msg = {
                            .topic = {
                                .struct_size = sizeof(pub_msg.topic),
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
    
                        err = libp2p_gossipsub_publish(gs, &pub_msg);
                        int publish_ok = (err == LIBP2P_ERR_OK);
                        print_result("gossipsub_publish_propagation", publish_ok);
                        if (!publish_ok)
                            failures++;
    
                        if (publish_ok)
                        {
                            usleep(10000);
                            size_t qlen_first = libp2p_gossipsub__peer_sendq_len(gs, &mesh_peer);
                            int qlen_first_ok = (qlen_first >= 1);
                            print_result("gossipsub_propagation_queue_after_first", qlen_first_ok);
                            if (!qlen_first_ok)
                                failures++;
    
                            if (qlen_first_ok)
                            {
                                (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peer);
    
                                err = libp2p_gossipsub_publish(gs, &pub_msg);
                                int publish_again_ok = (err == LIBP2P_ERR_OK);
                                print_result("gossipsub_publish_propagation_again", publish_again_ok);
                                if (!publish_again_ok)
                                    failures++;
    
                                if (publish_again_ok)
                                {
                                    usleep(10000);
                                    size_t qlen_second = libp2p_gossipsub__peer_sendq_len(gs, &mesh_peer);
                                    int qlen_second_ok = (qlen_second >= 1);
                                    print_result("gossipsub_propagation_queue_after_second", qlen_second_ok);
                                    if (!qlen_second_ok)
                                        failures++;
                                }
                            }
                        }
                    }
                }
            }
    
            if (mesh_peer_ok)
                peer_id_destroy(&mesh_peer);
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_unsubscribe_propagation_topic", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "propagation/inbound";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_subscribe_inbound_topic", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *source_peer_str = "12D3KooWNNK9n7fh5R7sFjstqA5H1vcs1PEqnbPGZL4sD7dJgxX8";
            const char *target_peer_str = "12D3KooWNtgPTUpWHPUEK35GhPty1jih6e9SxWi81o2wDpyo5R3x";
            peer_id_t source_peer = { 0 };
            peer_id_t target_peer = { 0 };
            int source_ok = (peer_id_create_from_string(source_peer_str, &source_peer) == PEER_ID_SUCCESS);
            int target_ok = (peer_id_create_from_string(target_peer_str, &target_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_inbound_source_peer_created", source_ok);
            if (!source_ok)
                failures++;
            print_result("gossipsub_inbound_target_peer_created", target_ok);
            if (!target_ok)
                failures++;
    
            if (subscribe_ok && target_ok)
            {
                err = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &target_peer, 1);
                int mesh_add_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_inbound_mesh_add_target", mesh_add_ok);
                if (!mesh_add_ok)
                    failures++;
    
                if (mesh_add_ok)
                {
                    err = libp2p_gossipsub__peer_set_connected(gs, &target_peer, 1);
                    int connected_ok = (err == LIBP2P_ERR_OK);
                    print_result("gossipsub_inbound_target_connected", connected_ok);
                    if (!connected_ok)
                        failures++;
                }
            }
    
            if (subscribe_ok && source_ok && target_ok)
            {
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &target_peer);
    
                const uint8_t payload[] = { 0x10, 0x20, 0x30, 0x40 };
                const uint8_t seqno[] = { 0x01, 0x02, 0x03, 0x04 };
                libp2p_gossipsub_message_t inbound_msg = {
                    .topic = {
                        .struct_size = sizeof(inbound_msg.topic),
                        .topic = topic_name
                    },
                    .data = payload,
                    .data_len = sizeof(payload),
                    .from = &source_peer,
                    .seqno = seqno,
                    .seqno_len = sizeof(seqno),
                    .raw_message = NULL,
                    .raw_message_len = 0
                };
    
                uint8_t *frame = NULL;
                size_t frame_len = 0;
                libp2p_err_t enc_rc = libp2p_gossipsub_rpc_encode_publish(&inbound_msg, &frame, &frame_len);
                int encode_ok = (enc_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_inbound_encode", encode_ok);
                if (!encode_ok)
                    failures++;
    
                if (encode_ok)
                {
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &source_peer, frame, frame_len);
                    int inject_ok = (inj_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_inbound_inject_first", inject_ok);
                    if (!inject_ok)
                        failures++;
    
                    if (inject_ok)
                    {
                        usleep(10000);
                        size_t qlen_first = libp2p_gossipsub__peer_sendq_len(gs, &target_peer);
                        int qlen_first_ok = (qlen_first >= 1);
                        print_result("gossipsub_inbound_queue_after_first", qlen_first_ok);
                        if (!qlen_first_ok)
                            failures++;
    
                        if (qlen_first_ok)
                        {
                            inj_rc = libp2p_gossipsub__inject_frame(gs, &source_peer, frame, frame_len);
                            int inject_second_ok = (inj_rc == LIBP2P_ERR_OK);
                            print_result("gossipsub_inbound_inject_second", inject_second_ok);
                            if (!inject_second_ok)
                                failures++;
    
                            if (inject_second_ok)
                            {
                                usleep(10000);
                                size_t qlen_second = libp2p_gossipsub__peer_sendq_len(gs, &target_peer);
                                int dedup_ok = (qlen_second == qlen_first);
                                print_result("gossipsub_inbound_dedup", dedup_ok);
                                if (!dedup_ok)
                                    failures++;
                            }
                        }
                    }
    
                    free(frame);
                }
            }
    
            if (target_ok)
                peer_id_destroy(&target_peer);
            if (source_ok)
                peer_id_destroy(&source_peer);
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_unsubscribe_inbound_topic", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "custom/message/id";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL,
                .message_id_fn = first_byte_message_id_fn,
                .message_id_user_data = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_custom_id_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *source_peer_str = "12D3KooWRGFmLWY4kCMgWyBTsmVEx9BwM8yHceSX8tRCJatG9A6L";
            const char *target_peer_str = "12D3KooWE9q4DXG4bqBNY3z3y7mEys6DKUkFyjtL1hwy6v3HXyFG";
            peer_id_t source_peer = { 0 };
            peer_id_t target_peer = { 0 };
            int source_ok = (peer_id_create_from_string(source_peer_str, &source_peer) == PEER_ID_SUCCESS);
            int target_ok = (peer_id_create_from_string(target_peer_str, &target_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_custom_id_source_peer", source_ok);
            if (!source_ok)
                failures++;
            print_result("gossipsub_custom_id_target_peer", target_ok);
            if (!target_ok)
                failures++;
    
            if (subscribe_ok && target_ok)
            {
                err = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &target_peer, 1);
                int mesh_add_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_custom_id_mesh_add", mesh_add_ok);
                if (!mesh_add_ok)
                    failures++;
    
                if (mesh_add_ok)
                {
                    err = libp2p_gossipsub__peer_set_connected(gs, &target_peer, 1);
                    int connected_ok = (err == LIBP2P_ERR_OK);
                    print_result("gossipsub_custom_id_target_connected", connected_ok);
                    if (!connected_ok)
                        failures++;
                }
            }
    
            if (subscribe_ok && source_ok && target_ok)
            {
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &target_peer);
    
                const uint8_t payload_first[] = { 0x42, 0x01, 0x02 };
                const uint8_t payload_second[] = { 0x42, 0x03, 0x04 };
                const uint8_t seqno_first[] = { 0x00, 0x00, 0x00, 0x01 };
                const uint8_t seqno_second[] = { 0x00, 0x00, 0x00, 0x02 };
    
                libp2p_gossipsub_message_t first_msg = {
                    .topic = {
                        .struct_size = sizeof(first_msg.topic),
                        .topic = topic_name
                    },
                    .data = payload_first,
                    .data_len = sizeof(payload_first),
                    .from = &source_peer,
                    .seqno = seqno_first,
                    .seqno_len = sizeof(seqno_first),
                    .raw_message = NULL,
                    .raw_message_len = 0
                };
    
                libp2p_gossipsub_message_t second_msg = {
                    .topic = {
                        .struct_size = sizeof(second_msg.topic),
                        .topic = topic_name
                    },
                    .data = payload_second,
                    .data_len = sizeof(payload_second),
                    .from = &source_peer,
                    .seqno = seqno_second,
                    .seqno_len = sizeof(seqno_second),
                    .raw_message = NULL,
                    .raw_message_len = 0
                };
    
                uint8_t *frame_first = NULL;
                size_t frame_first_len = 0;
                libp2p_err_t enc_first_rc = libp2p_gossipsub_rpc_encode_publish(&first_msg, &frame_first, &frame_first_len);
                int encode_first_ok = (enc_first_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_custom_id_encode_first", encode_first_ok);
                if (!encode_first_ok)
                    failures++;
    
                uint8_t *frame_second = NULL;
                size_t frame_second_len = 0;
                libp2p_err_t enc_second_rc = libp2p_gossipsub_rpc_encode_publish(&second_msg, &frame_second, &frame_second_len);
                int encode_second_ok = (enc_second_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_custom_id_encode_second", encode_second_ok);
                if (!encode_second_ok)
                    failures++;
    
                if (encode_first_ok && encode_second_ok)
                {
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &source_peer, frame_first, frame_first_len);
                    int inject_first_ok = (inj_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_custom_id_inject_first", inject_first_ok);
                    if (!inject_first_ok)
                        failures++;
    
                    if (inject_first_ok)
                    {
                        usleep(10000);
                        size_t qlen_first = libp2p_gossipsub__peer_sendq_len(gs, &target_peer);
                        int qlen_first_ok = (qlen_first >= 1);
                        print_result("gossipsub_custom_id_queue_after_first", qlen_first_ok);
                        if (!qlen_first_ok)
                            failures++;
    
                        if (qlen_first_ok)
                        {
                            inj_rc = libp2p_gossipsub__inject_frame(gs, &source_peer, frame_second, frame_second_len);
                            int inject_second_ok = (inj_rc == LIBP2P_ERR_OK);
                            print_result("gossipsub_custom_id_inject_second", inject_second_ok);
                            if (!inject_second_ok)
                                failures++;
    
                            if (inject_second_ok)
                            {
                                usleep(10000);
                                size_t qlen_second = libp2p_gossipsub__peer_sendq_len(gs, &target_peer);
                                int dedup_ok = (qlen_second == qlen_first);
                                print_result("gossipsub_custom_id_dedup", dedup_ok);
                                if (!dedup_ok)
                                    failures++;
                            }
                        }
                    }
                }
    
                if (frame_second)
                    free(frame_second);
                if (frame_first)
                    free(frame_first);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &target_peer);
            }
    
            if (target_ok)
                peer_id_destroy(&target_peer);
            if (source_ok)
                peer_id_destroy(&source_peer);
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_custom_id_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "control/ihave-iwant";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL,
                .message_id_fn = NULL,
                .message_id_user_data = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_control_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *source_peer_str = "12D3KooWGCwm3KcSXzdLyV4mYG8zxZ2wr4wAhoFeRT65nB4xRg8i";
            const char *ihave_peer_str = "12D3KooWLMEFQv1YCGxHNNVPiNzYfs2E31L6m1g9A3PXCAYpZrVQ";
            const char *request_peer_str = "12D3KooWExgVnyL9F9ktsHTTXV9cZ6rxWPPPwJ9V6u3yyFvEfYst";
    
            peer_id_t source_peer = { 0 };
            peer_id_t ihave_peer = { 0 };
            peer_id_t request_peer = { 0 };
            int source_ok = (peer_id_create_from_string(source_peer_str, &source_peer) == PEER_ID_SUCCESS);
            int ihave_ok = (peer_id_create_from_string(ihave_peer_str, &ihave_peer) == PEER_ID_SUCCESS);
            int request_ok = (peer_id_create_from_string(request_peer_str, &request_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_control_source_peer", source_ok);
            if (!source_ok)
                failures++;
            print_result("gossipsub_control_ihave_peer", ihave_ok);
            if (!ihave_ok)
                failures++;
            print_result("gossipsub_control_request_peer", request_ok);
            if (!request_ok)
                failures++;
    
            uint8_t seqno_bytes[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
            size_t message_id_len = source_peer.size + sizeof(seqno_bytes);
            uint8_t *message_id = (uint8_t *)malloc(message_id_len);
            int message_id_ok = (message_id != NULL);
            if (message_id_ok)
            {
                memcpy(message_id, source_peer.bytes, source_peer.size);
                memcpy(message_id + source_peer.size, seqno_bytes, sizeof(seqno_bytes));
            }
            print_result("gossipsub_control_message_id_alloc", message_id_ok);
            if (!message_id_ok)
                failures++;
    
            if (subscribe_ok && ihave_ok && message_id_ok)
            {
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &ihave_peer);
                uint8_t *ihave_frame = NULL;
                size_t ihave_frame_len = 0;
                libp2p_err_t ihave_enc = encode_control_ihave_rpc(topic_name, message_id, message_id_len, &ihave_frame, &ihave_frame_len);
                int ihave_enc_ok = (ihave_enc == LIBP2P_ERR_OK && ihave_frame && ihave_frame_len);
                print_result("gossipsub_control_ihave_encoded", ihave_enc_ok);
                if (!ihave_enc_ok)
                    failures++;
    
                if (ihave_enc_ok)
                {
                    libp2p_err_t inject_rc = libp2p_gossipsub__inject_frame(gs, &ihave_peer, ihave_frame, ihave_frame_len);
                    int inject_ok = (inject_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_control_ihave_injected", inject_ok);
                    if (!inject_ok)
                        failures++;
    
                    size_t want_queue_len = libp2p_gossipsub__peer_sendq_len(gs, &ihave_peer);
                    int want_queue_ok = (want_queue_len >= 1);
                    print_result("gossipsub_control_iwant_enqueued", want_queue_ok);
                    if (!want_queue_ok)
                        failures++;
    
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &ihave_peer);
                    free(ihave_frame);
                }
            }
    
            if (subscribe_ok && source_ok && message_id_ok)
            {
                const uint8_t payload[] = { 0xCA, 0xFE, 0xBA, 0xBE };
                libp2p_gossipsub_message_t pub_msg = {
                    .topic = {
                        .struct_size = sizeof(pub_msg.topic),
                        .topic = topic_name
                    },
                    .data = payload,
                    .data_len = sizeof(payload),
                    .from = &source_peer,
                    .seqno = seqno_bytes,
                    .seqno_len = sizeof(seqno_bytes),
                    .raw_message = NULL,
                    .raw_message_len = 0
                };
                uint8_t *pub_frame = NULL;
                size_t pub_frame_len = 0;
                libp2p_err_t pub_enc = libp2p_gossipsub_rpc_encode_publish(&pub_msg, &pub_frame, &pub_frame_len);
                int pub_enc_ok = (pub_enc == LIBP2P_ERR_OK && pub_frame && pub_frame_len);
                print_result("gossipsub_control_publish_encoded", pub_enc_ok);
                if (!pub_enc_ok)
                    failures++;
    
                if (pub_enc_ok)
                {
                    libp2p_err_t inject_rc = libp2p_gossipsub__inject_frame(gs, &source_peer, pub_frame, pub_frame_len);
                    int inject_ok = (inject_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_control_publish_injected", inject_ok);
                    if (!inject_ok)
                        failures++;
                    usleep(10000);
                    int cached = libp2p_gossipsub__message_in_cache(gs, message_id, message_id_len);
                    print_result("gossipsub_control_message_cached", cached);
                    if (!cached)
                        failures++;
                    free(pub_frame);
                }
            }
    
            if (subscribe_ok && request_ok && message_id_ok)
            {
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &request_peer);
                uint8_t *iwant_frame = NULL;
                size_t iwant_frame_len = 0;
                libp2p_err_t iwant_enc = encode_control_iwant_rpc(message_id, message_id_len, &iwant_frame, &iwant_frame_len);
                int iwant_enc_ok = (iwant_enc == LIBP2P_ERR_OK && iwant_frame && iwant_frame_len);
                print_result("gossipsub_control_iwant_encoded", iwant_enc_ok);
                if (!iwant_enc_ok)
                    failures++;
    
                if (iwant_enc_ok)
                {
                    libp2p_err_t inject_rc = libp2p_gossipsub__inject_frame(gs, &request_peer, iwant_frame, iwant_frame_len);
                    int inject_ok = (inject_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_control_iwant_injected", inject_ok);
                    if (!inject_ok)
                        failures++;
    
                    size_t publish_queue_len = 0;
                    for (int attempt = 0; attempt < 50; ++attempt)
                    {
                        publish_queue_len = libp2p_gossipsub__peer_sendq_len(gs, &request_peer);
                        if (publish_queue_len >= 1)
                            break;
                        usleep(1000);
                    }
                    int publish_queue_ok = (publish_queue_len >= 1);
                    print_result("gossipsub_control_publish_enqueued", publish_queue_ok);
                    if (!publish_queue_ok)
                        failures++;
    
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &request_peer);
                    free(iwant_frame);
                }
            }
    
            if (message_id)
                free(message_id);
            if (request_ok)
                peer_id_destroy(&request_peer);
            if (ihave_ok)
                peer_id_destroy(&ihave_peer);
            if (source_ok)
                peer_id_destroy(&source_peer);
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_control_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "control/ihave-throttle";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_ihave_throttle_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWJDNrXxWkEJqe6D9bXqEJ8T8DMeYb49UoLxqfjZt6weu9";
            peer_id_t throttle_peer = { 0 };
            int peer_ok = subscribe_ok && setup_gossip_peer(gs, topic_name, peer_str, &throttle_peer);
            print_result("gossipsub_ihave_throttle_peer_setup", peer_ok);
            if (!peer_ok && subscribe_ok)
                failures++;
    
            if (peer_ok)
            {
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &throttle_peer);
                for (int attempt = 0; attempt < 3; ++attempt)
                {
                    uint8_t message_id[4] = { (uint8_t)(0x40 | attempt), 0xAA, 0x55, (uint8_t)(0x10 + attempt) };
                    uint8_t *ihave_frame = NULL;
                    size_t ihave_frame_len = 0;
                    libp2p_err_t enc_rc = encode_control_ihave_rpc(topic_name,
                                                                   message_id,
                                                                   sizeof(message_id),
                                                                   &ihave_frame,
                                                                   &ihave_frame_len);
                    int enc_ok = (enc_rc == LIBP2P_ERR_OK && ihave_frame && ihave_frame_len);
                    char label[64];
                    snprintf(label, sizeof(label), "gossipsub_ihave_throttle_encode_%d", attempt + 1);
                    print_result(label, enc_ok);
                    if (!enc_ok)
                    {
                        failures++;
                        if (ihave_frame)
                            free(ihave_frame);
                        break;
                    }
    
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &throttle_peer, ihave_frame, ihave_frame_len);
                    snprintf(label, sizeof(label), "gossipsub_ihave_throttle_inject_%d", attempt + 1);
                    int inject_ok = (inj_rc == LIBP2P_ERR_OK);
                    print_result(label, inject_ok);
                    if (!inject_ok)
                        failures++;
    
                    size_t want_queue = libp2p_gossipsub__peer_sendq_len(gs, &throttle_peer);
                    snprintf(label, sizeof(label), "gossipsub_ihave_throttle_queue_%d", attempt + 1);
                    int expect_queue = (attempt < 2) ? (want_queue >= 1) : (want_queue == 0);
                    print_result(label, expect_queue);
                    if (!expect_queue)
                        failures++;
    
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &throttle_peer);
                    free(ihave_frame);
    
                    if (!inject_ok)
                        break;
                }
    
                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_ihave_throttle_heartbeat", hb_ok);
                if (!hb_ok)
                    failures++;
    
                if (hb_ok)
                {
                    uint8_t message_id[4] = { 0x7F, 0xBB, 0x66, 0x21 };
                    uint8_t *ihave_frame = NULL;
                    size_t ihave_frame_len = 0;
                    libp2p_err_t enc_rc = encode_control_ihave_rpc(topic_name,
                                                                   message_id,
                                                                   sizeof(message_id),
                                                                   &ihave_frame,
                                                                   &ihave_frame_len);
                    int enc_ok = (enc_rc == LIBP2P_ERR_OK && ihave_frame && ihave_frame_len);
                    print_result("gossipsub_ihave_throttle_encode_post_hb", enc_ok);
                    if (!enc_ok)
                    {
                        failures++;
                    }
                    else
                    {
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &throttle_peer, ihave_frame, ihave_frame_len);
                        int inject_ok = (inj_rc == LIBP2P_ERR_OK);
                        print_result("gossipsub_ihave_throttle_inject_post_hb", inject_ok);
                        if (!inject_ok)
                            failures++;
                        size_t want_queue = libp2p_gossipsub__peer_sendq_len(gs, &throttle_peer);
                        int queue_ok = (want_queue >= 1);
                        print_result("gossipsub_ihave_throttle_queue_post_hb", queue_ok);
                        if (!queue_ok)
                            failures++;
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &throttle_peer);
                    }
                    if (ihave_frame)
                        free(ihave_frame);
                }
    
                peer_id_destroy(&throttle_peer);
            }
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_ihave_throttle_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "threshold/gossip";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_threshold_topic_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            if (subscribe_ok)
            {
                libp2p_gossipsub__set_gossip_threshold(gs, -0.5);
                libp2p_gossipsub__set_graylist_threshold(gs, -0.9);
    
                uint8_t message_id[6] = { 0xAA, 0x10, 0x22, 0x33, 0x44, 0x55 };
                const char *high_peer_str = "12D3KooWPYo9fbqHANBfChyaez2BMuL6hSwgByMkUMNjz19RMH8j";
                const char *low_peer_str = "12D3KooWMJv9eJHRqHzU1Q5X1Mwp2vsBZ1vx3SmR5SQAiMa7QUPq";
    
                peer_id_t high_peer = { 0 };
                peer_id_t low_peer = { 0 };
                int high_peer_ok = setup_gossip_peer(gs, topic_name, high_peer_str, &high_peer);
                print_result("gossipsub_threshold_high_peer_setup", high_peer_ok);
                if (!high_peer_ok)
                    failures++;
                int low_peer_ok = setup_gossip_peer(gs, topic_name, low_peer_str, &low_peer);
                print_result("gossipsub_threshold_low_peer_setup", low_peer_ok);
                if (!low_peer_ok)
                    failures++;
    
                if (high_peer_ok)
                {
                    libp2p_err_t score_rc = libp2p_gossipsub__peer_set_score(gs, &high_peer, -0.2);
                    int score_ok = (score_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_threshold_high_score", score_ok);
                    if (!score_ok)
                        failures++;
                }
    
                if (low_peer_ok)
                {
                    libp2p_err_t score_rc = libp2p_gossipsub__peer_set_score(gs, &low_peer, -0.8);
                    int score_ok = (score_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_threshold_low_score", score_ok);
                    if (!score_ok)
                        failures++;
                }
    
                if (high_peer_ok)
                {
                    uint8_t *high_frame = NULL;
                    size_t high_frame_len = 0;
                    libp2p_err_t enc_rc = encode_control_ihave_rpc(topic_name,
                                                                   message_id,
                                                                   sizeof(message_id),
                                                                   &high_frame,
                                                                   &high_frame_len);
                    int enc_ok = (enc_rc == LIBP2P_ERR_OK && high_frame && high_frame_len);
                    print_result("gossipsub_threshold_high_encode", enc_ok);
                    if (!enc_ok)
                    {
                        failures++;
                    }
                    else
                    {
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &high_peer);
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &high_peer, high_frame, high_frame_len);
                        int inj_ok = (inj_rc == LIBP2P_ERR_OK);
                        print_result("gossipsub_threshold_high_inject", inj_ok);
                        if (!inj_ok)
                            failures++;
                        size_t want_queue_len = libp2p_gossipsub__peer_sendq_len(gs, &high_peer);
                        int want_ok = (want_queue_len >= 1);
                        print_result("gossipsub_threshold_high_iwant", want_ok);
                        if (!want_ok)
                            failures++;
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &high_peer);
                        free(high_frame);
                    }
                }
    
                if (low_peer_ok)
                {
                    uint8_t *low_frame = NULL;
                    size_t low_frame_len = 0;
                    libp2p_err_t enc_rc = encode_control_ihave_rpc(topic_name,
                                                                   message_id,
                                                                   sizeof(message_id),
                                                                   &low_frame,
                                                                   &low_frame_len);
                    int enc_ok = (enc_rc == LIBP2P_ERR_OK && low_frame && low_frame_len);
                    print_result("gossipsub_threshold_low_encode", enc_ok);
                    if (!enc_ok)
                    {
                        failures++;
                    }
                    else
                    {
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &low_peer);
                        libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &low_peer, low_frame, low_frame_len);
                        int inj_ok = (inj_rc == LIBP2P_ERR_OK);
                        print_result("gossipsub_threshold_low_inject", inj_ok);
                        if (!inj_ok)
                            failures++;
                        size_t want_queue_len = libp2p_gossipsub__peer_sendq_len(gs, &low_peer);
                        int want_ok = (want_queue_len == 0);
                        print_result("gossipsub_threshold_low_ignored", want_ok);
                        if (!want_ok)
                            failures++;
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &low_peer);
                        free(low_frame);
                    }
                }
    
                if (high_peer_ok)
                {
                    peer_id_destroy(&high_peer);
                }
                if (low_peer_ok)
                {
                    peer_id_destroy(&low_peer);
                }
    
                libp2p_gossipsub__set_gossip_threshold(gs, 0.0);
                libp2p_gossipsub__set_graylist_threshold(gs, -1.0);
            }
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_threshold_topic_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "threshold/gray/base";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_gray_base_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            peer_id_t gray_peer = { 0 };
            const char *gray_peer_str = "12D3KooWGuG8GbdWrwT4D6L1UMxeMGLYj1A2rcEbdS3PpFo6wiU5";
            int peer_ok = subscribe_ok && setup_gossip_peer(gs, topic_name, gray_peer_str, &gray_peer);
            print_result("gossipsub_gray_peer_setup", peer_ok);
            if (!peer_ok && subscribe_ok)
                failures++;
    
            libp2p_gossipsub__set_gossip_threshold(gs, -0.4);
            libp2p_gossipsub__set_graylist_threshold(gs, -0.7);
    
            if (peer_ok)
            {
                const char *blocked_topic = "threshold/gray/blocked";
                libp2p_err_t score_rc = libp2p_gossipsub__peer_set_score(gs, &gray_peer, -0.8);
                int score_ok = (score_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_gray_score_set", score_ok);
                if (!score_ok)
                    failures++;
    
                uint8_t *frame = NULL;
                size_t frame_len = 0;
                libp2p_err_t enc_rc = encode_subscription_rpc(blocked_topic, 1, &frame, &frame_len);
                int enc_ok = (enc_rc == LIBP2P_ERR_OK && frame && frame_len);
                print_result("gossipsub_gray_subscribe_encode", enc_ok);
                if (!enc_ok)
                {
                    failures++;
                }
                else
                {
                    (void)libp2p_gossipsub__peer_clear_sendq(gs, &gray_peer);
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &gray_peer, frame, frame_len);
                    int inj_ok = (inj_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_gray_inject", inj_ok);
                    if (!inj_ok)
                        failures++;
                    size_t queue_len = libp2p_gossipsub__peer_sendq_len(gs, &gray_peer);
                    int queue_ok = (queue_len == 0);
                    print_result("gossipsub_gray_sendq_empty", queue_ok);
                    if (!queue_ok)
                        failures++;
                    int subscribed = libp2p_gossipsub__peer_has_subscription(gs, &gray_peer, blocked_topic);
                    int sub_ok = (subscribed == 0);
                    print_result("gossipsub_gray_subscription_ignored", sub_ok);
                    if (!sub_ok)
                        failures++;
                    free(frame);
                }
    
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &gray_peer);
                peer_id_destroy(&gray_peer);
            }
    
            libp2p_gossipsub__set_gossip_threshold(gs, 0.0);
            libp2p_gossipsub__set_graylist_threshold(gs, -1.0);
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_gray_base_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
        }
    
        {
            const char *topic_name = "graft/accept/topic";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_graft_accept_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWFjecZx2YM5mAZ1bn46vCeWkQS9KpVwhM2r36EJt2vqCr";
            peer_id_t remote_peer = { 0 };
            int peer_ok = (peer_id_create_from_string(peer_str, &remote_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_graft_accept_peer_created", peer_ok);
            if (!peer_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                uint8_t *frame = NULL;
                size_t frame_len = 0;
                libp2p_err_t sub_enc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                int sub_enc_ok = (sub_enc == LIBP2P_ERR_OK && frame && frame_len);
                print_result("gossipsub_graft_accept_subscribe_encode", sub_enc_ok);
                if (!sub_enc_ok)
                    failures++;
    
                if (sub_enc_ok)
                {
                    libp2p_err_t sub_inj = libp2p_gossipsub__inject_frame(gs, &remote_peer, frame, frame_len);
                    int sub_inj_ok = (sub_inj == LIBP2P_ERR_OK);
                    print_result("gossipsub_graft_accept_subscribe_inject", sub_inj_ok);
                    if (!sub_inj_ok)
                        failures++;
                }
                if (frame)
                    free(frame);
    
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &remote_peer);
    
                uint8_t *graft_frame = NULL;
                size_t graft_frame_len = 0;
                libp2p_err_t graft_enc = encode_graft_rpc(topic_name, &graft_frame, &graft_frame_len);
                int graft_enc_ok = (graft_enc == LIBP2P_ERR_OK && graft_frame && graft_frame_len);
                print_result("gossipsub_graft_accept_encode", graft_enc_ok);
                if (!graft_enc_ok)
                    failures++;
    
                if (graft_enc_ok)
                {
                    libp2p_err_t graft_inj = libp2p_gossipsub__inject_frame(gs, &remote_peer, graft_frame, graft_frame_len);
                    int graft_inj_ok = (graft_inj == LIBP2P_ERR_OK);
                    print_result("gossipsub_graft_accept_inject", graft_inj_ok);
                    if (!graft_inj_ok)
                        failures++;
                }
                if (graft_frame)
                    free(graft_frame);
    
                size_t mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_ok = (mesh_sz == 1);
                print_result("gossipsub_graft_accept_mesh_join", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                size_t prune_queue = libp2p_gossipsub__peer_sendq_len(gs, &remote_peer);
                int prune_empty = (prune_queue == 0);
                print_result("gossipsub_graft_accept_no_prune", prune_empty);
                if (!prune_empty)
                    failures++;
            }
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_graft_accept_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&remote_peer);
        }
    
        {
            const char *topic_name = "graft/backoff/topic";
            libp2p_gossipsub_topic_config_t topic_cfg = {
                .struct_size = sizeof(topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(topic_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &topic_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_graft_backoff_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *peer_str = "12D3KooWDH8u1o1YiA1HXSwSReT7PwtZDs7JhdYKbnvSYnUrWhp2";
            peer_id_t remote_peer = { 0 };
            int peer_ok = (peer_id_create_from_string(peer_str, &remote_peer) == PEER_ID_SUCCESS);
            print_result("gossipsub_graft_backoff_peer_created", peer_ok);
            if (!peer_ok)
                failures++;
    
            if (subscribe_ok && peer_ok)
            {
                uint8_t *frame = NULL;
                size_t frame_len = 0;
                libp2p_err_t sub_enc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                int sub_enc_ok = (sub_enc == LIBP2P_ERR_OK && frame && frame_len);
                print_result("gossipsub_graft_backoff_subscribe_encode", sub_enc_ok);
                if (!sub_enc_ok)
                    failures++;
    
                if (sub_enc_ok)
                {
                    libp2p_err_t sub_inj = libp2p_gossipsub__inject_frame(gs, &remote_peer, frame, frame_len);
                    int sub_inj_ok = (sub_inj == LIBP2P_ERR_OK);
                    print_result("gossipsub_graft_backoff_subscribe_inject", sub_inj_ok);
                    if (!sub_inj_ok)
                        failures++;
                }
                if (frame)
                    free(frame);
    
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &remote_peer);
    
                uint8_t *graft_frame = NULL;
                size_t graft_frame_len = 0;
                libp2p_err_t graft_enc = encode_graft_rpc(topic_name, &graft_frame, &graft_frame_len);
                int graft_enc_ok = (graft_enc == LIBP2P_ERR_OK && graft_frame && graft_frame_len);
                print_result("gossipsub_graft_backoff_graft_encode", graft_enc_ok);
                if (!graft_enc_ok)
                    failures++;
    
                if (graft_enc_ok)
                {
                    libp2p_err_t graft_inj = libp2p_gossipsub__inject_frame(gs, &remote_peer, graft_frame, graft_frame_len);
                    int graft_inj_ok = (graft_inj == LIBP2P_ERR_OK);
                    print_result("gossipsub_graft_backoff_graft_inject", graft_inj_ok);
                    if (!graft_inj_ok)
                        failures++;
                }
                if (graft_frame)
                    free(graft_frame);
    
                size_t mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_ok = (mesh_sz == 1);
                print_result("gossipsub_graft_backoff_mesh_after_first", mesh_ok);
                if (!mesh_ok)
                    failures++;
    
                uint8_t *prune_frame = NULL;
                size_t prune_frame_len = 0;
                libp2p_err_t prune_enc = encode_prune_rpc(topic_name, 1, &prune_frame, &prune_frame_len);
                int prune_enc_ok = (prune_enc == LIBP2P_ERR_OK && prune_frame && prune_frame_len);
                print_result("gossipsub_graft_backoff_prune_encode", prune_enc_ok);
                if (!prune_enc_ok)
                    failures++;
    
                if (prune_enc_ok)
                {
                    libp2p_err_t prune_inj = libp2p_gossipsub__inject_frame(gs, &remote_peer, prune_frame, prune_frame_len);
                    int prune_inj_ok = (prune_inj == LIBP2P_ERR_OK);
                    print_result("gossipsub_graft_backoff_prune_inject", prune_inj_ok);
                    if (!prune_inj_ok)
                        failures++;
                }
                if (prune_frame)
                    free(prune_frame);
    
                mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_cleared = (mesh_sz == 0);
                print_result("gossipsub_graft_backoff_mesh_after_prune", mesh_cleared);
                if (!mesh_cleared)
                    failures++;
    
                int backoff_present = libp2p_gossipsub__topic_backoff_contains(gs, topic_name, &remote_peer);
                print_result("gossipsub_graft_backoff_recorded", backoff_present);
                if (!backoff_present)
                    failures++;
    
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &remote_peer);
    
                uint8_t *second_graft = NULL;
                size_t second_graft_len = 0;
                libp2p_err_t second_enc = encode_graft_rpc(topic_name, &second_graft, &second_graft_len);
                int second_enc_ok = (second_enc == LIBP2P_ERR_OK && second_graft && second_graft_len);
                print_result("gossipsub_graft_backoff_second_encode", second_enc_ok);
                if (!second_enc_ok)
                    failures++;
    
                if (second_enc_ok)
                {
                    libp2p_err_t second_inj = libp2p_gossipsub__inject_frame(gs, &remote_peer, second_graft, second_graft_len);
                    int second_inj_ok = (second_inj == LIBP2P_ERR_OK);
                    print_result("gossipsub_graft_backoff_second_inject", second_inj_ok);
                    if (!second_inj_ok)
                        failures++;
                }
                if (second_graft)
                    free(second_graft);
    
                size_t prune_queue = libp2p_gossipsub__peer_sendq_len(gs, &remote_peer);
                int prune_enqueued = (prune_queue >= 1);
                print_result("gossipsub_graft_backoff_prune_enqueued", prune_enqueued);
                if (!prune_enqueued)
                    failures++;
    
                uint8_t *queued_frame = NULL;
                size_t queued_len = 0;
                libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, &remote_peer, &queued_frame, &queued_len);
                int pop_ok = (pop_rc == LIBP2P_ERR_OK && queued_frame && queued_len);
                print_result("gossipsub_graft_backoff_prune_popped", pop_ok);
                if (!pop_ok)
                {
                    if (queued_frame)
                        free(queued_frame);
                    failures++;
                }
                else
                {
                    libp2p_gossipsub_RPC *rpc_msg = NULL;
                    libp2p_err_t dec_rc = libp2p_gossipsub_rpc_decode_frame(queued_frame, queued_len, &rpc_msg);
                    int dec_ok = (dec_rc == LIBP2P_ERR_OK && rpc_msg);
                    print_result("gossipsub_graft_backoff_prune_decoded", dec_ok);
                    if (!dec_ok)
                    {
                        failures++;
                    }
                    else
                    {
                        libp2p_gossipsub_ControlMessage *control = libp2p_gossipsub_RPC_get_control(rpc_msg);
                        int has_control = (control != NULL);
                        print_result("gossipsub_graft_backoff_prune_has_control", has_control);
                        if (!has_control)
                            failures++;
    
                        if (has_control)
                        {
                            int has_prune = libp2p_gossipsub_ControlMessage_has_prune(control);
                            print_result("gossipsub_graft_backoff_prune_flag", has_prune);
                            if (!has_prune)
                                failures++;
                            else
                            {
                                size_t count = libp2p_gossipsub_ControlMessage_count_prune(control);
                                int count_ok = (count >= 1);
                                print_result("gossipsub_graft_backoff_prune_count", count_ok);
                                if (!count_ok)
                                    failures++;
                                else
                                {
                                    libp2p_gossipsub_ControlPrune *prune_entry = libp2p_gossipsub_ControlMessage_get_at_prune(control, 0);
                                    int topic_match = 0;
                                    if (prune_entry && libp2p_gossipsub_ControlPrune_has_topic(prune_entry))
                                    {
                                        size_t len = libp2p_gossipsub_ControlPrune_get_size_topic(prune_entry);
                                        const char *raw = libp2p_gossipsub_ControlPrune_get_topic(prune_entry);
                                        if (raw && len == strlen(topic_name) && strncmp(raw, topic_name, len) == 0)
                                            topic_match = 1;
                                    }
                                    print_result("gossipsub_graft_backoff_prune_topic_match", topic_match);
                                    if (!topic_match)
                                        failures++;
    
                                    uint64_t backoff_val = prune_entry && libp2p_gossipsub_ControlPrune_has_backoff(prune_entry)
                                                               ? libp2p_gossipsub_ControlPrune_get_backoff(prune_entry)
                                                               : 0;
                                    int backoff_ok = (backoff_val == 60);
                                    print_result("gossipsub_graft_backoff_prune_backoff_seconds", backoff_ok);
                                    if (!backoff_ok)
                                        failures++;
                                }
                            }
                        }
                        libp2p_gossipsub_RPC_free(rpc_msg);
                    }
                    free(queued_frame);
                }
            }
    
            if (subscribe_ok)
            {
                err = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_graft_backoff_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
    
            if (peer_ok)
                peer_id_destroy(&remote_peer);
        }
    
        {
            const char *flood_topic_name = "flood/topic";
            libp2p_gossipsub_topic_config_t flood_topic_cfg = {
                .struct_size = sizeof(flood_topic_cfg),
                .descriptor = {
                    .struct_size = sizeof(flood_topic_cfg.descriptor),
                    .topic = flood_topic_name
                },
                .score_params = NULL,
                .publish_threshold = 0.0
            };
    
            libp2p_err_t flood_sub_rc = libp2p_gossipsub_subscribe(gs, &flood_topic_cfg);
            int flood_sub_ok = (flood_sub_rc == LIBP2P_ERR_OK);
            print_result("gossipsub_flood_subscribe", flood_sub_ok);
            if (!flood_sub_ok)
                failures++;
    
            if (flood_sub_ok)
            {
                libp2p_gossipsub__set_flood_publish(gs, 1);
                libp2p_gossipsub__set_publish_threshold(gs, 0.0);
                (void)libp2p_gossipsub__topic_set_publish_threshold(gs, flood_topic_name, 0.0);
    
                const char *flood_high_str = "12D3KooWExgVnyL9F9ktsHTTXV9cZ6rxWPPPwJ9V6u3yyFvEfYst";
                const char *flood_low_str = "12D3KooWFjecZx2YM5mAZ1bn46vCeWkQS9KpVwhM2r36EJt2vqCr";
                peer_id_t flood_high = { 0 };
                peer_id_t flood_low = { 0 };
                int high_peer_ok = setup_gossip_peer(gs, flood_topic_name, flood_high_str, &flood_high);
                int low_peer_ok = setup_gossip_peer(gs, flood_topic_name, flood_low_str, &flood_low);
                print_result("gossipsub_flood_high_peer_setup", high_peer_ok);
                if (!high_peer_ok)
                    failures++;
                print_result("gossipsub_flood_low_peer_setup", low_peer_ok);
                if (!low_peer_ok)
                    failures++;
    
                if (high_peer_ok && low_peer_ok)
                {
                    uint8_t flood_payload1[] = { 0xF1, 0x00 };
                    libp2p_gossipsub_message_t flood_msg1 = {
                        .topic = {
                            .struct_size = sizeof(flood_msg1.topic),
                            .topic = flood_topic_name
                        },
                        .data = flood_payload1,
                        .data_len = sizeof(flood_payload1),
                        .from = NULL,
                        .seqno = NULL,
                        .seqno_len = 0,
                        .raw_message = NULL,
                        .raw_message_len = 0
                    };
                    libp2p_err_t flood_pub1_rc = libp2p_gossipsub_publish(gs, &flood_msg1);
                    int flood_pub1_ok = (flood_pub1_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_flood_publish_initial", flood_pub1_ok);
                    if (!flood_pub1_ok)
                        failures++;
    
                    if (flood_pub1_ok)
                    {
                        int high_received_initial = gossipsub_wait_for_peer_frame(gs, &flood_high, 1000, NULL);
                        int low_received_initial = gossipsub_wait_for_peer_frame(gs, &flood_low, 1000, NULL);
                        int flood_all_receive = (high_received_initial && low_received_initial);
                        print_result("gossipsub_flood_all_peers_receive", flood_all_receive);
                        if (!flood_all_receive)
                            failures++;
                        (void)gossipsub_wait_for_peer_idle(gs, &flood_high, 200, NULL);
                        (void)gossipsub_wait_for_peer_idle(gs, &flood_low, 200, NULL);
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &flood_high);
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &flood_low);
                    }
    
                    libp2p_gossipsub__topic_set_publish_threshold(gs, flood_topic_name, 0.75);
                    (void)libp2p_gossipsub__peer_set_score(gs, &flood_high, 1.0);
                    (void)libp2p_gossipsub__peer_set_score(gs, &flood_low, 0.0);
    
                    uint8_t flood_payload2[] = { 0xF2, 0x01, 0x02 };
                    libp2p_gossipsub_message_t flood_msg2 = {
                        .topic = {
                            .struct_size = sizeof(flood_msg2.topic),
                            .topic = flood_topic_name
                        },
                        .data = flood_payload2,
                        .data_len = sizeof(flood_payload2),
                        .from = NULL,
                        .seqno = NULL,
                        .seqno_len = 0,
                        .raw_message = NULL,
                        .raw_message_len = 0
                    };
                    libp2p_err_t flood_pub2_rc = libp2p_gossipsub_publish(gs, &flood_msg2);
                    int flood_pub2_ok = (flood_pub2_rc == LIBP2P_ERR_OK);
                    print_result("gossipsub_flood_publish_threshold", flood_pub2_ok);
                    if (!flood_pub2_ok)
                        failures++;
    
                    if (flood_pub2_ok)
                    {
                        int high_received = gossipsub_wait_for_peer_frame(gs, &flood_high, 1000, NULL);
                        size_t low_queue = 0;
                        int low_stayed_empty = gossipsub_wait_for_peer_idle(gs, &flood_low, 200, &low_queue);
                        int flood_threshold_enforced = (high_received && low_stayed_empty && low_queue == 0);
                        print_result("gossipsub_flood_threshold_enforced", flood_threshold_enforced);
                        if (!flood_threshold_enforced)
                            failures++;
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &flood_high);
                        (void)libp2p_gossipsub__peer_clear_sendq(gs, &flood_low);
                    }
    
                    (void)libp2p_gossipsub__peer_set_score(gs, &flood_high, 0.0);
                    (void)libp2p_gossipsub__peer_set_score(gs, &flood_low, 0.0);
                    peer_id_destroy(&flood_high);
                    peer_id_destroy(&flood_low);
                }
    
                libp2p_gossipsub__set_flood_publish(gs, 0);
                libp2p_gossipsub__set_publish_threshold(gs, 0.0);
                (void)libp2p_gossipsub__topic_set_publish_threshold(gs, flood_topic_name, 0.0);
                libp2p_err_t flood_unsub_rc = libp2p_gossipsub_unsubscribe(gs, flood_topic_name);
                int flood_unsub_ok = (flood_unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_flood_unsubscribe", flood_unsub_ok);
                if (!flood_unsub_ok)
                    failures++;
            }
            else
            {
                (void)libp2p_gossipsub_unsubscribe(gs, flood_topic_name);
            }
        }
    
        {
            const char *topic_name = "opportunistic/topic";
            libp2p_gossipsub_topic_config_t opp_cfg = {
                .struct_size = sizeof(opp_cfg),
                .descriptor = {
                    .struct_size = sizeof(opp_cfg.descriptor),
                    .topic = topic_name
                },
                .score_params = NULL
            };
            err = libp2p_gossipsub_subscribe(gs, &opp_cfg);
            int subscribe_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_opportunistic_subscribe", subscribe_ok);
            if (!subscribe_ok)
                failures++;
    
            const char *mesh_ids[] = {
                "12D3KooWQbYFJd8hVZCqxx1Zt9KJ9kzPWxtLs5FoX4iVQQPPrw3X",
                "12D3KooWSer7LMGKc7n1kDGyFByofz8mP3p7xS4x2QVFGk3jfb9W",
                "12D3KooWM6RZs4VehN4LHsxrEqL3Wobr267uHX7cA9k6rMCMf1dS"
            };
            const double mesh_scores[] = { -0.2, 0.0, 0.1 };
            const int mesh_outbound[] = { 1, 0, 0 };
            const size_t mesh_count = sizeof(mesh_ids) / sizeof(mesh_ids[0]);
            peer_id_t mesh_peers[sizeof(mesh_ids) / sizeof(mesh_ids[0])];
            memset(mesh_peers, 0, sizeof(mesh_peers));
    
            const char *candidate_ids[] = {
                "12D3KooWJwKkHy2W2Ck3RyAEJgVhtSGcVwqDAVBBusZT6F4LmSpa",
                "12D3KooWBxkU3YdrNBwCYwiVdcgGqzGwdrDam6DCeU44y7Nys8KM"
            };
            const double candidate_scores[] = { 1.2, 0.9 };
            const size_t candidate_count = sizeof(candidate_ids) / sizeof(candidate_ids[0]);
            peer_id_t candidate_peers[sizeof(candidate_ids) / sizeof(candidate_ids[0])];
            memset(candidate_peers, 0, sizeof(candidate_peers));
    
            int mesh_setup_ok = subscribe_ok;
            if (mesh_setup_ok)
            {
                for (size_t i = 0; i < mesh_count; ++i)
                {
                    if (!setup_gossip_peer(gs, topic_name, mesh_ids[i], &mesh_peers[i]))
                    {
                        mesh_setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__peer_set_score(gs, &mesh_peers[i], mesh_scores[i]) != LIBP2P_ERR_OK)
                    {
                        mesh_setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &mesh_peers[i], mesh_outbound[i]) != LIBP2P_ERR_OK)
                    {
                        mesh_setup_ok = 0;
                        break;
                    }
                }
            }
            print_result("gossipsub_opportunistic_mesh_setup", mesh_setup_ok);
            if (!mesh_setup_ok)
                failures++;
    
            int candidate_setup_ok = mesh_setup_ok;
            if (candidate_setup_ok)
            {
                for (size_t i = 0; i < candidate_count; ++i)
                {
                    if (!setup_gossip_peer(gs, topic_name, candidate_ids[i], &candidate_peers[i]))
                    {
                        candidate_setup_ok = 0;
                        break;
                    }
                    if (libp2p_gossipsub__peer_set_score(gs, &candidate_peers[i], candidate_scores[i]) != LIBP2P_ERR_OK)
                    {
                        candidate_setup_ok = 0;
                        break;
                    }
                }
            }
            print_result("gossipsub_opportunistic_candidates_setup", candidate_setup_ok);
            if (!candidate_setup_ok)
                failures++;
    
            int prune_enc_ok = 0;
            int prune_inj_ok = 0;
            int backoff_seeded = 0;
            if (candidate_setup_ok && candidate_count > 0)
            {
                uint8_t *prune_buf = NULL;
                size_t prune_len = 0;
                libp2p_err_t prune_enc = encode_prune_rpc(topic_name, 1, &prune_buf, &prune_len);
                prune_enc_ok = (prune_enc == LIBP2P_ERR_OK && prune_buf && prune_len > 0);
                if (prune_enc_ok)
                {
                    libp2p_err_t prune_inj = libp2p_gossipsub__inject_frame(gs, &candidate_peers[0], prune_buf, prune_len);
                    prune_inj_ok = (prune_inj == LIBP2P_ERR_OK);
                }
                if (prune_buf)
                    free(prune_buf);
                if (prune_inj_ok)
                    backoff_seeded = libp2p_gossipsub__topic_backoff_contains(gs, topic_name, &candidate_peers[0]);
            }
            print_result("gossipsub_opportunistic_prune_encode", prune_enc_ok);
            if (!prune_enc_ok)
                failures++;
            print_result("gossipsub_opportunistic_prune_inject", prune_inj_ok);
            if (!prune_inj_ok)
                failures++;
            print_result("gossipsub_opportunistic_backoff_seeded", backoff_seeded);
            if (!backoff_seeded)
                failures++;
    
            int opp_ready = candidate_setup_ok && prune_inj_ok && backoff_seeded;
            int opp_ok = 0;
            if (opp_ready)
            {
                libp2p_err_t opp_rc = libp2p_gossipsub__opportunistic(gs);
                opp_ok = (opp_rc == LIBP2P_ERR_OK);
            }
            print_result("gossipsub_opportunistic_run", opp_ok);
            if (!opp_ok)
                failures++;
    
            int mesh_growth_ok = 0;
            int candidate_mesh_ok[sizeof(candidate_ids) / sizeof(candidate_ids[0])];
            int candidate_sendq_ok[sizeof(candidate_ids) / sizeof(candidate_ids[0])];
            memset(candidate_mesh_ok, 0, sizeof(candidate_mesh_ok));
            memset(candidate_sendq_ok, 0, sizeof(candidate_sendq_ok));
            int backoff_cleared = 0;
    
            if (opp_ok)
            {
                size_t mesh_after = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                size_t expected_mesh = mesh_count + ((candidate_count < (size_t)cfg.opportunistic_graft_peers) ? candidate_count : (size_t)cfg.opportunistic_graft_peers);
                if (mesh_after >= expected_mesh)
                    mesh_growth_ok = 1;
    
                for (size_t i = 0; i < candidate_count; ++i)
                {
                    candidate_mesh_ok[i] = libp2p_gossipsub__topic_mesh_contains(gs, topic_name, &candidate_peers[i], NULL, NULL);
                    size_t sendq_len = libp2p_gossipsub__peer_sendq_len(gs, &candidate_peers[i]);
                    candidate_sendq_ok[i] = (sendq_len > 0);
                }
                backoff_cleared = (libp2p_gossipsub__topic_backoff_contains(gs, topic_name, &candidate_peers[0]) == 0);
            }
    
            print_result("gossipsub_opportunistic_mesh_growth", mesh_growth_ok);
            if (!mesh_growth_ok)
                failures++;
            for (size_t i = 0; i < candidate_count; ++i)
            {
                char mesh_label[64];
                snprintf(mesh_label, sizeof(mesh_label), "gossipsub_opportunistic_candidate%zu_mesh", i);
                print_result(mesh_label, candidate_mesh_ok[i]);
                if (!candidate_mesh_ok[i])
                    failures++;
                char queue_label[64];
                snprintf(queue_label, sizeof(queue_label), "gossipsub_opportunistic_candidate%zu_graft_queue", i);
                print_result(queue_label, candidate_sendq_ok[i]);
                if (!candidate_sendq_ok[i])
                    failures++;
            }
            print_result("gossipsub_opportunistic_backoff_cleared", backoff_cleared);
            if (!backoff_cleared)
                failures++;
    
            for (size_t i = 0; i < candidate_count; ++i)
            {
                while (libp2p_gossipsub__peer_sendq_len(gs, &candidate_peers[i]) > 0)
                {
                    uint8_t *tmp_buf = NULL;
                    size_t tmp_len = 0;
                    libp2p_gossipsub__peer_pop_sendq(gs, &candidate_peers[i], &tmp_buf, &tmp_len);
                    if (tmp_buf)
                        free(tmp_buf);
                }
            }
    
            for (size_t i = 0; i < candidate_count; ++i)
            {
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &candidate_peers[i]);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &candidate_peers[i]);
                (void)libp2p_gossipsub__peer_set_connected(gs, &candidate_peers[i], 0);
            }
            for (size_t i = 0; i < mesh_count; ++i)
            {
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &mesh_peers[i]);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peers[i]);
                (void)libp2p_gossipsub__peer_set_connected(gs, &mesh_peers[i], 0);
            }
    
            if (subscribe_ok)
            {
                libp2p_err_t unsub_rc = libp2p_gossipsub_unsubscribe(gs, topic_name);
                int unsub_ok = (unsub_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_opportunistic_unsubscribe", unsub_ok);
                if (!unsub_ok)
                    failures++;
            }
            else
            {
                print_result("gossipsub_opportunistic_unsubscribe", 0);
                failures++;
            }
    
            for (size_t i = 0; i < candidate_count; ++i)
            {
                if (candidate_peers[i].bytes)
                    peer_id_destroy(&candidate_peers[i]);
            }
            for (size_t i = 0; i < mesh_count; ++i)
            {
                if (mesh_peers[i].bytes)
                    peer_id_destroy(&mesh_peers[i]);
            }
        }
    

    return failures;
}
