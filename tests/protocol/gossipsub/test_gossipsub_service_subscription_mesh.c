#include "test_gossipsub_service_common.h"

int gossipsub_service_run_subscription_mesh_tests(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 0;

    libp2p_gossipsub_t *gs = env->gs;
    libp2p_err_t err = LIBP2P_ERR_OK;
    int failures = 0;

    {
        const char *subscription_peer_str = "12D3KooWFnNMhkbi8d4Ryh5UCnmAeUXUQCA2PMAMFLyLLKkR6aom";
        const char *subscription_topic = "test/topic";
        peer_id_t subscription_peer = { 0 };
        int sub_peer_ok = (peer_id_create_from_string(subscription_peer_str, &subscription_peer) == PEER_ID_SUCCESS);
        print_result("gossipsub_subscription_peer_id", sub_peer_ok);
        if (!sub_peer_ok)
            failures++;

        libp2p_err_t sub_enc_err = LIBP2P_ERR_INTERNAL;
        libp2p_err_t sub_inj_err = LIBP2P_ERR_INTERNAL;
        int subscription_recorded = 0;
        if (sub_peer_ok)
        {
            uint8_t *frame = NULL;
            size_t frame_len = 0;
            sub_enc_err = encode_subscription_rpc(subscription_topic, 1, &frame, &frame_len);
            if (sub_enc_err == LIBP2P_ERR_OK && frame && frame_len)
                sub_inj_err = libp2p_gossipsub__inject_frame(gs, &subscription_peer, frame, frame_len);
            if (frame)
                free(frame);
            subscription_recorded = libp2p_gossipsub__peer_has_subscription(gs, &subscription_peer, subscription_topic);
        }

        print_result("gossipsub_subscription_rpc_encoded", sub_enc_err == LIBP2P_ERR_OK);
        if (sub_enc_err != LIBP2P_ERR_OK)
            failures++;

        int subscription_injected_ok = (sub_enc_err == LIBP2P_ERR_OK && sub_inj_err == LIBP2P_ERR_OK);
        print_result("gossipsub_subscription_rpc_injected", subscription_injected_ok);
        if (sub_enc_err == LIBP2P_ERR_OK && sub_inj_err != LIBP2P_ERR_OK)
            failures++;

        print_result("gossipsub_peer_subscription_recorded", subscription_recorded);
        if (!subscription_recorded)
            failures++;

        int mesh_add_ok = 0;
        if (subscription_recorded)
        {
            libp2p_err_t mesh_add_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, subscription_topic, &subscription_peer, 1);
            mesh_add_ok = (mesh_add_rc == LIBP2P_ERR_OK);
        }
        print_result("gossipsub_mesh_add_subscribed_peer", mesh_add_ok);
        if (!mesh_add_ok)
            failures++;

        libp2p_err_t unsub_enc_err = LIBP2P_ERR_INTERNAL;
        libp2p_err_t unsub_inj_err = LIBP2P_ERR_INTERNAL;
        int subscription_cleared = 0;
        size_t mesh_after_unsub = libp2p_gossipsub__topic_mesh_size(gs, subscription_topic);
        if (sub_peer_ok)
        {
            uint8_t *frame = NULL;
            size_t frame_len = 0;
            unsub_enc_err = encode_subscription_rpc(subscription_topic, 0, &frame, &frame_len);
            if (unsub_enc_err == LIBP2P_ERR_OK && frame && frame_len)
                unsub_inj_err = libp2p_gossipsub__inject_frame(gs, &subscription_peer, frame, frame_len);
            if (frame)
                free(frame);
            subscription_cleared = libp2p_gossipsub__peer_has_subscription(gs, &subscription_peer, subscription_topic) == 0;
            mesh_after_unsub = libp2p_gossipsub__topic_mesh_size(gs, subscription_topic);
        }

        print_result("gossipsub_unsubscription_rpc_encoded", unsub_enc_err == LIBP2P_ERR_OK);
        if (unsub_enc_err != LIBP2P_ERR_OK)
            failures++;

        int unsub_injected_ok = (unsub_enc_err == LIBP2P_ERR_OK && unsub_inj_err == LIBP2P_ERR_OK);
        print_result("gossipsub_unsubscription_rpc_injected", unsub_injected_ok);
        if (unsub_enc_err == LIBP2P_ERR_OK && unsub_inj_err != LIBP2P_ERR_OK)
            failures++;

        print_result("gossipsub_peer_subscription_cleared", subscription_cleared);
        if (!subscription_cleared)
            failures++;

        int mesh_cleared = (mesh_after_unsub == 0);
        print_result("gossipsub_mesh_cleared_on_unsubscribe", mesh_cleared);
        if (!mesh_cleared)
            failures++;

        if (sub_peer_ok)
            peer_id_destroy(&subscription_peer);
    }

    {
        const char *peer1_str = "12D3KooWDbSkFwsij4BjjHfZxQqJ1zuvBABFqQ5uwSX6ZiUvUv9d";
        const char *peer2_str = "12D3KooWN9oSkqZSS7Y7gsnAmfmNgmcByKYEzGyv1mCXN8vQiyTe";
        peer_id_t mesh_peer1 = { 0 };
        peer_id_t mesh_peer2 = { 0 };
        int peer1_ok = (peer_id_create_from_string(peer1_str, &mesh_peer1) == PEER_ID_SUCCESS);
        int peer2_ok = (peer_id_create_from_string(peer2_str, &mesh_peer2) == PEER_ID_SUCCESS);
        int mesh_ids_ok = peer1_ok && peer2_ok;
        print_result("gossipsub_mesh_peer_ids_created", mesh_ids_ok);
        if (!mesh_ids_ok)
            failures++;

        if (mesh_ids_ok)
        {
            err = libp2p_gossipsub__topic_mesh_add_peer(gs, "test/topic", &mesh_peer1, 1);
            int mesh_add1_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_mesh_add_peer1", mesh_add1_ok);
            if (!mesh_add1_ok)
                failures++;

            size_t mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, "test/topic");
            int mesh_sz_ok = (mesh_sz == 1);
            print_result("gossipsub_mesh_size_after_peer1", mesh_sz_ok);
            if (!mesh_sz_ok)
                failures++;

            int outbound_flag = -1;
            uint64_t hb_ms = 0;
            int contains1 = libp2p_gossipsub__topic_mesh_contains(gs, "test/topic", &mesh_peer1, &outbound_flag, &hb_ms);
            int contains1_ok = contains1 && outbound_flag == 1 && hb_ms > 0;
            print_result("gossipsub_mesh_contains_peer1", contains1_ok);
            if (!contains1_ok)
                failures++;

            err = libp2p_gossipsub__topic_mesh_add_peer(gs, "test/topic", &mesh_peer2, 0);
            int mesh_add2_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_mesh_add_peer2", mesh_add2_ok);
            if (!mesh_add2_ok)
                failures++;

            mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, "test/topic");
            mesh_sz_ok = (mesh_sz == 2);
            print_result("gossipsub_mesh_size_after_peer2", mesh_sz_ok);
            if (!mesh_sz_ok)
                failures++;

            outbound_flag = -1;
            hb_ms = 0;
            int contains2 = libp2p_gossipsub__topic_mesh_contains(gs, "test/topic", &mesh_peer2, &outbound_flag, &hb_ms);
            int contains2_ok = contains2 && outbound_flag == 0 && hb_ms > 0;
            print_result("gossipsub_mesh_contains_peer2", contains2_ok);
            if (!contains2_ok)
                failures++;

            err = libp2p_gossipsub__topic_mesh_remove_peer(gs, "test/topic", &mesh_peer1);
            mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, "test/topic");
            int mesh_remove1_ok = (err == LIBP2P_ERR_OK) && mesh_sz == 1;
            print_result("gossipsub_mesh_remove_peer1", mesh_remove1_ok);
            if (!mesh_remove1_ok)
                failures++;

            err = libp2p_gossipsub_peering_remove(gs, &mesh_peer2);
            mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, "test/topic");
            int mesh_remove2_ok = (err == LIBP2P_ERR_OK) && mesh_sz == 0;
            print_result("gossipsub_mesh_remove_peer2", mesh_remove2_ok);
            if (!mesh_remove2_ok)
                failures++;
        }

        if (peer1_ok)
            peer_id_destroy(&mesh_peer1);
        if (peer2_ok)
            peer_id_destroy(&mesh_peer2);
    }

    {
        const char *fanout_peer_str = "12D3KooWJMCZpZGsGWpRieyU7gnaNmJKbnHiKK4xqSSdoRRt9P5r";
        peer_id_t fanout_peer = { 0 };
        int fanout_peer_ok = (peer_id_create_from_string(fanout_peer_str, &fanout_peer) == PEER_ID_SUCCESS);
        print_result("gossipsub_fanout_peer_id_created", fanout_peer_ok);
        if (!fanout_peer_ok)
            failures++;

        if (fanout_peer_ok)
        {
            err = libp2p_gossipsub__topic_fanout_add_peer(gs, "fanout/topic", &fanout_peer, -1, 5000);
            int fanout_add_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_fanout_add_peer", fanout_add_ok);
            if (!fanout_add_ok)
                failures++;

            size_t fanout_sz = libp2p_gossipsub__topic_fanout_size(gs, "fanout/topic");
            int fanout_size_ok = (fanout_sz == 1);
            print_result("gossipsub_fanout_size_after_add", fanout_size_ok);
            if (!fanout_size_ok)
                failures++;

            int outbound_flag = -1;
            uint64_t last_publish_ms = 0;
            int fanout_contains = libp2p_gossipsub__topic_fanout_contains(gs, "fanout/topic", &fanout_peer, &outbound_flag, &last_publish_ms);
            int fanout_contains_ok = fanout_contains && last_publish_ms > 0;
            print_result("gossipsub_fanout_contains_peer", fanout_contains_ok);
            if (!fanout_contains_ok)
                failures++;

            uint64_t expire_ms = libp2p_gossipsub__topic_fanout_expire_ms(gs, "fanout/topic");
            int expire_ok = (expire_ms >= last_publish_ms);
            print_result("gossipsub_fanout_expire_set", expire_ok);
            if (!expire_ok)
                failures++;

            err = libp2p_gossipsub__topic_fanout_remove_peer(gs, "fanout/topic", &fanout_peer);
            fanout_sz = libp2p_gossipsub__topic_fanout_size(gs, "fanout/topic");
            int fanout_remove_ok = (err == LIBP2P_ERR_OK) && fanout_sz == 0;
            print_result("gossipsub_fanout_remove_peer", fanout_remove_ok);
            if (!fanout_remove_ok)
                failures++;
        }

        if (fanout_peer_ok)
            peer_id_destroy(&fanout_peer);
    }

    return failures;
}
