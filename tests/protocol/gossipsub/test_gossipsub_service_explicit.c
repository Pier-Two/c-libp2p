#include "test_gossipsub_service_common.h"

int gossipsub_service_run_explicit_peer_tests(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 0;

    libp2p_gossipsub_t *gs = env->gs;
    libp2p_err_t err = LIBP2P_ERR_OK;
    int failures = 0;

    const char *explicit_peer_str = "12D3KooWL9qw9QdCsiPUQXGWxZhwivKar35CFYuU9B9kavHuV2XZ";
    const char *mesh_peer_str = "12D3KooWL41axLhXgML3zbxTDkVxFvtz7ZzZWtH1yurVpbkWueMH";
    const char *explicit_topic_name = "explicit/test/topic";
    peer_id_t explicit_peer = { 0 };
    peer_id_t mesh_peer = { 0 };
    int explicit_peer_ok = (peer_id_create_from_string(explicit_peer_str, &explicit_peer) == PEER_ID_SUCCESS);
    int mesh_peer_ok = (peer_id_create_from_string(mesh_peer_str, &mesh_peer) == PEER_ID_SUCCESS);
    print_result("gossipsub_explicit_peer_id", explicit_peer_ok);
    if (!explicit_peer_ok)
        failures++;
    print_result("gossipsub_explicit_mesh_peer_id", mesh_peer_ok);
    if (!mesh_peer_ok)
        failures++;

    libp2p_gossipsub_topic_config_t explicit_topic_cfg = {
        .struct_size = sizeof(explicit_topic_cfg),
        .descriptor = {
            .struct_size = sizeof(explicit_topic_cfg.descriptor),
            .topic = explicit_topic_name
        },
        .score_params = NULL
    };

    libp2p_err_t explicit_sub_rc = LIBP2P_ERR_INTERNAL;
    libp2p_err_t peering_rc = LIBP2P_ERR_INTERNAL;
    int explicit_sub_ok = 0;
    int peering_add_ok = 0;
    if (explicit_peer_ok && mesh_peer_ok)
    {
        explicit_sub_rc = libp2p_gossipsub_subscribe(gs, &explicit_topic_cfg);
        peering_rc = libp2p_gossipsub_peering_add(gs, &explicit_peer);
    }

    explicit_sub_ok = (explicit_peer_ok && mesh_peer_ok && explicit_sub_rc == LIBP2P_ERR_OK);
    print_result("gossipsub_explicit_subscribe", explicit_sub_ok);
    if (!explicit_sub_ok)
        failures++;

    peering_add_ok = (explicit_peer_ok && mesh_peer_ok && peering_rc == LIBP2P_ERR_OK);
    print_result("gossipsub_explicit_peering_add", peering_add_ok);
    if (!peering_add_ok)
        failures++;

    if (explicit_sub_ok && peering_add_ok)
    {
        libp2p_err_t set_conn_rc = libp2p_gossipsub__peer_set_connected(gs, &explicit_peer, 1);
        int set_conn_ok = (set_conn_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_explicit_peer_mark_connected", set_conn_ok);
        if (!set_conn_ok)
            failures++;

        libp2p_err_t mesh_add_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, explicit_topic_name, &mesh_peer, 1);
        int mesh_add_ok = (mesh_add_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_explicit_mesh_peer_added", mesh_add_ok);
        if (!mesh_add_ok)
            failures++;

        if (mesh_add_ok)
            (void)libp2p_gossipsub__peer_set_connected(gs, &mesh_peer, 1);

        int explicit_in_mesh = libp2p_gossipsub__topic_mesh_contains(gs, explicit_topic_name, &explicit_peer, NULL, NULL);
        int explicit_not_mesh = (explicit_in_mesh == 0);
        print_result("gossipsub_explicit_peer_not_in_mesh", explicit_not_mesh);
        if (!explicit_not_mesh)
            failures++;

        uint8_t explicit_payload[3] = { 0x55, 0x66, 0x77 };
        libp2p_gossipsub_message_t explicit_msg = {
            .topic = {
                .struct_size = sizeof(explicit_msg.topic),
                .topic = explicit_topic_name
            },
            .data = explicit_payload,
            .data_len = sizeof(explicit_payload),
            .from = NULL,
            .seqno = NULL,
            .seqno_len = 0,
            .raw_message = NULL,
            .raw_message_len = 0
        };
        libp2p_err_t explicit_pub_rc = libp2p_gossipsub_publish(gs, &explicit_msg);
        int explicit_pub_ok = (explicit_pub_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_explicit_publish", explicit_pub_ok);
        if (!explicit_pub_ok)
            failures++;

        if (explicit_pub_ok)
        {
            size_t explicit_queue = 0;
            for (int i = 0; i < 200 && explicit_queue == 0; ++i)
            {
                explicit_queue = libp2p_gossipsub__peer_sendq_len(gs, &explicit_peer);
                if (explicit_queue == 0)
                    usleep(1000);
            }
            int explicit_forwarded = (explicit_queue > 0);
            print_result("gossipsub_explicit_peer_receives_publish", explicit_forwarded);
            if (!explicit_forwarded)
                failures++;

            if (explicit_queue > 0)
            {
                uint8_t *queued_frame = NULL;
                size_t queued_len = 0;
                libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, &explicit_peer, &queued_frame, &queued_len);
                int pop_ok = (pop_rc == LIBP2P_ERR_OK && queued_frame && queued_len);
                print_result("gossipsub_explicit_peer_pop_publish", pop_ok);
                if (!pop_ok)
                    failures++;
                if (queued_frame)
                    free(queued_frame);
            }
        }

        uint8_t *graft_frame = NULL;
        size_t graft_len = 0;
        libp2p_err_t graft_enc_rc = encode_graft_rpc(explicit_topic_name, &graft_frame, &graft_len);
        int graft_enc_ok = (graft_enc_rc == LIBP2P_ERR_OK && graft_frame && graft_len);
        print_result("gossipsub_explicit_graft_encode", graft_enc_ok);
        if (!graft_enc_ok)
            failures++;

        libp2p_err_t graft_inj_rc = LIBP2P_ERR_INTERNAL;
        if (graft_enc_ok)
            graft_inj_rc = libp2p_gossipsub__inject_frame(gs, &explicit_peer, graft_frame, graft_len);
        int graft_inj_ok = (graft_enc_ok && graft_inj_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_explicit_graft_inject", graft_inj_ok);
        if (!graft_inj_ok)
            failures++;
        if (graft_frame)
            free(graft_frame);

        size_t queue_after_graft = libp2p_gossipsub__peer_sendq_len(gs, &explicit_peer);
        int no_prune = (queue_after_graft == 0);
        print_result("gossipsub_explicit_graft_does_not_enqueue", no_prune);
        if (!no_prune)
        {
            failures++;
            while (queue_after_graft > 0)
            {
                uint8_t *tmp_buf = NULL;
                size_t tmp_len = 0;
                libp2p_gossipsub__peer_pop_sendq(gs, &explicit_peer, &tmp_buf, &tmp_len);
                if (tmp_buf)
                    free(tmp_buf);
                queue_after_graft = libp2p_gossipsub__peer_sendq_len(gs, &explicit_peer);
            }
        }

        libp2p_event_t close_evt;
        memset(&close_evt, 0, sizeof(close_evt));
        close_evt.kind = LIBP2P_EVT_CONN_CLOSED;
        close_evt.u.conn_closed.peer = &explicit_peer;
        close_evt.u.conn_closed.reason = 0;
        gossipsub_host_events_on_host_event(&close_evt, gs);

        int timer_id = libp2p_gossipsub__peer_explicit_timer_id(gs, &explicit_peer);
        int timer_scheduled = (timer_id > 0);
        print_result("gossipsub_explicit_redial_scheduled", timer_scheduled);
        if (!timer_scheduled)
            failures++;

        (void)libp2p_gossipsub_peering_remove(gs, &explicit_peer);
        (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, explicit_topic_name, &mesh_peer);
        (void)libp2p_gossipsub__peer_clear_sendq(gs, &explicit_peer);
        (void)libp2p_gossipsub__peer_clear_sendq(gs, &mesh_peer);
        libp2p_err_t explicit_unsub_rc = libp2p_gossipsub_unsubscribe(gs, explicit_topic_name);
        int explicit_unsub_ok = (explicit_unsub_rc == LIBP2P_ERR_OK);
        print_result("gossipsub_explicit_unsubscribe", explicit_unsub_ok);
        if (!explicit_unsub_ok)
            failures++;
    }

    if (!(explicit_sub_ok && peering_add_ok))
    {
        if (peering_add_ok)
            (void)libp2p_gossipsub_peering_remove(gs, &explicit_peer);
        if (explicit_sub_ok)
            (void)libp2p_gossipsub_unsubscribe(gs, explicit_topic_name);
    }

    if (explicit_peer_ok)
        peer_id_destroy(&explicit_peer);
    if (mesh_peer_ok)
        peer_id_destroy(&mesh_peer);

    return failures;
}
