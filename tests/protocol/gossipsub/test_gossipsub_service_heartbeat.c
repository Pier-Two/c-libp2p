#include "test_gossipsub_service_common.h"

#include "libp2p/stream_internal.h"

/* Test-only forward declaration (header isn't on the public include path for this target). */
struct libp2p_stream;
void gossipsub_on_stream_open(struct libp2p_stream *s, void *user_data);

typedef struct gossipsub_test_closed_stream_ctx
{
    int dummy;
} gossipsub_test_closed_stream_ctx_t;

static ssize_t gossipsub_test_closed_stream_read(void *io_ctx, void *buf, size_t len)
{
    (void)io_ctx;
    (void)buf;
    (void)len;
    return LIBP2P_ERR_AGAIN;
}

static ssize_t gossipsub_test_closed_stream_write(void *io_ctx, const void *buf, size_t len)
{
    (void)io_ctx;
    (void)buf;
    (void)len;
    return LIBP2P_ERR_CLOSED;
}

static int gossipsub_test_closed_stream_close(void *io_ctx)
{
    (void)io_ctx;
    return 0;
}

static void gossipsub_test_closed_stream_free_ctx(void *io_ctx)
{
    free(io_ctx);
}

int gossipsub_service_run_heartbeat_and_gossip_tests(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 0;

    libp2p_gossipsub_t *gs = env->gs;
    libp2p_err_t err = LIBP2P_ERR_OK;
    int failures = 0;
    const libp2p_gossipsub_config_t cfg = env->cfg;

    {
        /* Regression: if a peer's stream write reports CLOSED/RESET/EOF, mark the peer as
         * disconnected so we don't keep enqueueing frames for it and leak memory / spam logs. */
        const char *peer_str = "12D3KooWQvF8fCqVQk4CwPZ1NqK9h9kqg3jWm1e7j6r2pVw7JYxR";
        peer_id_t peer = {0};
        int peer_ok = (peer_id_create_from_string(peer_str, &peer) == PEER_ID_SUCCESS);
        print_result("gossipsub_stream_write_closed_peer_id", peer_ok);
        if (!peer_ok)
            failures++;

        libp2p_stream_t *s = NULL;
        if (peer_ok)
        {
            /* libp2p_stream_from_ops takes ownership of remote_peer */
            peer_id_t *remote = (peer_id_t *)calloc(1, sizeof(*remote));
            int remote_ok = (remote && peer_id_create_from_string(peer_str, remote) == PEER_ID_SUCCESS);
            print_result("gossipsub_stream_write_closed_remote_peer_alloc", remote_ok);
            if (!remote_ok)
                failures++;

            gossipsub_test_closed_stream_ctx_t *ctx = (gossipsub_test_closed_stream_ctx_t *)calloc(1, sizeof(*ctx));
            int ctx_ok = (ctx != NULL);
            print_result("gossipsub_stream_write_closed_ctx_alloc", ctx_ok);
            if (!ctx_ok)
                failures++;

            if (remote_ok && ctx_ok)
            {
                libp2p_stream_backend_ops_t ops;
                memset(&ops, 0, sizeof(ops));
                ops.read = gossipsub_test_closed_stream_read;
                ops.write = gossipsub_test_closed_stream_write;
                ops.close = gossipsub_test_closed_stream_close;
                ops.free_ctx = gossipsub_test_closed_stream_free_ctx;

                s = libp2p_stream_from_ops(env->host, ctx, &ops, "/meshsub/1.0.0", 1 /* initiator */, remote);
                int stream_ok = (s != NULL);
                print_result("gossipsub_stream_write_closed_stream_created", stream_ok);
                if (!stream_ok)
                    failures++;

                if (stream_ok)
                {
                    /* Open the stream (attaches and sends current subscriptions). */
                    gossipsub_on_stream_open(s, gs);

                    /* Ensure the peer is a propagation target for test/topic. */
                    err = libp2p_gossipsub__topic_mesh_add_peer(gs, "test/topic", &peer, 1);
                    int mesh_add_ok = (err == LIBP2P_ERR_OK);
                    print_result("gossipsub_stream_write_closed_mesh_add", mesh_add_ok);
                    if (!mesh_add_ok)
                        failures++;

                    /* Wait until any queued subscription frames are drained/cleared. */
                    size_t qlen = 0;
                    int idle_ok = gossipsub_wait_for_peer_idle(gs, &peer, 200, &qlen);
                    print_result("gossipsub_stream_write_closed_idle_after_subscribe", idle_ok);
                    if (!idle_ok)
                        failures++;

                    /* Publish; peer must not receive any queued frames after CLOSED write failure. */
                    const uint8_t payload = 0x42;
                    libp2p_gossipsub_message_t msg = {
                        .topic = {
                            .struct_size = sizeof(msg.topic),
                            .topic = "test/topic",
                        },
                        .data = &payload,
                        .data_len = 1,
                        .from = NULL,
                        .seqno = NULL,
                        .seqno_len = 0,
                        .raw_message = NULL,
                        .raw_message_len = 0,
                    };

                    err = libp2p_gossipsub_publish(gs, &msg);
                    int publish_ok = (err == LIBP2P_ERR_OK);
                    print_result("gossipsub_stream_write_closed_publish_ok", publish_ok);
                    if (!publish_ok)
                        failures++;

                    /* Give the callback thread a moment, then verify no enqueue occurred. */
                    usleep(2000);
                    qlen = libp2p_gossipsub__peer_sendq_len(gs, &peer);
                    int no_enqueue_ok = (qlen == 0);
                    print_result("gossipsub_stream_write_closed_no_enqueue", no_enqueue_ok);
                    if (!no_enqueue_ok)
                        failures++;
                }
            }

            if (s)
            {
                (void)libp2p_stream_close(s);
                libp2p_stream_free(s);
            }
            /* If stream creation failed, free what we own. */
            if (!s)
            {
                if (ctx)
                    free(ctx);
                if (remote)
                {
                    if (remote->bytes)
                        peer_id_destroy(remote);
                    free(remote);
                }
            }
        }

        if (peer_ok)
            peer_id_destroy(&peer);
    }

    {
        const char *fanout_topic = "fanout/heartbeat";
        const char *fanout_peer_str = "12D3KooWNsGu1ca6QiN29GTRxK6j22BYrhM1Y5AkwB68x5y61xwn";
        peer_id_t fanout_peer = { 0 };
        int fanout_peer_ok = (peer_id_create_from_string(fanout_peer_str, &fanout_peer) == PEER_ID_SUCCESS);
        print_result("gossipsub_heartbeat_fanout_peer_created", fanout_peer_ok);
        if (!fanout_peer_ok)
            failures++;

        if (fanout_peer_ok)
        {
            err = libp2p_gossipsub__topic_fanout_add_peer(gs, fanout_topic, &fanout_peer, -1, 1);
            int fanout_add_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_heartbeat_fanout_add", fanout_add_ok);
            if (!fanout_add_ok)
                failures++;

            if (fanout_add_ok)
            {
                size_t fanout_sz = libp2p_gossipsub__topic_fanout_size(gs, fanout_topic);
                int fanout_sz_ok = (fanout_sz == 1);
                print_result("gossipsub_heartbeat_fanout_size_before", fanout_sz_ok);
                if (!fanout_sz_ok)
                    failures++;

                usleep(2000);
                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_heartbeat_run_for_fanout", hb_ok);
                if (!hb_ok)
                    failures++;

                fanout_sz = libp2p_gossipsub__topic_fanout_size(gs, fanout_topic);
                int fanout_cleared_ok = (fanout_sz == 0);
                print_result("gossipsub_heartbeat_fanout_cleared", fanout_cleared_ok);
                if (!fanout_cleared_ok)
                    failures++;
            }
        }

        if (fanout_peer_ok)
            peer_id_destroy(&fanout_peer);
    }

    {
        const char *mesh_topic = "mesh/heartbeat";
        const char *mesh_peer_str = "12D3KooWHZjVdysJ8V5Y2Tyshzw31wY1M2fjTw83YVHC6rU1ttzv";
        peer_id_t mesh_peer = { 0 };
        int mesh_peer_ok = (peer_id_create_from_string(mesh_peer_str, &mesh_peer) == PEER_ID_SUCCESS);
        print_result("gossipsub_heartbeat_mesh_peer_created", mesh_peer_ok);
        if (!mesh_peer_ok)
            failures++;

        if (mesh_peer_ok)
        {
            err = libp2p_gossipsub__topic_mesh_add_peer(gs, mesh_topic, &mesh_peer, 1);
            int mesh_add_ok = (err == LIBP2P_ERR_OK);
            print_result("gossipsub_heartbeat_mesh_add", mesh_add_ok);
            if (!mesh_add_ok)
                failures++;

            if (mesh_add_ok)
            {
                err = libp2p_gossipsub__peer_set_connected(gs, &mesh_peer, 1);
                int mesh_connected_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_heartbeat_mesh_connected_initial", mesh_connected_ok);
                if (!mesh_connected_ok)
                    failures++;

                size_t mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, mesh_topic);
                int mesh_sz_ok = (mesh_sz == 1);
                print_result("gossipsub_heartbeat_mesh_size_before", mesh_sz_ok);
                if (!mesh_sz_ok)
                    failures++;

                err = libp2p_gossipsub__peer_set_connected(gs, &mesh_peer, 0);
                int mesh_disconnected_ok = (err == LIBP2P_ERR_OK);
                print_result("gossipsub_heartbeat_mesh_mark_disconnected", mesh_disconnected_ok);
                if (!mesh_disconnected_ok)
                    failures++;

                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_heartbeat_run_for_mesh", hb_ok);
                if (!hb_ok)
                    failures++;

                mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, mesh_topic);
                int mesh_cleared_ok = (mesh_sz == 0);
                print_result("gossipsub_heartbeat_mesh_cleared", mesh_cleared_ok);
                if (!mesh_cleared_ok)
                    failures++;
            }
        }

        if (mesh_peer_ok)
            peer_id_destroy(&mesh_peer);
    }

    {
        const char *topic_name = "heartbeat/mesh_fill";
        libp2p_gossipsub_topic_config_t hb_topic_cfg = {
            .struct_size = sizeof(hb_topic_cfg),
            .descriptor = {
                .struct_size = sizeof(hb_topic_cfg.descriptor),
                .topic = topic_name
            },
            .score_params = NULL
        };
        err = libp2p_gossipsub_subscribe(gs, &hb_topic_cfg);
        int subscribe_ok = (err == LIBP2P_ERR_OK);
        print_result("gossipsub_heartbeat_mesh_fill_subscribe", subscribe_ok);
        if (!subscribe_ok)
            failures++;

        const char *peer_strs[] = {
            "12D3KooWExgVnyL9F9ktsHTTXV9cZ6rxWPPPwJ9V6u3yyFvEfYst",
            "12D3KooWFjecZx2YM5mAZ1bn46vCeWkQS9KpVwhM2r36EJt2vqCr",
            "12D3KooWDH8u1o1YiA1HXSwSReT7PwtZDs7JhdYKbnvSYnUrWhp2"
        };
        const size_t peer_count = sizeof(peer_strs) / sizeof(peer_strs[0]);
        peer_id_t peers[sizeof(peer_strs) / sizeof(peer_strs[0])];
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
        print_result("gossipsub_heartbeat_mesh_fill_peers", peers_created);
        if (!peers_created)
            failures++;

        if (subscribe_ok && peers_created)
        {
            int subscriptions_ok = 1;
            for (size_t i = 0; i < peer_count; ++i)
            {
                uint8_t *frame = NULL;
                size_t frame_len = 0;
                libp2p_err_t enc_rc = encode_subscription_rpc(topic_name, 1, &frame, &frame_len);
                if (enc_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                {
                    subscriptions_ok = 0;
                }
                else
                {
                    libp2p_err_t inj_rc = libp2p_gossipsub__inject_frame(gs, &peers[i], frame, frame_len);
                    if (inj_rc != LIBP2P_ERR_OK)
                        subscriptions_ok = 0;
                }
                if (frame)
                    free(frame);
                if (!subscriptions_ok)
                    break;
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &peers[i]);
            }
            print_result("gossipsub_heartbeat_mesh_fill_subscriptions", subscriptions_ok);
            if (!subscriptions_ok)
                failures++;

            if (subscriptions_ok)
            {
                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_heartbeat_mesh_fill_run", hb_ok);
                if (!hb_ok)
                    failures++;

                size_t mesh_sz = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_sz_ok = (mesh_sz >= peer_count);
                print_result("gossipsub_heartbeat_mesh_fill_size", mesh_sz_ok);
                if (!mesh_sz_ok)
                    failures++;

                for (size_t i = 0; i < peer_count; ++i)
                {
                    int contains = libp2p_gossipsub__topic_mesh_contains(gs, topic_name, &peers[i], NULL, NULL);
                    print_result("gossipsub_heartbeat_mesh_fill_contains", contains);
                    if (!contains)
                        failures++;

                    uint8_t *frame = NULL;
                    size_t frame_len = 0;
                    libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, &peers[i], &frame, &frame_len);
                    int graft_seen = 0;
                    if (pop_rc == LIBP2P_ERR_OK && frame && frame_len)
                    {
                        libp2p_gossipsub_RPC *rpc = NULL;
                        if (libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &rpc) == LIBP2P_ERR_OK && rpc)
                        {
                            if (libp2p_gossipsub_RPC_has_control(rpc))
                            {
                                libp2p_gossipsub_ControlMessage *control = libp2p_gossipsub_RPC_get_control(rpc);
                                if (control && libp2p_gossipsub_ControlMessage_has_graft(control) &&
                                    libp2p_gossipsub_ControlMessage_count_graft(control) > 0)
                                {
                                    libp2p_gossipsub_ControlGraft *graft = libp2p_gossipsub_ControlMessage_get_at_graft(control, 0);
                                    if (graft && libp2p_gossipsub_ControlGraft_has_topic(graft))
                                    {
                                        size_t len = libp2p_gossipsub_ControlGraft_get_size_topic(graft);
                                        const char *raw = libp2p_gossipsub_ControlGraft_get_topic(graft);
                                        if (raw && len == strlen(topic_name) && memcmp(raw, topic_name, len) == 0)
                                            graft_seen = 1;
                                    }
                                }
                            }
                            libp2p_gossipsub_RPC_free(rpc);
                        }
                    }
                    print_result("gossipsub_heartbeat_mesh_fill_graft", graft_seen);
                    if (!graft_seen)
                        failures++;
                    if (frame)
                        free(frame);
                }
            }
        }

        for (size_t i = 0; i < peer_count; ++i)
        {
            if (peers[i].bytes)
            {
                (void)libp2p_gossipsub__topic_mesh_remove_peer(gs, topic_name, &peers[i]);
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &peers[i]);
                peer_id_destroy(&peers[i]);
            }
        }
        libp2p_gossipsub_unsubscribe(gs, topic_name);
    }

    {
        const char *topic_name = "heartbeat/prune";
        libp2p_gossipsub_topic_config_t prune_cfg = {
            .struct_size = sizeof(prune_cfg),
            .descriptor = {
                .struct_size = sizeof(prune_cfg.descriptor),
                .topic = topic_name
            },
            .score_params = NULL
        };
        err = libp2p_gossipsub_subscribe(gs, &prune_cfg);
        int subscribe_ok = (err == LIBP2P_ERR_OK);
        print_result("gossipsub_heartbeat_prune_subscribe", subscribe_ok);
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
        const size_t peer_count = sizeof(peer_strs) / sizeof(peer_strs[0]);
        peer_id_t peers[sizeof(peer_strs) / sizeof(peer_strs[0])];
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
        print_result("gossipsub_heartbeat_prune_peers", peers_created);
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

                libp2p_err_t conn_rc = libp2p_gossipsub__peer_set_connected(gs, &peers[i], 1);
                if (conn_rc != LIBP2P_ERR_OK)
                {
                    setup_ok = 0;
                    break;
                }
                libp2p_err_t mesh_rc = libp2p_gossipsub__topic_mesh_add_peer(gs, topic_name, &peers[i], (int)(i % 2));
                if (mesh_rc != LIBP2P_ERR_OK)
                {
                    setup_ok = 0;
                    break;
                }
                (void)libp2p_gossipsub__peer_clear_sendq(gs, &peers[i]);
            }
            print_result("gossipsub_heartbeat_prune_setup", setup_ok);
            if (!setup_ok)
                failures++;

            if (setup_ok)
            {
                size_t mesh_before = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_before_ok = (mesh_before == peer_count);
                print_result("gossipsub_heartbeat_prune_mesh_before", mesh_before_ok);
                if (!mesh_before_ok)
                    failures++;

                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_heartbeat_prune_run", hb_ok);
                if (!hb_ok)
                    failures++;

                size_t mesh_after = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_after_ok = (mesh_after <= cfg.d);
                print_result("gossipsub_heartbeat_prune_mesh_after", mesh_after_ok);
                if (!mesh_after_ok)
                    failures++;

                size_t pruned_count = 0;
                for (size_t i = 0; i < peer_count; ++i)
                {
                    int in_mesh = libp2p_gossipsub__topic_mesh_contains(gs, topic_name, &peers[i], NULL, NULL);
                    if (!in_mesh)
                    {
                        pruned_count++;
                        int prune_seen = 0;
                        while (1)
                        {
                            uint8_t *frame = NULL;
                            size_t frame_len = 0;
                            libp2p_err_t pop_rc = libp2p_gossipsub__peer_pop_sendq(gs, &peers[i], &frame, &frame_len);
                            if (pop_rc != LIBP2P_ERR_OK || !frame || frame_len == 0)
                            {
                                if (frame)
                                    free(frame);
                                break;
                            }

                            libp2p_gossipsub_RPC *rpc = NULL;
                            if (libp2p_gossipsub_rpc_decode_frame(frame, frame_len, &rpc) == LIBP2P_ERR_OK && rpc)
                            {
                                if (libp2p_gossipsub_RPC_has_control(rpc))
                                {
                                    libp2p_gossipsub_ControlMessage *control = libp2p_gossipsub_RPC_get_control(rpc);
                                    if (control && libp2p_gossipsub_ControlMessage_has_prune(control) &&
                                        libp2p_gossipsub_ControlMessage_count_prune(control) > 0)
                                    {
                                        libp2p_gossipsub_ControlPrune *prune = libp2p_gossipsub_ControlMessage_get_at_prune(control, 0);
                                        if (prune && libp2p_gossipsub_ControlPrune_has_topic(prune))
                                        {
                                            size_t len = libp2p_gossipsub_ControlPrune_get_size_topic(prune);
                                            const char *raw = libp2p_gossipsub_ControlPrune_get_topic(prune);
                                            if (raw && len == strlen(topic_name) && memcmp(raw, topic_name, len) == 0)
                                                prune_seen = 1;
                                        }
                                    }
                                }
                                libp2p_gossipsub_RPC_free(rpc);
                            }
                            free(frame);
                            if (prune_seen)
                                break;
                        }
                        print_result("gossipsub_heartbeat_prune_seen", prune_seen);
                        if (!prune_seen)
                            failures++;
                    }
                }

                int prunes_ok = (pruned_count > 0);
                print_result("gossipsub_heartbeat_prune_count", prunes_ok);
                if (!prunes_ok)
                    failures++;
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
        const char *topic_name = "heartbeat/outbound_quota";
        libp2p_gossipsub_topic_config_t quota_cfg = {
            .struct_size = sizeof(quota_cfg),
            .descriptor = {
                .struct_size = sizeof(quota_cfg.descriptor),
                .topic = topic_name
            },
            .score_params = NULL
        };
        err = libp2p_gossipsub_subscribe(gs, &quota_cfg);
        int subscribe_ok = (err == LIBP2P_ERR_OK);
        print_result("gossipsub_outbound_quota_subscribe", subscribe_ok);
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
        const double scores[] = { 1.2, 0.1, 0.2, 1.0, 0.3, -0.2, 0.05 };
        const size_t peer_count = sizeof(peer_strs) / sizeof(peer_strs[0]);
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
        print_result("gossipsub_outbound_quota_peers", peers_created);
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
            print_result("gossipsub_outbound_quota_setup", setup_ok);
            if (!setup_ok)
                failures++;

            if (setup_ok)
            {
                size_t mesh_before = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_before_ok = (mesh_before == peer_count);
                print_result("gossipsub_outbound_quota_mesh_before", mesh_before_ok);
                if (!mesh_before_ok)
                    failures++;

                libp2p_err_t hb_rc = libp2p_gossipsub__heartbeat(gs);
                int hb_ok = (hb_rc == LIBP2P_ERR_OK);
                print_result("gossipsub_outbound_quota_heartbeat", hb_ok);
                if (!hb_ok)
                    failures++;

                size_t mesh_after = libp2p_gossipsub__topic_mesh_size(gs, topic_name);
                int mesh_after_ok = (mesh_after <= cfg.d);
                print_result("gossipsub_outbound_quota_mesh_after", mesh_after_ok);
                if (!mesh_after_ok)
                    failures++;

                size_t outbound_in_mesh = 0;
                int outbound_retained = 1;
                size_t inbound_pruned = 0;
                for (size_t i = 0; i < peer_count; ++i)
                {
                    int outbound = 0;
                    int in_mesh = libp2p_gossipsub__topic_mesh_contains(gs, topic_name, &peers[i], &outbound, NULL);
                    if (outbound_flags[i])
                    {
                        outbound_retained &= in_mesh;
                        if (in_mesh && outbound)
                            outbound_in_mesh++;
                    }
                    else
                    {
                        if (!in_mesh)
                            inbound_pruned++;
                    }
                }

                size_t expected_outbound = (cfg.d_out > 0) ? (size_t)cfg.d_out : 0;
                if (mesh_after < expected_outbound)
                    expected_outbound = mesh_after;
                int outbound_count_ok = (outbound_in_mesh >= expected_outbound);
                int inbound_pruned_ok = (inbound_pruned > 0);
                print_result("gossipsub_outbound_quota_outbound_retained", outbound_retained);
                if (!outbound_retained)
                    failures++;
                print_result("gossipsub_outbound_quota_outbound_count", outbound_count_ok);
                if (!outbound_count_ok)
                    failures++;
                print_result("gossipsub_outbound_quota_inbound_pruned", inbound_pruned_ok);
                if (!inbound_pruned_ok)
                    failures++;
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

    return failures;
}
