#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p/errors.h"
#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/protocol.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/ping/protocol_ping.h"

#include "identify_test_utils.h"

static void print_case(const char *name, int ok) { printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL"); }

static int wait_for_event_addr(libp2p_host_t *h, libp2p_event_kind_t kind, char **out, int timeout_ms)
{
    const int step = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step, &evt);
        if (got == 1)
        {
            if (evt.kind == kind)
            {
                const char *addr = NULL;
                if (kind == LIBP2P_EVT_LISTEN_ADDR_ADDED)
                    addr = evt.u.listen_addr_added.addr;
                else if (kind == LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER)
                    addr = evt.u.new_external_addr_of_peer.addr;
                if (addr)
                {
                    *out = strdup(addr);
                    libp2p_event_free(&evt);
                    return 1;
                }
            }
            libp2p_event_free(&evt);
        }
        waited += step;
    }
    return 0;
}

static int wait_for_protocol_event(libp2p_host_t *h, const char *proto_id, int timeout_ms)
{
    const int step = 50;
    int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step, &evt);
        if (got == 1)
        {
            if (evt.kind == LIBP2P_EVT_PROTOCOL_NEGOTIATED && evt.u.protocol_negotiated.protocol_id && proto_id &&
                strcmp(evt.u.protocol_negotiated.protocol_id, proto_id) == 0)
            {
                libp2p_event_free(&evt);
                return 1;
            }
            libp2p_event_free(&evt);
        }
        waited += step;
    }
    return 0;
}

static int build_secp256k1_private_key_pb(const uint8_t *seed32, size_t seed_len, uint8_t **out, size_t *out_len)
{
    if (!seed32 || seed_len != 32 || !out || !out_len)
        return -1;
    uint8_t buf[64];
    size_t off = 0, sz = 0;
    buf[off++] = 0x08;
    unsigned_varint_encode(2, buf + off, sizeof(buf) - off, &sz);
    off += sz; /* KeyType=2 */
    buf[off++] = 0x12;
    unsigned_varint_encode(32, buf + off, sizeof(buf) - off, &sz);
    off += sz;
    memcpy(buf + off, seed32, 32);
    off += 32;
    uint8_t *ret = (uint8_t *)malloc(off);
    if (!ret)
        return -1;
    memcpy(ret, buf, off);
    *out = ret;
    *out_len = off;
    return 0;
}

int main(void)
{
    fprintf(stderr, "[TEST_PUB] start\n");
    const char *DUMMY_PROTO = "/dummy/1.0.0";
    libp2p_host_builder_t *ba = libp2p_host_builder_new();
    libp2p_host_builder_t *bb = libp2p_host_builder_new();
    if (!ba || !bb)
        return 1;
    (void)libp2p_host_builder_listen_addr(ba, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_listen_addr(bb, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_transport(ba, "tcp");
    (void)libp2p_host_builder_transport(bb, "tcp");
    (void)libp2p_host_builder_security(ba, "noise");
    (void)libp2p_host_builder_security(bb, "noise");
    (void)libp2p_host_builder_muxer(ba, "yamux");
    (void)libp2p_host_builder_muxer(bb, "yamux");
    /* Disable inbound auto-identify for stability */
    (void)libp2p_host_builder_flags(ba, LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);
    (void)libp2p_host_builder_flags(bb, LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);

    libp2p_host_t *ha = NULL, *hb = NULL;
    if (libp2p_host_builder_build(ba, &ha) != 0 || libp2p_host_builder_build(bb, &hb) != 0 || !ha || !hb)
        return 1;
    libp2p_host_builder_free(ba);
    libp2p_host_builder_free(bb);

    uint8_t seedA[32], seedB[32];
    for (int i = 0; i < 32; i++)
    {
        seedA[i] = (uint8_t)(i + 3);
        seedB[i] = (uint8_t)(0xBB - i);
    }
    uint8_t *pkA = NULL, *pkB = NULL;
    size_t pkAL = 0, pkBL = 0;
    if (build_secp256k1_private_key_pb(seedA, 32, &pkA, &pkAL) != 0)
        return 1;
    if (build_secp256k1_private_key_pb(seedB, 32, &pkB, &pkBL) != 0)
    {
        free(pkA);
        return 1;
    }
    if (libp2p_host_set_private_key(ha, pkA, pkAL) != 0 || libp2p_host_set_private_key(hb, pkB, pkBL) != 0)
    {
        free(pkA);
        free(pkB);
        return 1;
    }
    free(pkA);
    free(pkB);

    fprintf(stderr, "[TEST_PUB] starting hosts\n");
    if (libp2p_host_start(ha) != 0 || libp2p_host_start(hb) != 0)
        return 1;

    peer_id_t *pidA = NULL;
    if (libp2p_host_get_peer_id(ha, &pidA) != 0 || !pidA)
        return 1;

    /* B starts ping service to give us an active stream */
    libp2p_protocol_server_t *ping_srv = NULL;
    fprintf(stderr, "[TEST_PUB] starting ping service on hb\n");
    if (libp2p_ping_service_start(hb, &ping_srv) != 0)
        return 1;

    char *addrB = NULL;
    fprintf(stderr, "[TEST_PUB] waiting for hb listen addr\n");
    if (!wait_for_event_addr(hb, LIBP2P_EVT_LISTEN_ADDR_ADDED, &addrB, 3000))
        return 1;

    /* Dial ping from A to B and perform one ping roundtrip to ensure stream open */
    libp2p_stream_t *ping_stream = NULL;
    fprintf(stderr, "[TEST_PUB] dialing ping to hb at %s\n", addrB);
    if (libp2p_host_dial_protocol_blocking(ha, addrB, LIBP2P_PING_PROTO_ID, 3000, &ping_stream) != 0 || !ping_stream)
    {
        free(addrB);
        return 1;
    }
    fprintf(stderr, "[TEST_PUB] starting ping roundtrip on stream\n");
    uint64_t rtt = 0;
    (void)libp2p_ping_roundtrip_stream(ping_stream, 1000, &rtt);
    fprintf(stderr, "[TEST_PUB] ping roundtrip done (rtt=%llu)\n", (unsigned long long)rtt);

    /* Register a dummy local protocol on A -> triggers LOCAL_PROTOCOLS_UPDATED and publish */
    libp2p_protocol_def_t def = {.protocol_id = DUMMY_PROTO,
                                 .read_mode = LIBP2P_READ_PULL,
                                 .on_open = NULL,
                                 .on_data = NULL,
                                 .on_eof = NULL,
                                 .on_close = NULL,
                                 .on_error = NULL,
                                 .user_data = NULL};
    protocols_update_waiter_t proto_waiter;
    if (!protocols_update_waiter_start(&proto_waiter, hb, pidA, "[TEST_PUB]"))
    {
        peer_id_destroy(pidA);
        free(pidA);
        return 1;
    }

    fprintf(stderr, "[TEST_PUB] registering dummy protocol on ha (will trigger LOCAL_PROTOCOLS_UPDATED)\n");
    (void)libp2p_register_protocol(ha, &def);

    /* Wait for hb to receive peer address info via Identify Push (event-driven) */
    char *peer_addr_seen = NULL;
    (void)wait_for_event_addr(hb, LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER, &peer_addr_seen, 5000);
    free(peer_addr_seen);

    int saw_protocol_update = protocols_update_waiter_wait(&proto_waiter, 10000);

    /* Evaluate the pushed protocol list received via event */
    size_t observed = 0;
    int event_has_dummy = 0;
    if (hb && saw_protocol_update)
    {
        observed = proto_waiter.num_protocols;
        for (size_t i = 0; i < proto_waiter.num_protocols; i++)
        {
            const char *p = proto_waiter.protocols[i];
            if (p && strcmp(p, DUMMY_PROTO) == 0)
            {
                event_has_dummy = 1;
                break;
            }
        }
    }
    fprintf(stderr, "[TEST_PUB] protocols event processed; event_has_dummy=%d (received=%zu)\n", event_has_dummy, observed);

    /* Immediately query the peerstore to ensure the advertised protocols are visible without retries */
    const char **peerstore_protocols = NULL;
    size_t peerstore_count = 0;
    int peerstore_has_dummy = 0;
    int peerstore_rc = -1;
    if (hb && pidA)
    {
        peerstore_rc = libp2p_host_peer_protocols(hb, pidA, &peerstore_protocols, &peerstore_count);
        fprintf(stderr,
                "[TEST_PUB] peerstore query result rc=%d count=%zu\n",
                peerstore_rc,
                peerstore_count);
        if (peerstore_rc == 0)
        {
            for (size_t i = 0; i < peerstore_count; i++)
            {
                const char *p = peerstore_protocols[i];
                if (p && strcmp(p, DUMMY_PROTO) == 0)
                {
                    peerstore_has_dummy = 1;
                    break;
                }
            }
        }
        else if (peerstore_rc == LIBP2P_ERR_AGAIN)
        {
            fprintf(stderr, "[TEST_PUB] peerstore returned LIBP2P_ERR_AGAIN unexpectedly\n");
        }
    }

    int ok = event_has_dummy && peerstore_has_dummy;
    fprintf(stderr,
            "[TEST_PUB] verdict event_has_dummy=%d peerstore_has_dummy=%d\n",
            event_has_dummy,
            peerstore_has_dummy);
    print_case("identify push publish updates peerstore protocols", ok);

    if (peerstore_protocols)
        libp2p_host_free_peer_protocols(peerstore_protocols, peerstore_count);
    protocols_update_waiter_stop(&proto_waiter, hb);
    if (pidA)
    {
        peer_id_destroy(pidA);
        free(pidA);
    }
    fprintf(stderr, "[TEST_PUB] stopping hosts\n");
    libp2p_host_stop(ha);
    libp2p_host_stop(hb);
    libp2p_host_free(ha);
    libp2p_host_free(hb);
    fprintf(stderr, "[TEST_PUB] done\n");
    return ok ? 0 : 1;
}
