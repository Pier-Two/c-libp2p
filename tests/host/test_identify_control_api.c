#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/identify.h"
#include "libp2p/events.h"
#include "libp2p/peerstore.h"
#include "peer_id/peer_id.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#include "identify_test_utils.h"

static void print_case(const char *name, int ok)
{
    printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL");
}

static int wait_for_listen_addr(libp2p_host_t *h, char **out, int timeout_ms)
{
    const int step = 50; int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0};
        int got = libp2p_host_next_event(h, step, &evt);
        if (got == 1)
        {
            if (evt.kind == LIBP2P_EVT_LISTEN_ADDR_ADDED && evt.u.listen_addr_added.addr)
            { *out = strdup(evt.u.listen_addr_added.addr); libp2p_event_free(&evt); return 1; }
            libp2p_event_free(&evt);
        }
        waited += step;
    }
    return 0;
}

static int build_secp256k1_private_key_pb(const uint8_t *seed32, size_t seed_len, uint8_t **out, size_t *out_len)
{
    if (!seed32 || seed_len != 32 || !out || !out_len) return -1;
    uint8_t buf[64]; size_t off = 0, sz = 0;
    buf[off++] = 0x08; unsigned_varint_encode(2, buf + off, sizeof(buf) - off, &sz); off += sz; /* KeyType=2 */
    buf[off++] = 0x12; unsigned_varint_encode(32, buf + off, sizeof(buf) - off, &sz); off += sz;
    memcpy(buf + off, seed32, 32); off += 32;
    uint8_t *ret = (uint8_t *)malloc(off); if (!ret) return -1; memcpy(ret, buf, off);
    *out = ret; *out_len = off; return 0;
}

int main(void)
{
    libp2p_host_builder_t *ba = libp2p_host_builder_new();
    libp2p_host_builder_t *bb = libp2p_host_builder_new();
    if (!ba || !bb) return 1;
    (void)libp2p_host_builder_listen_addr(ba, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_listen_addr(bb, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_transport(ba, "tcp");
    (void)libp2p_host_builder_transport(bb, "tcp");
    (void)libp2p_host_builder_security(ba, "noise");
    (void)libp2p_host_builder_security(bb, "noise");
    (void)libp2p_host_builder_muxer(ba, "yamux");
    (void)libp2p_host_builder_muxer(bb, "yamux");
    /* Disable auto-identify outbound on A to ensure request path is exercised */
    (void)libp2p_host_builder_flags(ba, 0);
    (void)libp2p_host_builder_flags(bb, 0);

    libp2p_host_t *ha = NULL, *hb = NULL;
    if (libp2p_host_builder_build(ba, &ha) != 0 || libp2p_host_builder_build(bb, &hb) != 0)
        return 1;
    libp2p_host_builder_free(ba); libp2p_host_builder_free(bb);

    uint8_t seedA[32], seedB[32];
    for (int i = 0; i < 32; i++) { seedA[i] = (uint8_t)(i + 11); seedB[i] = (uint8_t)(0xA0 - i); }
    uint8_t *pkA = NULL, *pkB = NULL; size_t pkAL = 0, pkBL = 0;
    if (build_secp256k1_private_key_pb(seedA, 32, &pkA, &pkAL) != 0) return 1;
    if (build_secp256k1_private_key_pb(seedB, 32, &pkB, &pkBL) != 0) { free(pkA); return 1; }
    if (libp2p_host_set_private_key(ha, pkA, pkAL) != 0 || libp2p_host_set_private_key(hb, pkB, pkBL) != 0) { free(pkA); free(pkB); return 1; }
    free(pkA); free(pkB);

    if (libp2p_host_start(ha) != 0 || libp2p_host_start(hb) != 0)
        return 1;

    /* Get B's listen addr and peer id */
    char *addrB = NULL;
    if (!wait_for_listen_addr(hb, &addrB, 3000))
        return 1;
    peer_id_t *pidB = NULL; (void)libp2p_host_get_peer_id(hb, &pidB);
    if (!pidB) { free(addrB); return 1; }

    /* Seed A's peerstore with B's address using the host convenience API */
    (void)libp2p_host_add_peer_addr_str(ha, pidB, addrB, 60 * 1000);
    free(addrB);

    /* Identify controller */
    libp2p_identify_service_t *ids = NULL; libp2p_identify_opts_t opts = { .struct_size = sizeof(opts) };
    if (libp2p_identify_new(ha, &opts, &ids) != 0 || !ids) { peer_id_destroy(pidB); free(pidB); return 1; }

    protocols_update_waiter_t proto_waiter;
    if (!protocols_update_waiter_start(&proto_waiter, ha, pidB, "[TEST_CTRL]"))
    {
        libp2p_identify_ctrl_free(ids);
        peer_id_destroy(pidB); free(pidB);
        libp2p_host_stop(ha); libp2p_host_stop(hb);
        libp2p_host_free(ha); libp2p_host_free(hb);
        return 1;
    }

    int rc = libp2p_identify_request(ids, pidB);
    int ok = (rc == 0);

    if (ok)
        ok = protocols_update_waiter_wait(&proto_waiter, 5000);

    protocols_update_waiter_stop(&proto_waiter, ha);

    /* Verify A's peerstore now lists identify protocol for B */
    const char **protos = NULL; size_t n = 0;
    if (ok)
    {
        int lookup_rc = libp2p_host_peer_protocols(ha, pidB, &protos, &n);
        if (lookup_rc == LIBP2P_ERR_AGAIN)
        {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000L };
            nanosleep(&ts, NULL);
            lookup_rc = libp2p_host_peer_protocols(ha, pidB, &protos, &n);
        }
        ok = (lookup_rc == 0);
    }
    if (ok)
    {
        int has_id = 0;
        for (size_t i = 0; i < n; i++) if (protos[i] && strcmp(protos[i], "/ipfs/id/1.0.0") == 0) { has_id = 1; break; }
        ok = has_id;
    }
    print_case("identify_request updates peerstore via control API", ok);

    libp2p_host_free_peer_protocols(protos, n);
    libp2p_identify_ctrl_free(ids);
    peer_id_destroy(pidB); free(pidB);
    libp2p_host_stop(ha); libp2p_host_stop(hb);
    libp2p_host_free(ha); libp2p_host_free(hb);
    return ok ? 0 : 1;
}
