#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/lpmsg.h"
#include "libp2p/events.h"
#include "protocol/identify/protocol_identify.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

static void print_case(const char *name, int ok)
{
    printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL");
}

static int wait_for_event_addr(libp2p_host_t *h, libp2p_event_kind_t kind, char **out, int timeout_ms)
{
    const int step = 50; int waited = 0;
    while (waited < timeout_ms)
    {
        libp2p_event_t evt = {0}; int got = libp2p_host_next_event(h, step, &evt);
        if (got == 1)
        {
            const char *addr = NULL;
            if (evt.kind == kind)
            {
                if (kind == LIBP2P_EVT_LISTEN_ADDR_ADDED) addr = evt.u.listen_addr_added.addr;
                else if (kind == LIBP2P_EVT_CONN_OPENED) addr = evt.u.conn_opened.addr;
                else if (kind == LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE) addr = evt.u.new_external_addr_candidate.addr;
            }
            if (addr) { *out = strdup(addr); libp2p_event_free(&evt); return 1; }
            libp2p_event_free(&evt);
        }
        waited += step;
    }
    return 0;
}

/* Build a protobuf-encoded PrivateKey for Secp256k1 from a 32-byte seed */
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
    /* Build two hosts and set identities; disable auto-identify to avoid extra streams */
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
    (void)libp2p_host_builder_flags(ba, 0);
    (void)libp2p_host_builder_flags(bb, 0);

    libp2p_host_t *ha = NULL, *hb = NULL;
    if (libp2p_host_builder_build(ba, &ha) != 0 || libp2p_host_builder_build(bb, &hb) != 0 || !ha || !hb)
        return 1;
    libp2p_host_builder_free(ba); libp2p_host_builder_free(bb);

    uint8_t seedA[32], seedB[32]; for (int i = 0; i < 32; i++) { seedA[i] = (uint8_t)(i + 7); seedB[i] = (uint8_t)(0xCC - i); }
    uint8_t *pkA = NULL, *pkB = NULL; size_t pkAL = 0, pkBL = 0;
    if (build_secp256k1_private_key_pb(seedA, 32, &pkA, &pkAL) != 0) return 1;
    if (build_secp256k1_private_key_pb(seedB, 32, &pkB, &pkBL) != 0) { free(pkA); return 1; }
    if (libp2p_host_set_private_key(ha, pkA, pkAL) != 0 || libp2p_host_set_private_key(hb, pkB, pkBL) != 0)
    { free(pkA); free(pkB); return 1; }
    free(pkA); free(pkB);

    if (libp2p_host_start(ha) != 0 || libp2p_host_start(hb) != 0)
        return 1;

    char *addrA = NULL;
    if (!wait_for_event_addr(ha, LIBP2P_EVT_LISTEN_ADDR_ADDED, &addrA, 4000))
        return 1;

    /* 1) Verify encode_local produces binary multiaddr bytes */
    uint8_t *payload = NULL; size_t plen = 0;
    if (libp2p_identify_encode_local(ha, NULL, 0, &payload, &plen) != 0 || !payload || plen == 0)
        return 1;
    libp2p_identify_t *id_local = NULL;
    int dec_rc = libp2p_identify_message_decode(payload, plen, &id_local);
    int ok_local = (dec_rc == 0) && id_local && id_local->num_listen_addrs > 0;
    int parsed = 0;
    if (ok_local)
    {
        for (size_t i = 0; i < id_local->num_listen_addrs; i++)
        {
            int ma_err = 0;
            multiaddr_t *ma = multiaddr_new_from_bytes(id_local->listen_addrs[i], id_local->listen_addrs_lens[i], &ma_err);
            if (ma)
            {
                parsed++;
                multiaddr_free(ma);
            }
        }
    }
    ok_local = ok_local && (parsed > 0);
    print_case("identify encode_local listenAddrs are binary multiaddrs", ok_local);
    libp2p_identify_free(id_local);
    free(payload);

    /* 2) Verify observedAddr over the wire is binary multiaddr bytes */
    libp2p_stream_t *s = NULL;
    if (libp2p_host_dial_protocol_blocking(hb, addrA, LIBP2P_IDENTIFY_PROTO_ID, 3000, &s) != 0 || !s)
    { free(addrA); return 1; }
    uint8_t *buf = (uint8_t *)malloc(64 * 1024);
    if (!buf) { free(addrA); libp2p_stream_close(s); return 1; }
    ssize_t n = libp2p_lp_recv(s, buf, 64 * 1024);
    int ok_obs = 0;
    if (n > 0)
    {
        libp2p_identify_t *id = NULL;
        if (libp2p_identify_message_decode(buf, (size_t)n, &id) == 0 && id)
        {
            if (id->observed_addr && id->observed_addr_len)
            {
                int ma_err = 0; multiaddr_t *oma = multiaddr_new_from_bytes(id->observed_addr, id->observed_addr_len, &ma_err);
                if (oma)
                {
                    ok_obs = 1; multiaddr_free(oma);
                }
            }
            libp2p_identify_free(id);
        }
    }
    print_case("identify response observedAddr is binary multiaddr", ok_obs);
    free(buf);
    libp2p_stream_close(s);

    int ok_all = ok_local && ok_obs;
    free(addrA);
    libp2p_host_stop(ha); libp2p_host_stop(hb);
    libp2p_host_free(ha); libp2p_host_free(hb);
    return ok_all ? 0 : 1;
}

