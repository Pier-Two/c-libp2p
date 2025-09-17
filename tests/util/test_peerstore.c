#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/peerstore.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"

/* hex->bytes helper (duplicated minimal util for test) */
static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return NULL;
    size_t n = hex_len / 2;
    uint8_t *buf = (uint8_t *)malloc(n);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        char b[3] = { hex[2*i], hex[2*i+1], '\0' };
        buf[i] = (uint8_t)strtol(b, NULL, 16);
    }
    if (out_len) *out_len = n;
    return buf;
}

/* secp256k1 PublicKey protobuf (from peer_id tests) */
#define SECP256K1_PUBLIC_HEX "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"

static void print_result(const char *name, int ok)
{
    printf("TEST: %-40s | %s\n", name, ok ? "PASS" : "FAIL");
}

int main(void)
{
    int failures = 0;

    libp2p_peerstore_t *ps = libp2p_peerstore_new();
    if (!ps) { fprintf(stderr, "peerstore_new failed\n"); return 1; }

    size_t pub_len = 0;
    uint8_t *pub_pb = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pub_len);
    if (!pub_pb) { fprintf(stderr, "hex_to_bytes failed\n"); libp2p_peerstore_free(ps); return 1; }

    peer_id_t pid = {0};
    if (peer_id_create_from_public_key(pub_pb, pub_len, &pid) != PEER_ID_SUCCESS) {
        fprintf(stderr, "peer_id_create_from_public_key failed\n");
        free(pub_pb); libp2p_peerstore_free(ps); return 1;
    }

    /* Address add/get */
    int ma_err = 0;
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4001", &ma_err);
    if (!ma) { fprintf(stderr, "multiaddr_new_from_str failed\n"); goto out_err; }

    int rc = libp2p_peerstore_add_addr(ps, &pid, ma, 60*1000);
    print_result("peerstore_add_addr", rc == 0);
    if (rc != 0) { failures++; }

    const multiaddr_t **out_addrs = NULL; size_t out_len = 0;
    rc = libp2p_peerstore_get_addrs(ps, &pid, &out_addrs, &out_len);
    int ok = (rc == 0 && out_len >= 1 && out_addrs != NULL);
    print_result("peerstore_get_addrs", ok);
    if (!ok) { failures++; }

    if (ok) {
        int s1 = 0, s2 = 0;
        char *a1 = multiaddr_to_str(ma, &s1);
        char *a2 = multiaddr_to_str(out_addrs[0], &s2);
        ok = (a1 && a2 && strcmp(a1, a2) == 0);
        print_result("peerstore_get_addrs_match", ok);
        if (!ok) failures++;
        if (a1) free(a1); if (a2) free(a2);
    }
    libp2p_peerstore_free_addrs(out_addrs, out_len);

    /* Protocols set/get */
    const char *protos[2] = { "/ipfs/id/1.0.0", "/ipfs/ping/1.0.0" };
    rc = libp2p_peerstore_set_protocols(ps, &pid, protos, 2);
    print_result("peerstore_set_protocols", rc == 0);
    if (rc != 0) failures++;

    const char **got = NULL; size_t got_len = 0;
    rc = libp2p_peerstore_get_protocols(ps, &pid, &got, &got_len);
    ok = (rc == 0 && got && got_len == 2);
    print_result("peerstore_get_protocols", ok);
    if (!ok) failures++;
    if (ok) {
        /* Content check (order preserved) */
        ok = (strcmp(got[0], protos[0]) == 0 && strcmp(got[1], protos[1]) == 0);
        print_result("peerstore_protocols_match", ok);
        if (!ok) failures++;
    }
    libp2p_peerstore_free_protocols(got, got_len);

    /* Public key store (no getter; just store should succeed) */
    rc = libp2p_peerstore_set_public_key(ps, &pid, pub_pb, pub_len);
    print_result("peerstore_set_public_key", rc == 0);
    if (rc != 0) failures++;

    /* Public key getter and equality check */
    uint8_t *got_pb = NULL; size_t got_pb_len = 0;
    rc = libp2p_peerstore_get_public_key(ps, &pid, &got_pb, &got_pb_len);
    int okpk = (rc == 0 && got_pb && got_pb_len == pub_len && memcmp(got_pb, pub_pb, pub_len) == 0);
    print_result("peerstore_get_public_key", okpk);
    if (!okpk) failures++;
    free(got_pb);

    multiaddr_free(ma);
    free(pub_pb);
    peer_id_destroy(&pid);
    libp2p_peerstore_free(ps);

    return failures ? 1 : 0;

out_err:
    free(pub_pb);
    peer_id_destroy(&pid);
    libp2p_peerstore_free(ps);
    return 1;
}
