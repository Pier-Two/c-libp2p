#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/host.h"
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

/* secp256k1 PrivateKey protobuf (from peer_id tests) */
#define SECP256K1_PRIVATE_HEX "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"

static void print_result(const char *name, int ok)
{
    printf("TEST: %-40s | %s\n", name, ok ? "PASS" : "FAIL");
}

int main(void)
{
    int failures = 0;
    libp2p_host_options_t opts;
    if (libp2p_host_options_default(&opts) != 0) { fprintf(stderr, "opts default failed\n"); return 1; }

    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&opts, &host) != 0 || !host) { fprintf(stderr, "host_new failed\n"); return 1; }

    size_t sk_len = 0; uint8_t *sk = hex_to_bytes(SECP256K1_PRIVATE_HEX, &sk_len);
    if (!sk) { fprintf(stderr, "hex_to_bytes failed\n"); libp2p_host_free(host); return 1; }

    int rc = libp2p_host_set_private_key(host, sk, sk_len);
    print_result("host_set_private_key", rc == 0);
    if (rc != 0) { free(sk); libp2p_host_free(host); return 1; }

    peer_id_t expected = {0};
    if (peer_id_create_from_private_key(sk, sk_len, &expected) != PEER_ID_SUCCESS) {
        fprintf(stderr, "peer_id_create_from_private_key failed\n");
        free(sk); libp2p_host_free(host); return 1;
    }

    peer_id_t *got = NULL;
    rc = libp2p_host_get_peer_id(host, &got);
    int ok = (rc == 0 && got && got->bytes && got->size > 0);
    print_result("host_get_peer_id", ok);
    if (!ok) failures++;

    if (ok) {
        int eq = peer_id_equals(&expected, got);
        print_result("host_peer_id_matches_expected", eq == 1);
        if (eq != 1) failures++;
    }

    if (got) { peer_id_destroy(got); free(got); }
    peer_id_destroy(&expected);
    free(sk);
    libp2p_host_free(host);
    return failures ? 1 : 0;
}

