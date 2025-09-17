/* Unit test for Resource Manager per-protocol limits without networking. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/host.h"
#include "libp2p/resource_manager.h"
#include "peer_id/peer_id.h"

#define TEST_PROTO_ID "/rmtest/1.0.0"

static void print_case(const char *name, int ok)
{
    printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL");
}

int main(void)
{
    libp2p_host_options_t o; libp2p_host_options_default(&o);
    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&o, &host) != 0 || !host)
        return 1;

    libp2p_rsrc_mgr_t *rm = NULL;
    libp2p_rsrc_limits_t lim = {0}; lim.struct_size = sizeof(lim);
    if (libp2p_rsrc_mgr_new(&lim, &rm) != 0 || !rm)
    { libp2p_host_free(host); return 1; }
    libp2p_rsrc_perproto_limits_t pl = {0};
    pl.struct_size = sizeof(pl);
    pl.protocol_id = TEST_PROTO_ID;
    pl.max_inbound_per_peer = 1;
    pl.max_inbound_total = 1;
    pl.max_outbound_per_peer = 0;
    (void)libp2p_rsrc_set_limits_for_protocol(rm, &pl);
    (void)libp2p_host_set_resource_manager(host, rm);

    /* Two fake peers */
    peer_id_t p1 = {0}, p2 = {0};
    p1.bytes = (uint8_t *)malloc(4); p1.size = 4; memcpy(p1.bytes, "P1__", 4);
    p2.bytes = (uint8_t *)malloc(4); p2.size = 4; memcpy(p2.bytes, "P2__", 4);

    /* First admit should pass */
    int rc1 = libp2p_rsrc_admit_stream(host, &p1, TEST_PROTO_ID, 0);
    print_case("admit first inbound", rc1 == 0);
    if (rc1 != 0) { peer_id_destroy(&p1); peer_id_destroy(&p2); libp2p_host_free(host); return 1; }

    /* Second admit for same peer should fail (per-peer limit = 1) */
    int rc2 = libp2p_rsrc_admit_stream(host, &p1, TEST_PROTO_ID, 0);
    print_case("deny second inbound same peer", rc2 != 0);
    if (rc2 == 0) { libp2p_rsrc_release_stream(host, &p1, TEST_PROTO_ID, 0); libp2p_rsrc_release_stream(host, &p1, TEST_PROTO_ID, 0); peer_id_destroy(&p1); peer_id_destroy(&p2); libp2p_host_free(host); return 1; }

    /* Second admit from different peer should fail (total cap = 1) */
    int rc3 = libp2p_rsrc_admit_stream(host, &p2, TEST_PROTO_ID, 0);
    print_case("deny second inbound different peer due to total cap", rc3 != 0);
    if (rc3 == 0) { libp2p_rsrc_release_stream(host, &p2, TEST_PROTO_ID, 0); libp2p_rsrc_release_stream(host, &p1, TEST_PROTO_ID, 0); peer_id_destroy(&p1); peer_id_destroy(&p2); libp2p_host_free(host); return 1; }

    /* Release first, then admit from peer2 should succeed */
    libp2p_rsrc_release_stream(host, &p1, TEST_PROTO_ID, 0);
    int rc4 = libp2p_rsrc_admit_stream(host, &p2, TEST_PROTO_ID, 0);
    print_case("admit after release from another peer", rc4 == 0);
    if (rc4 != 0) { peer_id_destroy(&p1); peer_id_destroy(&p2); libp2p_host_free(host); return 1; }

    /* Cleanup */
    libp2p_rsrc_release_stream(host, &p2, TEST_PROTO_ID, 0);
    peer_id_destroy(&p1); peer_id_destroy(&p2);
    libp2p_host_free(host);
    return 0;
}
