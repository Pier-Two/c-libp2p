#include "protocol/quic/protocol_quic.h"

#include "multiformats/multiaddr/multiaddr.h"

#include <stdio.h>
#include <stdlib.h>

static void print_result(const char *name, const char *details, int ok)
{
    if (ok)
        printf("TEST: %-70s | PASS\n", name);
    else
        printf("TEST: %-70s | FAIL: %s\n", name, details ? details : "");
}

static int failures = 0;

#define TEST_TRUE(name, cond, fmt, ...)                                                                                                             \
    do                                                                                                                                              \
    {                                                                                                                                               \
        if (cond)                                                                                                                                   \
            print_result(name, "", 1);                                                                                                             \
        else                                                                                                                                        \
        {                                                                                                                                           \
            char _msg[256];                                                                                                                         \
            snprintf(_msg, sizeof(_msg), fmt, ##__VA_ARGS__);                                                                                       \
            print_result(name, _msg, 0);                                                                                                            \
            failures++;                                                                                                                             \
        }                                                                                                                                           \
    } while (0)

static void run_case(libp2p_transport_t *transport, const char *name, const char *addr_str, int expect)
{
    multiaddr_t *addr = NULL;
    int err = MULTIADDR_SUCCESS;
    if (addr_str)
    {
        addr = multiaddr_new_from_str(addr_str, &err);
        char parse_label[128];
        snprintf(parse_label, sizeof(parse_label), "%s (parse)", name);
        TEST_TRUE(parse_label, addr != NULL && err == MULTIADDR_SUCCESS, "multiaddr_new err=%d", err);
        if (!addr || err != MULTIADDR_SUCCESS)
        {
            if (addr)
                multiaddr_free(addr);
            return;
        }
    }

    int actual = libp2p_transport_can_handle(transport, addr) ? 1 : 0;
    char match_label[128];
    snprintf(match_label, sizeof(match_label), "%s (match)", name);
    TEST_TRUE(match_label, actual == expect, "expected %d, got %d", expect, actual);

    if (addr)
        multiaddr_free(addr);
}

int main(void)
{
    libp2p_transport_t *transport = libp2p_quic_transport_new(NULL);
    TEST_TRUE("Instantiate QUIC transport", transport != NULL, "libp2p_quic_transport_new returned NULL");
    if (!transport)
        return 1;

    run_case(transport, "Null address", NULL, 0);
    run_case(transport, "IPv4 QUIC v1", "/ip4/127.0.0.1/udp/4001/quic_v1", 1);
    run_case(transport, "IPv4 QUIC legacy", "/ip4/127.0.0.1/udp/4001/quic", 1);
    run_case(transport, "IPv6 QUIC", "/ip6/::1/udp/4001/quic", 1);
    run_case(transport, "Trailing p2p allowed", "/ip4/203.0.113.9/udp/4444/quic_v1/p2p/12D3KooWK99", 1);
    run_case(transport, "Too few protocols", "/ip4/127.0.0.1/quic_v1", 0);
    run_case(transport, "Missing quic", "/ip4/127.0.0.1/udp/4001", 0);
    run_case(transport, "Wrong transport code", "/ip4/127.0.0.1/tcp/4001/quic_v1", 0);
    run_case(transport, "Disallow extra transport layering", "/ip4/127.0.0.1/udp/4001/quic/ws", 0);
    run_case(transport, "Disallow extra transport layering (wss)", "/ip4/127.0.0.1/udp/4001/quic_v1/wss", 0);
    run_case(transport, "Reject DNS addresses", "/dns4/example.com/udp/4001/quic_v1", 0);

    libp2p_transport_free(transport);

    if (failures == 0)
        print_result("QUIC can_handle multiaddr coverage", "", 1);
    else
        print_result("QUIC can_handle multiaddr coverage", "failures detected", 0);

    return failures == 0 ? 0 : 1;
}
