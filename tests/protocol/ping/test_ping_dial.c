#include <noise/protocol.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/stream.h"
#include "protocol/ping/protocol_ping.h"

// Constants for test configuration
#define WAIT_TIMEOUT_SECONDS 30
#define RESPONSE_TIMEOUT_SECONDS 5
#define WAIT_INTERVAL_MS 10
#define RESPONSE_WAIT_ITERATIONS_PER_SECOND 100

// Structure to hold ping test context
typedef struct
{
    int ping_completed;
    uint64_t rtt;
    int result;
} test_ping_ctx_t;

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <multiaddr>\n", argv[0]);
        return 1;
    }

    logmsg("=== Ping Protocol Test (Unified API) ===\n");
    logmsg("connecting to: %s\n", argv[1]);

    libp2p_host_builder_t *builder = libp2p_host_builder_new();
    if (!builder)
        return 1;
    (void)libp2p_host_builder_transport(builder, "tcp");
    (void)libp2p_host_builder_security(builder, "noise");
    (void)libp2p_host_builder_muxer(builder, "yamux");
    (void)libp2p_host_builder_multistream(builder, 5000, false);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(builder, &host) != 0 || !host)
    {
        libp2p_host_builder_free(builder);
        return 1;
    }

    libp2p_stream_t *s = NULL;
    if (libp2p_host_dial_protocol_blocking(host, argv[1], LIBP2P_PING_PROTO_ID, WAIT_TIMEOUT_SECONDS * 1000, &s) != 0 || !s)
    {
        fprintf(stderr, "ping dial failed\n");
        libp2p_host_free(host);
        libp2p_host_builder_free(builder);
        return 1;
    }

    uint8_t payload[32] = {0};
    noise_randstate_generate_simple(payload, sizeof(payload));

    if ((ssize_t)sizeof(payload) != libp2p_stream_write(s, payload, sizeof(payload)))
    {
        fprintf(stderr, "write failed\n");
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        libp2p_host_free(host);
        libp2p_host_builder_free(builder);
        return 1;
    }

    uint8_t echo[32] = {0};
    size_t got = 0;
    for (int i = 0; i < RESPONSE_TIMEOUT_SECONDS * RESPONSE_WAIT_ITERATIONS_PER_SECOND; i++)
    {
        ssize_t n = libp2p_stream_read(s, echo + got, sizeof(echo) - got);
        if (n > 0)
        {
            got += (size_t)n;
            if (got == sizeof(echo))
                break;
        }
        else if (n == -5)
        {
            usleep(1000 * WAIT_INTERVAL_MS);
        }
        else if (n == 0)
        {
            usleep(1000 * WAIT_INTERVAL_MS);
        }
        else
        {
            usleep(1000 * WAIT_INTERVAL_MS);
        }
    }

    int ok = (got == sizeof(echo) && memcmp(payload, echo, sizeof(echo)) == 0);
    libp2p_stream_close(s);
    libp2p_stream_free(s);
    libp2p_host_free(host);
    libp2p_host_builder_free(builder);

    logmsg("=== Test completed ===\n");
    return ok ? 0 : 1;
}
