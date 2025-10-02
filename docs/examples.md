# Example Host, Listener, and Dialer

The unified API wires transports, security, multiplexing, and protocol
negotiation through a single `libp2p_host_t`. This guide walks through two small
programs that use the public headers only: a listener that echoes any payload it
receives, and a dialer that connects to it.

Both snippets are intentionally compact; consult `examples/unified_echo.c` and
the tests under `tests/host/` for production-style patterns with fuller error
handling.

## Listener with a custom protocol

```c
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/protocol_listen.h"
#include "libp2p/stream.h"

#define ECHO_PROTO "/example/echo/1.0.0"

static volatile int keep_running = 1;
static void handle_sigint(int sig) { (void)sig; keep_running = 0; }

static void echo_on_open(libp2p_stream_t *s, void *user_data)
{
    (void)user_data;
    printf("stream opened by %s\n", libp2p_stream_protocol_id(s));
}

static void echo_on_data(libp2p_stream_t *s, const uint8_t *data, size_t len, void *user_data)
{
    (void)user_data;
    (void)libp2p_stream_write(s, data, len);  /* echo back */
}

static void echo_on_close(libp2p_stream_t *s, void *user_data)
{
    (void)user_data;
    printf("stream closed for protocol %s\n", libp2p_stream_protocol_id(s));
    libp2p_stream_close(s);
}

int main(void)
{
    signal(SIGINT, handle_sigint);

    libp2p_host_builder_t *builder = libp2p_host_builder_new();
    libp2p_host_builder_listen_addr(builder, "/ip4/127.0.0.1/tcp/4001");
    /* Use /ip4/127.0.0.1/udp/4001/quic_v1 when exposing QUIC */
    libp2p_host_builder_transport(builder, "tcp");
    /* Add libp2p_host_builder_transport(builder, "quic") to accept QUIC */
    libp2p_host_builder_security(builder, "noise");
    libp2p_host_builder_muxer(builder, "yamux");

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(builder, &host) != 0) {
        fprintf(stderr, "failed to build host\n");
        return 1;
    }
    libp2p_host_builder_free(builder);

    libp2p_protocol_def_t echo_def = {
        .protocol_id = ECHO_PROTO,
        .read_mode = LIBP2P_READ_PUSH,
        .on_open = echo_on_open,
        .on_data = echo_on_data,
        .on_close = echo_on_close,
    };
    libp2p_protocol_server_t *echo_server = NULL;
    if (libp2p_host_listen_protocol(host, &echo_def, &echo_server) != 0) {
        fprintf(stderr, "failed to register echo handler\n");
        libp2p_host_free(host);
        return 1;
    }

    if (libp2p_host_start(host) != 0) {
        fprintf(stderr, "failed to start host\n");
        libp2p_host_free(host);
        return 1;
    }

    printf("listening on /ip4/127.0.0.1/tcp/4001\n");
    printf("press Ctrl+C to stop...\n");

    while (keep_running) {
        libp2p_event_t evt = {0};
        if (libp2p_host_next_event(host, 500 /* ms */, &evt) == 0) {
            if (evt.kind == LIBP2P_EVT_CONN_OPENED) {
                printf("connection opened from %s\n", evt.u.conn_opened.addr);
            }
            libp2p_event_free(&evt);
        }
    }

    libp2p_host_stop(host);
    libp2p_host_unlisten(host, echo_server);
    libp2p_host_free(host);
    return 0;
}
```

Highlights:

- The listener is configured entirely through the host builder.
- The protocol definition uses `LIBP2P_READ_PUSH`, so the host invokes
  `echo_on_data()` whenever bytes arrive. For pull-style processing, set the
  `read_mode` to `LIBP2P_READ_PULL` and call `libp2p_stream_read()` manually.
- Events are polled with a timeout to keep the example simple. Real projects can
  subscribe for asynchronous delivery via `libp2p_event_subscribe()`.

- Enable QUIC by registering the transport (`libp2p_host_builder_transport(builder, "quic")`) and switching the listen multiaddr to `/udp/.../quic_v1`.

## Dialer targeting the echo service

```c
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/stream.h"

#define ECHO_PROTO "/example/echo/1.0.0"

int main(int argc, char **argv)
{
    const char *target = (argc > 1) ? argv[1] : "/ip4/127.0.0.1/tcp/4001";
    /* Swap the default for /ip4/127.0.0.1/udp/4001/quic_v1 to dial QUIC */

    libp2p_host_builder_t *builder = libp2p_host_builder_new();
    libp2p_host_builder_transport(builder, "tcp");
    /* Call again with "quic" to favour QUIC dialing */
    libp2p_host_builder_security(builder, "noise");
    libp2p_host_builder_muxer(builder, "yamux");

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(builder, &host) != 0) {
        fprintf(stderr, "failed to build host\n");
        return 1;
    }
    libp2p_host_builder_free(builder);

    libp2p_stream_t *stream = NULL;
    if (libp2p_host_dial_protocol_blocking(host, target, ECHO_PROTO, 5000, &stream) != 0 || !stream) {
        fprintf(stderr, "dial failed\n");
        libp2p_host_free(host);
        return 1;
    }

    const char payload[] = "hello from c-libp2p";
    if (libp2p_stream_write(stream, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) {
        fprintf(stderr, "write failed\n");
    }

    char buf[64] = {0};
    ssize_t n = libp2p_stream_read(stream, buf, sizeof(buf));
    if (n > 0) {
        printf("received %zd bytes: %.*s\n", n, (int)n, buf);
    }

    libp2p_stream_close(stream);
    libp2p_host_free(host);
    return 0;
}
```

The dialer builds an outbound-only host, requests the echo protocol, writes a
message, and reads the echoed payload. In asynchronous setups you can use
`libp2p_host_dial_protocol()` instead of the blocking variant—your callback will
run on the host’s single-threaded executor.

## Next steps

- Add Identify support by calling `libp2p_host_set_private_key()` before
  `libp2p_host_start()` so peers learn your identity immediately.
- Register the ping responder with `libp2p_ping_service_start()` and monitor
  `LIBP2P_EVT_STREAM_OPENED` events to log inbound probes.
- Explore `libp2p_host_listen_selected()` and `libp2p_host_dial_selected()` for
  prefix and semantic-version protocol matching when supporting a family of
  protocol versions.

Use the unit tests under `tests/host/` and the specification documents in
`specs/` as additional references while building your own host applications.
