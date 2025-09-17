# Ping Protocol

The ping protocol (`/ipfs/ping/1.0.0`) is a lightweight way to check whether a
peer is reachable and to measure round-trip latency. c-libp2p provides helpers
that operate on negotiated streams and optional services that reply to pings
without extra wiring.

## Dialling and measuring RTT

Use the host runtime to establish a stream to the remote ping service, then call
`libp2p_ping_roundtrip_stream()`:

```c
#include <inttypes.h>
#include <stdio.h>
#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/stream.h"
#include "protocol/ping/protocol_ping.h"

libp2p_host_builder_t *b = libp2p_host_builder_new();
libp2p_host_builder_transport(b, "tcp");
libp2p_host_builder_security(b, "noise");
libp2p_host_builder_muxer(b, "yamux");

libp2p_host_t *host = NULL;
libp2p_host_builder_build(b, &host);
libp2p_host_builder_free(b);

libp2p_stream_t *stream = NULL;
if (libp2p_host_dial_protocol_blocking(host, "/ip4/127.0.0.1/tcp/4001",
                                       LIBP2P_PING_PROTO_ID,
                                       5000 /* ms timeout */, &stream) == 0) {
    uint64_t rtt_ms = 0;
    if (libp2p_ping_roundtrip_stream(stream, 2000 /* ms */, &rtt_ms) == LIBP2P_PING_OK) {
        printf("ping RTT: %" PRIu64 " ms\n", rtt_ms);
    }
    libp2p_stream_close(stream);
}

libp2p_host_free(host);
```

`libp2p_ping_roundtrip_stream()` writes a 32-byte payload, waits for it to be
echoed back, and reports the latency. It is safe to call multiple times on the
same stream.

For asynchronous code paths, use `libp2p_host_dial_protocol()` and issue the
round-trip once the callback receives the stream handle.

## Serving ping requests

Register a responder so other peers can measure your availability:

```c
#include "libp2p/host.h"
#include "libp2p/protocol_listen.h"
#include "protocol/ping/protocol_ping.h"

libp2p_protocol_server_t *ping_server = NULL;
if (libp2p_ping_service_start(host, &ping_server) != 0) {
    /* fallback: register your own handler */
}
```

The helper registers `libp2p_ping_serve_stream()` for inbound streams and keeps
running until you call `libp2p_ping_service_stop(host, ping_server)`.

If you prefer to manage the lifecycle yourself, listen on the ping protocol
manually and forward incoming streams to `libp2p_ping_serve_stream()`:

```c
static void on_ping_stream(libp2p_stream_t *s, void *ud) {
    (void)ud;
    (void)libp2p_ping_serve_stream(s);
    libp2p_stream_close(s);
}

libp2p_protocol_def_t def = {
    .protocol_id = LIBP2P_PING_PROTO_ID,
    .read_mode = LIBP2P_READ_PULL,
    .on_open = on_ping_stream,
};
libp2p_host_listen_protocol(host, &def, NULL);
```

## Working at the connection layer

Legacy utilities still exist if you have a raw upgraded connection rather than a
`libp2p_stream_t`:

```c
libp2p_ping_roundtrip(conn, 2000 /* ms */, &rtt_ms);
libp2p_ping_serve(conn);
```

Streams are preferred in new code because they automatically carry the protocol
ID, peer metadata, and deadline helpers.

Combine ping with the event bus (see [overview.md](overview.md)) to surface
reachability information in your application or to drive reconnection logic.
