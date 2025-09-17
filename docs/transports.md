# Transports

Transports are the lowest layer in c-libp2p. They provide raw, bidirectional
byte pipes and are oblivious to security, multiplexing, and protocol
negotiation. The host runtime selects and drives transports automatically, but
you can also use them directly for bespoke setups or testing.

## Built-in transport factories

`include/libp2p/transport.h` exposes convenience factories for the transports
shipped with the library:

```c
#include "libp2p/transport.h"

libp2p_transport_t *tcp = NULL;
if (libp2p_transport_tcp(&tcp) != 0) {
    /* TCP not available */
}
```

The helper returns a configured `libp2p_transport_t` whose virtual table matches
`include/transport/transport.h`. At runtime the host builder translates
transport names (for example `"tcp"`) into the corresponding factory calls and
stores the resulting handles on the host.

## Dialling and listening manually

Once you hold a `libp2p_transport_t`, you can open and accept raw connections
using multiaddresses:

```c
#include "multiformats/multiaddr/multiaddr.h"
#include "transport/connection.h"

int err = 0;
multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4001", &err);
libp2p_conn_t *conn = NULL;
if (libp2p_transport_dial(tcp, addr, &conn) != LIBP2P_TRANSPORT_OK) {
    /* handle failure */
}

/* When finished */
libp2p_conn_close(conn);
libp2p_conn_free(conn);
multiaddr_free(addr);
```

Listening follows the same pattern:

```c
libp2p_listener_t *lst = NULL;
if (libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK) {
    for (;;) {
        libp2p_conn_t *incoming = NULL;
        if (libp2p_listener_accept(lst, &incoming) == LIBP2P_TRANSPORT_OK) {
            /* upgrade or inspect the raw connection */
            libp2p_conn_close(incoming);
            libp2p_conn_free(incoming);
        }
    }
    libp2p_listener_close(lst);
    libp2p_listener_free(lst);
}
```

The host runtime wraps these primitives to perform security and muxer
negotiation automatically. Manual access is still useful for unit tests or when
building custom tooling.

## Integration with the host builder

The host builder converts high-level configuration into the appropriate
transport instances:

```c
#include "libp2p/host_builder.h"

libp2p_host_builder_t *b = libp2p_host_builder_new();
libp2p_host_builder_transport(b, "tcp");
libp2p_host_builder_listen_addr(b, "/ip4/0.0.0.0/tcp/4001");
/* add security + muxers, then build */
```

During operation the host picks the first registered transport whose
`can_handle()` callback returns true for the target multiaddress. This makes it
straightforward to add additional transports in the future without changing the
application-facing API.

## Implementing custom transports

Custom transports populate a `libp2p_transport_t` with a dispatch table
(`libp2p_transport_vtbl_t`). Provide thread-safe implementations of:

- `can_handle(const multiaddr_t *addr)`
- `dial(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_conn_t **out)`
- `listen(libp2p_transport_t *self, const multiaddr_t *addr, libp2p_listener_t **out)`
- `close` and `free`

See `src/protocol/tcp/protocol_tcp.c` for a reference implementation. As long as
your transport returns `libp2p_conn_t` handles that obey the connection API
(`libp2p_conn_read`, `libp2p_conn_write`, deadlines, etc.), the host and
upgrader stack will work unchanged.

## Timeouts and metrics

Hosts propagate dial timeouts from `libp2p_host_options_t` down to the transport
layer. The TCP factory also wires any host-level metrics sink into its internal
context so that byte counters and latency histograms are reported consistently.

Continue with [upgrading.md](upgrading.md) to see how the host layers security
and multiplexing on top of these raw connections.
