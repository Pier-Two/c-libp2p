# Connection Upgrading

Upgrading turns a raw transport connection into something that can carry secure,
multiplexed streams. In the unified API the **host runtime** drives the entire
upgrade pipeline; applications no longer assemble an upgrader manually. This
document explains what happens behind the scenes and how to tune the process.

## Upgrade stages

Whenever you dial with `libp2p_host_dial_protocol()` (or accept an inbound
connection), the host executes the following steps:

1. **Transport dial** – Pick the first configured transport that reports it can
   handle the target multiaddress and establish a raw `libp2p_conn_t`.
2. **Security negotiation** – Run the chosen security transport (Noise by
   default) to authenticate the remote peer and encrypt the stream.
3. **Multiplexer negotiation** – Select a stream multiplexer (Yamux is the
   default) and create a `libp2p_stream_t` abstraction on top of it.
4. **Protocol negotiation** – If you requested a protocol ID, the host performs
   multistream-select v1 to enter that protocol and passes the resulting stream
to your callback.

This mirrors the libp2p reference architecture, but the host makes it a single
atomic operation with a clear timeout budget.

## Configuring proposals and timeouts

Use either `libp2p_host_options_t` or the builder helpers to customise each
stage:

```c
libp2p_host_builder_t *b = libp2p_host_builder_new();
libp2p_host_builder_transport(b, "tcp");
libp2p_host_builder_security(b, "noise");          /* ordered proposals */
libp2p_host_builder_muxer(b, "yamux");             /* fall back to mplex if added */
libp2p_host_builder_multistream(b, 10000, true);    /* ms-select timeout + enable "ls" */
libp2p_host_builder_max_conns(b, 128, 128);         /* limit inbound/outbound connections */
libp2p_host_builder_per_conn_stream_caps(b, 32, 32);
```

Call `libp2p_host_builder_transport(b, "quic")` as well if you want the host to consider QUIC addresses during dialing and listening.

All of these setters copy their arguments, so you can free any temporary arrays
once the builder call returns.

The lower-level `libp2p_host_options_t` structure exposes the same fields plus
explicit slots for dial and handshake timeouts (`dial_timeout_ms` and
`handshake_timeout_ms`). Call `libp2p_host_options_default()` to seed sensible
values before tweaking them.

## Inspecting negotiated streams

Once a dial succeeds you receive a `libp2p_stream_t *`. The stream carries the
Negotiated protocol ID (`libp2p_stream_protocol_id()`), local/remote multiaddr,
and the authenticated peer ID. Use the stream API in `include/libp2p/stream.h`
to read, write, set deadlines, and register readability callbacks.

If you need to defer protocol selection, dial without a protocol ID and call
`libp2p_host_open_stream()` later using cached peerstore addresses. That function
reuses existing upgraded connections when possible, falling back to a fresh dial
if necessary.

## Advanced: manual control

While strongly recommended for application code, the host orchestrator is not
mandatory. If you need absolute control—for example when developing a new
transport or security handshake—you can still instantiate security transports,
muxers, and the upgrader directly. Include the abstract interfaces from
`include/libp2p/security.h` and `include/libp2p/muxer.h`, then opt into
factories such as `include/libp2p/security_noise.h` and
`include/libp2p/muxer_yamux.h` as needed alongside `transport/upgrader.h`.
This is exactly what the host does internally.

Manual upgrades resemble the older workflow:

```c
libp2p_security_t *noise = NULL;
libp2p_muxer_t *yamux = NULL;
libp2p_security_noise(&noise);
libp2p_muxer_yamux(&yamux);
libp2p_upgrader_t *up = libp2p_upgrader_new(...);
libp2p_upgraded_conn_t *uconn = NULL;
libp2p_upgrader_upgrade_outbound(up, raw_conn, NULL, &uconn);
```

Most users should prefer the host APIs, but the lower-level primitives remain
available for experimentation and integration tests.

## Connection lifecycle events

The host publishes upgrade progress through the event bus:

- `LIBP2P_EVT_DIALING` – a dial attempt has started.
- `LIBP2P_EVT_PROTOCOL_NEGOTIATED` – the multistream-select handshake completed.
- `LIBP2P_EVT_CONN_OPENED` / `LIBP2P_EVT_CONN_CLOSED` – connection lifecycle.
- `LIBP2P_EVT_STREAM_OPENED` / `LIBP2P_EVT_STREAM_CLOSED` – stream lifecycle.
- `LIBP2P_EVT_OUTGOING_CONNECTION_ERROR` – dial or handshake failure (error code
 and message included).

Subscribe with `libp2p_event_subscribe()` or poll via
`libp2p_host_next_event()` to observe and react to these transitions.

> **Note**
> QUIC multiaddresses (`/ip*/.../udp/.../quic-v1`) bundle TLS 1.3 and stream
> multiplexing directly into the transport. When the host detects such an
> address it executes the transport dial and protocol negotiation stages, but
> skips the separate Noise and Yamux/Mplex steps described above. This keeps the
> upgrading pipeline consistent while letting QUIC act as a fully upgraded
> session.

## Protocol selection utilities

For more elaborate negotiation rules, combine the upgrader with the protocol
selector/listener helpers:

- `libp2p_host_dial_selected()` accepts a `libp2p_proto_selector_t` describing
  exact IDs, lists, prefixes, or semantic version ranges.
- `libp2p_host_listen_selected()` pairs a listener configuration with a
  `libp2p_protocol_def_t` to serve multiple protocol variants from one
  implementation.

These helpers use the same upgrading pipeline; they simply give you richer
matching semantics once the secure channel and multiplexed session are in place.

With the upgrade process demystified, continue to [identify.md](identify.md) to
see how peer metadata flows across upgraded connections.
