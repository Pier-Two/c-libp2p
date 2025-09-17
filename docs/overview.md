# c-libp2p Overview

c-libp2p is a production-focused implementation of the libp2p networking stack
written in C. The modern API centers around a **host runtime** that takes care
of transports, secure channel negotiation, stream multiplexing, protocol
registration, and event delivery. This document highlights the major building
blocks and how the rest of the documentation fits together.

## Host-centric architecture

The `libp2p_host_t` type (see `include/libp2p/host.h`) encapsulates the runtime:

- Transports (TCP today, with hooks for QUIC and others)
- Security transports (Noise is built in) and stream multiplexers (Yamux and
  mplex) negotiated via multistream-select v1
- A single-threaded callback executor so user protocol callbacks always run in a
  predictable context
- Automatic Identify responders and Identify Push consumers that keep the
  peerstore updated
- An event bus that reports lifecycle changes such as new connections, new
  streams, and protocol updates

Hosts are usually constructed with the ergonomic builder in
`include/libp2p/host_builder.h` and then started with `libp2p_host_start()`.

## Key components

- **Peer identities** – Defined in `include/peer_id/*.h`. Helpers create IDs from
  protobuf-encoded keys, convert them to strings, and compare them safely. See
  [peer-id.md](peer-id.md).
- **Multiaddresses** – Utilities in
  `include/multiformats/multiaddr/multiaddr.h` parse and serialize self-
  describing addresses. They are used everywhere a remote endpoint is
  referenced. See [multiaddress.md](multiaddress.md).
- **Transports** – Implementations of the raw byte-pipe abstraction reside under
  `src/protocol/tcp` and are exposed through `include/libp2p/transport.h`. Hosts
  select the first transport that reports it can handle a given multiaddress.
  See [transports.md](transports.md).
- **Security + multiplexing** – Security transports and muxers are requested via
  host options or the builder API. The upgrader is no longer wired manually; the
  host performs the full pipeline automatically. Details live in
  [upgrading.md](upgrading.md).
- **Stream API** – Negotiated protocols surface as `libp2p_stream_t` objects.
  They provide POSIX-like read/write semantics plus deadline and callback
  helpers. Custom protocols register callbacks through
  `libp2p_protocol_def_t`. The Examples guide ties everything together.
- **Peerstore** – `include/libp2p/peerstore.h` offers a simple in-memory store
  for addresses, public keys, and supported protocols. The Identify service and
  Identify Push integration keep it populated.
- **Events and observability** – Subscribe via `libp2p_event_subscribe()` to
  receive connection, stream, and error notifications, or poll with
  `libp2p_host_next_event()`. Logging can be routed through
  `libp2p_log_set_writer()` and optional metrics counters live in
  `include/libp2p/metrics.h`.

## Built-in services

- **Identify responder** – Automatically answers `/ipfs/id/1.0.0` requests using
  the host’s configured identity and listen addresses.
- **Identify push** – Listens on `/ipfs/id/push/1.0.0` and updates the
  peerstore plus event stream whenever a remote peer advertises new metadata.
- **Ping helper** – `libp2p_ping_service_start()` registers a responder for
  `/ipfs/ping/1.0.0`, and `libp2p_ping_roundtrip_stream()` makes issuing a ping
  trivial once a stream is open.

## Navigating the documentation

A good reading order for the refreshed documentation is:

1. [building.md](building.md) – set up your build.
2. [peer-id.md](peer-id.md) – create and inspect peer identities.
3. [multiaddress.md](multiaddress.md) – manipulate multiaddresses.
4. [transports.md](transports.md) – understand raw transports and how hosts use them.
5. [upgrading.md](upgrading.md) – see how the host negotiates security and multiplexing.
6. [identify.md](identify.md) – learn how identity information propagates.
7. [ping.md](ping.md) – issue liveness checks and respond to probes.
8. [examples.md](examples.md) – assemble a minimal dialer and listener with the unified API.

Keep the `specs/` directory handy for the formal API reference and extended
rationales behind each subsystem.
