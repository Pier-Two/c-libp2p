# Identify Protocol

libp2p nodes exchange metadata such as supported protocols, listen addresses,
and public keys through the **Identify** protocol (`/ipfs/id/1.0.0`). The modern
c-libp2p host wires a responder automatically and integrates Identify Push
updates so the peerstore always reflects the latest information. This guide
shows how to work with those pieces from application code.

## Local identity and automatic behaviour

Install your node identity before calling `libp2p_host_start()`:

```c
#include "libp2p/host.h"

/* protobuf-encoded PrivateKey message */
if (libp2p_host_set_private_key(host, privkey_pb, privkey_len) != 0) {
    /* handle error */
}
```

The host derives the local Peer ID, configures Noise to authenticate with this
identity, and responds to `/ipfs/id/1.0.0` automatically. Two host flags control
additional behaviour:

- `LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND` (default) issues an Identify request
after a successful outbound dial.
- `LIBP2P_HOST_F_AUTO_IDENTIFY_INBOUND` triggers a request when an inbound
connection completes its handshake.

Set the flags via `libp2p_host_builder_flags()` or by filling `libp2p_host_options_t`.

## Requesting metadata on demand

For explicit Identify requests—e.g. to refresh cached information or when auto
Identify is disabled—use the controller in `include/libp2p/identify.h`:

```c
#include "libp2p/identify.h"

libp2p_identify_service_t *identify = NULL;
libp2p_identify_new(host, NULL, &identify);

peer_id_t *remote = NULL;
libp2p_host_get_peer_id(other_host, &remote); /* example source */

if (libp2p_identify_request(identify, remote) == 0) {
    /* peerstore now holds the fresh metadata */
}

libp2p_identify_ctrl_free(identify);
peer_id_destroy(remote);
```

`libp2p_identify_request()` opens a stream using the peerstore addresses, waits
for the Identify response, decodes it, and updates the host’s peerstore with the
remote public key, listen addresses, and protocol list. The host also publishes a
`LIBP2P_EVT_PEER_PROTOCOLS_UPDATED` event whenever these details change.

## Consuming Identify Push updates

Peers that implement [Identify Push](https://github.com/libp2p/specs/tree/master/identify)
announce changes on `/ipfs/id/push/1.0.0`. The host registers a listener for
that protocol and handles decoding automatically. Incoming updates:

- Store advertised listen addresses in the peerstore
- Refresh the set of supported protocols
- Surface the observed address through `LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER`
  events so applications can adjust reachability heuristics

Subscribe to events or inspect the peerstore directly to track these changes.

## Customising responses (advanced)

`libp2p_identify_encode_local()` prepares the protobuf payload the host uses to
answer Identify requests. You can call it yourself when implementing a custom
response handler or when you need to inspect the exact bytes sent on the wire.
To replace the default responder entirely, unregister the built-in server with
`libp2p_identify_service_stop()` and register your own protocol handler via
`libp2p_host_listen_protocol()`.

## Related tooling

- `libp2p_host_peer_protocols()` returns the cached list of protocol IDs for a
  peer (as populated by Identify).
- `libp2p_host_supported_protocols()` exposes local protocol registrations so
  you can include them in Identify responses or diagnostics.
- `LIBP2P_EVT_LOCAL_PROTOCOLS_UPDATED` announces when the set of local
  protocols changes, making it easy to trigger Identify Push announcements.

Combine Identify with the [event bus](overview.md) and peerstore to build a
complete view of the network, and see [examples.md](examples.md) for end-to-end
usage inside a host application.
