# Multiaddress Usage

Multiaddresses provide a self-describing way to express how to reach a peer.
Every transport and dial operation in c-libp2p accepts the canonical multiaddr
format. The helpers in `include/multiformats/multiaddr/multiaddr.h` cover parsing,
serialization, inspection, and composition.

## Creating multiaddresses

```c
#include "multiformats/multiaddr/multiaddr.h"

int err = 0;
multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4001", &err);
if (!addr || err != MULTIADDR_SUCCESS) {
    /* handle parse error */
}

multiaddr_t *quic = multiaddr_new_from_str("/ip4/127.0.0.1/udp/4001/quic-v1", &err);
if (!quic || err != MULTIADDR_SUCCESS) {
    /* QUIC multiaddress parse error */
}
```

Binary multiaddr bytes received over the network can be parsed with
`multiaddr_new_from_bytes()`:

```c
const uint8_t raw[] = { /* varint <proto><addr>... */ };
multiaddr_t *decoded = multiaddr_new_from_bytes(raw, sizeof(raw), &err);
```

`multiaddr_copy()` performs a deep clone when you need to keep your own copy of
an address object.

## Converting to strings and bytes

`multiaddr_to_str()` returns a newly allocated, human-readable string:

```c
int s_err = 0;
char *s = multiaddr_to_str(addr, &s_err);
printf("listening on %s\n", s);
free(s);
```

To serialize back into bytes, use `multiaddr_get_bytes()`:

```c
uint8_t buffer[64];
int written = multiaddr_get_bytes(addr, buffer, sizeof(buffer));
if (written < 0) {
    /* negative values are multiaddr_error_t codes */
}
```

## Inspecting components

A multiaddress is a stack of protocol components. Query its shape with:

```c
size_t count = multiaddr_nprotocols(addr);
for (size_t i = 0; i < count; ++i) {
    uint64_t code = 0;
    if (multiaddr_get_protocol_code(addr, i, &code) == 0) {
        /* compare against MULTIADDR_TCP, MULTIADDR_IP4, etc. */
    }
}
```

`multiaddr_get_address_bytes()` copies the raw address portion for a given
component into a caller-provided buffer.

## Composing addresses

Multiaddresses can be composed and decomposed without touching strings:

```c
int m_err = 0;
multiaddr_t *tcp = multiaddr_new_from_str("/tcp/4001", &m_err);
multiaddr_t *combined = multiaddr_encapsulate(addr, tcp, &m_err);  /* /ip4/.../tcp/... */

multiaddr_t *base = multiaddr_decapsulate(combined, tcp, &m_err);   /* back to /ip4/... */
```

Remember to free every address you allocate:

```c
multiaddr_free(addr);
multiaddr_free(tcp);
multiaddr_free(combined);
multiaddr_free(base);
```

## Multiaddresses and the host

The host builder and all dialing APIs accept multiaddresses as strings. During a
connection attempt the host parses the string once and then lets each configured
transport test whether it can handle the resulting object.

`LIBP2P_EVT_LISTEN_ADDR_ADDED` and related events carry canonical multiaddr
strings so that applications can surface them directly or transform them back
into binary form with `multiaddr_new_from_str()`.

Refer to the [transports](transports.md) guide to see multiaddresses in action,
and consult the libp2p [addressing specification](../specs/addressing/README.md)
for the full codec catalogue.
