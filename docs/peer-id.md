# Peer Identities

Every libp2p node is identified by a **Peer ID**. In c-libp2p a Peer ID is the
multihash of a deterministically-encoded public key (protobuf `PublicKey`). The
helpers in `include/peer_id/*.h` cover key conversion, string encoding, and
memory management so that applications do not have to craft protobuf messages by
hand.

## Deriving a peer ID from protobuf keys

If you already have libp2p protobuf messages, call the generic helpers:

```c
#include "peer_id/peer_id.h"

peer_id_t pid = {0};
peer_id_error_t err = peer_id_create_from_public_key(pubkey_pb, pubkey_pb_len, &pid);
if (err != PEER_ID_SUCCESS) {
    /* handle failure */
}

/* ... use pid ... */
peer_id_destroy(&pid);
```

`peer_id_create_from_private_key()` performs the same operation but accepts a
protobuf `PrivateKey` message and derives the public key internally before
computing the multihash.

## Starting from raw private keys

Helpers for each supported key type export the corresponding protobuf `PublicKey`
bytes. Pass the output into `peer_id_create_from_public_key()` to obtain the
stable Peer ID.

```c
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_ed25519.h"

uint8_t secret[64] = { /* 32-byte seed + 32-byte public component */ };
uint8_t *pub_pb = NULL;
size_t pub_pb_len = 0;

if (peer_id_create_from_private_key_ed25519(secret, sizeof(secret), &pub_pb, &pub_pb_len) == PEER_ID_SUCCESS) {
    peer_id_t pid = {0};
    if (peer_id_create_from_public_key(pub_pb, pub_pb_len, &pid) == PEER_ID_SUCCESS) {
        /* pid.bytes now contains the canonical multihash */
        peer_id_destroy(&pid);
    }
    free(pub_pb);
}
```

Equivalent helpers exist for RSA, secp256k1, and ECDSA keys:

- `peer_id_create_from_private_key_rsa()` (DER-encoded PKCS#1)
- `peer_id_create_from_private_key_secp256k1()` (32-byte raw secret)
- `peer_id_create_from_private_key_ecdsa()` (ASN.1 DER private key)

Each helper returns a freshly allocated protobuf public key, making it easy to
support both protobuf-driven and raw-key workflows.

## Converting to and from text

Peer IDs are commonly exchanged in two textual forms. Use
`peer_id_create_from_string()` to accept either representation:

```c
peer_id_t pid = {0};
peer_id_create_from_string("bafybeigdyrzt...", &pid);  /* CIDv1 */
```

When emitting strings, choose a format explicitly:

```c
char out[128];
int n = peer_id_to_string(&pid, PEER_ID_FMT_BASE58_LEGACY, out, sizeof(out));
if (n >= 0) {
    printf("legacy form: %s\n", out);
}

n = peer_id_to_string(&pid, PEER_ID_FMT_MULTIBASE_CIDv1, out, sizeof(out));
if (n >= 0) {
    printf("CIDv1 form: %s\n", out);
}
```

The function returns the number of characters written (excluding the null
terminator) or a negative `peer_id_error_t` code on failure.

## Equality and lifetime management

`peer_id_equals()` compares two IDs in constant time. Destroy IDs with
`peer_id_destroy()` once they are no longer needed; this releases the multihash
buffer and zeroes the size field.

```c
peer_id_t a = {0}, b = {0};
/* ... initialise a and b ... */
if (peer_id_equals(&a, &b) == 1) {
    /* same peer */
}
peer_id_destroy(&a);
peer_id_destroy(&b);
```

## Using peer IDs with the host

Call `libp2p_host_set_private_key()` with a protobuf `PrivateKey` message to
install the local identity on a host. The host derives and caches the Peer ID,
propagates it to Noise handshakes, and makes it available via
`libp2p_host_get_peer_id()`. Remote IDs learned through Identify are stored in
the peerstore and surfaced through `libp2p_host_peer_protocols()` and related
helpers.

Consult the peer ID tests in `tests/peer_id/test_peer_id.c` for additional usage
patterns and error handling scenarios.
