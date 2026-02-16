# Peer IDs

Peer IDs are now handled by a single opaque, heap-owned API in
`include/peer_id/peer_id.h`.

- `peer_id_t` is opaque.
- Constructors allocate `peer_id_t` objects.
- Callers must release objects with `peer_id_free()`.
- Public per-key helper headers are no longer part of the API surface.

## Constructors

Create IDs from protobuf keys, text, or raw multihash bytes:

```c
#include "peer_id/peer_id.h"

peer_id_t *pid = NULL;
peer_id_error_t rc = peer_id_new_from_public_key_pb(pub_pb, pub_pb_len, &pid);
if (rc != PEER_ID_OK) {
    /* handle error */
}

/* ... use pid ... */
peer_id_free(pid);
```

Available constructors:

- `peer_id_new_from_public_key_pb()`
- `peer_id_new_from_private_key_pb()`
- `peer_id_new_from_text()`
- `peer_id_new_from_multihash()`

## Ownership And Access

Use clone and accessor APIs instead of direct struct field access.

```c
peer_id_t *a = NULL;
peer_id_t *b = NULL;
const uint8_t *mh = NULL;
size_t mh_len = 0;

if (peer_id_new_from_text(text, &a) == PEER_ID_OK &&
    peer_id_clone(a, &b) == PEER_ID_OK &&
    peer_id_multihash_view(b, &mh, &mh_len) == PEER_ID_OK) {
    /* mh/mh_len points into b; do not free mh */
}

peer_id_free(b);
peer_id_free(a);
```

Use `peer_id_multihash_copy()` when the caller needs an owned byte buffer.

## Equality

`peer_id_equal(a, b)` performs constant-time comparison and returns `1` for
equal IDs and `0` otherwise.

## Text Parsing And Formatting

Input parsing is strict and spec-driven:

- Legacy form is accepted only for strings starting with `1` or `Qm`.
- Multibase-prefixed values are parsed strictly as CIDv1.
- CID checks enforce version `1`, codec `libp2p-key` (`0x72`), and valid multihash.
- No permissive CID-to-legacy fallback is applied.

Formatting:

- `peer_id_text_write(pid, PEER_ID_TEXT_LEGACY_BASE58, ...)`
- `peer_id_text_write(pid, PEER_ID_TEXT_CIDV1_BASE32, ...)`
- `peer_id_text_write_default(...)` emits legacy base58.

```c
char out[128];
size_t n = 0;

if (peer_id_text_write_default(pid, out, sizeof(out), &n) == PEER_ID_OK) {
    /* out contains a NUL-terminated string, n excludes the NUL byte */
}
```

## Public Key Derivation From Raw Private Keys

Use the unified helper to derive protobuf-encoded public keys from raw private
key bytes:

```c
uint8_t *pub_pb = NULL;
size_t pub_pb_len = 0;

peer_id_error_t rc = peer_id_public_key_pb_from_private_raw(
    PEER_ID_KEY_ED25519, raw_private, raw_private_len, &pub_pb, &pub_pb_len);
if (rc == PEER_ID_OK) {
    /* use pub_pb/pub_pb_len */
    free(pub_pb);
}
```

Supported key types:

- `PEER_ID_KEY_RSA`
- `PEER_ID_KEY_ED25519`
- `PEER_ID_KEY_SECP256K1`
- `PEER_ID_KEY_ECDSA`

## Notes

- Peer ID derivation follows the spec threshold rule exactly:
  protobuf public key length `<= 42` uses identity multihash; otherwise SHA2-256.
- See `tests/peer_id/test_peer_id.c` for conformance vectors, strict parse
  cases, deterministic protobuf checks, and ownership/error-path coverage.
