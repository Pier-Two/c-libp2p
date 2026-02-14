#ifndef LIBP2P_MULTIHASH_SHA3_COMPAT_H
#define LIBP2P_MULTIHASH_SHA3_COMPAT_H

#include <stddef.h>
#include <stdint.h>

/* Minimal SHA-3 API needed by multihash; avoids MSVC parsing issues in vendor header. */
void sha3_224(const uint8_t *src, size_t len, uint8_t *dst);
void sha3_256(const uint8_t *src, size_t len, uint8_t *dst);
void sha3_384(const uint8_t *src, size_t len, uint8_t *dst);
void sha3_512(const uint8_t *src, size_t len, uint8_t *dst);

#endif /* LIBP2P_MULTIHASH_SHA3_COMPAT_H */
