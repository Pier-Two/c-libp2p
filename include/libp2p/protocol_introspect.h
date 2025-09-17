/* Introspection helpers for local application protocols. */
#ifndef LIBP2P_PROTOCOL_INTROSPECT_H
#define LIBP2P_PROTOCOL_INTROSPECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct libp2p_host;

/*
 * Snapshot the host's currently registered local protocol IDs.
 *
 * Ownership and lifetime:
 * - Returns a heap-allocated array (the container) of `const char*` IDs.
 * - The array itself must be freed via `libp2p_host_free_supported_protocols()`.
 * - The `const char*` elements are BORROWED pointers into the host's internal
 *   registry; they are not duplicated. They remain valid while the host lives
 *   (or until their specific protocols are unregistered). Do not free them.
 *
 * Concurrency:
 * - This function is thread-safe; it takes an internal snapshot under the
 *   host's lock and returns the snapshot without requiring the caller to hold
 *   any locks.
 */
int libp2p_host_supported_protocols(const struct libp2p_host *host, const char ***out_ids, size_t *out_len);

/* Free the heap-allocated container returned by libp2p_host_supported_protocols(). */
void libp2p_host_free_supported_protocols(const char **ids, size_t len);

/* Optional: remote protocol listing using multistream-select "ls". Not implemented yet here. */
typedef void (*libp2p_on_protocol_list_fn)(const char *const *ids, size_t n, int err, void *ud);
int libp2p_protocol_ls(struct libp2p_host *host, const char *remote_multiaddr, libp2p_on_protocol_list_fn on_list, void *ud);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_INTROSPECT_H */
