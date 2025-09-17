#ifndef PROTOCOL_TCP_UTIL_H
#define PROTOCOL_TCP_UTIL_H

/**
 * @file protocol_tcp_util.h
 * @brief Utility helpers shared across the TCP implementation.
 */

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "transport/listener.h"
#include "transport/transport.h"

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief SIGPIPE helpers */
/** Ignore SIGPIPE for a single operation. */
void ignore_sigpipe_once(void);

/** Block SIGPIPE and store the old signal mask. Returns 0 on success. */
int sigpipe_block(sigset_t *oldset);

/** Restore a signal mask saved by sigpipe_block(). */
void sigpipe_restore(const sigset_t *oldset);

/** @brief Small helper utilities */
/** Set a file descriptor to non-blocking mode. */
int set_nonblocking(int fd);

/** Percent-encode an interface name into @p out. */
int pct_encode_iface(const char *iface, char *out, size_t out_len);

/** Return the current monotonic time in milliseconds. */
uint64_t now_mono_ms(void);

/** Add seconds and nanoseconds safely to a timespec. */
void timespec_add_safe(struct timespec *ts, int64_t add_sec, long add_nsec);

/** @brief Address-classification helpers */
/** Check if a multicodec represents a transport. */
bool is_transport_code(uint64_t code);

/** Determine whether the TCP transport can handle the given address. */
bool tcp_can_handle(const multiaddr_t *addr);

/** @brief errno to transport-error helper */
/** Map a socket errno to a libp2p_transport_err_t code. */
libp2p_transport_err_t map_sockopt_errno(int errsv);

/** @brief Fatal-on-error mutex helpers */
/** Acquire a mutex or abort on failure. */
int safe_mutex_lock(pthread_mutex_t *mtx);

/** Release a mutex or abort on failure. */
int safe_mutex_unlock(pthread_mutex_t *mtx);

/** @brief Lock-free helpers */
/** Backoff loop for failed CAS operations (may be NULL). */
void cas_backoff(_Atomic uint64_t *attempts);

/** Atomically decrement a listener refcount (saturating). */
unsigned listener_refcount_fetch_sub(libp2p_listener_t *l);

/** @brief multiaddr ↔ sockaddr helpers */
/** Convert a multiaddr to a sockaddr structure. */
int multiaddr_to_sockaddr(const multiaddr_t *maddr, struct sockaddr_storage *ss, socklen_t *ss_len);

/** Convert a sockaddr structure to a newly allocated multiaddr. */
multiaddr_t *sockaddr_to_multiaddr(const struct sockaddr_storage *ss, socklen_t ss_len);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_TCP_UTIL_H */
