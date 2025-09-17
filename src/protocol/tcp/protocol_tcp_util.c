#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include "libp2p/log.h"

/*
 * Provide a weak fallback for libp2p_logf so protocol_tcp can link
 * independently of libp2p_unified. When the unified library is linked, its
 * strong definition in src/util/log.c overrides this weak one.
 */
#if defined(__APPLE__) || defined(__GNUC__)
__attribute__((weak)) void libp2p_logf(libp2p_log_level_t lvl, const char *fmt, ...)
{
    const char *prefix = "";
    switch (lvl)
    {
        case LIBP2P_LOG_ERROR: prefix = "[ERROR] "; break;
        case LIBP2P_LOG_WARN:  prefix = "[WARN ] "; break;
        case LIBP2P_LOG_INFO:  prefix = "[INFO ] "; break;
        case LIBP2P_LOG_DEBUG: prefix = "[DEBUG] "; break;
        case LIBP2P_LOG_TRACE: prefix = "[TRACE] "; break;
        default: break;
    }
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s%s\n", prefix, buf);
}
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "protocol/tcp/protocol_tcp_util.h"

/* ------------------------------------------------------------------------- */
/*  SIGPIPE-related helpers – skipped on Windows                             */
/* ------------------------------------------------------------------------- */

#ifndef _WIN32

static void ignore_sigpipe_init(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
}

void ignore_sigpipe_once(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, ignore_sigpipe_init);
}

inline int sigpipe_block(sigset_t *oldset)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    return pthread_sigmask(SIG_BLOCK, &set, oldset);
}

inline void sigpipe_restore(const sigset_t *oldset)
{
    if (oldset != NULL)
    {
        (void)pthread_sigmask(SIG_SETMASK, oldset, NULL);
    }
}

#endif /* !_WIN32 */

/**
 * @brief Set a file descriptor to non-blocking mode.
 *
 * @param fd The file descriptor to modify.
 * @return 0 on success, -1 on failure.
 */
int set_nonblocking(int fd)
{
#ifdef _WIN32
    u_long mode = 1;
    /* On Windows the socket descriptor is a SOCKET (uintptr_t).  The MinGW
       runtime lets us treat it as an int for POSIX compatibility, but
       ioctlsocket expects the native SOCKET type – cast accordingly. */
    SOCKET s = (SOCKET)fd;
    return ioctlsocket(s, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/**
 * @brief Percent-encode a network interface name for use in multiaddrs.
 *
 * @param iface The input interface name string.
 * @param out The output buffer to write the encoded string.
 * @param out_len The size of the output buffer.
 * @return Number of bytes written (excluding null terminator), or -1 on error.
 */
int pct_encode_iface(const char *iface, char *out, size_t out_len)
{
    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)iface; *p; ++p)
    {
        if (isalnum(*p) || *p == '_' || *p == '.' || *p == '-')
        {
            if (w + 1 >= out_len)
            {
                return -1;
            }
            out[w++] = (char)*p;
        }
        else
        {
            if (w + 3 >= out_len)
            {
                return -1;
            }
            static const char hex[] = "0123456789ABCDEF";
            out[w++] = '%';
            out[w++] = hex[*p >> 4];
            out[w++] = hex[*p & 0x0F];
        }
    }
    if (w >= out_len)
    {
        return -1;
    }
    out[w] = '\0';
    return (int)w;
}

/**
 * @brief Get the current monotonic time in milliseconds.
 *
 * @return The current monotonic time in milliseconds.
 */
uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/**
 * @brief Safely add seconds and nanoseconds to a struct timespec without
 *        overflowing time_t on 32‑bit systems (Y2038 problem).
 *
 * This helper saturates tv_sec at INT32_MAX when sizeof(time_t)==4 so that the
 * resulting absolute timeout passed to pthread_cond_timedwait() never exceeds
 * the maximum representable value.  On 64‑bit time_t the behaviour is a normal
 * saturating add with nanosecond carry.
 *
 * @param ts       Pointer to timespec to update.
 * @param add_sec  Seconds to add (non‑negative).
 * @param add_nsec Nanoseconds to add (non‑negative, < 1 000 000 000 expected).
 */
inline void timespec_add_safe(struct timespec *ts, int64_t add_sec, long add_nsec)
{
    /* normalize nanoseconds so tv_nsec is in [0, 1e9) */
    int64_t nsec_total = (int64_t)ts->tv_nsec + (int64_t)add_nsec;

    /* carry / borrow loop — executes at most twice in practice */
    while (nsec_total >= 1000000000LL)
    {
        nsec_total -= 1000000000LL;
        add_sec++;
    }
    while (nsec_total < 0)
    {
        nsec_total += 1000000000LL;
        add_sec--;
    }

    /* compute seconds with explicit overflow / underflow clamp */
    int64_t sec_total;
    if (add_sec > 0 && add_sec > INT64_MAX - (int64_t)ts->tv_sec)
    {
        /* positive overflow – saturate */
        sec_total = INT64_MAX;
        nsec_total = 999999999L;
    }
    else if (add_sec < 0 && add_sec < INT64_MIN - (int64_t)ts->tv_sec)
    {
        /* negative overflow (underflow) – saturate */
        sec_total = INT64_MIN;
        nsec_total = 0;
    }
    else
    {
        sec_total = (int64_t)ts->tv_sec + add_sec;
    }

    /* clamp to INT32 range on 32‑bit time_t to avoid Y2038 overflow/underflow */
    if (sizeof(time_t) == 4)
    {
        if (sec_total > INT32_MAX)
        {
            sec_total = INT32_MAX;
            nsec_total = 999999999L;
        }
        else if (sec_total < INT32_MIN)
        {
            sec_total = INT32_MIN;
            nsec_total = 0;
        }
    }

    ts->tv_sec = (time_t)sec_total;
    ts->tv_nsec = (long)nsec_total;
}

/**
 * @brief Checks if the given multicodec code corresponds to a transport protocol.
 *
 * Recognized transport protocols include UDP, QUIC, WebSockets, TLS, WebRTC, and related variants.
 *
 * @param code The multicodec protocol code to check.
 * @return true if the code is a known transport protocol, false otherwise.
 */
inline bool is_transport_code(uint64_t code)
{
    switch (code)
    {
        case MULTICODEC_UDP:               /* /udp */
        case MULTICODEC_QUIC_V1:           /* /quic-v1 */
        case MULTICODEC_WS:                /* /ws */
        case MULTICODEC_WSS:               /* /wss */
        case MULTICODEC_TLS:               /* /tls */
        case MULTICODEC_WEBRTC:            /* /webrtc */
        case MULTICODEC_WEBRTC_DIRECT:     /* /webrtc-direct */
        case MULTICODEC_WEBTRANSPORT:      /* /webtransport */
        case MULTICODEC_P2P_WEBRTC_STAR:   /* /p2p-webrtc-star */
        case MULTICODEC_P2P_WEBRTC_DIRECT: /* /p2p-webrtc-direct */
            return true;
        default:
            return false;
    }
}

/**
 * @brief Determines if the given multiaddress is a valid TCP address that this transport can handle.
 *
 * This function checks that the address contains a TCP protocol (optionally after an IP6 zone),
 * and does not contain any encapsulated transport protocols after TCP (such as QUIC, WebSockets, etc).
 *
 * @param addr The multiaddress to check.
 * @return true if the address is a valid TCP address for this transport, false otherwise.
 */
bool tcp_can_handle(const multiaddr_t *addr)
{
    /* defensive NULL check: reject NULL addresses early */
    if (addr == NULL)
    {
        return false;
    }

    size_t n = multiaddr_nprotocols(addr);
    if (n < 2)
    {
        return false;
    }

    /* find the index of the TCP protocol (skip an optional ip6zone) */
    size_t idx = 1;
    uint64_t code;
    if (multiaddr_get_protocol_code(addr, idx, &code) != 0)
    {
        return false;
    }

    if (code == MULTICODEC_IP6ZONE)
    {
        /* skip the zone protocol */
        idx++;
        if (idx >= n || multiaddr_get_protocol_code(addr, idx, &code) != 0)
        {
            return false;
        }
    }

    /* must now be TCP */
    if (code != MULTICODEC_TCP)
    {
        return false;
    }

    /* if there's a protocol after TCP, reject if it's an encapsulated transport */
    if (idx < n - 1)
    {
        uint64_t next;
        if (multiaddr_get_protocol_code(addr, idx + 1, &next) == 0 && is_transport_code(next))
        {
            return false;
        }
    }

    return true;
}

/**
 * @brief Map a socket option errno value to a libp2p_transport_err_t error code.
 *
 * @param errsv The errno value returned by a failed setsockopt/getsockopt call.
 * @return libp2p_transport_err_t The corresponding transport error code.
 */
libp2p_transport_err_t map_sockopt_errno(int errsv)
{
    switch (errsv)
    {
        case ENOPROTOOPT:
            return LIBP2P_TRANSPORT_ERR_SOCKOPT_OPT_NOT_SUPPORTED;
        case EACCES:
        case EPERM:
            return LIBP2P_TRANSPORT_ERR_SOCKOPT_PERMISSION;
        case EINVAL:
            return LIBP2P_TRANSPORT_ERR_SOCKOPT_INVALID_ARG;
        case ENOBUFS:
            return LIBP2P_TRANSPORT_ERR_SOCKOPT_NO_RESOURCES;
        default:
            return LIBP2P_TRANSPORT_ERR_SOCKOPT_OTHER_FAIL;
    }
}

/**
 * @brief Lock a pthread mutex or terminate on failure.
 *
 * Mirrors safe_mutex_unlock(): on any non‑zero return from
 * pthread_mutex_lock() the program aborts, because continuing while
 * assuming the mutex is owned would corrupt internal state or deadlock.
 *
 * @param mtx Pointer to the pthread_mutex_t to lock.
 * @return 0 on success (the only way it returns).
 */
int safe_mutex_lock(pthread_mutex_t *mtx)
{
    int rc = pthread_mutex_lock(mtx);
    if (rc != 0)
    {
        const char *detail;
        switch (rc)
        {
            case EINVAL:
                detail = "invalid or destroyed mutex";
                break;
            case EDEADLK:
                detail = "deadlock detected";
                break;
#ifdef EOWNERDEAD /* robust mutexes */
            case EOWNERDEAD:
                detail = "owner died – robust mutex";
                break;
            case ENOTRECOVERABLE:
                detail = "robust mutex unrecoverable";
                break;
#endif
            default:
                detail = "unknown reason";
                break;
        }
        LP_LOGE("TCP", "safe_mutex_lock(%p): %s (pthread_mutex_lock: %s)", (void *)mtx, detail, strerror(rc));
        abort();
    }
    return 0;
}

/**
 * @brief Unlock a pthread mutex or terminate on failure.
 *
 * On success the function returns 0.
 * If @p pthread_mutex_unlock() fails, the mutex is still locked and the
 * program cannot recover safely – continuing would dead‑lock other
 * threads.  The function therefore logs the error and calls @c abort().
 *
 * @param mtx Pointer to the pthread_mutex_t to unlock (must be owned by the
 *            calling thread).
 * @return 0 on success (this is the only way the function returns).
 * @note On error this function never returns.
 */
int safe_mutex_unlock(pthread_mutex_t *mtx)
{
    int rc = pthread_mutex_unlock(mtx);
    if (rc != 0)
    {
        const char *detail;
        switch (rc)
        {
            case EPERM:
                detail = "current thread does not own the mutex";
                break;
            case EINVAL:
                detail = "invalid mutex (uninitialised or destroyed)";
                break;
#ifdef EDEADLK
            case EDEADLK:
                detail = "deadlock detected";
                break;
#endif
            default:
                detail = "unknown reason";
                break;
        }

        LP_LOGE("TCP", "safe_mutex_unlock(%p): %s (pthread_mutex_unlock: %s)", (void *)mtx, detail, strerror(rc));
        abort(); /* cannot continue with a locked mutex */
    }
    return 0;
}

/**
 * @brief Atomically decrement the listener's reference count, with saturation at zero.
 *
 * This function performs a thread-safe, saturating decrement of the listener's
 * reference count. If the reference count is already zero, it returns 0 and does
 * not decrement further to avoid wraparound. Otherwise, it decrements the count
 * and returns the previous (non-zero) value.
 *
 * @param l Pointer to the libp2p_listener_t whose refcount to decrement.
 * @return The previous value of the refcount if non-zero, or 0 if already zero.
 */
unsigned listener_refcount_fetch_sub(libp2p_listener_t *l)
{
    unsigned cur = atomic_load_explicit(&l->refcount, memory_order_relaxed);

    /* saturating decrement: if already zero, return 0 to avoid wraparound. */
    for (;;)
    {
        if (cur == 0)
        {
            /* no references left; nothing to do. */
            return 0;
        }
        if (atomic_compare_exchange_weak_explicit(&l->refcount, &cur, cur - 1, memory_order_acq_rel, memory_order_relaxed))
        {
            return cur; /* previous non‑zero value */
        }
        /* cur now holds a fresh value – retry */
    }
}

/**
 * @brief Progressive back-off for CAS (compare-and-swap) contention.
 *
 * This function implements a progressive back-off strategy to reduce contention
 * when repeatedly failing a CAS operation. It uses processor pause instructions,
 * yields to the OS scheduler, and finally sleeps for increasing durations.
 *
 * @param attempts Pointer to a counter tracking the number of CAS attempts.
 */
inline void cas_backoff(_Atomic uint64_t *attempts)
{
    /* must receive a valid pointer even in release builds */
    if (attempts == NULL)
    {
        /* yield once to avoid tight spin and return */
        sched_yield();
        return;
    }

#ifndef NDEBUG
    assert(attempts && "cas_backoff: attempts pointer is NULL");
#endif

    /* atomically increment attempts, saturating at UINT64_MAX. */
    if (atomic_load_explicit(attempts, memory_order_relaxed) != UINT64_MAX)
    {
        /* increment atomically, but do not wrap past UINT64_MAX. */
        (void)atomic_fetch_add_explicit(attempts, 1, memory_order_relaxed);
    }

    uint64_t cur = atomic_load_explicit(attempts, memory_order_relaxed);

    /* yield to scheduler for the first 40 failed attempts. */
    if (cur <= 40)
    {
        sched_yield();
        return;
    }

    /* progressive nanosleep with unsigned arithmetic to avoid UB */
    const uint64_t base_ns = 50ULL * 1000ULL; /* 50 µs */

    /* compute shift without risking unsigned wrap when cur ≤ 40 */
    uint64_t over = (cur > 40) ? (cur - 40) : 0;
    uint64_t shift = over / 256; /* grow slowly */

    /* clamp exponent to prevent overflow */
    if (shift > 20)
    {
        shift = 20;
    }
    uint64_t ns_u = base_ns << shift; /* safe (unsigned) */

    /* cap total sleep to 1 ms */
    const uint64_t cap_ns = 1ULL * 1000ULL * 1000ULL;
    if (ns_u > cap_ns)
    {
        ns_u = cap_ns;
    }

    struct timespec ts = {.tv_sec = 0, .tv_nsec = (long)ns_u};

    /* fall back to sched_yield() if nanosleep fails for a non‑EINTR reason */
    if (nanosleep(&ts, NULL) != 0 && errno != EINTR)
    {
        sched_yield();
    }
}

/**
 * @brief Convert a multiaddr to a sockaddr_storage and its length.
 *
 * Supports /ip4/.../tcp/..., /ip6/.../tcp/..., /ip6/.../ip6zone/.../tcp/..., and /dns4|dns6/.../tcp/...
 *
 * @param addr The multiaddr to convert.
 * @param ss Output: sockaddr_storage to fill.
 * @param ss_len Output: length of the sockaddr_storage.
 * @return 0 on success, -1 on failure.
 */
int multiaddr_to_sockaddr(const multiaddr_t *addr, struct sockaddr_storage *ss, socklen_t *ss_len)
{
    if (!addr || !ss || !ss_len)
    {
        return -1;
    }

    const size_t n = multiaddr_nprotocols(addr);
    if (n < 2)
    {
        return -1;
    }

    uint64_t p0, p1;
    if (multiaddr_get_protocol_code(addr, 0, &p0) || multiaddr_get_protocol_code(addr, 1, &p1))
    {
        return -1;
    }

    if (p0 == MULTICODEC_IP4)
    {
        if (p1 != MULTICODEC_TCP)
        {
            return -1;
        }

        uint8_t ip[4];
        size_t ip_len = sizeof ip;
        if (multiaddr_get_address_bytes(addr, 0, ip, &ip_len) != MULTIADDR_SUCCESS || ip_len != 4)
        {
            return -1;
        }

        uint8_t pb[2];
        size_t pb_len = sizeof pb;
        if (multiaddr_get_address_bytes(addr, 1, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != 2)
        {
            return -1;
        }
        const uint16_t port_host = (uint16_t)((pb[0] << 8) | pb[1]);

        struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
        memset(v4, 0, sizeof *v4);
        v4->sin_family = AF_INET;
        memcpy(&v4->sin_addr, ip, 4);
        v4->sin_port = htons(port_host);

        *ss_len = sizeof *v4;
        return 0;
    }

    if (p0 == MULTICODEC_IP6)
    {
        uint8_t ip6[16];
        size_t ip6_len = sizeof ip6;
        if (multiaddr_get_address_bytes(addr, 0, ip6, &ip6_len) != MULTIADDR_SUCCESS || ip6_len != 16)
        {
            return -1;
        }

        size_t idx = 1;
        char zonebuf[IFNAMSIZ] = {0};

        uint64_t code;
        if (multiaddr_get_protocol_code(addr, idx, &code))
        {
            return -1;
        }

        if (code == MULTICODEC_IP6ZONE)
        {
            if (idx + 1 >= n)
            {
                return -1;
            }

            size_t zl = IFNAMSIZ - 1;
            if (multiaddr_get_address_bytes(addr, idx, (uint8_t *)zonebuf, &zl) != MULTIADDR_SUCCESS || zl == 0)
            {
                return -1;
            }
            zonebuf[zl] = '\0';
            idx++;

            if (multiaddr_get_protocol_code(addr, idx, &code) || code != MULTICODEC_TCP)
            {
                return -1;
            }
        }
        else if (code != MULTICODEC_TCP)
        {
            return -1;
        }

        if (idx + 1 >= n)
        {
            return -1;
        }

        uint8_t pb[2];
        size_t pb_len = sizeof pb;
        if (multiaddr_get_address_bytes(addr, idx + 1, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != 2)
        {
            return -1;
        }
        const uint16_t port_host = (uint16_t)((pb[0] << 8) | pb[1]);
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
        memset(v6, 0, sizeof *v6);
        v6->sin6_family = AF_INET6;
        memcpy(&v6->sin6_addr, ip6, 16);
        v6->sin6_port = htons(port_host);

        if (zonebuf[0])
        {
            v6->sin6_scope_id = if_nametoindex(zonebuf);
        }

        *ss_len = sizeof *v6;
        return 0;
    }

    if (p0 == MULTICODEC_DNS4 || p0 == MULTICODEC_DNS6)
    {
        if (p1 != MULTICODEC_TCP)
        {
            return -1;
        }

        uint8_t hostb[255];
        size_t hostb_len = sizeof hostb;
        if (multiaddr_get_address_bytes(addr, 0, hostb, &hostb_len) != MULTIADDR_SUCCESS || hostb_len == 0)
        {
            return -1;
        }

        char *host = malloc(hostb_len + 1);
        if (!host)
        {
            return -1;
        }
        memcpy(host, hostb, hostb_len);
        host[hostb_len] = '\0';

        uint8_t pb[2];
        size_t pb_len = sizeof pb;
        if (multiaddr_get_address_bytes(addr, 1, pb, &pb_len) != MULTIADDR_SUCCESS || pb_len != 2)
        {
            free(host);
            return -1;
        }
        char portstr[6];
        snprintf(portstr, sizeof portstr, "%u", (pb[0] << 8) | pb[1]);

        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = (p0 == MULTICODEC_DNS4 ? AF_INET : AF_INET6);

        if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        {
            free(host);
            return -1;
        }
        for (struct addrinfo *rp = res; rp; rp = rp->ai_next)
        {
            if (rp->ai_addrlen <= (socklen_t)sizeof *ss)
            {
                memcpy(ss, rp->ai_addr, rp->ai_addrlen);
                *ss_len = rp->ai_addrlen;
                freeaddrinfo(res);
                free(host);
                return 0;
            }
        }
        freeaddrinfo(res);
        free(host);
        return -1;
    }

    return -1;
}

/**
 * @brief Convert a sockaddr_storage to a multiaddr.
 *
 * Supports AF_INET and AF_INET6 (with optional scope).
 *
 * @param ss The sockaddr_storage to convert.
 * @param ss_len The length of the sockaddr_storage (unused).
 * @return Pointer to a new multiaddr_t on success, or NULL on failure.
 */
multiaddr_t *sockaddr_to_multiaddr(const struct sockaddr_storage *ss, socklen_t ss_len)
{
    (void)ss_len;

    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port;

    if (ss->ss_family == AF_INET)
    {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)ss;
        inet_ntop(AF_INET, &v4->sin_addr, ipstr, sizeof ipstr);
        port = ntohs(v4->sin_port);

        char buf[64];
        int n = snprintf(buf, sizeof buf, "/ip4/%s/tcp/%" PRIu16, ipstr, port);
        if (n < 0 || (size_t)n >= sizeof buf)
        {
            return NULL;
        }

        return multiaddr_new_from_str(buf, NULL);
    }

    if (ss->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)ss;
        inet_ntop(AF_INET6, &v6->sin6_addr, ipstr, sizeof ipstr);
        port = ntohs(v6->sin6_port);

        char zone_enc[3 * IFNAMSIZ + 1];
        const bool has_scope = v6->sin6_scope_id != 0;
        bool zone_ok = false;

        if (has_scope)
        {
            char zone_raw[IFNAMSIZ];
            if (if_indextoname(v6->sin6_scope_id, zone_raw) && pct_encode_iface(zone_raw, zone_enc, sizeof zone_enc) >= 0)
            {
                zone_ok = true;
            }
        }

        char buf[160];
        int n;

        if (zone_ok)
        {
            n = snprintf(buf, sizeof buf, "/ip6/%s/ip6zone/%s/tcp/%" PRIu16, ipstr, zone_enc, port);
        }
        else
        {
            n = snprintf(buf, sizeof buf, "/ip6/%s/tcp/%" PRIu16, ipstr, port);
        }

        if (n < 0 || (size_t)n >= sizeof buf)
        {
            return NULL;
        }

        return multiaddr_new_from_str(buf, NULL);
    }

    return NULL;
}
