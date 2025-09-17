#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "libp2p/host.h"
#include "libp2p/events.h"
#include "libp2p/host_builder.h"
#include "libp2p/stream.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/ping/protocol_ping.h"
#include "libp2p/log.h"

#ifndef NOW_MONO_MS_DECLARED
static inline uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}
#endif

/* Hard-coded private key (protobuf) for interop runs.
 * Taken from tests/host/test_host_identity.c (secp256k1).
 * Hex encoding of PrivateKey protobuf. */
/* Use an ED25519 PrivateKey protobuf to maximise interop with rust-libp2p
 * default builds (which often disable secp256k1 by default). */
#define ED25519_PRIVATE_HEX "080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return NULL;
    size_t n = hex_len / 2;
    uint8_t *buf = (uint8_t *)malloc(n);
    if (!buf)
        return NULL;
    for (size_t i = 0; i < n; i++)
    {
        char b[3] = {hex[2 * i], hex[2 * i + 1], '\0'};
        buf[i] = (uint8_t)strtol(b, NULL, 16);
    }
    if (out_len)
        *out_len = n;
    return buf;
}

static int redis_connect(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0)
    {
        freeaddrinfo(res);
        return -1;
    }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0)
    {
        freeaddrinfo(res);
        close(fd);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int redis_send(int fd, const char *cmd)
{
    size_t len = strlen(cmd);
    const char *p = cmd;
    ssize_t n;
    while (len)
    {
        n = send(fd, p, len, 0);
        if (n <= 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int redis_read_line(int fd, char *buf, size_t max)
{
    size_t pos = 0;
    char c;
    while (pos + 1 < max)
    {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0)
            return -1;
        buf[pos++] = c;
        if (c == '\n')
            break;
    }
    buf[pos] = 0;
    return (int)pos;
}

static int redis_rpush(int fd, const char *key, const char *val)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "*3\r\n$5\r\nRPUSH\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n", strlen(key), key, strlen(val), val);
    LP_LOGD("INTEROP", "Redis RPUSH command: %s", cmd);
    if (redis_send(fd, cmd) != 0)
    {
        LP_LOGD("INTEROP", "redis_send failed");
        return -1;
    }
    char line[128];
    int bytes_read = redis_read_line(fd, line, sizeof(line));
    LP_LOGD("INTEROP", "Redis response: bytes_read=%d, line=%s", bytes_read, bytes_read > 0 ? line : "NULL");
    if (bytes_read <= 0)
    {
        LP_LOGD("INTEROP", "redis_read_line failed");
        return -1;
    }
    int result = line[0] == ':' ? 0 : -1;
    LP_LOGD("INTEROP", "Redis RPUSH result: %d (line[0]='%c')", result, line[0]);
    return result;
}

static char *redis_blpop(int fd, const char *key, int timeout_sec)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "*3\r\n$5\r\nBLPOP\r\n$%zu\r\n%s\r\n$%d\r\n%d\r\n", strlen(key), key, (int)snprintf(NULL, 0, "%d", timeout_sec),
             timeout_sec);
    if (redis_send(fd, cmd) != 0)
        return NULL;
    char line[256];
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL;
    if (line[0] != '*')
        return NULL;
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL; // key bulk
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL; // key value
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL;          // value bulk header
    int len = atoi(line + 1); // skip '$'
    char *val = malloc((size_t)len + 1);
    if (!val)
        return NULL;
    size_t got = 0;
    while (got < (size_t)len)
    {
        ssize_t n = recv(fd, val + got, len - got, 0);
        if (n <= 0)
        {
            free(val);
            return NULL;
        }
        got += n;
    }
    val[len] = 0;
    recv(fd, line, 2, 0); // consume CRLF
    return val;
}

typedef struct
{
    char publish_addr[256];
    int have_addr;
    int ping_seen;
    int ping_closed;
    int open_streams; /* total open streams counter */
    pthread_mutex_t mtx;
    pthread_cond_t cv;
} interop_sync_t;

static void interop_evt_cb(const libp2p_event_t *evt, void *ud)
{
    interop_sync_t *sync = (interop_sync_t *)ud;
    if (!evt || !sync)
        return;
    if (evt->kind == LIBP2P_EVT_LISTEN_ADDR_ADDED && evt->u.listen_addr_added.addr)
    {
        const char *bound_str = evt->u.listen_addr_added.addr;
        const char *publish_str = bound_str;
        char actual_addr[256];
        if (strstr(bound_str, "0.0.0.0"))
        {
            const char *tcp_start = strstr(bound_str, "/tcp/");
            if (tcp_start)
            {
                int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (test_sock >= 0)
                {
                    struct sockaddr_in test_addr;
                    test_addr.sin_family = AF_INET;
                    test_addr.sin_port = htons(80);
                    inet_pton(AF_INET, "8.8.8.8", &test_addr.sin_addr);
                    if (connect(test_sock, (struct sockaddr *)&test_addr, sizeof(test_addr)) == 0)
                    {
                        struct sockaddr_in local_addr;
                        socklen_t len = sizeof(local_addr);
                        if (getsockname(test_sock, (struct sockaddr *)&local_addr, &len) == 0)
                        {
                            char ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &local_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                            snprintf(actual_addr, sizeof(actual_addr), "/ip4/%s%s", ip_str, tcp_start);
                            publish_str = actual_addr;
                        }
                    }
                    close(test_sock);
                }
            }
        }
        pthread_mutex_lock(&sync->mtx);
        snprintf(sync->publish_addr, sizeof(sync->publish_addr), "%s", publish_str);
        sync->have_addr = 1;
        pthread_cond_broadcast(&sync->cv);
        pthread_mutex_unlock(&sync->mtx);
    }
    else if (evt->kind == LIBP2P_EVT_STREAM_OPENED)
    {
        pthread_mutex_lock(&sync->mtx);
        sync->open_streams++;
        if (evt->u.stream_opened.protocol_id && strcmp(evt->u.stream_opened.protocol_id, LIBP2P_PING_PROTO_ID) == 0)
            sync->ping_seen = 1;
        pthread_cond_broadcast(&sync->cv);
        pthread_mutex_unlock(&sync->mtx);
    }
    else if (evt->kind == LIBP2P_EVT_STREAM_CLOSED)
    {
        pthread_mutex_lock(&sync->mtx);
        if (sync->open_streams > 0)
            sync->open_streams--;
        /* Treat "ping finished" as "no more open streams after ping was seen".
         * This avoids prematurely stopping on an Identify close event. */
        if (sync->ping_seen && sync->open_streams == 0)
            sync->ping_closed = 1;
        pthread_cond_broadcast(&sync->cv);
        pthread_mutex_unlock(&sync->mtx);
    }
}

static int run_listener(const char *ip, const char *redis_host, const char *redis_port, int timeout, const char *muxer_name)
{
    LP_LOGI("INTEROP", "run_listener: ip=%s redis_host=%s redis_port=%s timeout=%d muxer=%s", ip, redis_host, redis_port, timeout, muxer_name);

    char listen_maddr[64];
    snprintf(listen_maddr, sizeof(listen_maddr), "/ip4/%s/tcp/0", ip);

    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    (void)libp2p_host_builder_listen_addr(b, listen_maddr);
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    if (muxer_name && (strcmp(muxer_name, "yamux") == 0 || strcmp(muxer_name, "mplex") == 0))
        (void)libp2p_host_builder_muxer(b, muxer_name);
    else
        (void)libp2p_host_builder_muxer(b, "yamux");
    (void)libp2p_host_builder_multistream(b, 5000, true);
    (void)libp2p_host_builder_flags(b, LIBP2P_HOST_F_AUTO_IDENTIFY_INBOUND | LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(b, &host) != 0 || !host)
    {
        libp2p_host_builder_free(b);
        return 1;
    }

    /* Ensure Noise handshake has an identity key. */
    {
        size_t sk_len = 0;
        uint8_t *sk = hex_to_bytes(ED25519_PRIVATE_HEX, &sk_len);
        if (sk)
        {
            (void)libp2p_host_set_private_key(host, sk, sk_len);
            free(sk);
        }
    }

    /* Start standard protocol services using new Host API */
    libp2p_protocol_server_t *ping_srv = NULL;
    (void)libp2p_ping_service_start(host, &ping_srv);

    /* Subscribe for events (address + ping) */
    interop_sync_t sync;
    memset(&sync, 0, sizeof(sync));
    pthread_mutex_init(&sync.mtx, NULL);
    pthread_cond_init(&sync.cv, NULL);
    libp2p_subscription_t *sub = NULL;
    (void)libp2p_event_subscribe(host, interop_evt_cb, &sync, &sub);

    (void)libp2p_host_start(host);

    /* Wait for listen addr event and publish to Redis */
    {
        const int publish_wait_ms = 5000;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += publish_wait_ms / 1000;
        ts.tv_nsec += (publish_wait_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        pthread_mutex_lock(&sync.mtx);
        while (!sync.have_addr)
        {
            if (pthread_cond_timedwait(&sync.cv, &sync.mtx, &ts) == ETIMEDOUT)
                break;
        }
        pthread_mutex_unlock(&sync.mtx);
    }
    if (!sync.have_addr)
    {
        LP_LOGE("INTEROP", "listener: failed to get listen address event");
        if (sub)
            libp2p_event_unsubscribe(host, sub);
        libp2p_host_stop(host);
        libp2p_host_free(host);
        libp2p_host_builder_free(b);
        return 1;
    }

    LP_LOGD("INTEROP", "Connecting to Redis at %s:%s...", redis_host, redis_port);
    int rfd = redis_connect(redis_host, redis_port);
    if (rfd < 0)
    {
        LP_LOGE("INTEROP", "listener failed to connect to redis");
        libp2p_host_stop(host);
        libp2p_host_free(host);
        libp2p_host_builder_free(b);
        return 1;
    }
    LP_LOGD("INTEROP", "Publishing address to Redis: %s", sync.publish_addr);
    if (redis_rpush(rfd, "listenerAddr", sync.publish_addr) != 0)
    {
        LP_LOGD("INTEROP", "Failed to publish address to Redis");
        close(rfd);
        if (sub)
            libp2p_event_unsubscribe(host, sub);
        libp2p_host_stop(host);
        libp2p_host_free(host);
        libp2p_host_builder_free(b);
        return 1;
    }
    close(rfd);

    /* Wait for ping stream opened or until timeout */
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout;
        pthread_mutex_lock(&sync.mtx);
        while (!sync.ping_seen)
        {
            if (pthread_cond_timedwait(&sync.cv, &sync.mtx, &ts) == ETIMEDOUT)
                break;
        }
        pthread_mutex_unlock(&sync.mtx);
    }

    /* If ping opened, wait for it to close (echo completed) before stopping. */
    if (sync.ping_seen)
    {
        struct timespec ts2;
        clock_gettime(CLOCK_REALTIME, &ts2);
        ts2.tv_sec += timeout;
        pthread_mutex_lock(&sync.mtx);
        while (!sync.ping_closed)
        {
            if (pthread_cond_timedwait(&sync.cv, &sync.mtx, &ts2) == ETIMEDOUT)
                break;
        }
        pthread_mutex_unlock(&sync.mtx);
    }

    if (ping_srv)
        (void)libp2p_ping_service_stop(host, ping_srv);
    if (sub)
        libp2p_event_unsubscribe(host, sub);
    libp2p_host_stop(host);
    libp2p_host_free(host);
    libp2p_host_builder_free(b);
    return 0;
}

static int run_dialer(const char *redis_host, const char *redis_port, int timeout, const char *muxer_name)
{
    LP_LOGI("INTEROP", "run_dialer: redis_host=%s redis_port=%s timeout=%d muxer=%s", redis_host, redis_port, timeout, muxer_name);

    LP_LOGD("INTEROP", "Connecting to Redis...");
    int rfd = redis_connect(redis_host, redis_port);
    if (rfd < 0)
    {
        LP_LOGE("INTEROP", "dialer failed to connect to redis");
        return 1;
    }
    LP_LOGD("INTEROP", "Connected to Redis successfully");

    LP_LOGD("INTEROP", "Waiting for listener address from Redis (timeout=%d)...", timeout);
    char *addr_str = redis_blpop(rfd, "listenerAddr", timeout);
    close(rfd);
    if (!addr_str)
    {
        LP_LOGE("INTEROP", "dialer failed to get listener address from redis");
        return 1;
    }
    LP_LOGD("INTEROP", "Got listener address: %s", addr_str);

    /* Build unified host with desired proposals */
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
        return 1;
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    if (muxer_name && (strcmp(muxer_name, "yamux") == 0 || strcmp(muxer_name, "mplex") == 0))
        (void)libp2p_host_builder_muxer(b, muxer_name);
    else
        (void)libp2p_host_builder_muxer(b, "yamux");
    (void)libp2p_host_builder_multistream(b, 5000, false);
    (void)libp2p_host_builder_flags(b, LIBP2P_HOST_F_AUTO_IDENTIFY_INBOUND | LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(b, &host) != 0 || !host)
    {
        libp2p_host_builder_free(b);
        return 1;
    }

    /* Ensure Noise handshake has an identity key. */
    {
        size_t sk_len = 0;
        uint8_t *sk = hex_to_bytes(ED25519_PRIVATE_HEX, &sk_len);
        if (sk)
        {
            (void)libp2p_host_set_private_key(host, sk, sk_len);
            free(sk);
        }
    }

    uint64_t start = now_mono_ms();
    libp2p_stream_t *ping_stream = NULL;
    int rc = libp2p_host_dial_protocol_blocking(host, addr_str, LIBP2P_PING_PROTO_ID, timeout * 1000, &ping_stream);
    free(addr_str);
    if (rc != 0 || !ping_stream)
    {
        LP_LOGE("INTEROP", "failed to dial protocol (err=%d)", rc);
        libp2p_host_free(host);
        libp2p_host_builder_free(b);
        return 1;
    }

    /* Dial succeeded at this point: emit logs expected by interop checks. */
    LP_LOGI("INTEROP", "Dial successful");
    LP_LOGI("INTEROP", "negotiated muxer = %s", muxer_name ? muxer_name : "unknown");

    uint64_t ping_ms = 0;
    libp2p_ping_err_t prc = libp2p_ping_roundtrip_stream(ping_stream, (uint64_t)timeout * 1000ULL, &ping_ms);
    if (prc != LIBP2P_PING_OK)
    {
        LP_LOGE("INTEROP", "ping failed (err=%d)", (int)prc);
        libp2p_stream_close(ping_stream);
        libp2p_host_free(host);
        libp2p_host_builder_free(b);
        return 1;
    }
    libp2p_stream_close(ping_stream);

    uint64_t handshake_plus_rtt_ms = now_mono_ms() - start;
    printf("{\"handshakePlusOneRTTMillis\":%.3f,\"pingRTTMilllis\":%.3f}\n", (double)handshake_plus_rtt_ms, (double)ping_ms);

    libp2p_host_free(host);
    libp2p_host_builder_free(b);
    return 0;
}

int main(void)
{
    LP_LOGI("INTEROP", "Starting interop program");
    /* Increase verbosity to aid interop debugging. */
    libp2p_log_set_level(LIBP2P_LOG_DEBUG);
    setvbuf(stderr, NULL, _IONBF, 0);
    const char *transport = getenv("transport");
    LP_LOGD("INTEROP", "transport = %s", transport ? transport : "NULL");
    if (!transport || strcmp(transport, "tcp") != 0)
    {
        LP_LOGE("INTEROP", "unsupported transport");
        return 1;
    }
    const char *muxer = getenv("muxer");
    LP_LOGD("INTEROP", "muxer = %s", muxer ? muxer : "NULL");
    if (!muxer || (strcmp(muxer, "yamux") != 0 && strcmp(muxer, "mplex") != 0))
    {
        LP_LOGE("INTEROP", "unsupported muxer (supported: yamux, mplex)");
        return 1;
    }
    const char *sec = getenv("security");
    LP_LOGD("INTEROP", "security = %s", sec ? sec : "NULL");
    if (!sec || strcmp(sec, "noise") != 0)
    {
        LP_LOGE("INTEROP", "unsupported security");
        return 1;
    }
    int is_dialer = getenv("is_dialer") && strcmp(getenv("is_dialer"), "true") == 0;
    LP_LOGD("INTEROP", "is_dialer = %s", is_dialer ? "true" : "false");
    const char *ip = getenv("ip");
    if (!ip)
        ip = "0.0.0.0";
    LP_LOGD("INTEROP", "ip = %s", ip);
    const char *redis_addr = getenv("redis_addr");
    if (!redis_addr)
        redis_addr = "redis:6379"; // Default to Docker service name
    LP_LOGD("INTEROP", "redis_addr = %s", redis_addr);
    int timeout = getenv("test_timeout_seconds") ? atoi(getenv("test_timeout_seconds")) : 180;
    LP_LOGD("INTEROP", "timeout = %d", timeout);
    char host[64] = "", port[16] = "";
    sscanf(redis_addr, "%63[^:]:%15s", host, port);
    if (!*port)
        strcpy(port, "6379");
    LP_LOGD("INTEROP", "redis host = %s, port = %s", host, port);
    if (is_dialer)
    {
        LP_LOGI("INTEROP", "Running as dialer");
        return run_dialer(host, port, timeout, muxer);
    }
    else
    {
        LP_LOGI("INTEROP", "Running as listener");
        return run_listener(ip, host, port, timeout, muxer);
    }
}
