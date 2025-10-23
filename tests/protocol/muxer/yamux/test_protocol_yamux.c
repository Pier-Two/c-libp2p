#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdatomic.h>

#define TLOG(fmt, ...) fprintf(stderr, "[YAMUX_TEST] %s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

/* Standardized test output (aligned with multibase tests) */
static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
    {
        printf("TEST: %-50s | PASS\n", test_name);
    }
    else
    {
        printf("TEST: %-50s | FAIL: %s\n", test_name, details ? details : "");
    }
}

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include "protocol/tcp/sys/socket.h"
#include <io.h>
#endif
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/tcp/protocol_tcp.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

#define YAMUX_INITIAL_WINDOW (256 * 1024)

static inline uint64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ull + (uint64_t)tv.tv_usec / 1000ull;
}

#define RUN_TEST(fn)                                                                                                                                 \
    do                                                                                                                                               \
    {                                                                                                                                                \
        fn();                                                                                                                                        \
    } while (0)

#define RUN_ONE(fn)                                                                                                                                  \
    do                                                                                                                                               \
    {                                                                                                                                                \
        const char *only = getenv("YAMUX_TEST_ONLY");                                                                                                \
        if (!only || strcmp(only, #fn) == 0)                                                                                                         \
        {                                                                                                                                            \
            RUN_TEST(fn);                                                                                                                            \
        }                                                                                                                                            \
    } while (0)

// Helper for partial-frame test: writer threads that write in two chunks
typedef struct writer_args_s
{
    libp2p_conn_t *conn;
    uint8_t *buf;
    size_t n1;
    size_t n2;
} writer_args_t;

static void *writer_thread(void *arg)
{
    writer_args_t *wa = (writer_args_t *)arg;
    ssize_t n = libp2p_conn_write(wa->conn, wa->buf, wa->n1);
    TLOG("wrote first chunk: %zd bytes", n);
    usleep(50000); // 50ms
    n = libp2p_conn_write(wa->conn, wa->buf + wa->n1, wa->n2);
    TLOG("wrote second chunk: %zd bytes", n);
    return NULL;
}

static libp2p_yamux_err_t g_dial_rc;
static libp2p_yamux_err_t g_listen_rc;
static libp2p_yamux_err_t g_loop_rc;

typedef struct
{
    int rfd;
    int wfd;
} pipe_ctx_t;

static ssize_t pipe_read(libp2p_conn_t *c, void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    ssize_t n = read(p->rfd, buf, len);
    if (n > 0)
        return n;
    if (n == 0)
        return LIBP2P_CONN_ERR_EOF;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return LIBP2P_CONN_ERR_AGAIN;
    TLOG("pipe_read: rfd=%d errno=%d", p->rfd, errno);
    return LIBP2P_CONN_ERR_INTERNAL;
}

static ssize_t pipe_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    if (!p)
    {
        TLOG("pipe_write: ctx=NULL for conn=%p", (void *)c);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
#ifdef MSG_NOSIGNAL
    ssize_t n = send(p->wfd, buf, len, MSG_NOSIGNAL);
#else
    ssize_t n = write(p->wfd, buf, len);
#endif
    if (n >= 0)
        return n;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return LIBP2P_CONN_ERR_AGAIN;
    TLOG("pipe_write: conn=%p ctx=%p wfd=%d errno=%d", (void *)c, (void *)p, p->wfd, errno);
    return LIBP2P_CONN_ERR_INTERNAL;
}

static libp2p_conn_err_t pipe_deadline(libp2p_conn_t *c, uint64_t ms)
{
    (void)c;
    (void)ms;
    return LIBP2P_CONN_OK;
}

static const multiaddr_t *pipe_addr(libp2p_conn_t *c)
{
    (void)c;
    return NULL;
}

static libp2p_conn_err_t pipe_close(libp2p_conn_t *c)
{
    pipe_ctx_t *p = c->ctx;
    if (p)
    {
        if (p->rfd > 2)
            close(p->rfd);
        if (p->wfd > 2 && p->wfd != p->rfd)
            close(p->wfd);
    }
    return LIBP2P_CONN_OK;
}

static void pipe_free(libp2p_conn_t *c)
{
    pipe_ctx_t *p = c->ctx;
    free(p);
}

static const libp2p_conn_vtbl_t PIPE_VTBL = {
    .read = pipe_read,
    .write = pipe_write,
    .set_deadline = pipe_deadline,
    .local_addr = pipe_addr,
    .remote_addr = pipe_addr,
    .close = pipe_close,
    .free = pipe_free,
};

typedef struct
{
    atomic_int in_write;
    atomic_int overlap;
} race_conn_ctx_t;

static ssize_t race_conn_read(libp2p_conn_t *c, void *buf, size_t len)
{
    (void)c;
    (void)buf;
    (void)len;
    return LIBP2P_CONN_ERR_AGAIN;
}

static ssize_t race_conn_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    race_conn_ctx_t *ctx = c->ctx;
    if (!ctx)
        return LIBP2P_CONN_ERR_INTERNAL;
    if (atomic_fetch_add_explicit(&ctx->in_write, 1, memory_order_acq_rel) != 0)
        atomic_store_explicit(&ctx->overlap, 1, memory_order_release);
    /* Small delay to increase overlap window if locking is missing. */
    usleep(1000);
    atomic_fetch_sub_explicit(&ctx->in_write, 1, memory_order_acq_rel);
    return (ssize_t)len;
}

static libp2p_conn_err_t race_conn_deadline(libp2p_conn_t *c, uint64_t ms)
{
    (void)c;
    (void)ms;
    return LIBP2P_CONN_OK;
}

static const multiaddr_t *race_conn_addr(libp2p_conn_t *c)
{
    (void)c;
    return NULL;
}

static libp2p_conn_err_t race_conn_close(libp2p_conn_t *c)
{
    (void)c;
    return LIBP2P_CONN_OK;
}

static void race_conn_free(libp2p_conn_t *c)
{
    (void)c;
}

static const libp2p_conn_vtbl_t RACE_CONN_VTBL = {
    .read = race_conn_read,
    .write = race_conn_write,
    .set_deadline = race_conn_deadline,
    .local_addr = race_conn_addr,
    .remote_addr = race_conn_addr,
    .close = race_conn_close,
    .free = race_conn_free,
};

static void ensure_stdio_open(void)
{
    int fds[3] = {0, 1, 2};
    for (int i = 0; i < 3; i++)
    {
        errno = 0;
        int rc = fcntl(fds[i], F_GETFD);
        if (rc == -1 && errno == EBADF)
        {
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0 && dn != fds[i])
            {
                // If open returned a different fd, dup to desired slot
                dup2(dn, fds[i]);
                close(dn);
            }
        }
    }
}

static void make_pipe_pair(libp2p_conn_t *a, libp2p_conn_t *b)
{
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
    {
        TLOG("make_pipe_pair: socketpair failed errno=%d", errno);
        assert(0 && "socketpair failed");
    }
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    fcntl(sp[1], F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(sp[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    setsockopt(sp[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    // Avoid closing stdio later
    for (int i = 0; i < 2; i++)
    {
        if (sp[i] <= 2)
        {
            int dupfd = fcntl(sp[i], F_DUPFD, 3);
            if (dupfd >= 0)
            {
                close(sp[i]);
                sp[i] = dupfd;
                fcntl(sp[i], F_SETFL, O_NONBLOCK);
            }
        }
    }
    pipe_ctx_t *actx = malloc(sizeof(*actx));
    pipe_ctx_t *bctx = malloc(sizeof(*bctx));
    assert(actx && bctx);
    actx->rfd = sp[0];
    actx->wfd = sp[0];
    bctx->rfd = sp[1];
    bctx->wfd = sp[1];
    TLOG("make_pipe_pair: sp=[%d,%d] actx=%p r/w=%d bctx=%p r/w=%d", sp[0], sp[1], (void *)actx, actx->rfd, (void *)bctx, bctx->rfd);
    a->vt = &PIPE_VTBL;
    a->ctx = actx;
    b->vt = &PIPE_VTBL;
    b->ctx = bctx;
}

typedef struct
{
    libp2p_yamux_ctx_t *ctx;
    uint32_t stream_id;
    const uint8_t *buf;
    size_t len;
    libp2p_yamux_err_t rc;
} yamux_send_args_t;

static void *yamux_send_thread(void *arg)
{
    yamux_send_args_t *a = (yamux_send_args_t *)arg;
    a->rc = libp2p_yamux_stream_send(a->ctx, a->stream_id, a->buf, a->len, 0);
    return NULL;
}

static void *dial_thread(void *arg)
{
    libp2p_conn_t *c = arg;
    g_dial_rc = libp2p_yamux_negotiate_outbound(c, 5000);
    TLOG("dial_thread negotiate_outbound rc=%d", g_dial_rc);
    return NULL;
}

static void *listen_thread(void *arg)
{
    libp2p_conn_t *c = arg;
    g_listen_rc = libp2p_yamux_negotiate_inbound(c, 5000);
    TLOG("listen_thread negotiate_inbound rc=%d", g_listen_rc);
    return NULL;
}

static void *loop_thread(void *arg)
{
    g_loop_rc = libp2p_yamux_process_loop((libp2p_yamux_ctx_t *)arg);
    return NULL;
}

static void test_negotiate(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4311", &err);
    assert(addr && err == 0);

    libp2p_listener_t *lst = NULL;
    libp2p_transport_err_t lrc = libp2p_transport_listen(tcp, addr, &lst);
    TLOG("listen rc=%d lst=%p", lrc, (void *)lst);
    assert(lrc == LIBP2P_TRANSPORT_OK);
    if (lst)
        TLOG("lst->vt=%p ctx=%p", (void *)lst->vt, lst->ctx);

    libp2p_conn_t *c = NULL;
    libp2p_transport_err_t drc = libp2p_transport_dial(tcp, addr, &c);
    TLOG("dial rc=%d c=%p", drc, (void *)c);
    assert(drc == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    {
        int spin = 0;
        libp2p_listener_err_t ar = 0;
        while ((ar = libp2p_listener_accept(lst, &s)) == LIBP2P_LISTENER_ERR_AGAIN)
        {
            if ((++spin % 1000) == 0)
                TLOG("accept: waiting, s=%p", (void *)s);
            usleep(1000);
        }
        TLOG("accept: rc=%d, s=%p", ar, (void *)s);
    }

    TLOG("c=%p s(pre-accept)=%p", (void *)c, (void *)s);
    TLOG("c=%p s=%p (before threads)", (void *)c, (void *)s);
    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    int ok = (g_dial_rc == LIBP2P_YAMUX_OK && g_listen_rc == LIBP2P_YAMUX_OK);
    print_standard("yamux negotiate", ok ? "" : "negotiate failed", ok);

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

struct mux_args
{
    libp2p_muxer_t *m;
    libp2p_conn_t *c;
};
static libp2p_muxer_err_t g_mux_dial_rc;
static libp2p_muxer_err_t g_mux_listen_rc;

static void *dial_mux_thread(void *arg)
{
    struct mux_args *a = arg;
    g_mux_dial_rc = libp2p_muxer_negotiate_outbound(a->m, a->c, 5000);
    return NULL;
}

static void *listen_mux_thread(void *arg)
{
    struct mux_args *a = arg;
    g_mux_listen_rc = libp2p_muxer_negotiate_inbound(a->m, a->c, 5000);
    return NULL;
}

static void test_muxer_wrapper(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4322", &err);
    assert(addr && err == 0);

    libp2p_listener_t *lst = NULL;
    libp2p_transport_err_t lrc2 = libp2p_transport_listen(tcp, addr, &lst);
    TLOG("mux_wrapper: listen rc=%d lst=%p", lrc2, (void *)lst);
    assert(lrc2 == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    libp2p_transport_err_t drc2 = libp2p_transport_dial(tcp, addr, &c);
    TLOG("mux_wrapper: dial rc=%d c=%p", drc2, (void *)c);
    assert(drc2 == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    {
        libp2p_listener_err_t ar = 0;
        while ((ar = libp2p_listener_accept(lst, &s)) == LIBP2P_LISTENER_ERR_AGAIN)
            usleep(1000);
        TLOG("mux_wrapper: accept rc=%d s=%p", ar, (void *)s);
    }
    assert(s);
    TLOG("mux_wrapper: c=%p s=%p", (void *)c, (void *)s);

    libp2p_muxer_t *m_dial = libp2p_yamux_new();
    libp2p_muxer_t *m_listen = libp2p_yamux_new();
    assert(m_dial && m_listen);

    struct mux_args dargs = {m_dial, c};
    struct mux_args sargs = {m_listen, s};
    pthread_t td, ts;
    pthread_create(&td, NULL, dial_mux_thread, &dargs);
    pthread_create(&ts, NULL, listen_mux_thread, &sargs);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    TLOG("mux_wrapper: rc dial=%d listen=%d", g_mux_dial_rc, g_mux_listen_rc);
    int ok = (g_mux_dial_rc == LIBP2P_MUXER_OK && g_mux_listen_rc == LIBP2P_MUXER_OK);
    print_standard("yamux muxer wrapper negotiation", ok ? "" : "muxer negotiate failed", ok);

    libp2p_muxer_free(m_dial);
    libp2p_muxer_free(m_listen);
    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_frame_roundtrip(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4312", &err);
    assert(addr && err == 0);

    libp2p_listener_t *lst = NULL;
    libp2p_transport_err_t lrc3 = libp2p_transport_listen(tcp, addr, &lst);
    TLOG("frame_rt: listen rc=%d lst=%p", lrc3, (void *)lst);
    assert(lrc3 == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    libp2p_transport_err_t drc3 = libp2p_transport_dial(tcp, addr, &c);
    TLOG("frame_rt: dial rc=%d c=%p", drc3, (void *)c);
    assert(drc3 == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    {
        libp2p_listener_err_t ar = 0;
        while ((ar = libp2p_listener_accept(lst, &s)) == LIBP2P_LISTENER_ERR_AGAIN)
            usleep(1000);
        TLOG("frame_rt: accept rc=%d s=%p", ar, (void *)s);
    }

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);
    assert(g_dial_rc == LIBP2P_YAMUX_OK && g_listen_rc == LIBP2P_YAMUX_OK);

    const char *msg = "hi";
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 3,
        .length = 2,
        .data = (uint8_t *)msg,
        .data_len = 2,
    };
    TLOG("frame_rt: sending frame on c=%p", (void *)c);
    libp2p_yamux_err_t s_rc = libp2p_yamux_send_frame(c, &fr);
    TLOG("frame_rt: send rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t rec = {0};
    TLOG("frame_rt: setting read deadline on s=%p", (void *)s);
    libp2p_conn_set_deadline(s, 2000);
    TLOG("frame_rt: reading frame on s=%p", (void *)s);
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(s, &rec);
    TLOG("frame_rt: read rc=%d type=%u id=%u len=%u", rc, (unsigned)rec.type, rec.stream_id, rec.length);
    libp2p_conn_set_deadline(s, 0);

    int ok = (rc == LIBP2P_YAMUX_OK && rec.stream_id == 3 && rec.data_len == 2 && memcmp(rec.data, msg, 2) == 0);
    print_standard("yamux frame roundtrip", ok ? "" : "unexpected frame or payload", ok);

    libp2p_yamux_frame_free(&rec);
    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

typedef struct
{
    libp2p_conn_t *conn;
    libp2p_yamux_frame_t fr;
    libp2p_yamux_err_t rc;
    atomic_bool done;
} read_arg_t;

static void *read_frame_thread(void *arg)
{
    read_arg_t *ra = arg;
    ra->rc = libp2p_yamux_read_frame(ra->conn, &ra->fr);
    atomic_store_explicit(&ra->done, true, memory_order_release);
    return NULL;
}

typedef struct
{
    libp2p_yamux_ctx_t *ctx;
    libp2p_yamux_err_t rc;
    atomic_bool done;
} process_one_arg_t;

static void *process_one_thread(void *arg)
{
    process_one_arg_t *pa = arg;
    pa->rc = libp2p_yamux_process_one(pa->ctx);
    atomic_store_explicit(&pa->done, true, memory_order_release);
    return NULL;
}

static void test_large_frame(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    size_t len = 256 * 1024; /* trimmed to 256 KiB for speed */
    uint8_t *buf = malloc(len);
    assert(buf);
    memset(buf, 'x', len);

    read_arg_t ra = {.conn = &s, .fr = {0}, .rc = 0};
    atomic_init(&ra.done, false);
    pthread_t th;
    pthread_create(&th, NULL, read_frame_thread, &ra);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 3,
        .length = (uint32_t)len,
        .data = buf,
        .data_len = len,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    pthread_join(th, NULL);

    int ok = (ra.rc == LIBP2P_YAMUX_OK && ra.fr.stream_id == 3 && ra.fr.data_len == len && memcmp(ra.fr.data, buf, len) == 0);
    print_standard("yamux large frame", ok ? "" : "mismatch after large frame", ok);

    libp2p_yamux_frame_free(&ra.fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
    free(buf);
}

static void test_invalid_version(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    TLOG("invalid_version: c=%p ctx=%p s=%p sctx=%p", (void *)&c, c.ctx, (void *)&s, s.ctx);

    libp2p_yamux_frame_t fr = {
        .version = 1,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 3,
        .length = 0,
        .data = NULL,
        .data_len = 0,
    };
    libp2p_yamux_err_t s_rc = libp2p_yamux_send_frame(&c, &fr);
    TLOG("invalid_version: send rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t rec = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &rec);
    TLOG("invalid_version: read rc=%d", rc);

    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    print_standard("yamux invalid version", ok ? "" : "expected protocol error", ok);

    libp2p_yamux_frame_free(&rec);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_stream_id_zero(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    TLOG("stream_id_zero: pipe pair made c.ctx=%p s.ctx=%p", c.ctx, s.ctx);

    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(srv);
    TLOG("stream_id_zero: srv ctx=%p", (void *)srv);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 0,
        .length = 0,
        .data = NULL,
        .data_len = 0,
    };
    libp2p_yamux_err_t s_rc = libp2p_yamux_send_frame(&c, &fr);
    TLOG("stream_id_zero: send_frame rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    TLOG("stream_id_zero: calling process_one ...");
    libp2p_yamux_err_t rc = libp2p_yamux_process_one(srv);
    TLOG("stream_id_zero: process_one rc=%d", rc);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    print_standard("yamux stream id zero", ok ? "" : "expected protocol error", ok);

    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_stream_id_parity(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    TLOG("stream_id_parity: pipe pair made c.ctx=%p s.ctx=%p", c.ctx, s.ctx);

    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(srv);
    TLOG("stream_id_parity: srv ctx=%p", (void *)srv);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = LIBP2P_YAMUX_SYN,
        .stream_id = 2,
        .length = 0,
        .data = NULL,
        .data_len = 0,
    };
    libp2p_yamux_err_t s_rc = libp2p_yamux_send_frame(&c, &fr);
    TLOG("stream_id_parity: send_frame rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    TLOG("stream_id_parity: calling process_one ...");
    libp2p_yamux_err_t rc = libp2p_yamux_process_one(srv);
    TLOG("stream_id_parity: process_one rc=%d", rc);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    print_standard("yamux stream id parity", ok ? "" : "expected protocol error", ok);

    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_window_update(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    TLOG("window_update: before send");
    libp2p_yamux_err_t s_rc = libp2p_yamux_window_update(&c, 5, 123, 0);
    TLOG("window_update: send rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    TLOG("window_update: reading frame ...");
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);
    TLOG("window_update: read rc=%d type=%u id=%u len=%u", rc, (unsigned)fr.type, fr.stream_id, fr.length);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && fr.stream_id == 5 && fr.length == 123);
    print_standard("yamux window update", ok ? "" : "did not receive expected window update", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_ping_pong(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    TLOG("ping_pong: sending PING SYN ...");
    libp2p_yamux_err_t s_rc = libp2p_yamux_ping(&c, 42, LIBP2P_YAMUX_SYN);
    TLOG("ping_pong: send rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    TLOG("ping_pong: reading frame (expect SYN) ...");
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);
    TLOG("ping_pong: read rc=%d type=%u flags=0x%x len=%u", rc, (unsigned)fr.type, fr.flags, fr.length);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_PING && fr.length == 42 && (fr.flags & LIBP2P_YAMUX_SYN));

    print_standard("yamux ping", ok ? "" : "SYN not received", ok);

    libp2p_yamux_frame_free(&fr);

    TLOG("ping_pong: sending PING ACK ...");
    s_rc = libp2p_yamux_ping(&s, 42, LIBP2P_YAMUX_ACK);
    TLOG("ping_pong: ACK send rc=%d", s_rc);
    assert(s_rc == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t ack = {0};
    TLOG("ping_pong: reading ACK ...");
    rc = libp2p_yamux_read_frame(&c, &ack);
    TLOG("ping_pong: read ACK rc=%d type=%u flags=0x%x len=%u", rc, (unsigned)ack.type, ack.flags, ack.length);
    ok = (rc == LIBP2P_YAMUX_OK && ack.type == LIBP2P_YAMUX_PING && ack.length == 42 && (ack.flags & LIBP2P_YAMUX_ACK));
    print_standard("yamux ping ack", ok ? "" : "ACK not received", ok);

    libp2p_yamux_frame_free(&ack);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void ping_cb(libp2p_yamux_ctx_t *ctx, uint32_t value, uint64_t rtt_ms, void *arg)
{
    (void)ctx;
    (void)value;
    *(uint64_t *)arg = rtt_ms;
}

static void test_ping_callback(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    TLOG("ping_cb: pipe pair made c.ctx=%p s.ctx=%p", c.ctx, s.ctx);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);
    TLOG("ping_cb: ctx created=%p", (void *)ctx);

    uint64_t rtt = 0;
    libp2p_yamux_set_ping_cb(ctx, ping_cb, &rtt);
    TLOG("ping_cb: callback installed, rtt ptr=%p", (void *)&rtt);

    libp2p_yamux_err_t prc = libp2p_yamux_ctx_ping(ctx, 7);
    TLOG("ping_cb: ctx_ping rc=%d", prc);
    assert(prc == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    TLOG("ping_cb: reading PING on peer (timed) ...");
    read_arg_t rarg = {.conn = &s, .fr = {0}, .rc = 0};
    atomic_init(&rarg.done, false);
    pthread_t rth;
    pthread_create(&rth, NULL, read_frame_thread, &rarg);
    /* 2s watchdog */
    uint64_t start = now_ms();
    while (!atomic_load_explicit(&rarg.done, memory_order_acquire) && now_ms() - start < 2000)
    {
        usleep(10000);
    }
    if (!atomic_load_explicit(&rarg.done, memory_order_acquire))
    {
        TLOG("ping_cb: read watchdog fired; canceling thread");
        pthread_cancel(rth);
        pthread_join(rth, NULL);
        assert(!"read_frame timeout in ping_cb");
    }
    pthread_join(rth, NULL);
    fr = rarg.fr;
    libp2p_yamux_err_t rc = rarg.rc;
    TLOG("ping_cb: read rc=%d type=%u flags=0x%x len=%u", rc, (unsigned)fr.type, fr.flags, fr.length);
    assert(rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_PING);
    libp2p_yamux_err_t arc = libp2p_yamux_ping(&s, fr.length, LIBP2P_YAMUX_ACK);
    TLOG("ping_cb: sending ACK rc=%d", arc);
    assert(arc == LIBP2P_YAMUX_OK);
    libp2p_yamux_frame_free(&fr);

    TLOG("ping_cb: processing ACK on ctx (timed) ...");
    process_one_arg_t parg = {.ctx = ctx, .rc = 0};
    atomic_init(&parg.done, false);
    pthread_t pth;
    pthread_create(&pth, NULL, process_one_thread, &parg);
    start = now_ms();
    while (!atomic_load_explicit(&parg.done, memory_order_acquire) && now_ms() - start < 2000)
    {
        usleep(10000);
    }
    if (!atomic_load_explicit(&parg.done, memory_order_acquire))
    {
        TLOG("ping_cb: process_one watchdog fired; canceling thread");
        pthread_cancel(pth);
        pthread_join(pth, NULL);
        assert(!"process_one timeout in ping_cb");
    }
    pthread_join(pth, NULL);
    rc = parg.rc;
    TLOG("ping_cb: process_one rc=%d, rtt=%llu", rc, (unsigned long long)rtt);
    int ok = (rc == LIBP2P_YAMUX_OK && rtt >= 0);
    print_standard("yamux ping callback", ok ? "" : "callback not invoked", ok);

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_ping_bad_flags(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_PING,
        .flags = LIBP2P_YAMUX_SYN | LIBP2P_YAMUX_ACK,
        .stream_id = 0,
        .length = 1,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    print_standard("yamux ping bad flags", ok ? "" : "expected protocol error", ok);

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    assert(libp2p_yamux_go_away(&c, LIBP2P_YAMUX_GOAWAY_OK) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_GO_AWAY && fr.length == LIBP2P_YAMUX_GOAWAY_OK);
    print_standard("yamux go away", ok ? "" : "unexpected go away frame", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_stop_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_stop(ctx);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_GO_AWAY && fr.length == LIBP2P_YAMUX_GOAWAY_OK);
    print_standard("yamux stop go away", ok ? "" : "unexpected go away on stop", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_open_after_stop(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_stop(ctx);

    uint32_t id = 0;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_open(ctx, &id);

    int ok = (rc == LIBP2P_YAMUX_ERR_EOF);
    print_standard("yamux open after stop", ok ? "" : "expected EOF after stop", ok);

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_ctx_free_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_ctx_free(ctx);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_GO_AWAY && fr.length == LIBP2P_YAMUX_GOAWAY_OK);
    print_standard("yamux ctx free go away", ok ? "" : "unexpected go away on free", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_go_away_flags(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_GO_AWAY,
        .flags = LIBP2P_YAMUX_SYN,
        .stream_id = 0,
        .length = LIBP2P_YAMUX_GOAWAY_OK,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    print_standard("yamux go away flags", ok ? "" : "expected protocol error", ok);

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_send_window(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);
    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(ctx, &id) == LIBP2P_YAMUX_OK);

    pthread_mutex_lock(&ctx->mtx);
    ctx->streams[0]->send_window = 1;
    pthread_mutex_unlock(&ctx->mtx);

    uint8_t buf[4] = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_stream_send(ctx, id, buf, sizeof(buf), 0);
    int ok = (rc == LIBP2P_YAMUX_ERR_AGAIN);
    print_standard("yamux send window", ok ? "" : "expected flow control backpressure", ok);

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_recv_window_update(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(cli, &id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    libp2p_yamux_stream_t *st = NULL;
    assert(libp2p_yamux_accept_stream(srv, &st) == LIBP2P_YAMUX_OK);

    const char *msg = "test";
    assert(libp2p_yamux_stream_send(cli, id, (const uint8_t *)msg, 4, 0) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    pthread_mutex_lock(&srv->mtx);
    size_t rw = srv->streams[0]->recv_window;
    pthread_mutex_unlock(&srv->mtx);
    int ok = (rw == srv->max_window - 4);

    uint8_t rbuf[4];
    size_t n = 0;
    assert(libp2p_yamux_stream_recv(srv, id, rbuf, sizeof(rbuf), &n) == LIBP2P_YAMUX_OK);
    assert(n == 4 && memcmp(rbuf, msg, 4) == 0);

    pthread_mutex_lock(&srv->mtx);
    rw = srv->streams[0]->recv_window;
    pthread_mutex_unlock(&srv->mtx);
    ok = ok && (rw == srv->max_window);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    if (fr.type == LIBP2P_YAMUX_DATA && (fr.flags & LIBP2P_YAMUX_ACK))
    {
        libp2p_yamux_frame_free(&fr);
        assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    }
    ok = ok && (fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && fr.stream_id == id && fr.length > 0);
    print_standard("yamux recv window update", ok ? "" : "window update missing", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_delayed_ack(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(cli, &id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    libp2p_yamux_stream_t *st = NULL;
    assert(libp2p_yamux_accept_stream(srv, &st) == LIBP2P_YAMUX_OK);

    pthread_mutex_lock(&srv->mtx);
    int acked = srv->streams[0]->acked;
    pthread_mutex_unlock(&srv->mtx);
    int ok = (acked == 0);

    const char *msg = "hi";
    assert(libp2p_yamux_stream_send(srv, id, (const uint8_t *)msg, 2, 0) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    ok = ok && (fr.type == LIBP2P_YAMUX_DATA && (fr.flags & LIBP2P_YAMUX_ACK));
    libp2p_yamux_frame_free(&fr);

    pthread_mutex_lock(&srv->mtx);
    acked = srv->streams[0]->acked;
    pthread_mutex_unlock(&srv->mtx);
    ok = ok && (acked == 1);

    print_standard("yamux delayed ack", ok ? "" : "ACK not delayed/processed", ok);

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_initial_window_syn(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    uint32_t big = YAMUX_INITIAL_WINDOW * 2;
    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, big);
    assert(ctx);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(ctx, &id) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&s, &fr) == LIBP2P_YAMUX_OK);
    int ok =
        (fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && (fr.flags & LIBP2P_YAMUX_SYN) && fr.stream_id == id && fr.length == big - YAMUX_INITIAL_WINDOW);
    print_standard("yamux large window syn", ok ? "" : "missing SYN window update", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_initial_window_ack(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    uint32_t big = YAMUX_INITIAL_WINDOW * 2;
    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, big);
    assert(cli && srv);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(cli, &id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    int ok =
        (fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && (fr.flags & LIBP2P_YAMUX_ACK) && fr.stream_id == id && fr.length == big - YAMUX_INITIAL_WINDOW);
    print_standard("yamux large window ack", ok ? "" : "missing ACK window update", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_keepalive(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    assert(libp2p_yamux_enable_keepalive(ctx, 50) == LIBP2P_YAMUX_OK);

    usleep(120000); /* allow ping to be sent */

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);
    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_PING && (fr.flags & LIBP2P_YAMUX_SYN));
    print_standard("yamux keepalive ping", ok ? "" : "keepalive ping not observed", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_stop(ctx);

    // Give the background keepalive thread time to properly exit
    usleep(100000); // 100ms

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_recv_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    assert(libp2p_yamux_go_away(&s, LIBP2P_YAMUX_GOAWAY_OK) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(ctx) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_ERR_EOF && ctx->goaway_received && ctx->goaway_code == LIBP2P_YAMUX_GOAWAY_OK);
    print_standard("yamux recv go away", ok ? "" : "did not process go away", ok);

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test yamux muxer creation and basic functionality
 * This verifies the yamux implementation basics work as expected
 */
static void test_yamux_muxer_creation(void)
{
    libp2p_muxer_t *muxer = libp2p_yamux_new();
    assert(muxer != NULL);
    assert(muxer->ctx == NULL); // Context should be NULL until negotiation

    print_standard("yamux muxer creation", "", 1);

    libp2p_muxer_free(muxer);
}

/**
 * Test yamux frame operations work correctly without hanging
 * This verifies basic frame send/receive functionality that interop tests rely on
 */
static void test_yamux_frame_operations(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    // Test basic frame send/receive
    libp2p_yamux_frame_t send_frame = {
        .version = 0,
        .type = LIBP2P_YAMUX_PING,
        .flags = LIBP2P_YAMUX_SYN,
        .stream_id = 0,
        .length = 42,
        .data = NULL,
        .data_len = 0,
    };

    libp2p_yamux_err_t send_rc = libp2p_yamux_send_frame(&c, &send_frame);
    if (send_rc != LIBP2P_YAMUX_OK)
    {
        char details[64];
        snprintf(details, sizeof(details), "send failed: %d", send_rc);
        print_standard("yamux frame operations", details, 0);
        goto cleanup;
    }

    libp2p_yamux_frame_t recv_frame = {0};
    libp2p_yamux_err_t recv_rc = libp2p_yamux_read_frame(&s, &recv_frame);
    if (recv_rc != LIBP2P_YAMUX_OK)
    {
        char details[64];
        snprintf(details, sizeof(details), "recv failed: %d", recv_rc);
        print_standard("yamux frame operations", details, 0);
        goto cleanup;
    }

    int ok = (recv_frame.type == LIBP2P_YAMUX_PING && recv_frame.flags == LIBP2P_YAMUX_SYN && recv_frame.length == 42);
    print_standard("yamux frame operations", ok ? "" : "unexpected ping frame content", ok);

    libp2p_yamux_frame_free(&recv_frame);

cleanup:
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test multiple concurrent streams handling
 * This test ensures multi-stream protocol handling works correctly
 */
static void test_multiple_concurrent_streams(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    const int num_streams = 3; /* trimmed for speed */
    uint32_t stream_ids[num_streams];

    // Open multiple streams
    for (int i = 0; i < num_streams; i++)
    {
        assert(libp2p_yamux_stream_open(cli, &stream_ids[i]) == LIBP2P_YAMUX_OK);
    }

    // Process all incoming streams on server
    for (int i = 0; i < num_streams; i++)
    {
        assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    }

    // Send data on all streams
    for (int i = 0; i < num_streams; i++)
    {
        char data[32];
        snprintf(data, sizeof(data), "Stream %d data", i);
        assert(libp2p_yamux_stream_send(cli, stream_ids[i], (const uint8_t *)data, strlen(data), 0) == LIBP2P_YAMUX_OK);
    }

    // Process all data frames on server
    for (int i = 0; i < num_streams; i++)
    {
        assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    }

    // Verify all streams received correct data
    int all_correct = 1;
    for (int i = 0; i < num_streams; i++)
    {
        uint8_t buf[64];
        size_t len = 0;
        libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(srv, stream_ids[i], buf, sizeof(buf), &len);

        char expected[32];
        snprintf(expected, sizeof(expected), "Stream %d data", i);

        if (rc != LIBP2P_YAMUX_OK || len != strlen(expected) || memcmp(buf, expected, strlen(expected)) != 0)
        {
            all_correct = 0;
            break;
        }
    }

    print_standard("yamux multiple concurrent streams", all_correct ? "" : "data mismatch across streams", all_correct);

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test yamux muxer context storage after negotiation
 * This test prevents regression where context wasn't stored in muxer->ctx
 */
static void test_muxer_context_storage(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_muxer_t *m_dial = libp2p_yamux_new();
    libp2p_muxer_t *m_listen = libp2p_yamux_new();
    assert(m_dial && m_listen);

    // Initially, context should be NULL
    assert(m_dial->ctx == NULL);
    assert(m_listen->ctx == NULL);

    struct mux_args dargs = {m_dial, &c};
    struct mux_args sargs = {m_listen, &s};
    pthread_t td, ts;
    pthread_create(&td, NULL, dial_mux_thread, &dargs);
    pthread_create(&ts, NULL, listen_mux_thread, &sargs);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    // After successful negotiation, context should be stored in muxer->ctx
    int ok = (g_mux_dial_rc == LIBP2P_MUXER_OK && g_mux_listen_rc == LIBP2P_MUXER_OK && m_dial->ctx != NULL && m_listen->ctx != NULL);
    print_standard("yamux muxer context storage after negotiation", ok ? "" : "muxer->ctx not set", ok);

    libp2p_muxer_free(m_dial);
    libp2p_muxer_free(m_listen);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test partial frame reading to ensure non-blocking behavior
 * This test verifies that partial frame reads are handled correctly
 */
static void test_partial_frame_reading(void)
{
    TLOG("enter");
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    // Build a full DATA frame header for stream id=1, len=0
    uint8_t header[12];
    memset(header, 0, sizeof(header));
    header[0] = 0;                          // version
    header[1] = (uint8_t)LIBP2P_YAMUX_DATA; // type
    // flags = 0
    uint32_t sid = htonl(1);
    memcpy(&header[4], &sid, 4);
    uint32_t len = htonl(0);
    memcpy(&header[8], &len, 4);

    // Writer thread that writes the header in two chunks with a small delay
    writer_args_t w = {&c, header, 6, 6};
    pthread_t thw;
    pthread_create(&thw, NULL, writer_thread, &w);

    // Process once – this will block until the header is complete, then succeed
    TLOG("calling libp2p_yamux_process_one (expect OK after writer completes) ...");
    libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
    TLOG("process_one returned: %d", rc);
    int ok = (rc == LIBP2P_YAMUX_OK);

    pthread_join(thw, NULL);

    print_standard("yamux partial frame reading", ok ? "" : "process_one did not complete", ok);

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test stream flow control with window updates
 * This test ensures flow control works correctly with window updates
 */
static void test_stream_flow_control(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    // Open a stream
    uint32_t stream_id = 0;
    assert(libp2p_yamux_stream_open(cli, &stream_id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    // Reduce send window to test flow control
    pthread_mutex_lock(&cli->mtx);
    if (cli->num_streams > 0)
    {
        cli->streams[0]->send_window = 10; // Very small window
    }
    pthread_mutex_unlock(&cli->mtx);

    // Try to send more data than window allows
    uint8_t large_data[100];
    memset(large_data, 'x', sizeof(large_data));
    libp2p_yamux_err_t rc = libp2p_yamux_stream_send(cli, stream_id, large_data, sizeof(large_data), 0);

    // Should fail with AGAIN due to flow control
    int ok = (rc == LIBP2P_YAMUX_ERR_AGAIN);
    print_standard("yamux stream flow control", ok ? "" : "expected backpressure", ok);

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_yamux_serializes_concurrent_writes(void)
{
    race_conn_ctx_t rctx;
    atomic_init(&rctx.in_write, 0);
    atomic_init(&rctx.overlap, 0);

    libp2p_conn_t conn = {0};
    conn.vt = &RACE_CONN_VTBL;
    conn.ctx = &rctx;

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&conn, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    uint32_t sid1 = 0;
    uint32_t sid2 = 0;
    assert(libp2p_yamux_stream_open(ctx, &sid1) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_stream_open(ctx, &sid2) == LIBP2P_YAMUX_OK);

    const uint8_t payload1[] = "serial-one";
    const uint8_t payload2[] = "serial-two";

    yamux_send_args_t a1 = {.ctx = ctx, .stream_id = sid1, .buf = payload1, .len = sizeof(payload1) - 1, .rc = LIBP2P_YAMUX_OK};
    yamux_send_args_t a2 = {.ctx = ctx, .stream_id = sid2, .buf = payload2, .len = sizeof(payload2) - 1, .rc = LIBP2P_YAMUX_OK};

    pthread_t t1 = 0;
    pthread_t t2 = 0;
    pthread_create(&t1, NULL, yamux_send_thread, &a1);
    pthread_create(&t2, NULL, yamux_send_thread, &a2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    int overlap = atomic_load_explicit(&rctx.overlap, memory_order_acquire);
    int ok = (overlap == 0) && (a1.rc == LIBP2P_YAMUX_OK) && (a2.rc == LIBP2P_YAMUX_OK);
    print_standard("yamux serializes concurrent writes", ok ? "" : "detected overlapping writes", ok);

    libp2p_yamux_ctx_free(ctx);
    if (!ok)
        exit(1);
}

/**
 * Test basic stream data exchange without process loop
 * This test verifies that data can be sent and received between streams
 */
static void test_basic_stream_data_exchange(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    // Open a stream
    uint32_t stream_id = 0;
    assert(libp2p_yamux_stream_open(cli, &stream_id) == LIBP2P_YAMUX_OK);

    // Process the stream open on server
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    // Send data from client to server
    const char *test_data = "Hello yamux!";
    size_t test_len = strlen(test_data);
    assert(libp2p_yamux_stream_send(cli, stream_id, (const uint8_t *)test_data, test_len, 0) == LIBP2P_YAMUX_OK);

    // Process the data frame on server
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    // Receive data on server
    uint8_t recv_buf[64];
    size_t recv_len = 0;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(srv, stream_id, recv_buf, sizeof(recv_buf), &recv_len);

    int ok = (rc == LIBP2P_YAMUX_OK && recv_len == test_len && memcmp(recv_buf, test_data, test_len) == 0);
    print_standard("yamux basic stream data exchange", ok ? "" : "unexpected payload received", ok);

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

int main(void)
{
    /*
     * Silence verbose stderr logs from lower layers by default to keep
     * the test runtime within the ctest 60s timeout. Enable verbose
     * diagnostics by setting YAMUX_TEST_VERBOSE=1 in the environment.
     */
    const char *v = getenv("YAMUX_TEST_VERBOSE");
    if (!v || strcmp(v, "1") != 0)
    {
        FILE *devnull = fopen("/dev/null", "w");
        if (devnull)
        {
            (void)dup2(fileno(devnull), STDERR_FILENO);
            fclose(devnull);
        }
    }

    TLOG("MAIN START");
    RUN_ONE(test_negotiate);
    RUN_ONE(test_muxer_wrapper);
    RUN_ONE(test_frame_roundtrip);
    RUN_ONE(test_invalid_version);
    RUN_ONE(test_stream_id_zero);
    RUN_ONE(test_stream_id_parity);
    RUN_ONE(test_window_update);
    RUN_ONE(test_ping_pong);
    RUN_ONE(test_ping_callback);
    RUN_ONE(test_ping_bad_flags);
    RUN_ONE(test_go_away);
    RUN_ONE(test_stop_go_away);
    RUN_ONE(test_open_after_stop);
    RUN_ONE(test_ctx_free_go_away);
    RUN_ONE(test_go_away_flags);
    RUN_ONE(test_send_window);
    RUN_ONE(test_recv_window_update);
    RUN_ONE(test_initial_window_syn);
    RUN_ONE(test_initial_window_ack);
    RUN_ONE(test_delayed_ack);
    RUN_ONE(test_keepalive);
    RUN_ONE(test_large_frame);
    RUN_ONE(test_recv_go_away);

    // New regression tests for yamux fixes from debug report
    RUN_ONE(test_yamux_muxer_creation);
    RUN_ONE(test_yamux_frame_operations);
    RUN_ONE(test_multiple_concurrent_streams);
    RUN_ONE(test_muxer_context_storage);
    RUN_ONE(test_basic_stream_data_exchange);
    RUN_ONE(test_yamux_serializes_concurrent_writes);

    return 0;
}
