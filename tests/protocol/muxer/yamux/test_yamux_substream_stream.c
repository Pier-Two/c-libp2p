#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef _WIN32
#include "protocol/tcp/sys/socket.h"
#include <io.h>
#else
#include <fcntl.h>
#include <sys/socket.h>
#endif

#include "libp2p/stream.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/muxer/yamux/yamux_stream_adapter.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", test_name);
    else
        printf("TEST: %-50s | FAIL: %s\n", test_name, details ? details : "");
}

typedef struct
{
    int rfd;
    int wfd;
    int closed;
    pthread_mutex_t mtx;
} pipe_ctx_t;
static ssize_t pipe_read(libp2p_conn_t *c, void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    pthread_mutex_lock(&p->mtx);
    if (p->closed)
    {
        pthread_mutex_unlock(&p->mtx);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    ssize_t n = read(p->rfd, buf, len);
    pthread_mutex_unlock(&p->mtx);
    if (n > 0)
        return n;
    if (n == 0)
        return LIBP2P_CONN_ERR_EOF;
    return LIBP2P_CONN_ERR_AGAIN;
}
static ssize_t pipe_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    pthread_mutex_lock(&p->mtx);
    if (p->closed)
    {
        pthread_mutex_unlock(&p->mtx);
        return LIBP2P_CONN_ERR_CLOSED;
    }
#ifdef MSG_NOSIGNAL
    ssize_t n = send(p->wfd, buf, len, MSG_NOSIGNAL);
#else
    ssize_t n = write(p->wfd, buf, len);
#endif
    pthread_mutex_unlock(&p->mtx);
    if (n >= 0)
        return n;
    return LIBP2P_CONN_ERR_AGAIN;
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
        pthread_mutex_lock(&p->mtx);
        if (!p->closed)
        {
            p->closed = 1;
            if (p->rfd > 2)
                close(p->rfd);
            if (p->wfd > 2 && p->wfd != p->rfd)
                close(p->wfd);
        }
        pthread_mutex_unlock(&p->mtx);
    }
    return LIBP2P_CONN_OK;
}
static void pipe_free(libp2p_conn_t *c)
{
    if (!c || !c->ctx)
        return;
    pipe_ctx_t *p = c->ctx;
    pthread_mutex_destroy(&p->mtx);
    free(p);
}
static const libp2p_conn_vtbl_t PIPE_VTBL = {.read = pipe_read,
                                             .write = pipe_write,
                                             .set_deadline = pipe_deadline,
                                             .local_addr = pipe_addr,
                                             .remote_addr = pipe_addr,
                                             .close = pipe_close,
                                             .free = pipe_free};

static void make_pair(libp2p_conn_t *a, libp2p_conn_t *b)
{
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
        abort();
#ifndef _WIN32
    /* Make both ends non-blocking to avoid indefinite blocking in reads */
    int fl0 = fcntl(sp[0], F_GETFL, 0);
    if (fl0 != -1)
        fcntl(sp[0], F_SETFL, fl0 | O_NONBLOCK);
    int fl1 = fcntl(sp[1], F_GETFL, 0);
    if (fl1 != -1)
        fcntl(sp[1], F_SETFL, fl1 | O_NONBLOCK);
#endif
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(sp[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    (void)setsockopt(sp[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    pipe_ctx_t *ac = calloc(1, sizeof(*ac));
    pipe_ctx_t *bc = calloc(1, sizeof(*bc));
    ac->rfd = sp[0];
    ac->wfd = sp[0];
    pthread_mutex_init(&ac->mtx, NULL);
    a->vt = &PIPE_VTBL;
    a->ctx = ac;
    bc->rfd = sp[1];
    bc->wfd = sp[1];
    pthread_mutex_init(&bc->mtx, NULL);
    b->vt = &PIPE_VTBL;
    b->ctx = bc;
}

static void *loop_thread(void *arg)
{
    libp2p_yamux_ctx_t *ctx = arg;
    libp2p_yamux_process_loop(ctx);
    return NULL;
}

static libp2p_yamux_err_t g_out_rc, g_in_rc;
static void *neg_out(void *p)
{
    g_out_rc = libp2p_yamux_negotiate_outbound((libp2p_conn_t *)p, 2000);
    return NULL;
}
static void *neg_in(void *p)
{
    g_in_rc = libp2p_yamux_negotiate_inbound((libp2p_conn_t *)p, 2000);
    return NULL;
}

int main(void)
{
    libp2p_conn_t a = {0}, b = {0};
    make_pair(&a, &b);
    /* Negotiate yamux over raw conn (concurrently) */
    pthread_t tn1, tn2;
    pthread_create(&tn1, NULL, neg_out, &a);
    pthread_create(&tn2, NULL, neg_in, &b);
    pthread_join(tn1, NULL);
    pthread_join(tn2, NULL);
    assert(g_out_rc == LIBP2P_YAMUX_OK && g_in_rc == LIBP2P_YAMUX_OK);
    /* Create contexts */
    libp2p_yamux_ctx_t *ca = libp2p_yamux_ctx_new(&a, 1, 256 * 1024);
    libp2p_yamux_ctx_t *cb = libp2p_yamux_ctx_new(&b, 0, 256 * 1024);
    assert(ca && cb);
    /* Run loops */
    pthread_t ta, tb;
    pthread_create(&ta, NULL, loop_thread, ca);
    pthread_create(&tb, NULL, loop_thread, cb);
    /* Open a stream on A and accept on B */
    uint32_t sid = 0;
    assert(libp2p_yamux_stream_open(ca, &sid) == LIBP2P_YAMUX_OK);
    libp2p_yamux_stream_t *yst = NULL;
    int spins = 0;
    while (libp2p_yamux_accept_stream(cb, &yst) != LIBP2P_YAMUX_OK || !yst)
    {
        usleep(1000);
        if (++spins > 5000)
            break;
    }
    assert(yst && yst->id);
    /* Wrap as libp2p_stream on both ends */
    libp2p_stream_t *sa = libp2p_stream_from_yamux(NULL, ca, sid, "/test/1.0.0", 1, NULL);
    libp2p_stream_t *sb = libp2p_stream_from_yamux(NULL, cb, yst->id, "/test/1.0.0", 0, NULL);
    assert(sa && sb);
    /* Verify roundtrip */
    const char *msg = "ping";
    ssize_t wn = libp2p_stream_write(sa, msg, strlen(msg));
    assert(wn == (ssize_t)strlen(msg));
    char buf[16];
    ssize_t rn = 0;
    spins = 0;
    do
    {
        rn = libp2p_stream_read(sb, buf, sizeof(buf));
        if (rn == LIBP2P_ERR_AGAIN)
        {
            usleep(1000);
        }
    } while (rn == LIBP2P_ERR_AGAIN && ++spins < 2000);
    int ok = (rn == (ssize_t)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0);
    print_standard("yamux substream as libp2p_stream", ok ? "" : "mismatch", ok);
    /* Cleanup */
    libp2p_stream_close(sa);
    libp2p_stream_close(sb);
    libp2p_stream_free(sa);
    libp2p_stream_free(sb);
    libp2p_yamux_stop(ca);
    libp2p_yamux_stop(cb);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    libp2p_yamux_ctx_free(ca);
    libp2p_yamux_ctx_free(cb);
    libp2p_conn_close(&a);
    libp2p_conn_close(&b);
    libp2p_conn_free(&a);
    libp2p_conn_free(&b);
    return ok ? 0 : 1;
}
