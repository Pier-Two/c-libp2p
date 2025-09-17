#include "protocol/ping/protocol_ping.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#define pipe(fds) _pipe(fds, 4096, _O_BINARY)
#define read_func _read
#define write_func _write
#define close_func _close
#else
#include <fcntl.h>
#include <unistd.h>
#define read_func read
#define write_func write
#define close_func close
#endif

typedef struct
{
    int rfd;
    int wfd;
} pipe_ctx_t;

static ssize_t pipe_read(libp2p_conn_t *c, void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    ssize_t n = read_func(p->rfd, buf, len);
    if (n > 0)
        return n;
    if (n == 0)
        return LIBP2P_CONN_ERR_EOF;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return LIBP2P_CONN_ERR_AGAIN;
    fprintf(stdout, "pipe_read: unexpected errno=%d (rfd=%d)\n", errno, p->rfd);
    return LIBP2P_CONN_ERR_INTERNAL;
}

static ssize_t pipe_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    ssize_t n = write_func(p->wfd, buf, len);
    if (n >= 0)
        return n;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return LIBP2P_CONN_ERR_AGAIN;
    fprintf(stdout, "pipe_write: unexpected errno=%d (wfd=%d)\n", errno, p->wfd);
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
        close_func(p->rfd);
        close_func(p->wfd);
    }
    return LIBP2P_CONN_OK;
}

static void pipe_free(libp2p_conn_t *c) { free(c->ctx); }

static const libp2p_conn_vtbl_t PIPE_VTBL = {
    .read = pipe_read,
    .write = pipe_write,
    .set_deadline = pipe_deadline,
    .local_addr = pipe_addr,
    .remote_addr = pipe_addr,
    .close = pipe_close,
    .free = pipe_free,
};

static void make_pipe_pair(libp2p_conn_t *a, libp2p_conn_t *b)
{
    int ab[2];
    int ba[2];
    int rc1 = pipe(ab);
    int rc2 = pipe(ba);
    assert(rc1 == 0 && rc2 == 0);
#ifndef _WIN32
    fcntl(ab[0], F_SETFL, O_NONBLOCK);
    fcntl(ab[1], F_SETFL, O_NONBLOCK);
    fcntl(ba[0], F_SETFL, O_NONBLOCK);
    fcntl(ba[1], F_SETFL, O_NONBLOCK);
#endif
    pipe_ctx_t *actx = malloc(sizeof(*actx));
    pipe_ctx_t *bctx = malloc(sizeof(*bctx));
    assert(actx && bctx);
    actx->rfd = ba[0];
    actx->wfd = ab[1];
    bctx->rfd = ab[0];
    bctx->wfd = ba[1];
    // Pipes created; assign vtables/contexts
    a->vt = &PIPE_VTBL;
    a->ctx = actx;
    b->vt = &PIPE_VTBL;
    b->ctx = bctx;
}

static void print_standard(const char *name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", name);
    else
        printf("TEST: %-50s | FAIL: %s\n", name, details);
}

static void *serve_thread(void *arg)
{
    libp2p_conn_t *c = arg;
    libp2p_ping_serve(c);
    return NULL;
}

int main(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);
    // Start a serving thread on one end
    pthread_t th;
    pthread_create(&th, NULL, serve_thread, &s);

    uint64_t rtt = 0;
    libp2p_ping_err_t rc = libp2p_ping_roundtrip(&c, 1000, &rtt);
    libp2p_conn_close(&c);
    pthread_join(th, NULL);
    int ok = (rc == LIBP2P_PING_OK);
    print_standard("ping roundtrip", ok ? "" : "failed", ok);

    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
    return ok ? 0 : 1;
}
