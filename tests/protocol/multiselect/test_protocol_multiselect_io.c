#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef _WIN32
#include "protocol/tcp/sys/socket.h"
#include <io.h>
#else
#include <sys/socket.h>
#endif

#include "protocol/multiselect/protocol_multiselect.h"
#include "libp2p/io.h"
#include "transport/connection.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed) printf("TEST: %-50s | PASS\n", test_name);
    else printf("TEST: %-50s | FAIL: %s\n", test_name, details ? details : "");
}

typedef struct { int rfd; int wfd; } pipe_ctx_t;

static ssize_t pipe_read(libp2p_conn_t *c, void *buf, size_t len)
{
    pipe_ctx_t *p = (pipe_ctx_t *)c->ctx;
    ssize_t n = read(p->rfd, buf, len);
    if (n > 0) return n;
    if (n == 0) return LIBP2P_CONN_ERR_EOF;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return LIBP2P_CONN_ERR_AGAIN;
    return LIBP2P_CONN_ERR_INTERNAL;
}
static ssize_t pipe_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    pipe_ctx_t *p = (pipe_ctx_t *)c->ctx;
    ssize_t n = write(p->wfd, buf, len);
    if (n >= 0) return n;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return LIBP2P_CONN_ERR_AGAIN;
    return LIBP2P_CONN_ERR_INTERNAL;
}
static libp2p_conn_err_t pipe_deadline(libp2p_conn_t *c, uint64_t ms) { (void)c; (void)ms; return LIBP2P_CONN_OK; }
static const multiaddr_t *pipe_addr(libp2p_conn_t *c) { (void)c; return NULL; }
static libp2p_conn_err_t pipe_close(libp2p_conn_t *c) { pipe_ctx_t *p=c->ctx; if (p){ if(p->rfd>2) close(p->rfd); if(p->wfd>2 && p->wfd!=p->rfd) close(p->wfd);} return LIBP2P_CONN_OK; }
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
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
        abort();
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    fcntl(sp[1], F_SETFL, O_NONBLOCK);
    pipe_ctx_t *actx = (pipe_ctx_t *)calloc(1, sizeof(*actx));
    pipe_ctx_t *bctx = (pipe_ctx_t *)calloc(1, sizeof(*bctx));
    actx->rfd = sp[0]; actx->wfd = sp[0];
    bctx->rfd = sp[1]; bctx->wfd = sp[1];
    a->vt = &PIPE_VTBL; a->ctx = actx;
    b->vt = &PIPE_VTBL; b->ctx = bctx;
}

typedef struct {
    libp2p_io_t *io;
    const char *const *supported;
    const char *accepted;
    libp2p_multiselect_err_t rc;
} listen_arg_t;

static void *listen_thread(void *arg)
{
    listen_arg_t *la = (listen_arg_t *)arg;
    libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
    cfg.enable_ls = true;
    la->rc = libp2p_multiselect_listen_io(la->io, la->supported, &cfg, &la->accepted);
    return NULL;
}

typedef struct {
    libp2p_io_t *io;
    const char *const *proposals;
    const char *accepted;
    libp2p_multiselect_err_t rc;
} dial_arg_t;

static void *dial_thread(void *arg)
{
    dial_arg_t *da = (dial_arg_t *)arg;
    da->rc = libp2p_multiselect_dial_io(da->io, da->proposals, 2000, &da->accepted);
    return NULL;
}

int main(void)
{
    libp2p_conn_t a = {0}, b = {0};
    make_pipe_pair(&a, &b);
    libp2p_io_t *aio = libp2p_io_from_conn(&a);
    libp2p_io_t *bio = libp2p_io_from_conn(&b);
    assert(aio && bio);

    const char *supported[] = { "/foo/1.0.0", "/bar/1.0.0", NULL };
    const char *proposals[] = { "/bar/1.0.0", "/baz/1.0.0", NULL };

    listen_arg_t la = { .io = bio, .supported = supported, .accepted = NULL, .rc = 0 };
    pthread_t tl; pthread_create(&tl, NULL, listen_thread, &la);

    dial_arg_t da = { .io = aio, .proposals = proposals, .accepted = NULL, .rc = 0 };
    pthread_t td; pthread_create(&td, NULL, dial_thread, &da);

    pthread_join(td, NULL);
    pthread_join(tl, NULL);

    int ok = (da.rc == LIBP2P_MULTISELECT_OK && la.rc == LIBP2P_MULTISELECT_OK && da.accepted && la.accepted && strcmp(da.accepted, "/bar/1.0.0") == 0 && strcmp(la.accepted, "/bar/1.0.0") == 0);
    print_standard("multiselect io negotiation", ok ? "" : "unexpected result", ok);

    libp2p_io_free(aio);
    libp2p_io_free(bio);
    libp2p_conn_close(&a);
    libp2p_conn_close(&b);
    libp2p_conn_free(&a);
    libp2p_conn_free(&b);
    return ok ? 0 : 1;
}
