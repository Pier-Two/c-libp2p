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

#include "libp2p/io.h"
#include "libp2p/lpmsg.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "transport/connection.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed) printf("TEST: %-50s | PASS\n", test_name);
    else printf("TEST: %-50s | FAIL: %s\n", test_name, details ? details : "");
}

typedef struct { int rfd; int wfd; } pipe_ctx_t;

static ssize_t pipe_read(libp2p_conn_t *c, void *buf, size_t len)
{ pipe_ctx_t *p=(pipe_ctx_t*)c->ctx; ssize_t n = read(p->rfd, buf, len); if (n>0) return n; if(n==0) return LIBP2P_CONN_ERR_EOF; if(errno==EAGAIN||errno==EWOULDBLOCK) return LIBP2P_CONN_ERR_AGAIN; return LIBP2P_CONN_ERR_INTERNAL; }
static ssize_t pipe_write(libp2p_conn_t *c, const void *buf, size_t len)
{ pipe_ctx_t *p=(pipe_ctx_t*)c->ctx; ssize_t n = write(p->wfd, buf, len); if(n>=0) return n; if(errno==EAGAIN||errno==EWOULDBLOCK) return LIBP2P_CONN_ERR_AGAIN; return LIBP2P_CONN_ERR_INTERNAL; }
static libp2p_conn_err_t pipe_deadline(libp2p_conn_t *c, uint64_t ms){(void)c;(void)ms;return LIBP2P_CONN_OK;}
static const multiaddr_t *pipe_addr(libp2p_conn_t *c){(void)c;return NULL;}
static libp2p_conn_err_t pipe_close(libp2p_conn_t *c){pipe_ctx_t *p=c->ctx; if(p){ if(p->rfd>2) close(p->rfd); if(p->wfd>2 && p->wfd!=p->rfd) close(p->wfd);} return LIBP2P_CONN_OK;}
static void pipe_free(libp2p_conn_t *c){ free(c->ctx); }

static const libp2p_conn_vtbl_t PIPE_VTBL = {
    .read = pipe_read,
    .write = pipe_write,
    .set_deadline = pipe_deadline,
    .local_addr = pipe_addr,
    .remote_addr = pipe_addr,
    .close = pipe_close,
    .free = pipe_free,
};

static void make_pair(libp2p_conn_t *a, libp2p_conn_t *b)
{
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) abort();
    fcntl(sp[0], F_SETFL, O_NONBLOCK); fcntl(sp[1], F_SETFL, O_NONBLOCK);
    pipe_ctx_t *actx = (pipe_ctx_t *)calloc(1, sizeof(*actx));
    pipe_ctx_t *bctx = (pipe_ctx_t *)calloc(1, sizeof(*bctx));
    actx->rfd = sp[0]; actx->wfd = sp[0]; a->vt = &PIPE_VTBL; a->ctx = actx;
    bctx->rfd = sp[1]; bctx->wfd = sp[1]; b->vt = &PIPE_VTBL; b->ctx = bctx;
}

static void test_lp_recv_io_basic(void)
{
    libp2p_conn_t a = {0}, b = {0};
    make_pair(&a, &b);
    libp2p_io_t *aio = libp2p_io_from_conn(&a);
    libp2p_io_t *bio = libp2p_io_from_conn(&b);
    const char *msg = "hello";
    uint8_t hdr[10]; size_t hlen = 0; unsigned_varint_encode(strlen(msg), hdr, sizeof(hdr), &hlen);
    /* Write header+payload on B → read on A */
    ssize_t wn = libp2p_io_write(bio, hdr, hlen); (void)wn;
    wn = libp2p_io_write(bio, msg, strlen(msg)); (void)wn;
    uint8_t buf[32]; ssize_t rn = libp2p_lp_recv_io(aio, buf, sizeof(buf));
    int ok = (rn == (ssize_t)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0);
    print_standard("lpmsg io basic", ok ? "" : "mismatch", ok);
    libp2p_io_free(aio); libp2p_io_free(bio);
    libp2p_conn_close(&a); libp2p_conn_close(&b); libp2p_conn_free(&a); libp2p_conn_free(&b);
}

static void test_lp_recv_io_too_large(void)
{
    libp2p_conn_t a = {0}, b = {0};
    make_pair(&a, &b);
    libp2p_io_t *aio = libp2p_io_from_conn(&a);
    libp2p_io_t *bio = libp2p_io_from_conn(&b);
    uint8_t hdr[10]; size_t hlen = 0; unsigned_varint_encode(1000, hdr, sizeof(hdr), &hlen);
    libp2p_io_write(bio, hdr, hlen);
    uint8_t buf[8]; ssize_t rn = libp2p_lp_recv_io(aio, buf, sizeof(buf));
    int ok = (rn == LIBP2P_ERR_MSG_TOO_LARGE);
    print_standard("lpmsg io too-large", ok ? "" : "expected MSG_TOO_LARGE", ok);
    libp2p_io_free(aio); libp2p_io_free(bio);
    libp2p_conn_close(&a); libp2p_conn_close(&b); libp2p_conn_free(&a); libp2p_conn_free(&b);
}

int main(void)
{
    test_lp_recv_io_basic();
    test_lp_recv_io_too_large();
    return 0;
}
