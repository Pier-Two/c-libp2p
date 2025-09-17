#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "libp2p/host.h"
#include "libp2p/metrics.h"
#include "libp2p/stream_internal.h"

typedef struct { int dummy; } fake_io_t;

static ssize_t fake_write(void *io_ctx, const void *buf, size_t len) {
    (void)io_ctx; (void)buf; return (ssize_t)len; /* pretend success */
}
static ssize_t fake_read(void *io_ctx, void *buf, size_t len) {
    (void)io_ctx; (void)buf; (void)len; return 0; /* no data */
}
static int fake_close(void *io_ctx){ (void)io_ctx; return 0; }
static int fake_reset(void *io_ctx){ (void)io_ctx; return 0; }
static int fake_deadline(void *io_ctx, uint64_t ms){ (void)io_ctx; (void)ms; return 0; }
static const multiaddr_t *fake_addr(void *io_ctx){ (void)io_ctx; return NULL; }

static const libp2p_stream_backend_ops_t OPS = {
    .read = fake_read,
    .write = fake_write,
    .close = fake_close,
    .reset = fake_reset,
    .set_deadline = fake_deadline,
    .local_addr = fake_addr,
    .remote_addr = fake_addr,
};

static double g_sent = 0.0;
static double g_recv = 0.0;
static void counter_cb(const char *name, const char *labels_json, double value, void *ud)
{
    (void)ud;
    if (!name) return;
    if (strcmp(name, "libp2p_bytes_sent") == 0) {
        g_sent += value;
        /* Ensure the protocol label is present */
        assert(labels_json && strstr(labels_json, "/test/1.0.0") != NULL);
    } else if (strcmp(name, "libp2p_bytes_received") == 0) {
        g_recv += value;
    }
}
static void hist_cb(const char *name, const char *labels_json, double value, void *ud)
{ (void)name; (void)labels_json; (void)value; (void)ud; }

int main(void)
{
    /* Metrics */
    libp2p_metrics_t *m = NULL;
    assert(libp2p_metrics_new(&m) == 0 && m);
    libp2p_metrics_set_writer(m, counter_cb, hist_cb, NULL);

    /* Minimal host */
    libp2p_host_t *host = NULL;
    const char *none[] = { NULL };
    assert(libp2p_host_new_default(none, 0, &host) == 0 && host);
    assert(libp2p_host_set_metrics(host, m) == 0);

    /* Build a stream bound to this host with fake ops */
    libp2p_stream_t *s = libp2p_stream_from_ops(host, NULL, &OPS, "/test/1.0.0", 1, NULL);
    assert(s);

    /* Write some bytes; metrics should reflect the total sent */
    char buf[128]; memset(buf, 'x', sizeof(buf));
    ssize_t n = libp2p_stream_write(s, buf, sizeof(buf));
    printf("write ret=%zd g_sent=%.0f expected=%zu\n", n, g_sent, sizeof(buf));
    assert(n == (ssize_t)sizeof(buf));
    assert(g_sent == (double)sizeof(buf));

    /* Cleanup */
    printf("closing stream...\n");
    (void)libp2p_stream_close(s);
    printf("closed stream. (skipping host_free in this unit test)\n");
    (void)host; /* intentionally leaked for this short-lived test process */
    printf("freeing metrics...\n");
    libp2p_metrics_free(m);
    printf("freed metrics.\n");

    printf("TEST: metrics counter on stream write | PASS\n");
    return 0;
}
