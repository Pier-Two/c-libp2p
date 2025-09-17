#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>

#include "libp2p/host_builder.h"
#include "libp2p/dial.h"
#include "libp2p/cancel.h"

typedef struct {
    atomic_int called;
    int err;
} cb_state_t;

static void on_open_cb(libp2p_stream_t *s, void *user_data, int err)
{
    (void)s;
    cb_state_t *st = (cb_state_t *)user_data;
    st->err = err;
    atomic_store(&st->called, 1);
}

int main(void)
{
    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b) return 1;
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    (void)libp2p_host_builder_muxer(b, "yamux");
    (void)libp2p_host_builder_multistream(b, 2000, true);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(b, &host) != 0 || !host)
    {
        libp2p_host_builder_free(b);
        return 2;
    }
    libp2p_host_builder_free(b);

    libp2p_dial_opts_t opts = {0};
    opts.struct_size = sizeof(opts);
    opts.remote_multiaddr = "/ip4/127.0.0.1/tcp/65535"; /* closed port; won't matter */
    opts.protocol_id = "/ping/1.0.0";
    opts.timeout_ms = 10000; /* long enough that cancel should be seen first */
    opts.enable_happy_eyeballs = false;

    libp2p_cancel_token_t *tok = libp2p_cancel_token_new();
    if (!tok)
    {
        libp2p_host_free(host);
        return 3;
    }
    libp2p_cancel_token_cancel(tok);

    cb_state_t st = {0};
    atomic_store(&st.called, 0);
    st.err = 0;

    int rc = libp2p_host_dial_opts_cancellable(host, &opts, tok, on_open_cb, &st);
    if (rc != LIBP2P_ERR_CANCELED)
    {
        libp2p_cancel_token_free(tok);
        libp2p_host_free(host);
        return 4;
    }

    /* Wait up to ~1s for callback */
    struct timespec ts = {0, 10000000}; /* 10ms */
    int spins = 0;
    while (!atomic_load(&st.called) && spins++ < 200)
        nanosleep(&ts, NULL);

    libp2p_cancel_token_free(tok);
    libp2p_host_free(host);

    if (!atomic_load(&st.called))
        return 5;
    if (st.err != LIBP2P_ERR_CANCELED)
        return 6;
    return 0;
}

