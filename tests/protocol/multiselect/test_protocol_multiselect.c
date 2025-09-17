#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/tcp/protocol_tcp.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

/* ------------------------------------------------------------------------- */
/*  Test parameters                                                          */
/* ------------------------------------------------------------------------- */

static const char *const g_proposals[] = {"/other/1.0.0", "/myproto/1.0.0", NULL};

static const char *const g_supported[] = {"/myproto/1.0.0", "/other/1.0.0", NULL};

static const char *g_dial_result = NULL;
static char g_listen_result[64] = {0};

/* ------------------------------------------------------------------------- */
/*  Helper utilities                                                         */
/* ------------------------------------------------------------------------- */

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
    {
        printf("TEST: %-50s | PASS\n", test_name);
    }
    else
    {
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
    }
}

static void conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    while (len)
    {
        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
            continue;
        assert(0 && "conn_write failed");
    }
}

static void send_raw_msg(libp2p_conn_t *c, const char *msg)
{
    uint8_t var[10];
    const size_t payload_len = strlen(msg) + 1; /* include newline */
    size_t vlen;
    int rc = unsigned_varint_encode((uint64_t)payload_len, var, sizeof(var), &vlen);
    assert(rc == UNSIGNED_VARINT_OK);

    const size_t frame_len = vlen + payload_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    assert(frame);
    memcpy(frame, var, vlen);
    memcpy(frame + vlen, msg, payload_len - 1);
    frame[vlen + payload_len - 1] = '\n';

    conn_write_all(c, frame, frame_len);
    free(frame);
}

/* ------------------------------------------------------------------------- */
/*  Dialer thread                                                            */
/* ------------------------------------------------------------------------- */

static void *dial_thread(void *arg)
{
    libp2p_conn_t *c = (libp2p_conn_t *)arg;
    const char *accepted = NULL;
    fprintf(stderr, "[TEST_MS] dial_thread: starting libp2p_multiselect_dial()\n");
    libp2p_multiselect_err_t rc = libp2p_multiselect_dial(c, g_proposals, 5000, &accepted);
    fprintf(stderr, "[TEST_MS] dial_thread: libp2p_multiselect_dial() rc=%d accepted=%s\n", (int)rc, accepted ? accepted : "(null)");
    assert(rc == LIBP2P_MULTISELECT_OK);
    g_dial_result = accepted; /* pointer from proposals array */
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*  Listener thread                                                          */
/* ------------------------------------------------------------------------- */

static void *listen_thread(void *arg)
{
    libp2p_conn_t *s = (libp2p_conn_t *)arg;
    const char *accepted_heap = NULL;
    fprintf(stderr, "[TEST_MS] listen_thread: starting libp2p_multiselect_listen()\n");
    libp2p_multiselect_err_t rc = libp2p_multiselect_listen(s, g_supported, NULL, &accepted_heap);
    fprintf(stderr, "[TEST_MS] listen_thread: libp2p_multiselect_listen() rc=%d accepted=%s\n", (int)rc, accepted_heap ? accepted_heap : "(null)");
    assert(rc == LIBP2P_MULTISELECT_OK);
    strncpy(g_listen_result, accepted_heap, sizeof(g_listen_result) - 1);
    free((void *)accepted_heap);
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*  Test cases                                                               */
/* ------------------------------------------------------------------------- */

static void test_handshake_success(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);
    fprintf(stderr, "[TEST_MS] test_handshake_success: created tcp transport\n");

    int ma_err;
    /* Bind to an ephemeral port to avoid collisions with other parallel tests */
    multiaddr_t *bind_addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/0", &ma_err);
    assert(bind_addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    fprintf(stderr, "[TEST_MS] test_handshake_success: listening on /ip4/127.0.0.1/tcp/0\n");
    {
        int rc_listen = libp2p_transport_listen(tcp, bind_addr, &lst);
        fprintf(stderr, "[TEST_MS] test_handshake_success: listen rc=%d lst=%p\n", rc_listen, (void*)lst);
        assert(rc_listen == LIBP2P_TRANSPORT_OK && lst != NULL);
        fprintf(stderr, "[TEST_MS] test_handshake_success: listen established\n");
    }

    /* Discover the actual bound address (with the real port) */
    multiaddr_t *dial_addr = NULL;
    libp2p_listener_err_t la_rc = libp2p_listener_local_addr(lst, &dial_addr);
    fprintf(stderr, "[TEST_MS] test_handshake_success: libp2p_listener_local_addr rc=%d\n", (int)la_rc);
    if (!dial_addr)
    {
        int se = 0;
        char *bind_str = multiaddr_to_str(bind_addr, &se);
        fprintf(stderr, "[TEST_MS] test_handshake_success: dial_addr is NULL, bind_addr=%s (err=%d)\n", bind_str ? bind_str : "(null)", se);
        free(bind_str);
    }
    assert(la_rc == LIBP2P_LISTENER_OK);
    assert(dial_addr);
    {
        int se = 0;
        char *addr_str = multiaddr_to_str(dial_addr, &se);
        fprintf(stderr, "[TEST_MS] test_handshake_success: listener local addr: %s (err=%d)\n", addr_str ? addr_str : "(null)", se);
        free(addr_str);
    }

    libp2p_conn_t *c = NULL;
    fprintf(stderr, "[TEST_MS] test_handshake_success: dialing...\n");
    {
        int rc_dial = libp2p_transport_dial(tcp, dial_addr, &c);
        fprintf(stderr, "[TEST_MS] test_handshake_success: dial rc=%d c=%p\n", rc_dial, (void*)c);
        assert(rc_dial == LIBP2P_TRANSPORT_OK && c != NULL);
        fprintf(stderr, "[TEST_MS] test_handshake_success: dialed\n");
    }

    libp2p_conn_t *s = NULL;
    fprintf(stderr, "[TEST_MS] test_handshake_success: waiting accept...\n");
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);
    fprintf(stderr, "[TEST_MS] test_handshake_success: accepted inbound conn\n");

    pthread_t tid_dial, tid_listen;
    fprintf(stderr, "[TEST_MS] test_handshake_success: starting threads\n");
    assert(pthread_create(&tid_dial, NULL, dial_thread, c) == 0);
    assert(pthread_create(&tid_listen, NULL, listen_thread, s) == 0);

    pthread_join(tid_dial, NULL);
    pthread_join(tid_listen, NULL);

    assert(strcmp(g_dial_result, "/other/1.0.0") == 0);
    assert(strcmp(g_listen_result, "/other/1.0.0") == 0);

    {
        char test_name[128];
        sprintf(test_name, "multiselect handshake successful: %s", g_dial_result);
        print_standard(test_name, "", 1);
    }

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(bind_addr);
    multiaddr_free(dial_addr);
    libp2p_transport_free(tcp);
}

static void test_reject_missing_header(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);
    fprintf(stderr, "[TEST_MS] test_reject_missing_header: created tcp transport\n");

    int ma_err;
    /* Bind to an ephemeral port to avoid collisions with other parallel tests */
    multiaddr_t *bind_addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/0", &ma_err);
    assert(bind_addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    fprintf(stderr, "[TEST_MS] test_reject_missing_header: listening on /ip4/127.0.0.1/tcp/0\n");
    {
        int rc_listen2 = libp2p_transport_listen(tcp, bind_addr, &lst);
        fprintf(stderr, "[TEST_MS] test_reject_missing_header: listen rc=%d lst=%p\n", rc_listen2, (void*)lst);
        assert(rc_listen2 == LIBP2P_TRANSPORT_OK && lst != NULL);
        fprintf(stderr, "[TEST_MS] test_reject_missing_header: listen established\n");
    }

    /* Discover the actual bound address (with the real port) */
    multiaddr_t *dial_addr = NULL;
    libp2p_listener_err_t la2_rc = libp2p_listener_local_addr(lst, &dial_addr);
    fprintf(stderr, "[TEST_MS] test_reject_missing_header: libp2p_listener_local_addr rc=%d\n", (int)la2_rc);
    if (!dial_addr)
    {
        int se = 0;
        char *bind_str = multiaddr_to_str(bind_addr, &se);
        fprintf(stderr, "[TEST_MS] test_reject_missing_header: dial_addr is NULL, bind_addr=%s (err=%d)\n", bind_str ? bind_str : "(null)", se);
        free(bind_str);
    }
    assert(la2_rc == LIBP2P_LISTENER_OK);
    assert(dial_addr);
    {
        int se = 0;
        char *addr_str = multiaddr_to_str(dial_addr, &se);
        fprintf(stderr, "[TEST_MS] test_reject_missing_header: listener local addr: %s (err=%d)\n", addr_str ? addr_str : "(null)", se);
        free(addr_str);
    }

    libp2p_conn_t *c = NULL;
    fprintf(stderr, "[TEST_MS] test_reject_missing_header: dialing...\n");
    {
        int rc_dial2 = libp2p_transport_dial(tcp, dial_addr, &c);
        fprintf(stderr, "[TEST_MS] test_reject_missing_header: dial rc=%d c=%p\n", rc_dial2, (void*)c);
        assert(rc_dial2 == LIBP2P_TRANSPORT_OK && c != NULL);
        fprintf(stderr, "[TEST_MS] test_reject_missing_header: dialed\n");
    }

    libp2p_conn_t *s = NULL;
    fprintf(stderr, "[TEST_MS] test_reject_missing_header: waiting accept...\n");
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);
    fprintf(stderr, "[TEST_MS] test_reject_missing_header: accepted inbound conn\n");

    /* Send invalid message before the multistream header */
    send_raw_msg(s, "ls");

    const char *accepted = NULL;
    libp2p_multiselect_err_t rc = libp2p_multiselect_dial(c, g_proposals, 1000, &accepted);
    assert(rc == LIBP2P_MULTISELECT_ERR_PROTO_MAL);

    print_standard("multiselect handshake aborted on invalid header", "", 1);

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(bind_addr);
    multiaddr_free(dial_addr);
    libp2p_transport_free(tcp);
}

/* ------------------------------------------------------------------------- */
/*  Main                                                                     */
/* ------------------------------------------------------------------------- */

int main(void)
{
    test_handshake_success();
    test_reject_missing_header();
    return 0;
}
