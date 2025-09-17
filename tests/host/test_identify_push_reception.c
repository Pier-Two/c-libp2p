#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/events.h"
#include "libp2p/lpmsg.h"
#include "peer_id/peer_id.h"
#include "protocol/identify/protocol_identify.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#include "identify_test_utils.h"

static void print_case(const char *name, int ok)
{
    printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL");
}

typedef struct
{
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int done;
    char *addr;
    libp2p_event_kind_t kind;
} addr_wait_ctx_t;

static void addr_wait_cb(const libp2p_event_t *evt, void *ud)
{
    addr_wait_ctx_t *ctx = (addr_wait_ctx_t *)ud;
    if (!ctx || !evt || evt->kind != ctx->kind)
        return;

    const char *addr = NULL;
    switch (evt->kind)
    {
        case LIBP2P_EVT_LISTEN_ADDR_ADDED:
            addr = evt->u.listen_addr_added.addr;
            break;
        case LIBP2P_EVT_NEW_EXTERNAL_ADDR_OF_PEER:
            addr = evt->u.new_external_addr_of_peer.addr;
            break;
        case LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE:
            addr = evt->u.new_external_addr_candidate.addr;
            break;
        case LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED:
            addr = evt->u.external_addr_confirmed.addr;
            break;
        default:
            break;
    }
    if (!addr)
        return;

    pthread_mutex_lock(&ctx->mtx);
    if (!ctx->done)
    {
        char *dup = strdup(addr);
        if (dup)
        {
            ctx->addr = dup;
            ctx->done = 1;
            pthread_cond_signal(&ctx->cv);
        }
    }
    pthread_mutex_unlock(&ctx->mtx);
}

static int wait_for_event_addr(libp2p_host_t *h,
                               libp2p_event_kind_t kind,
                               char **out,
                               int timeout_ms,
                               void (*trigger_cb)(void *),
                               void *trigger_ud)
{
    if (!h || !out || timeout_ms < 0)
        return 0;

    addr_wait_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.kind = kind;
    pthread_mutex_init(&ctx.mtx, NULL);
    pthread_cond_init(&ctx.cv, NULL);

    libp2p_subscription_t *sub = NULL;
    if (libp2p_event_subscribe(h, addr_wait_cb, &ctx, &sub) != 0)
    {
        pthread_cond_destroy(&ctx.cv);
        pthread_mutex_destroy(&ctx.mtx);
        return 0;
    }

    if (trigger_cb)
        trigger_cb(trigger_ud);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L)
    {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&ctx.mtx);
    int rc = 0;
    while (!ctx.done && rc == 0)
    {
        rc = pthread_cond_timedwait(&ctx.cv, &ctx.mtx, &ts);
        if (rc == ETIMEDOUT)
            break;
    }
    int success = ctx.done;
    pthread_mutex_unlock(&ctx.mtx);

    libp2p_event_unsubscribe(h, sub);
    pthread_cond_destroy(&ctx.cv);
    pthread_mutex_destroy(&ctx.mtx);

    if (success && ctx.addr)
    {
        *out = ctx.addr;
        return 1;
    }
    free(ctx.addr);
    return 0;
}

typedef struct
{
    libp2p_host_t *ha;
    libp2p_host_t *hb;
    int rc;
} start_hosts_ctx_t;

static void start_hosts_cb(void *ud)
{
    start_hosts_ctx_t *ctx = (start_hosts_ctx_t *)ud;
    if (!ctx)
        return;
    if (ctx->ha && libp2p_host_start(ctx->ha) != 0)
        ctx->rc = 1;
    if (ctx->hb && libp2p_host_start(ctx->hb) != 0)
        ctx->rc = 1;
}

/* Build a protobuf-encoded PrivateKey for Secp256k1 from a 32-byte seed */
static int build_secp256k1_private_key_pb(const uint8_t *seed32, size_t seed_len, uint8_t **out, size_t *out_len)
{
    if (!seed32 || seed_len != 32 || !out || !out_len) return -1;
    /* tag1=0x08, type=1; tag2=0x12, len=32, data=seed */
    uint8_t buf[1 + 2 + 1 + 2 + 32];
    size_t off = 0;
    buf[off++] = 0x08; /* field 1 varint */
    size_t sz = 0;
    unsigned_varint_encode(2, buf + off, sizeof(buf) - off, &sz); off += sz; /* KeyType=2 (Secp256k1) */
    buf[off++] = 0x12; /* field 2 length-delimited */
    unsigned_varint_encode(32, buf + off, sizeof(buf) - off, &sz); off += sz;
    memcpy(buf + off, seed32, 32); off += 32;
    uint8_t *ret = (uint8_t *)malloc(off);
    if (!ret) return -1;
    memcpy(ret, buf, off);
    *out = ret;
    *out_len = off;
    return 0;
}

int main(void)
{
    fprintf(stderr, "[TEST_RCV] start\n");
    /* Build two hosts and set identities */
    libp2p_host_builder_t *ba = libp2p_host_builder_new();
    libp2p_host_builder_t *bb = libp2p_host_builder_new();
    if (!ba || !bb) return 1;
    (void)libp2p_host_builder_listen_addr(ba, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_listen_addr(bb, "/ip4/127.0.0.1/tcp/0");
    (void)libp2p_host_builder_transport(ba, "tcp");
    (void)libp2p_host_builder_transport(bb, "tcp");
    (void)libp2p_host_builder_security(ba, "noise");
    (void)libp2p_host_builder_security(bb, "noise");
    (void)libp2p_host_builder_muxer(ba, "yamux");
    (void)libp2p_host_builder_muxer(bb, "yamux");

    /* Disable inbound auto-identify to avoid handshake contention in tests */
    (void)libp2p_host_builder_flags(ba, LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);
    (void)libp2p_host_builder_flags(bb, LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);

    libp2p_host_t *ha = NULL, *hb = NULL;
    if (libp2p_host_builder_build(ba, &ha) != 0 || libp2p_host_builder_build(bb, &hb) != 0 || !ha || !hb)
        return 1;
    libp2p_host_builder_free(ba); libp2p_host_builder_free(bb);

    uint8_t seedA[32], seedB[32];
    for (int i = 0; i < 32; i++) { seedA[i] = (uint8_t)(i + 1); seedB[i] = (uint8_t)(0xAA - i); }
    uint8_t *pkA = NULL, *pkB = NULL; size_t pkAL = 0, pkBL = 0;
    if (build_secp256k1_private_key_pb(seedA, 32, &pkA, &pkAL) != 0) return 1;
    if (build_secp256k1_private_key_pb(seedB, 32, &pkB, &pkBL) != 0) { free(pkA); return 1; }
    if (libp2p_host_set_private_key(ha, pkA, pkAL) != 0 || libp2p_host_set_private_key(hb, pkB, pkBL) != 0)
    { free(pkA); free(pkB); return 1; }
    free(pkA); free(pkB);

    /* Start both hosts (triggered within the event wait) */
    fprintf(stderr, "[TEST_RCV] hosts built; starting\n");

    /* Get hb listening address from events */
    char *addrB = NULL;
    fprintf(stderr, "[TEST_RCV] waiting for hb listen addr\n");
    start_hosts_ctx_t start_ctx = {.ha = ha, .hb = hb, .rc = 0};
    if (!wait_for_event_addr(hb, LIBP2P_EVT_LISTEN_ADDR_ADDED, &addrB, 3000, start_hosts_cb, &start_ctx) || start_ctx.rc != 0)
        return 1;

    /* Build local Identify payload for A and push to B */
    libp2p_stream_t *push = NULL;
    fprintf(stderr, "[TEST_RCV] dialing identify-push to hb at %s\n", addrB);
    if (libp2p_host_dial_protocol_blocking(ha, addrB, LIBP2P_IDENTIFY_PUSH_PROTO_ID, 3000, &push) != 0 || !push)
    { free(addrB); return 1; }
    fprintf(stderr, "[TEST_RCV] dial returned; sending payload\n");
    uint8_t *payload = NULL; size_t plen = 0;
    if (libp2p_identify_encode_local(ha, NULL, 0, &payload, &plen) != 0 || !payload)
    { free(addrB); libp2p_stream_close(push); return 1; }

    peer_id_t *pidA = NULL; (void)libp2p_host_get_peer_id(ha, &pidA);
    protocols_update_waiter_t waiter;
    if (!hb || !protocols_update_waiter_start(&waiter, hb, pidA, "[TEST_RCV]"))
    {
        libp2p_stream_close(push);
        free(payload);
        free(addrB);
        return 1;
    }

    if (libp2p_lp_send(push, payload, plen) < 0)
    {
        protocols_update_waiter_stop(&waiter, hb);
        libp2p_stream_close(push);
        free(payload);
        free(addrB);
        if (pidA) { peer_id_destroy(pidA); free(pidA); }
        return 1;
    }
    if (!protocols_update_waiter_wait(&waiter, 5000))
    {
        protocols_update_waiter_stop(&waiter, hb);
        libp2p_stream_close(push);
        free(payload);
        free(addrB);
        if (pidA) { peer_id_destroy(pidA); free(pidA); }
        return 1;
    }
    protocols_update_waiter_stop(&waiter, hb);
    fprintf(stderr, "[TEST_RCV] sent payload (%zu bytes); closing push stream\n", plen);
    libp2p_stream_close(push);
    free(payload);

    /* Verify hb.peerstore now lists a protocol for ha's peer id */
    const char **protos = NULL; size_t n = 0;
    int ok = 0;
    fprintf(stderr, "[TEST_RCV] checking hb.peerstore protocols for A\n");
    if (hb)
    {
        int lookup_rc = libp2p_host_peer_protocols(hb, pidA, &protos, &n);
        if (lookup_rc == LIBP2P_ERR_AGAIN)
        {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000L };
            nanosleep(&ts, NULL);
            lookup_rc = libp2p_host_peer_protocols(hb, pidA, &protos, &n);
        }
        if (lookup_rc == 0 && n > 0)
        {
            /* Expect identify protocol among supported */
            for (size_t i = 0; i < n; i++)
                if (protos[i] && strcmp(protos[i], "/ipfs/id/1.0.0") == 0)
                    ok = 1;
        }
    }
    fprintf(stderr, "[TEST_RCV] protocols lookup done; ok=%d (n=%zu)\n", ok, n);
    print_case("identify push reception updates peerstore protocols", ok);

    libp2p_host_free_peer_protocols(protos, n);
    free(addrB);
    if (pidA) { peer_id_destroy(pidA); free(pidA); }
    fprintf(stderr, "[TEST_RCV] stopping hosts\n");
    libp2p_host_stop(hb); libp2p_host_stop(ha);
    libp2p_host_stop(ha); libp2p_host_stop(hb);
    libp2p_host_free(ha); libp2p_host_free(hb);
    fprintf(stderr, "[TEST_RCV] done\n");
    return ok ? 0 : 1;
}
