#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/errors.h"
#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"
#include "protocol/identify/protocol_identify.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

static void print_case(const char *name, int ok)
{
    printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL");
}

/* Build a protobuf-encoded PrivateKey for Secp256k1 from a 32-byte seed */
static int build_secp256k1_private_key_pb(const uint8_t *seed32, size_t seed_len, uint8_t **out, size_t *out_len)
{
    if (!seed32 || seed_len != 32 || !out || !out_len) return -1;
    uint8_t buf[64]; size_t off = 0, sz = 0;
    buf[off++] = 0x08; unsigned_varint_encode(2, buf + off, sizeof(buf) - off, &sz); off += sz; /* KeyType=2 */
    buf[off++] = 0x12; unsigned_varint_encode(32, buf + off, sizeof(buf) - off, &sz); off += sz;
    memcpy(buf + off, seed32, 32); off += 32;
    uint8_t *ret = (uint8_t *)malloc(off); if (!ret) return -1; memcpy(ret, buf, off);
    *out = ret; *out_len = off; return 0;
}

typedef struct fake_stream_ctx
{
    multiaddr_t *remote;
} fake_stream_ctx_t;

static ssize_t fake_stream_read(void *ctx, void *buf, size_t len)
{
    (void)ctx; (void)buf; (void)len; return LIBP2P_ERR_AGAIN;
}

static ssize_t fake_stream_write(void *ctx, const void *buf, size_t len)
{
    (void)ctx; (void)buf; (void)len; return LIBP2P_ERR_AGAIN;
}

static int fake_stream_close(void *ctx)
{
    (void)ctx; return 0;
}

static int fake_stream_reset(void *ctx)
{
    (void)ctx; return 0;
}

static int fake_stream_deadline(void *ctx, uint64_t ms)
{
    (void)ctx; (void)ms; return 0;
}

static const multiaddr_t *fake_stream_local_addr(void *ctx)
{
    (void)ctx; return NULL;
}

static const multiaddr_t *fake_stream_remote_addr(void *ctx)
{
    fake_stream_ctx_t *c = (fake_stream_ctx_t *)ctx;
    return c ? c->remote : NULL;
}

static const libp2p_stream_backend_ops_t FAKE_STREAM_OPS = {
    .read = fake_stream_read,
    .write = fake_stream_write,
    .close = fake_stream_close,
    .reset = fake_stream_reset,
    .set_deadline = fake_stream_deadline,
    .local_addr = fake_stream_local_addr,
    .remote_addr = fake_stream_remote_addr,
};

int main(void)
{
    libp2p_host_builder_t *builder = libp2p_host_builder_new();
    if (!builder)
        return 1;
    (void)libp2p_host_builder_listen_addr(builder, "/ip4/127.0.0.1/tcp/4001");
    (void)libp2p_host_builder_transport(builder, "tcp");
    (void)libp2p_host_builder_security(builder, "noise");
    (void)libp2p_host_builder_muxer(builder, "yamux");
    (void)libp2p_host_builder_flags(builder, 0);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(builder, &host) != 0 || !host)
    {
        libp2p_host_builder_free(builder);
        return 1;
    }
    libp2p_host_builder_free(builder);

    uint8_t seed[32];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)(i + 7);
    uint8_t *pk = NULL;
    size_t pk_len = 0;
    if (build_secp256k1_private_key_pb(seed, sizeof(seed), &pk, &pk_len) != 0)
    {
        libp2p_host_free(host);
        return 1;
    }
    if (libp2p_host_set_private_key(host, pk, pk_len) != 0)
    {
        free(pk);
        libp2p_host_free(host);
        return 1;
    }
    free(pk);

    /* 1) Verify encode_local produces binary multiaddr bytes */
    uint8_t *payload = NULL; size_t plen = 0;
    if (libp2p_identify_encode_local(host, NULL, 0, &payload, &plen) != 0 || !payload || plen == 0)
    {
        libp2p_host_free(host);
        return 1;
    }
    libp2p_identify_t *id_local = NULL;
    int dec_rc = libp2p_identify_message_decode(payload, plen, &id_local);
    int ok_local = (dec_rc == 0) && id_local && id_local->num_listen_addrs > 0;
    int parsed = 0;
    if (ok_local)
    {
        for (size_t i = 0; i < id_local->num_listen_addrs; i++)
        {
            int ma_err = 0;
            multiaddr_t *ma = multiaddr_new_from_bytes(id_local->listen_addrs[i], id_local->listen_addrs_lens[i], &ma_err);
            if (ma)
            {
                parsed++;
                multiaddr_free(ma);
            }
        }
    }
    ok_local = ok_local && (parsed > 0);
    print_case("identify encode_local listenAddrs are binary multiaddrs", ok_local);
    libp2p_identify_free(id_local);
    free(payload);

    /* 2) Verify observedAddr over the wire is binary multiaddr bytes */
    int ma_err = 0;
    fake_stream_ctx_t fctx = {0};
    fctx.remote = multiaddr_new_from_str("/ip4/198.51.100.1/tcp/1234", &ma_err);
    if (!fctx.remote || ma_err != 0)
    {
        if (fctx.remote)
            multiaddr_free(fctx.remote);
        libp2p_host_free(host);
        return 1;
    }
    libp2p_stream_t *fake_stream = libp2p_stream_from_ops(host, &fctx, &FAKE_STREAM_OPS, LIBP2P_IDENTIFY_PROTO_ID, 0, NULL);
    if (!fake_stream)
    {
        multiaddr_free(fctx.remote);
        libp2p_host_free(host);
        return 1;
    }

    uint8_t *payload2 = NULL;
    size_t plen2 = 0;
    int enc_rc = libp2p_identify_encode_local(host, fake_stream, 1, &payload2, &plen2);
    if (enc_rc != 0 || !payload2 || plen2 == 0)
    {
        libp2p_stream_close(fake_stream);
        libp2p_stream_free(fake_stream);
        multiaddr_free(fctx.remote);
        libp2p_host_free(host);
        return 1;
    }
    ssize_t n = (ssize_t)plen2;
    int ok_obs = 0;
    if (n > 0)
    {
        libp2p_identify_t *id = NULL;
        if (libp2p_identify_message_decode(payload2, (size_t)n, &id) == 0 && id)
        {
            if (id->observed_addr && id->observed_addr_len)
            {
                int ma_err = 0; multiaddr_t *oma = multiaddr_new_from_bytes(id->observed_addr, id->observed_addr_len, &ma_err);
                if (oma)
                {
                    ok_obs = 1; multiaddr_free(oma);
                }
            }
            libp2p_identify_free(id);
        }
    }
    print_case("identify response observedAddr is binary multiaddr", ok_obs);
    free(payload2);
    libp2p_stream_close(fake_stream);
    libp2p_stream_free(fake_stream);
    multiaddr_free(fctx.remote);

    int ok_all = ok_local && ok_obs;
    libp2p_host_free(host);
    return ok_all ? 0 : 1;
}
