#include "protocol/identify/protocol_identify.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_standard(const char *name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", name);
    else
        printf("TEST: %-50s | FAIL: %s\n", name, details);
}

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    if (alen != blen)
        return 0;
    return (alen == 0) || (memcmp(a, b, alen) == 0);
}

int main(void)
{
    /* Build a full identify message */
    libp2p_identify_t msg = {0};
    msg.protocol_version = strdup("/test/9.9.9");
    msg.agent_version = strdup("agent/xyz");

    /* publicKey: arbitrary bytes (protobuf-encoded key in real usage) */
    const uint8_t pk_src[] = {0xAA, 0xBB, 0xCC, 0xDD};
    msg.public_key_len = sizeof(pk_src);
    msg.public_key = (uint8_t *)malloc(msg.public_key_len);
    memcpy(msg.public_key, pk_src, msg.public_key_len);

    /* listenAddrs */
    const char *addrs[] = {
        "/ip4/127.0.0.1/tcp/4001",
        "/dns4/example.com/tcp/443"
    };
    msg.num_listen_addrs = sizeof(addrs) / sizeof(addrs[0]);
    msg.listen_addrs = (uint8_t **)calloc(msg.num_listen_addrs, sizeof(uint8_t *));
    msg.listen_addrs_lens = (size_t *)calloc(msg.num_listen_addrs, sizeof(size_t));
    for (size_t i = 0; i < msg.num_listen_addrs; i++)
    {
        size_t len = strlen(addrs[i]);
        msg.listen_addrs_lens[i] = len;
        msg.listen_addrs[i] = (uint8_t *)malloc(len);
        memcpy(msg.listen_addrs[i], addrs[i], len);
    }

    /* observedAddr */
    const char *obs = "/ip4/203.0.113.5/tcp/12345";
    msg.observed_addr_len = strlen(obs);
    msg.observed_addr = (uint8_t *)malloc(msg.observed_addr_len);
    memcpy(msg.observed_addr, obs, msg.observed_addr_len);

    /* protocols */
    const char *protos[] = {
        "/ipfs/id/1.0.0",
        "/ipfs/ping/1.0.0"
    };
    msg.num_protocols = sizeof(protos) / sizeof(protos[0]);
    msg.protocols = (char **)calloc(msg.num_protocols, sizeof(char *));
    for (size_t i = 0; i < msg.num_protocols; i++)
        msg.protocols[i] = strdup(protos[i]);

    /* Encode */
    uint8_t *buf = NULL; size_t blen = 0;
    int enc_rc = libp2p_identify_message_encode(&msg, &buf, &blen);
    if (enc_rc != 0 || !buf)
    {
        print_standard("identify roundtrip encode", "encode failed", 0);
        libp2p_identify_free(&msg);
        return 1;
    }

    /* Decode */
    libp2p_identify_t *dec = NULL;
    int dec_rc = libp2p_identify_message_decode(buf, blen, &dec);
    int ok = (enc_rc == 0) && (dec_rc == 0) && dec;
    ok = ok && strcmp(dec->protocol_version, msg.protocol_version) == 0;
    ok = ok && strcmp(dec->agent_version, msg.agent_version) == 0;
    ok = ok && bytes_eq(dec->public_key, dec->public_key_len, msg.public_key, msg.public_key_len);
    ok = ok && dec->num_listen_addrs == msg.num_listen_addrs;
    for (size_t i = 0; ok && i < msg.num_listen_addrs; i++)
        ok = ok && bytes_eq(dec->listen_addrs[i], dec->listen_addrs_lens[i], msg.listen_addrs[i], msg.listen_addrs_lens[i]);
    ok = ok && bytes_eq(dec->observed_addr, dec->observed_addr_len, msg.observed_addr, msg.observed_addr_len);
    ok = ok && dec->num_protocols == msg.num_protocols;
    for (size_t i = 0; ok && i < msg.num_protocols; i++)
        ok = ok && strcmp(dec->protocols[i], msg.protocols[i]) == 0;

    print_standard("identify roundtrip encode/decode", ok ? "" : "mismatch", ok);

    /* Unknown field tolerance: append an unknown length‑delimited field tag=0x3A */
    uint8_t unk_tag = 0x3A; /* (field=7, wire=2) */
    uint8_t len_buf[10]; size_t len_sz = 0;
    unsigned_varint_encode(3, len_buf, sizeof(len_buf), &len_sz);
    size_t appended = blen + 1 + len_sz + 3;
    uint8_t *buf2 = (uint8_t *)malloc(appended);
    memcpy(buf2, buf, blen);
    size_t off = blen;
    buf2[off++] = unk_tag;
    memcpy(buf2 + off, len_buf, len_sz); off += len_sz;
    buf2[off++] = 0xDE; buf2[off++] = 0xAD; buf2[off++] = 0xBE;

    libp2p_identify_t *dec2 = NULL;
    int dec2_rc = libp2p_identify_message_decode(buf2, appended, &dec2);
    int ok2 = (dec2_rc == 0) && dec2;
    ok2 = ok2 && strcmp(dec2->agent_version, msg.agent_version) == 0;
    print_standard("identify decode with unknown field", ok2 ? "" : "decode failed", ok2);

    /* Cleanup */
    libp2p_identify_free(dec);
    libp2p_identify_free(dec2);
    free(buf);
    free(buf2);
    if (msg.public_key) free(msg.public_key);
    if (msg.listen_addrs)
    {
        for (size_t i = 0; i < msg.num_listen_addrs; i++)
            free(msg.listen_addrs[i]);
        free(msg.listen_addrs);
    }
    if (msg.listen_addrs_lens) free(msg.listen_addrs_lens);
    if (msg.observed_addr) free(msg.observed_addr);
    if (msg.protocols)
    {
        for (size_t i = 0; i < msg.num_protocols; i++)
            free(msg.protocols[i]);
        free(msg.protocols);
    }
    free(msg.protocol_version);
    free(msg.agent_version);

    return (ok && ok2) ? 0 : 1;
}
