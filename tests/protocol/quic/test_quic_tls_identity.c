#include "protocol/quic/protocol_quic.h"

#include "libp2p/errors.h"
#include "peer_id/peer_id.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_TYPE_ED25519 1
#define KEY_TYPE_SECP256K1 2
#define KEY_TYPE_ECDSA 3

static void print_result(const char *name, const char *details, int ok)
{
    if (ok)
        printf("TEST: %-70s | PASS\n", name);
    else
        printf("TEST: %-70s | FAIL: %s\n", name, details ? details : "");
}

static int failures = 0;

#define TEST_TRUE(name, cond, fmt, ...)                                                                                                             \
    do                                                                                                                                              \
    {                                                                                                                                               \
        if (cond)                                                                                                                                   \
            print_result(name, "", 1);                                                                                                             \
        else                                                                                                                                        \
        {                                                                                                                                           \
            char _msg[256];                                                                                                                         \
            snprintf(_msg, sizeof(_msg), fmt, ##__VA_ARGS__);                                                                                       \
            print_result(name, _msg, 0);                                                                                                            \
            failures++;                                                                                                                             \
        }                                                                                                                                           \
    } while (0)

static int hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t **out_buf, size_t *out_len)
{
    if (!hex || !out_buf || !out_len)
        return -1;

    size_t digits = 0;
    for (const char *p = hex; *p; ++p)
    {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
            continue;
        if (hex_char_to_val(*p) < 0)
            return -1;
        digits++;
    }

    if ((digits & 1U) != 0)
        return -1;

    size_t len = digits / 2;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf)
        return -1;

    size_t idx = 0;
    int high = -1;
    for (const char *p = hex; *p; ++p)
    {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
            continue;
        int val = hex_char_to_val(*p);
        if (val < 0)
        {
            free(buf);
            return -1;
        }
        if (high < 0)
        {
            high = val;
        }
        else
        {
            buf[idx++] = (uint8_t)((high << 4) | val);
            high = -1;
        }
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}

static const char CERT_ED25519[] =
    "308201ae30820156a0030201020204499602d2300a06082a8648ce3d04030230"
    "2031123010060355040a13096c69627032702e696f310a300806035504051301"
    "313020170d3735303130313133303030305a180f343039363031303131333030"
    "30305a302031123010060355040a13096c69627032702e696f310a3008060355"
    "04051301313059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "0c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd60133"
    "1c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569e"
    "a37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92"
    "fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d"
    "2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215"
    "a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a"
    "06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c"
    "9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a2"
    "5682f7248ea1cb764d322ea983ed36a31b77";

static const char CERT_ECDSA[] =
    "308201f63082019da0030201020204499602d2300a06082a8648ce3d04030230"
    "2031123010060355040a13096c69627032702e696f310a300806035504051301"
    "313020170d3735303130313133303030305a180f343039363031303131333030"
    "30305a302031123010060355040a13096c69627032702e696f310a3008060355"
    "04051301313059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "0c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd60133"
    "1c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569e"
    "a381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f080312"
    "5b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f"
    "909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7"
    "563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045"
    "0220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9"
    "386a022100aa59d704a931b5f72fb9222cb6cc51f954d04a4e2e5450f8805fe8"
    "918f71eaae300a06082a8648ce3d04030203470030440220799395b0b6c1e940"
    "a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f"
    "95205c779be86581d3e31c01871ad5d1f3435bcf375cb0e5088a";

static const char CERT_SECP256K1[] =
    "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d04030230"
    "2031123010060355040a13096c69627032702e696f310a300806035504051301"
    "313020170d3735303130313133303030305a180f343039363031303131333030"
    "30305a302031123010060355040a13096c69627032702e696f310a3008060355"
    "04051301313059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "0c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd60133"
    "1c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569e"
    "a38184308181307f060a2b0601040183a25a01010471306f0425080212210206"
    "dc6968726765b820f050263ececf7f71e4955892776c0970542efd689d238204"
    "4630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5a385eedc34ec"
    "f464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666"
    "d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef"
    "9ec9204b3f774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00d"
    "afa549d0f03547878338c7b15e7502888f6d45db387e5ae6b5d46899cef0";

static const char CERT_INVALID[] =
    "308201f73082019da0030201020204499602d2300a06082a8648ce3d04030230"
    "2031123010060355040a13096c69627032702e696f310a300806035504051301"
    "313020170d3735303130313133303030305a180f343039363031303131333030"
    "30305a302031123010060355040a13096c69627032702e696f310a3008060355"
    "04051301313059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "0c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd60133"
    "1c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569e"
    "a381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f080312"
    "5b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f"
    "909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7"
    "563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045"
    "022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65c"
    "ade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f"
    "2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717"
    "358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d"
    "41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df";

static void expect_peer_id(const char *name,
                           const char *hex_cert,
                           const char *expected_peer,
                           uint64_t expected_key_type)
{
    uint8_t *cert = NULL;
    size_t cert_len = 0;
    int rc = hex_to_bytes(hex_cert, &cert, &cert_len);
    char label[128];
    snprintf(label, sizeof(label), "%s (decode)", name);
    TEST_TRUE(label, rc == 0 && cert && cert_len > 0, "hex decode failed");
    if (rc != 0 || !cert)
        return;

    libp2p_quic_tls_identity_t ident;
    rc = libp2p_quic_tls_identity_from_certificate(cert, cert_len, &ident);
    snprintf(label, sizeof(label), "%s (parse)", name);
    TEST_TRUE(label, rc == LIBP2P_ERR_OK, "parse rc=%d", rc);
    if (rc == LIBP2P_ERR_OK)
    {
        snprintf(label, sizeof(label), "%s (key type)", name);
        TEST_TRUE(label, ident.key_type == expected_key_type,
                  "expected key type %" PRIu64 ", got %" PRIu64,
                  expected_key_type, ident.key_type);
        snprintf(label, sizeof(label), "%s (public key)", name);
        TEST_TRUE(label, ident.public_key_proto != NULL && ident.public_key_len > 0,
                  "public key missing (len=%zu)", ident.public_key_len);

        char buf[128] = {0};
        int str_rc = peer_id_to_string(ident.peer, PEER_ID_FMT_BASE58_LEGACY, buf, sizeof(buf));
        snprintf(label, sizeof(label), "%s (peer id encode)", name);
        TEST_TRUE(label, str_rc > 0 && (size_t)str_rc < sizeof(buf),
                  "peer_id_to_string rc=%d", str_rc);
        if (str_rc > 0 && (size_t)str_rc < sizeof(buf))
        {
            buf[str_rc] = '\0';
            snprintf(label, sizeof(label), "%s (peer id match)", name);
            TEST_TRUE(label, strcmp(buf, expected_peer) == 0,
                      "expected %s, got %s", expected_peer, buf);
        }

        libp2p_quic_tls_identity_clear(&ident);
    }

    free(cert);
}

static void expect_parse_failure(const char *name, const char *hex_cert)
{
    uint8_t *cert = NULL;
    size_t cert_len = 0;
    int rc = hex_to_bytes(hex_cert, &cert, &cert_len);
    char label[128];
    snprintf(label, sizeof(label), "%s (decode)", name);
    TEST_TRUE(label, rc == 0 && cert && cert_len > 0, "hex decode failed");
    if (rc != 0 || !cert)
        return;

    libp2p_quic_tls_identity_t ident;
    rc = libp2p_quic_tls_identity_from_certificate(cert, cert_len, &ident);
    snprintf(label, sizeof(label), "%s (parse)", name);
    TEST_TRUE(label, rc != LIBP2P_ERR_OK, "unexpected success rc=%d", rc);
    if (rc == LIBP2P_ERR_OK)
        libp2p_quic_tls_identity_clear(&ident);

    free(cert);
}

int main(void)
{
    expect_peer_id("ED25519 certificate", CERT_ED25519,
                   "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv",
                   KEY_TYPE_ED25519);

    expect_peer_id("ECDSA certificate", CERT_ECDSA,
                   "QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE",
                   KEY_TYPE_ECDSA);

    expect_peer_id("secp256k1 certificate", CERT_SECP256K1,
                   "16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs",
                   KEY_TYPE_SECP256K1);

    expect_parse_failure("Invalid certificate", CERT_INVALID);

    if (failures == 0)
        print_result("QUIC TLS identity vectors", "", 1);
    else
        print_result("QUIC TLS identity vectors", "failures detected", 0);

    return failures == 0 ? 0 : 1;
}
