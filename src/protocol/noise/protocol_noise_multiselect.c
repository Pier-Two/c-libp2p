#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/noise/protocol_noise.h"
#include "security/security.h"

libp2p_security_err_t libp2p_noise_negotiate_outbound(libp2p_security_t *sec, libp2p_conn_t *conn, const peer_id_t *remote_hint, uint64_t timeout_ms,
                                                      libp2p_conn_t **out, peer_id_t **remote_peer)
{
    if (!sec || !conn || !out)
        return LIBP2P_SECURITY_ERR_NULL_PTR;

    const char *proposals[] = {LIBP2P_NOISE_PROTO_ID, NULL};
    libp2p_multiselect_err_t rc = libp2p_multiselect_dial(conn, proposals, timeout_ms, NULL);
    if (rc != LIBP2P_MULTISELECT_OK)
        return LIBP2P_SECURITY_ERR_HANDSHAKE;

    return libp2p_security_secure_outbound(sec, conn, remote_hint, timeout_ms, out, remote_peer);
}

libp2p_security_err_t libp2p_noise_negotiate_inbound(libp2p_security_t *sec, libp2p_conn_t *conn, uint64_t timeout_ms, libp2p_conn_t **out,
                                                     peer_id_t **remote_peer)
{
    if (!sec || !conn || !out)
        return LIBP2P_SECURITY_ERR_NULL_PTR;

    const char *supported[] = {LIBP2P_NOISE_PROTO_ID, NULL};
    libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
    cfg.handshake_timeout_ms = timeout_ms;
    libp2p_multiselect_err_t rc = libp2p_multiselect_listen(conn, supported, &cfg, NULL);
    if (rc != LIBP2P_MULTISELECT_OK)
        return LIBP2P_SECURITY_ERR_HANDSHAKE;

    return libp2p_security_secure_inbound(sec, conn, timeout_ms, out, remote_peer);
}
