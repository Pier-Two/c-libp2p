#include "host_internal.h"
#include <string.h>
#include "libp2p/error_map.h"
#include "transport/upgrader.h"
#include "libp2p/muxer.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include "protocol/muxer/mplex/protocol_mplex.h"

int libp2p__host_upgrade_outbound(libp2p_host_t *host,
                                  libp2p_conn_t *raw,
                                  const peer_id_t *remote_hint,
                                  int allow_mplex,
                                  libp2p_uconn_t **out_uc)
{
    if (!host || !raw || !out_uc)
        return LIBP2P_ERR_NULL_PTR;

    /* Build muxer proposals from host configuration. Prefer the muxer selected
     * during host initialisation to respect builder preferences (e.g. mplex).
     * Optionally add mplex as a fallback when allowed. */
    libp2p_muxer_t *preferred = NULL;
    /* Respect first muxer proposal from options if provided */
    if (host->opts.num_muxer_proposals > 0 && host->opts.muxer_proposals && host->opts.muxer_proposals[0])
    {
        const char *name = host->opts.muxer_proposals[0];
        if (strcmp(name, "mplex") == 0)
            (void)libp2p_muxer_mplex(&preferred);
        else
            (void)libp2p_muxer_yamux(&preferred);
    }
    else
    {
        /* Fallback to yamux if no explicit preference */
        (void)libp2p_muxer_yamux(&preferred);
    }
    libp2p_muxer_t *fallback_mplex = NULL;
    if (allow_mplex)
        (void)libp2p_muxer_mplex(&fallback_mplex);

    const libp2p_security_t *secs_arr[2] = {host->noise, NULL};
    const libp2p_muxer_t *mx_arr[3] = {preferred, fallback_mplex, NULL};

    libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
    ucfg.security = secs_arr;
    ucfg.n_security = 1;
    ucfg.muxers = mx_arr;
    ucfg.n_muxers = (fallback_mplex ? 2 : 1);
    ucfg.handshake_timeout_ms = host->opts.handshake_timeout_ms;

    libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);
    if (!up)
    {
        /* Free proposals and raw, emit error */
        if (preferred)
            libp2p_muxer_free(preferred);
        if (fallback_mplex)
            libp2p_muxer_free(fallback_mplex);
        libp2p_conn_free(raw);
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = LIBP2P_ERR_INTERNAL;
        evt.u.outgoing_conn_error.msg = "upgrader init failed";
        libp2p_event_publish(host, &evt);
        return LIBP2P_ERR_INTERNAL;
    }

    libp2p_uconn_t *uc = NULL;
    libp2p_upgrader_err_t urc = libp2p_upgrader_upgrade_outbound(up, raw, remote_hint, &uc);
    libp2p_upgrader_free(up);

    if (urc != LIBP2P_UPGRADER_OK || !uc || !uc->conn || !uc->muxer)
    {
        if (urc != LIBP2P_UPGRADER_OK && raw)
            libp2p_conn_free(raw);
        if (preferred)
            libp2p_muxer_free(preferred);
        if (fallback_mplex)
            libp2p_muxer_free(fallback_mplex);

        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_OUTGOING_CONNECTION_ERROR;
        evt.u.outgoing_conn_error.peer = NULL;
        evt.u.outgoing_conn_error.code = libp2p_error_from_upgrader(urc);
        evt.u.outgoing_conn_error.msg = (urc == LIBP2P_UPGRADER_ERR_MUXER) ? "muxer negotiation failed" : "security negotiation failed";
        libp2p_event_publish(host, &evt);
        return libp2p_error_from_upgrader(urc);
    }

    /* Free any unselected proposals to avoid leaks */
    if (preferred && uc->muxer != preferred)
        libp2p_muxer_free(preferred);
    if (fallback_mplex && uc->muxer != fallback_mplex)
        libp2p_muxer_free(fallback_mplex);

    *out_uc = uc;
    return 0;
}

int libp2p__host_upgrade_inbound(libp2p_host_t *host,
                                 libp2p_conn_t *raw,
                                 int allow_mplex,
                                 libp2p_uconn_t **out_uc)
{
    if (!host || !raw || !out_uc)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_muxer_t *preferred = NULL;
    if (host->opts.num_muxer_proposals > 0 && host->opts.muxer_proposals && host->opts.muxer_proposals[0])
    {
        const char *name = host->opts.muxer_proposals[0];
        if (strcmp(name, "mplex") == 0)
            (void)libp2p_muxer_mplex(&preferred);
        else
            (void)libp2p_muxer_yamux(&preferred);
    }
    else
    {
        (void)libp2p_muxer_yamux(&preferred);
    }
    libp2p_muxer_t *fallback_mplex = NULL;
    if (allow_mplex)
        (void)libp2p_muxer_mplex(&fallback_mplex);

    const libp2p_security_t *secs_arr[2] = {host->noise, NULL};
    const libp2p_muxer_t *mx_arr[3] = {preferred, fallback_mplex, NULL};

    libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
    ucfg.security = secs_arr;
    ucfg.n_security = 1;
    ucfg.muxers = mx_arr;
    ucfg.n_muxers = (fallback_mplex ? 2 : 1);
    ucfg.handshake_timeout_ms = host->opts.handshake_timeout_ms;

    libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);
    if (!up)
    {
        if (preferred)
            libp2p_muxer_free(preferred);
        if (fallback_mplex)
            libp2p_muxer_free(fallback_mplex);
        libp2p_conn_free(raw);
        /* No event here previously, but keep symmetry minimal by omitting extra error */
        return LIBP2P_ERR_INTERNAL;
    }

    libp2p_uconn_t *uc = NULL;
    libp2p_upgrader_err_t urc = libp2p_upgrader_upgrade_inbound(up, raw, &uc);
    libp2p_upgrader_free(up);

    if (urc != LIBP2P_UPGRADER_OK || !uc || !uc->conn || !uc->muxer)
    {
        if (urc != LIBP2P_UPGRADER_OK && raw)
            libp2p_conn_free(raw);
        if (preferred)
            libp2p_muxer_free(preferred);
        if (fallback_mplex)
            libp2p_muxer_free(fallback_mplex);

        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_INCOMING_CONNECTION_ERROR;
        evt.u.incoming_conn_error.peer = NULL;
        evt.u.incoming_conn_error.code = libp2p_error_from_upgrader(urc);
        evt.u.incoming_conn_error.msg = (urc == LIBP2P_UPGRADER_ERR_MUXER) ? "muxer negotiation failed" : "noise negotiation failed";
        libp2p_event_publish(host, &evt);
        return libp2p_error_from_upgrader(urc);
    }

    if (preferred && uc->muxer != preferred)
        libp2p_muxer_free(preferred);
    if (fallback_mplex && uc->muxer != fallback_mplex)
        libp2p_muxer_free(fallback_mplex);

    *out_uc = uc;
    return 0;
}
