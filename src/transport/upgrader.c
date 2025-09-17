#include "transport/upgrader.h"
#include "protocol/noise/protocol_noise.h" /* For negotiation helpers */
#include "transport/muxer.h"
#include <stdlib.h>

/* Context for the upgrader.  Currently very small and only stores the
 * configuration pointers provided at construction time. */
struct libp2p_upgrader_ctx
{
    const peer_id_t *local_peer;
    const struct libp2p_security *const *security;
    size_t n_security;
    const struct libp2p_muxer *const *muxers;
    size_t n_muxers;
    uint64_t handshake_timeout_ms;
};

static void uconn_free(libp2p_uconn_t *uc)
{
    if (!uc)
        return;
    libp2p_conn_free(uc->conn);
    if (uc->remote_peer)
        peer_id_destroy(uc->remote_peer);
    free(uc);
}

/* ------------------------------------------------------------------------- */
/* Upgrader methods                                                          */
/* ------------------------------------------------------------------------- */

static libp2p_upgrader_err_t upgrader_upgrade_outbound(libp2p_upgrader_t *self, libp2p_conn_t *raw, const peer_id_t *remote_hint,
                                                       libp2p_uconn_t **out)
{
    if (!self || !raw || !out)
        return LIBP2P_UPGRADER_ERR_NULL_PTR;

    struct libp2p_upgrader_ctx *ctx = self->ctx;
    if (!ctx || !ctx->security || ctx->n_security == 0)
        return LIBP2P_UPGRADER_ERR_SECURITY;

    /* Only Noise is implemented at the moment.  Use the first security entry
     * and run the multistream negotiation helper provided by the Noise module. */
    libp2p_conn_t *secured = NULL;
    peer_id_t *remote_peer = NULL;
    libp2p_security_err_t rc =
        libp2p_noise_negotiate_outbound((libp2p_security_t *)ctx->security[0], raw, remote_hint, ctx->handshake_timeout_ms, &secured, &remote_peer);
    if (rc != LIBP2P_SECURITY_OK)
        return LIBP2P_UPGRADER_ERR_HANDSHAKE;

    const libp2p_muxer_t *selected = NULL;
    if (ctx->muxers && ctx->n_muxers > 0)
    {
        for (size_t i = 0; i < ctx->n_muxers; i++)
        {
            libp2p_muxer_err_t mrc = libp2p_muxer_negotiate_outbound((libp2p_muxer_t *)ctx->muxers[i], secured, ctx->handshake_timeout_ms);
            if (mrc == LIBP2P_MUXER_OK)
            {
                selected = ctx->muxers[i];
                break;
            }
        }
        if (!selected)
        {
            libp2p_conn_free(secured);
            peer_id_destroy(remote_peer);
            return LIBP2P_UPGRADER_ERR_MUXER;
        }
    }
    else
    {
    }

    libp2p_uconn_t *uc = calloc(1, sizeof(*uc));
    if (!uc)
    {
        libp2p_conn_free(secured);
        peer_id_destroy(remote_peer);
        return LIBP2P_UPGRADER_ERR_INTERNAL;
    }
    uc->conn = secured;
    uc->remote_peer = remote_peer;
    uc->muxer = selected;
    *out = uc;
    return LIBP2P_UPGRADER_OK;
}

static libp2p_upgrader_err_t upgrader_upgrade_inbound(libp2p_upgrader_t *self, libp2p_conn_t *raw, libp2p_uconn_t **out)
{
    if (!self || !raw || !out)
        return LIBP2P_UPGRADER_ERR_NULL_PTR;

    struct libp2p_upgrader_ctx *ctx = self->ctx;
    if (!ctx || !ctx->security || ctx->n_security == 0)
        return LIBP2P_UPGRADER_ERR_SECURITY;

    libp2p_conn_t *secured = NULL;
    peer_id_t *remote_peer = NULL;
    libp2p_security_err_t rc =
        libp2p_noise_negotiate_inbound((libp2p_security_t *)ctx->security[0], raw, ctx->handshake_timeout_ms, &secured, &remote_peer);
    if (rc != LIBP2P_SECURITY_OK)
        return LIBP2P_UPGRADER_ERR_HANDSHAKE;

    const libp2p_muxer_t *selected = NULL;
    if (ctx->muxers && ctx->n_muxers > 0)
    {
        for (size_t i = 0; i < ctx->n_muxers; i++)
        {
            libp2p_muxer_err_t mrc = libp2p_muxer_negotiate_inbound((libp2p_muxer_t *)ctx->muxers[i], secured, ctx->handshake_timeout_ms);
            if (mrc == LIBP2P_MUXER_OK)
            {
                selected = ctx->muxers[i];
                break;
            }
        }
        if (!selected)
        {
            libp2p_conn_free(secured);
            peer_id_destroy(remote_peer);
            return LIBP2P_UPGRADER_ERR_MUXER;
        }
    }
    else
    {
    }

    libp2p_uconn_t *uc = calloc(1, sizeof(*uc));
    if (!uc)
    {
        libp2p_conn_free(secured);
        peer_id_destroy(remote_peer);
        return LIBP2P_UPGRADER_ERR_INTERNAL;
    }
    uc->conn = secured;
    uc->remote_peer = remote_peer;
    uc->muxer = selected;
    *out = uc;
    return LIBP2P_UPGRADER_OK;
}

static libp2p_upgrader_err_t upgrader_close(libp2p_upgrader_t *self)
{
    (void)self;
    return LIBP2P_UPGRADER_OK;
}

static void upgrader_free(libp2p_upgrader_t *self)
{
    if (!self)
        return;
    if (self->ctx)
        free(self->ctx);
    free(self);
}

/* ------------------------------------------------------------------------- */
/* Constructor                                                               */
/* ------------------------------------------------------------------------- */

libp2p_upgrader_t *libp2p_upgrader_new(const libp2p_upgrader_config_t *cfg)
{
    if (!cfg)
        return NULL;
    libp2p_upgrader_t *u = calloc(1, sizeof(*u));
    struct libp2p_upgrader_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!u || !ctx)
    {
        free(u);
        free(ctx);
        return NULL;
    }

    ctx->local_peer = cfg->local_peer;
    ctx->security = cfg->security;
    ctx->n_security = cfg->n_security;
    ctx->muxers = cfg->muxers;
    ctx->n_muxers = cfg->n_muxers;
    ctx->handshake_timeout_ms = cfg->handshake_timeout_ms;

    static const libp2p_upgrader_vtbl_t VTBL = {
        .upgrade_outbound = upgrader_upgrade_outbound,
        .upgrade_inbound = upgrader_upgrade_inbound,
        .close = upgrader_close,
        .free = upgrader_free,
    };

    u->vt = &VTBL;
    u->ctx = ctx;
    return u;
}
