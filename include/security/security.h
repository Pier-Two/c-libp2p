#ifndef SECURITY_H
#define SECURITY_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"
#include "transport/connection.h"

/* ------------------------------------------------------------------------- */
/* Forward declarations                                                      */
/* ------------------------------------------------------------------------- */

struct libp2p_security;
typedef struct libp2p_security libp2p_security_t;

/* ------------------------------------------------------------------------- */
/* Error codes                                                               */
/* ------------------------------------------------------------------------- */

typedef enum
{
    LIBP2P_SECURITY_OK = 0,
    LIBP2P_SECURITY_ERR_NULL_PTR = -1,
    LIBP2P_SECURITY_ERR_HANDSHAKE = -2,
    LIBP2P_SECURITY_ERR_INTERNAL = -3
} libp2p_security_err_t;

/* ------------------------------------------------------------------------- */
/* Virtual table                                                             */
/* ------------------------------------------------------------------------- */

typedef struct
{
    /* Run the protocol handshake on an outbound connection.
     * timeout_ms: 0 → no overall deadline; otherwise monotonic budget. */
    libp2p_security_err_t (*secure_outbound)(libp2p_security_t *self, libp2p_conn_t *raw, const peer_id_t *remote_hint, uint64_t timeout_ms,
                                             libp2p_conn_t **out, peer_id_t **remote_peer);

    /* Run the protocol handshake on an inbound connection. */
    libp2p_security_err_t (*secure_inbound)(libp2p_security_t *self, libp2p_conn_t *raw, uint64_t timeout_ms, libp2p_conn_t **out,
                                            peer_id_t **remote_peer);

    libp2p_security_err_t (*close)(libp2p_security_t *self);
    void (*free)(libp2p_security_t *self);
} libp2p_security_vtbl_t;

/* ------------------------------------------------------------------------- */
/* Public struct                                                             */
/* ------------------------------------------------------------------------- */

struct libp2p_security
{
    const libp2p_security_vtbl_t *vt;
    void *ctx;
};

/* ------------------------------------------------------------------------- */
/* Convenience inline wrappers                                               */
/* ------------------------------------------------------------------------- */

static inline libp2p_security_err_t libp2p_security_secure_outbound(libp2p_security_t *s, libp2p_conn_t *raw, const peer_id_t *remote_hint,
                                                                    uint64_t timeout_ms, libp2p_conn_t **out, peer_id_t **remote)
{
    if (!s || !raw || !out)
        return LIBP2P_SECURITY_ERR_NULL_PTR;
    return s->vt->secure_outbound(s, raw, remote_hint, timeout_ms, out, remote);
}

static inline libp2p_security_err_t libp2p_security_secure_inbound(libp2p_security_t *s, libp2p_conn_t *raw, uint64_t timeout_ms, libp2p_conn_t **out,
                                                                   peer_id_t **remote)
{
    if (!s || !raw || !out)
        return LIBP2P_SECURITY_ERR_NULL_PTR;
    return s->vt->secure_inbound(s, raw, timeout_ms, out, remote);
}

static inline libp2p_security_err_t libp2p_security_close(libp2p_security_t *s)
{
    return s && s->vt ? s->vt->close(s) : LIBP2P_SECURITY_ERR_NULL_PTR;
}

static inline void libp2p_security_free(libp2p_security_t *s)
{
    if (s && s->vt && s->vt->free)
        s->vt->free(s);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SECURITY_H */
