#ifndef UPGRADER_H
#define UPGRADER_H
/**
 * @file upgrader.h
 * @brief Security + multiplexing negotiator for C-libp2p.
 *
 * An **upgrader** takes a raw transport @ref libp2p_conn_t and performs
 *   1. a security handshake (e.g. Noise, TLS),
 *   2. stream-multiplexing negotiation (e.g. Yamux, MPLEX),
 * turning it into a fully secured, stream-capable connection.
 *
 *               ┌─────────────────────────────┐
 *               │  libp2p_stream  (future)    │
 *               └──────────┬──────────────────┘
 *                          │  (muxer streams)
 *               ┌──────────┴──────────────────┐
 *               │  Upgraded / muxed channel   │ ← @ref libp2p_uconn_t
 *               └──────────┬──────────────────┘
 *                          │  (this module)
 *               ┌──────────┴──────────────────┐
 *               │    Raw transport conn       │ ← @ref libp2p_conn_t
 *               └─────────────────────────────┘
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"      /* peer identity       */
#include "transport/connection.h" /* raw conn            */
#include "transport/muxer.h"      /* muxer definitions    */

#ifdef __cplusplus
extern "C"
{
#endif

struct libp2p_security; /* Noise, TLS, etc. (defined elsewhere) */
struct libp2p_muxer;    /* Yamux, MPLEX, … (defined elsewhere)  */

/**
 * @brief Secured + multiplexed connection produced by the upgrader.
 */
struct libp2p_upgraded_conn
{
    libp2p_conn_t *conn;
    peer_id_t *remote_peer;
    const libp2p_muxer_t *muxer;
};
typedef struct libp2p_upgraded_conn libp2p_uconn_t;

/* The upgrader itself */
struct libp2p_upgrader;
typedef struct libp2p_upgrader libp2p_upgrader_t;

typedef enum
{
    LIBP2P_UPGRADER_OK = 0,             /**< Success.                                */
    LIBP2P_UPGRADER_ERR_NULL_PTR = -1,  /**< Required pointer was NULL.              */
    LIBP2P_UPGRADER_ERR_TIMEOUT = -2,   /**< Handshake deadline expired.             */
    LIBP2P_UPGRADER_ERR_SECURITY = -3,  /**< No mutually supported security proto.   */
    LIBP2P_UPGRADER_ERR_MUXER = -4,     /**< No mutually supported muxer proto.      */
    LIBP2P_UPGRADER_ERR_HANDSHAKE = -5, /**< Security handshake failed.             */
    LIBP2P_UPGRADER_ERR_INTERNAL = -6   /**< Unexpected internal failure.            */
} libp2p_upgrader_err_t;

/**
 * @brief Upgrader configuration options.
 */

/**
 * @struct libp2p_upgrader_config_t
 * @brief “Shopping list’’ of security and muxer modules to negotiate.
 *
 * The arrays are *ordered*: the upgrader will try each entry in turn
 * when proposing protocols via multistream-select.
 */
typedef struct
{
    /* Local identity (used by security transports that need a key). */
    const peer_id_t *local_peer;

    /* Security transports */
    const struct libp2p_security *const *security; /**< NULL-terminated array. */
    size_t n_security;                             /**< Number of entries.     */

    /* Stream multiplexers */
    const struct libp2p_muxer *const *muxers; /**< NULL-terminated array. */
    size_t n_muxers;                          /**< Number of entries.     */

    /* Handshake deadline (0 → no timeout) */
    uint64_t handshake_timeout_ms;

} libp2p_upgrader_config_t;

/**
 * @brief Canonical defaults: no timeout and empty proto lists.
 *
 * Security and muxer arrays **must** be filled in by the caller
 * before @ref libp2p_upgrader_new() will succeed.
 */
static inline libp2p_upgrader_config_t libp2p_upgrader_config_default(void)
{
    return (libp2p_upgrader_config_t){
        .local_peer = NULL, .security = NULL, .n_security = 0, .muxers = NULL, .n_muxers = 0, .handshake_timeout_ms = 0};
}

/**
 * @brief Virtual table for upgrader operations.
 */

typedef struct
{
    /**
     * @brief Upgrade an *outbound* (dialer) raw connection.
     *
     * @param self          Upgrader instance.
     * @param raw           Consumed raw transport connection.
     * @param remote_hint   Optional expected remote peer (may be NULL).
     * @param out           On success, new upgraded connection.
     */
    libp2p_upgrader_err_t (*upgrade_outbound)(libp2p_upgrader_t *self, libp2p_conn_t *raw, const peer_id_t *remote_hint, libp2p_uconn_t **out);

    /**
     * @brief Upgrade an *inbound* (acceptor) raw connection.
     *
     * @param self   Upgrader instance.
     * @param raw    Consumed raw transport connection.
     * @param out    On success, new upgraded connection.
     */
    libp2p_upgrader_err_t (*upgrade_inbound)(libp2p_upgrader_t *self, libp2p_conn_t *raw, libp2p_uconn_t **out);

    /* Lifecycle management */

    libp2p_upgrader_err_t (*close)(libp2p_upgrader_t *self);
    void (*free)(libp2p_upgrader_t *self);

} libp2p_upgrader_vtbl_t;

/**
 * @brief Upgrader instance with implementation context.
 */

struct libp2p_upgrader
{
    const libp2p_upgrader_vtbl_t *vt;
    void *ctx; /**< Implementation private data. */
};

/* Constructor / destructor */

/**
 * @brief Create a new upgrader.
 *
 * @param cfg  Configuration (must not be NULL; arrays may be empty).
 * @return     Heap-allocated upgrader or NULL on OOM.
 *
 * Free with @ref libp2p_upgrader_free().
 */
libp2p_upgrader_t *libp2p_upgrader_new(const libp2p_upgrader_config_t *cfg);

/* Convenience inline wrappers */

/**
 * @brief Upgrade an outbound connection using the configured security and muxer.
 *
 * @param u      Upgrader instance.
 * @param raw    Raw connection to upgrade.
 * @param remote Expected remote peer ID (may be NULL).
 * @param out    Receives the upgraded connection.
 * @return LIBP2P_UPGRADER_OK or an error code.
 */
static inline libp2p_upgrader_err_t libp2p_upgrader_upgrade_outbound(libp2p_upgrader_t *u, libp2p_conn_t *raw, const peer_id_t *remote,
                                                                     libp2p_uconn_t **out)
{
    if (!u || !raw || !out)
        return LIBP2P_UPGRADER_ERR_NULL_PTR;
    return u->vt->upgrade_outbound(u, raw, remote, out);
}

/**
 * @brief Upgrade an inbound connection using the configured security and muxer.
 *
 * @param u   Upgrader instance.
 * @param raw Raw connection to upgrade.
 * @param out Receives the upgraded connection.
 * @return LIBP2P_UPGRADER_OK or an error code.
 */
static inline libp2p_upgrader_err_t libp2p_upgrader_upgrade_inbound(libp2p_upgrader_t *u, libp2p_conn_t *raw, libp2p_uconn_t **out)
{
    if (!u || !raw || !out)
        return LIBP2P_UPGRADER_ERR_NULL_PTR;
    return u->vt->upgrade_inbound(u, raw, out);
}

/**
 * @brief Close the upgrader instance.
 *
 * @param u Upgrader instance.
 * @return LIBP2P_UPGRADER_OK or an error code.
 */
static inline libp2p_upgrader_err_t libp2p_upgrader_close(libp2p_upgrader_t *u)
{
    return u && u->vt ? u->vt->close(u) : LIBP2P_UPGRADER_ERR_NULL_PTR;
}

/**
 * @brief Free the upgrader instance.
 *
 * @param u Upgrader instance (may be NULL).
 */
static inline void libp2p_upgrader_free(libp2p_upgrader_t *u)
{
    if (u && u->vt && u->vt->free)
        u->vt->free(u);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* UPGRADER_H */