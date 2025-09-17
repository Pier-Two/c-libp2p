#ifndef LIBP2P_MUXER_H
#define LIBP2P_MUXER_H

#include "transport/connection.h"
#include <stdbool.h>
#include <stdint.h>

/* Provide a portable alias for libp2p_stream_t without forcing inclusion order */
#ifndef LIBP2P_STREAM_TYPEDEF_DONE
struct libp2p_stream;
typedef struct libp2p_stream libp2p_stream_t;
#define LIBP2P_STREAM_TYPEDEF_DONE 1
#endif

#ifdef __cplusplus
extern "C"
{
#endif

struct libp2p_muxer;
typedef struct libp2p_muxer libp2p_muxer_t;

/**
 * @enum libp2p_muxer_err_t
 * @brief Return codes for muxer operations.
 */
typedef enum
{
    LIBP2P_MUXER_OK = 0,
    LIBP2P_MUXER_ERR_NULL_PTR = -1,
    LIBP2P_MUXER_ERR_HANDSHAKE = -2,
    LIBP2P_MUXER_ERR_INTERNAL = -3
} libp2p_muxer_err_t;

/**
 * @brief Dispatch table for muxer operations.
 */
struct libp2p_muxer_vtbl
{
    libp2p_muxer_err_t (*negotiate)(libp2p_muxer_t *mx, libp2p_conn_t *c, uint64_t timeout_ms, bool inbound);
    libp2p_muxer_err_t (*open_stream)(libp2p_muxer_t *mx, const uint8_t *name, size_t name_len, libp2p_stream_t **out);
    ssize_t (*stream_read)(libp2p_stream_t *s, void *buf, size_t len);
    ssize_t (*stream_write)(libp2p_stream_t *s, const void *buf, size_t len);
    void (*stream_close)(libp2p_stream_t *s);
    void (*free)(libp2p_muxer_t *mx);
};
typedef struct libp2p_muxer_vtbl libp2p_muxer_vtbl_t;

/**
 * @brief Muxer instance wrapping the virtual table and context.
 */
struct libp2p_muxer
{
    const libp2p_muxer_vtbl_t *vt;
    void *ctx;
};

/**
 * @brief Perform outbound muxer negotiation.
 *
 * @param m Muxer instance.
 * @param c Underlying connection.
 * @param t Timeout in milliseconds.
 * @return LIBP2P_MUXER_OK or an error code.
 */
static inline libp2p_muxer_err_t libp2p_muxer_negotiate_outbound(libp2p_muxer_t *m, libp2p_conn_t *c, uint64_t t)
{
    if (!m || !c)
        return LIBP2P_MUXER_ERR_NULL_PTR;
    return m->vt->negotiate(m, c, t, false);
}

/**
 * @brief Perform inbound muxer negotiation.
 *
 * @param m Muxer instance.
 * @param c Underlying connection.
 * @param t Timeout in milliseconds.
 * @return LIBP2P_MUXER_OK or an error code.
 */
static inline libp2p_muxer_err_t libp2p_muxer_negotiate_inbound(libp2p_muxer_t *m, libp2p_conn_t *c, uint64_t t)
{
    if (!m || !c)
        return LIBP2P_MUXER_ERR_NULL_PTR;
    return m->vt->negotiate(m, c, t, true);
}

/**
 * @brief Free the muxer instance.
 *
 * @param m Muxer instance (may be NULL).
 */
static inline void libp2p_muxer_free(libp2p_muxer_t *m)
{
    if (m && m->vt && m->vt->free)
        m->vt->free(m);
}

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MUXER_H */
