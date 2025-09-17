#ifndef LIBP2P_ERRORS_H
#define LIBP2P_ERRORS_H

/*
 * Canonical error codes for the unified libp2p API.
 * These map subsystem-specific errors (transport, muxer, security, etc.)
 * into a single enum suitable for public APIs.
 */

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    LIBP2P_ERR_OK = 0,
    LIBP2P_ERR_NULL_PTR = -1,
    LIBP2P_ERR_AGAIN = -2,
    LIBP2P_ERR_EOF = -3,
    LIBP2P_ERR_TIMEOUT = -4,
    LIBP2P_ERR_CLOSED = -5,
    LIBP2P_ERR_RESET = -6,
    LIBP2P_ERR_INTERNAL = -7,
    LIBP2P_ERR_PROTO_NEGOTIATION_FAILED = -8,
    LIBP2P_ERR_MSG_TOO_LARGE = -9,
    LIBP2P_ERR_UNSUPPORTED = -10,
    LIBP2P_ERR_CANCELED = -11
} libp2p_err_t;

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_ERRORS_H */
