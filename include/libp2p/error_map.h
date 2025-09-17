#ifndef LIBP2P_ERROR_MAP_H
#define LIBP2P_ERROR_MAP_H

/*
 * Helper functions to normalize subsystem error enums to libp2p_err_t.
 *
 * Modules: transport, listener, upgrader, multiselect
 */

#include "libp2p/errors.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include "transport/upgrader.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Map transport layer errors to canonical libp2p_err_t. */
libp2p_err_t libp2p_error_from_transport(libp2p_transport_err_t e);

/* Map listener errors to canonical libp2p_err_t. */
libp2p_err_t libp2p_error_from_listener(libp2p_listener_err_t e);

/* Map upgrader errors (security+muxer) to canonical libp2p_err_t. */
libp2p_err_t libp2p_error_from_upgrader(libp2p_upgrader_err_t e);

/* Map multistream-select errors to canonical libp2p_err_t. */
libp2p_err_t libp2p_error_from_multiselect(libp2p_multiselect_err_t e);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_ERROR_MAP_H */
