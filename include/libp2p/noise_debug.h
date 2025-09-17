#ifndef LIBP2P_NOISE_DEBUG_H
#define LIBP2P_NOISE_DEBUG_H

#include "transport/connection.h" /* libp2p_conn_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Lightweight debug hooks implemented by the Noise connection layer. */
void noise_conn_debug_set_phase(libp2p_conn_t *c, const char *phase);
const char *noise_conn_debug_get_phase(const libp2p_conn_t *c);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_NOISE_DEBUG_H */

