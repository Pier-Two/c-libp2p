#ifndef LIBP2P_PUBLIC_TRANSPORT_H
#define LIBP2P_PUBLIC_TRANSPORT_H

#include "transport/transport.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Convenience factory for TCP transport (spec public API) */
int libp2p_transport_tcp(libp2p_transport_t **out);

/* Optional QUIC transport (TLS 1.3 + ALPN "libp2p").
 * This stub returns non-zero if QUIC is not compiled in. */
int libp2p_transport_quic(libp2p_transport_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PUBLIC_TRANSPORT_H */
