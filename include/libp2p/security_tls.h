#ifndef LIBP2P_PUBLIC_SECURITY_TLS_H
#define LIBP2P_PUBLIC_SECURITY_TLS_H

#include "libp2p/security.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Optional TLS security transport entry point (not implemented in this build).
 * Returns non-zero to signal that TLS handshakes are unavailable. */
int libp2p_security_tls(libp2p_security_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PUBLIC_SECURITY_TLS_H */
