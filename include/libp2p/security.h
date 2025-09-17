#ifndef LIBP2P_PUBLIC_SECURITY_H
#define LIBP2P_PUBLIC_SECURITY_H

#include "protocol/noise/protocol_noise.h"
#include "security/security.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Convenience factory for the Noise security transport */
int libp2p_security_noise(libp2p_security_t **out);

/* Optional TLS security transport (not implemented in this build).
 * Provided as a stub to make builder defaults explicit when users
 * request TLS; returns non-zero to indicate unsupported. */
int libp2p_security_tls(libp2p_security_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PUBLIC_SECURITY_H */
