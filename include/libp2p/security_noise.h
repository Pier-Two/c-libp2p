#ifndef LIBP2P_PUBLIC_SECURITY_NOISE_H
#define LIBP2P_PUBLIC_SECURITY_NOISE_H

#include "libp2p/security.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Convenience factory for the Noise XX security transport. */
int libp2p_security_noise(libp2p_security_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PUBLIC_SECURITY_NOISE_H */
