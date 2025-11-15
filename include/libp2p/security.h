#ifndef LIBP2P_PUBLIC_SECURITY_H
#define LIBP2P_PUBLIC_SECURITY_H

#include "security/security.h"

/* This header intentionally exposes only the abstract security vtable.
 * Implementation factories (Noise, TLS, etc.) live in libp2p/security_*.h
 * so applications can opt into concrete handshakes explicitly. */

#endif /* LIBP2P_PUBLIC_SECURITY_H */
