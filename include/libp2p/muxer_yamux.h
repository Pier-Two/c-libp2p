#ifndef LIBP2P_PUBLIC_MUXER_YAMUX_H
#define LIBP2P_PUBLIC_MUXER_YAMUX_H

#include "libp2p/muxer.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Convenience factory for the Yamux stream multiplexer. */
int libp2p_muxer_yamux(libp2p_muxer_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PUBLIC_MUXER_YAMUX_H */
