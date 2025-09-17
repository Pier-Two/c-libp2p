#ifndef LIBP2P_PUBLIC_MUXER_H
#define LIBP2P_PUBLIC_MUXER_H

#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol/muxer/yamux/protocol_yamux.h"
#include "transport/muxer.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Convenience factories for muxers (spec public API) */
int libp2p_muxer_yamux(libp2p_muxer_t **out);
int libp2p_muxer_mplex(libp2p_muxer_t **out);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PUBLIC_MUXER_H */
