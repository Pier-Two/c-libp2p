#include "libp2p/muxer_mplex.h"
#include "libp2p/muxer_yamux.h"
#include "protocol/muxer/mplex/protocol_mplex.h"
#include "protocol/muxer/yamux/protocol_yamux.h"

int libp2p_muxer_yamux(libp2p_muxer_t **out)
{
    if (!out)
        return -1;
    *out = libp2p_yamux_new();
    return *out ? 0 : -1;
}

int libp2p_muxer_mplex(libp2p_muxer_t **out)
{
    if (!out)
        return -1;
    *out = libp2p_mplex_muxer_new();
    return *out ? 0 : -1;
}
