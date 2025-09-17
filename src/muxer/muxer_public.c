#include "libp2p/muxer.h"

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
