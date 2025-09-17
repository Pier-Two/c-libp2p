#ifndef MPLEX_IO_ADAPTER_H
#define MPLEX_IO_ADAPTER_H

#include <stdint.h>

struct libp2p_io;
struct libp2p_mplex_stream;

/* Build a generic libp2p_io_t wrapper over a single mplex substream. */
struct libp2p_io *libp2p_io_from_mplex(struct libp2p_mplex_stream *s);

#endif /* MPLEX_IO_ADAPTER_H */
