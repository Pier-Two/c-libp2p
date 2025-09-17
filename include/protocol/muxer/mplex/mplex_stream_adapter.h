#ifndef MPLEX_STREAM_ADAPTER_H
#define MPLEX_STREAM_ADAPTER_H

#include <stdint.h>

struct libp2p_stream;
struct libp2p_host;
struct libp2p_mplex_ctx;
struct libp2p_mplex_stream;
struct peer_id;

/* Construct a libp2p_stream_t backed by an mplex substream. Does not take
 * ownership of ctx or stream. Takes ownership of remote_peer (may be NULL). */
struct libp2p_stream *libp2p_stream_from_mplex(struct libp2p_host *host, struct libp2p_mplex_ctx *ctx, struct libp2p_mplex_stream *stream,
                                               const char *protocol_id, int initiator, struct peer_id *remote_peer);

#endif /* MPLEX_STREAM_ADAPTER_H */
