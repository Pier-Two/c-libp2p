#ifndef YAMUX_STREAM_ADAPTER_H
#define YAMUX_STREAM_ADAPTER_H

#include <stdint.h>

struct libp2p_stream;
struct libp2p_host;
struct libp2p_yamux_ctx;
struct peer_id;

/* Construct a libp2p_stream_t backed by a yamux substream (ctx,id).
 * Takes ownership of remote_peer (may be NULL). Does not take ownership
 * of ctx; holds an internal reference until stream close/reset. */
struct libp2p_stream *libp2p_stream_from_yamux(struct libp2p_host *host, struct libp2p_yamux_ctx *ctx, uint32_t id, const char *protocol_id,
                                               int initiator, struct peer_id *remote_peer);

#endif /* YAMUX_STREAM_ADAPTER_H */
