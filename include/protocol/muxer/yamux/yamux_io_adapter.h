#ifndef YAMUX_IO_ADAPTER_H
#define YAMUX_IO_ADAPTER_H

#include <stdint.h>

struct libp2p_io;
struct libp2p_yamux_ctx;

/* Create a non-owning I/O adapter for a yamux substream (ctx+id).
 * The adapter does not close the substream or manage ctx lifetime; it
 * simply forwards I/O to yamux for temporary use (e.g., multiselect).
 */
struct libp2p_io *libp2p_io_from_yamux(struct libp2p_yamux_ctx *ctx, uint32_t id);

#endif /* YAMUX_IO_ADAPTER_H */
