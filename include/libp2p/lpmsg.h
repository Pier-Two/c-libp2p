#ifndef LIBP2P_LPMSG_H
#define LIBP2P_LPMSG_H

#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

ssize_t libp2p_lp_send(libp2p_stream_t *s, const uint8_t *data, size_t len);
ssize_t libp2p_lp_recv(libp2p_stream_t *s, uint8_t *buf, size_t max_len);
/* Variant using the generic I/O adapter for early-stage negotiations. */
struct libp2p_io; /* fwd */
ssize_t libp2p_lp_recv_io(struct libp2p_io *io, uint8_t *buf, size_t max_len);
/* Timeout-configurable variant. If stall_timeout_ms == 0, uses library default. */
ssize_t libp2p_lp_recv_io_timeout(struct libp2p_io *io, uint8_t *buf, size_t max_len, uint64_t stall_timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_LPMSG_H */
