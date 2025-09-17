#ifndef LIBP2P_STREAM_H
#define LIBP2P_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#include "libp2p/errors.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef LIBP2P_STREAM_TYPEDEF_DONE
typedef struct libp2p_stream libp2p_stream_t;
#define LIBP2P_STREAM_TYPEDEF_DONE 1
#endif
typedef void (*libp2p_on_writable_fn)(libp2p_stream_t *s, void *user_data);
typedef void (*libp2p_on_readable_fn)(libp2p_stream_t *s, void *user_data);

ssize_t libp2p_stream_write(libp2p_stream_t *s, const void *buf, size_t len);
ssize_t libp2p_stream_writev(libp2p_stream_t *s, const struct iovec *iov, int iovcnt);
int libp2p_stream_close(libp2p_stream_t *s);
int libp2p_stream_reset(libp2p_stream_t *s);
ssize_t libp2p_stream_read(libp2p_stream_t *s, void *buf, size_t len);
int libp2p_stream_set_read_interest(libp2p_stream_t *s, bool enable);
int libp2p_stream_on_writable(libp2p_stream_t *s, libp2p_on_writable_fn cb, void *user_data);
int libp2p_stream_on_readable(libp2p_stream_t *s, libp2p_on_readable_fn cb, void *user_data);
int libp2p_stream_set_deadline(libp2p_stream_t *s, uint64_t ms);
bool libp2p_stream_is_initiator(const libp2p_stream_t *s);
void libp2p_stream_set_user_data(libp2p_stream_t *s, void *user_data);
void *libp2p_stream_get_user_data(const libp2p_stream_t *s);
const peer_id_t *libp2p_stream_remote_peer(const libp2p_stream_t *s);
const char *libp2p_stream_protocol_id(const libp2p_stream_t *s);
const multiaddr_t *libp2p_stream_local_addr(const libp2p_stream_t *s);
const multiaddr_t *libp2p_stream_remote_addr(const libp2p_stream_t *s);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_STREAM_H */
