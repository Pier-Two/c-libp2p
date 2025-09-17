#ifndef LIBP2P_IO_H
#define LIBP2P_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "libp2p/errors.h"
#include "multiformats/multiaddr/multiaddr.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Generic I/O adapter that abstracts over libp2p_conn_t, libp2p_stream_t,
 * or protocol-specific substreams (e.g., yamux). Intended for use by
 * protocol negotiation (multiselect) and other helpers that only need
 * byte I/O, deadlines and address metadata. */

typedef struct libp2p_io libp2p_io_t;

typedef struct libp2p_io_vtbl
{
    ssize_t (*read)(libp2p_io_t *self, void *buf, size_t len);
    ssize_t (*write)(libp2p_io_t *self, const void *buf, size_t len);
    int (*set_deadline)(libp2p_io_t *self, uint64_t ms);
    const multiaddr_t *(*local_addr)(libp2p_io_t *self);
    const multiaddr_t *(*remote_addr)(libp2p_io_t *self);
    int (*close)(libp2p_io_t *self);
    void (*free)(libp2p_io_t *self);
} libp2p_io_vtbl_t;

struct libp2p_io
{
    const libp2p_io_vtbl_t *vt;
    void *ctx; /* backend-specific */
};

static inline ssize_t libp2p_io_read(libp2p_io_t *io, void *buf, size_t len)
{
    return io && io->vt && io->vt->read ? io->vt->read(io, buf, len) : LIBP2P_ERR_NULL_PTR;
}

static inline ssize_t libp2p_io_write(libp2p_io_t *io, const void *buf, size_t len)
{
    return io && io->vt && io->vt->write ? io->vt->write(io, buf, len) : LIBP2P_ERR_NULL_PTR;
}

static inline int libp2p_io_set_deadline(libp2p_io_t *io, uint64_t ms)
{
    return io && io->vt && io->vt->set_deadline ? io->vt->set_deadline(io, ms) : LIBP2P_ERR_NULL_PTR;
}

static inline const multiaddr_t *libp2p_io_local_addr(libp2p_io_t *io) { return io && io->vt && io->vt->local_addr ? io->vt->local_addr(io) : NULL; }

static inline const multiaddr_t *libp2p_io_remote_addr(libp2p_io_t *io)
{
    return io && io->vt && io->vt->remote_addr ? io->vt->remote_addr(io) : NULL;
}

static inline int libp2p_io_close(libp2p_io_t *io) { return io && io->vt && io->vt->close ? io->vt->close(io) : 0; }

static inline void libp2p_io_free(libp2p_io_t *io)
{
    if (io && io->vt && io->vt->free)
        io->vt->free(io);
}

/* Factories */
struct libp2p_connection; /* fwd */
struct libp2p_stream;     /* fwd */

libp2p_io_t *libp2p_io_from_conn(struct libp2p_connection *c);
libp2p_io_t *libp2p_io_from_stream(struct libp2p_stream *s);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_IO_H */
