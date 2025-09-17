#ifndef LIBP2P_PROTOCOL_H
#define LIBP2P_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libp2p/stream.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    LIBP2P_READ_PUSH,
    LIBP2P_READ_PULL
} libp2p_read_mode_t;

typedef struct
{
    const char *protocol_id;
    libp2p_read_mode_t read_mode;
    /*
     * Called when an inbound stream for this protocol is opened.
     * Threading: executed on the host's application callback executor
     * (single-threaded), not on the muxer/transport worker thread.
     */
    void (*on_open)(struct libp2p_stream *s, void *user_data);
    void (*on_data)(struct libp2p_stream *s, const uint8_t *data, size_t len, void *user_data);
    void (*on_eof)(struct libp2p_stream *s, void *user_data);
    void (*on_close)(struct libp2p_stream *s, void *user_data);
    void (*on_error)(struct libp2p_stream *s, int err, void *user_data);
    void *user_data;
} libp2p_protocol_def_t;

int libp2p_register_protocol(struct libp2p_host *host, const libp2p_protocol_def_t *def);
int libp2p_unregister_protocol(struct libp2p_host *host, const char *protocol_id);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_H */
