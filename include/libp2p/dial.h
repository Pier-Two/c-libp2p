#ifndef LIBP2P_DIAL_H
#define LIBP2P_DIAL_H

#include <stdbool.h>
#include <stddef.h>

#include "libp2p/host.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    size_t struct_size;           /* must be set to sizeof(libp2p_dial_opts_t) */
    const char *remote_multiaddr; /* required unless dialing by peer id (not yet supported) */
    const char *protocol_id;      /* optional; if NULL, returns a stream without protocol selection */
    int timeout_ms;               /* overrides host dial timeout; 0 = host default */
    bool enable_happy_eyeballs;   /* reserved for future use */
} libp2p_dial_opts_t;

int libp2p_host_dial_opts(libp2p_host_t *host, const libp2p_dial_opts_t *opts, libp2p_on_stream_open_fn on_open, void *user_data);

/* Optional cancellable variant */
struct libp2p_cancel_token;
int libp2p_host_dial_opts_cancellable(libp2p_host_t *host, const libp2p_dial_opts_t *opts, struct libp2p_cancel_token *cancel,
                                      libp2p_on_stream_open_fn on_open, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_DIAL_H */
