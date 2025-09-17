#ifndef LIBP2P_EVENT_POLL_H
#define LIBP2P_EVENT_POLL_H

#include "libp2p/events.h"

#ifdef __cplusplus
extern "C"
{
#endif

int libp2p_host_next_event(libp2p_host_t *host, int timeout_ms, libp2p_event_t *out_evt);
void libp2p_event_free(libp2p_event_t *evt);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_EVENT_POLL_H */
