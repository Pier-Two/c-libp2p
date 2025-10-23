#ifndef LIBP2P_GOSSIPSUB_HOST_EVENTS_H
#define LIBP2P_GOSSIPSUB_HOST_EVENTS_H

#include "gossipsub_internal.h"
#include "libp2p/events.h"

#ifdef __cplusplus
extern "C" {
#endif

void gossipsub_host_events_populate_protocol_defs(libp2p_gossipsub_t *gs);
void *gossipsub_host_events_runtime_thread(void *arg);
void gossipsub_host_events_on_host_event(const libp2p_event_t *evt, void *user_data);
void gossipsub_on_stream_open(struct libp2p_stream *s, void *user_data);
void gossipsub_on_stream_data(struct libp2p_stream *s, const uint8_t *data, size_t len, void *user_data);
void gossipsub_on_stream_eof(struct libp2p_stream *s, void *user_data);
void gossipsub_on_stream_close(struct libp2p_stream *s, void *user_data);
void gossipsub_on_stream_error(struct libp2p_stream *s, int err, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_GOSSIPSUB_HOST_EVENTS_H */
