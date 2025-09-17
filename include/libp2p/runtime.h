#ifndef LIBP2P_RUNTIME_H
#define LIBP2P_RUNTIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_runtime libp2p_runtime_t;

typedef void (*libp2p_rt_fd_cb)(int fd, short events, void *user_data);
typedef void (*libp2p_rt_timer_cb)(void *user_data);

/* Minimal portable event loop with FD watchers and timers. */

/* Create/destroy */
libp2p_runtime_t *libp2p_runtime_new(void);
void libp2p_runtime_free(libp2p_runtime_t *rt);

/* Control loop */
void libp2p_runtime_stop(libp2p_runtime_t *rt);
int libp2p_runtime_run(libp2p_runtime_t *rt);

/* Watch an fd for readability (and optionally writability via events bitmask). */
int libp2p_runtime_add_fd(libp2p_runtime_t *rt, int fd, int want_read, int want_write, libp2p_rt_fd_cb cb, void *user_data);
int libp2p_runtime_mod_fd(libp2p_runtime_t *rt, int fd, int want_read, int want_write);
int libp2p_runtime_del_fd(libp2p_runtime_t *rt, int fd);

/* Add a one-shot or repeating timer. Returns timer id >= 1 on success. */
int libp2p_runtime_add_timer(libp2p_runtime_t *rt, uint64_t delay_ms, int repeat, libp2p_rt_timer_cb cb, void *user_data);
int libp2p_runtime_cancel_timer(libp2p_runtime_t *rt, int timer_id);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_RUNTIME_H */
