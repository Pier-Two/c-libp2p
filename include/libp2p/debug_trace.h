#ifndef LIBP2P_DEBUG_TRACE_H
#define LIBP2P_DEBUG_TRACE_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Lightweight runtime tracing helpers.
 *
 * Enable by setting the environment variable LIBP2P_TRACE_FILE to a writable
 * path (or "stderr"). When disabled the trace calls are compiled to cheap
 * checks and return immediately.
 */

void libp2p_debug_trace(const char *tag, const char *fmt, ...);
void libp2p_debug_trace_v(const char *tag, const char *fmt, va_list ap);
void libp2p_debug_trace_shutdown(void);

#define LIBP2P_TRACE(tag, fmt, ...) \
    libp2p_debug_trace((tag), (fmt), ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_DEBUG_TRACE_H */
