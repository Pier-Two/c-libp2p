#ifndef LIBP2P_LOG_H
#define LIBP2P_LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    LIBP2P_LOG_ERROR = 0,
    LIBP2P_LOG_WARN,
    LIBP2P_LOG_INFO,
    LIBP2P_LOG_DEBUG,
    LIBP2P_LOG_TRACE
} libp2p_log_level_t;

/* Runtime controls */
void libp2p_log_set_level(libp2p_log_level_t lvl);
void libp2p_log_set_writer(void (*writer)(libp2p_log_level_t lvl, const char *msg, void *ud), void *ud);

/* Internal convenience for library use; applications shouldn't rely on it. */
void libp2p_logf(libp2p_log_level_t lvl, const char *fmt, ...);

/* ----------------------------------------------------
 * Lightweight logging macros with structured context
 * ----------------------------------------------------
 * - Severity helpers: LP_LOGE/W/I/D/T
 * - Structured fields embedded in the message prefix:
 *     module=... file=... line=... func=...
 * - Compiled out in release builds (when NDEBUG is set), unless
 *   LIBP2P_LOGGING_FORCE is defined to keep logs.
 */

#if defined(NDEBUG) && !defined(LIBP2P_LOGGING_FORCE)
#define LIBP2P_LOGGING_ENABLED 0
#else
#define LIBP2P_LOGGING_ENABLED 1
#endif

#if LIBP2P_LOGGING_ENABLED
#define LP_LOGF(_lvl, _module, _fmt, ...)                                                                                                            \
    libp2p_logf((_lvl), "[module=%s file=%s line=%d func=%s] " _fmt, (_module), __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define LP_LOGF(_lvl, _module, _fmt, ...) ((void)0)
#endif

#define LP_LOGE(_module, _fmt, ...) LP_LOGF(LIBP2P_LOG_ERROR, (_module), _fmt, ##__VA_ARGS__)
#define LP_LOGW(_module, _fmt, ...) LP_LOGF(LIBP2P_LOG_WARN, (_module), _fmt, ##__VA_ARGS__)
#define LP_LOGI(_module, _fmt, ...) LP_LOGF(LIBP2P_LOG_INFO, (_module), _fmt, ##__VA_ARGS__)
#define LP_LOGD(_module, _fmt, ...) LP_LOGF(LIBP2P_LOG_DEBUG, (_module), _fmt, ##__VA_ARGS__)
#define LP_LOGT(_module, _fmt, ...) LP_LOGF(LIBP2P_LOG_TRACE, (_module), _fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_LOG_H */
