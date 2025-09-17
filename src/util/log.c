#include "libp2p/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static libp2p_log_level_t g_level = LIBP2P_LOG_ERROR;
static void (*g_writer)(libp2p_log_level_t lvl, const char *msg, void *ud) = NULL;
static void *g_ud = NULL;

void libp2p_log_set_level(libp2p_log_level_t lvl) { g_level = lvl; }

void libp2p_log_set_writer(void (*writer)(libp2p_log_level_t lvl, const char *msg, void *ud), void *ud)
{
    g_writer = writer;
    g_ud = ud;
}

void libp2p_logf(libp2p_log_level_t lvl, const char *fmt, ...)
{
    if (lvl > g_level)
        return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (g_writer)
    {
        g_writer(lvl, buf, g_ud);
    }
    else
    {
        const char *prefix = "";
        switch (lvl)
        {
            case LIBP2P_LOG_ERROR:
                prefix = "[ERROR] ";
                break;
            case LIBP2P_LOG_WARN:
                prefix = "[WARN ] ";
                break;
            case LIBP2P_LOG_INFO:
                prefix = "[INFO ] ";
                break;
            case LIBP2P_LOG_DEBUG:
                prefix = "[DEBUG] ";
                break;
            case LIBP2P_LOG_TRACE:
                prefix = "[TRACE] ";
                break;
            default:
                break;
        }
        fprintf(stderr, "%s%s\n", prefix, buf);
    }
}
