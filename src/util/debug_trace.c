#include "libp2p/debug_trace.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <pthread.h>
#define THREAD_ID() ((unsigned long)pthread_mach_thread_np(pthread_self()))
#else
#define THREAD_ID() ((unsigned long)pthread_self())
#endif

typedef enum
{
    TRACE_STATE_INIT = 0,
    TRACE_STATE_DISABLED = -1,
    TRACE_STATE_ENABLED = 1
} trace_state_t;

static atomic_int g_trace_state = ATOMIC_VAR_INIT(TRACE_STATE_INIT);
static FILE *g_trace_fp = NULL;
static pthread_mutex_t g_trace_mutex = PTHREAD_MUTEX_INITIALIZER;

static void trace_close(void)
{
    FILE *fp = NULL;
    pthread_mutex_lock(&g_trace_mutex);
    fp = g_trace_fp;
    g_trace_fp = NULL;
    pthread_mutex_unlock(&g_trace_mutex);
    if (fp && fp != stderr)
        fclose(fp);
    atomic_store(&g_trace_state, TRACE_STATE_DISABLED);
}

void libp2p_debug_trace_shutdown(void) { trace_close(); }

static int trace_open_if_needed(void)
{
    int state = atomic_load(&g_trace_state);
    if (state == TRACE_STATE_ENABLED)
        return 1;
    if (state == TRACE_STATE_DISABLED)
        return 0;

    pthread_mutex_lock(&g_trace_mutex);
    if (g_trace_fp)
    {
        atomic_store(&g_trace_state, TRACE_STATE_ENABLED);
        pthread_mutex_unlock(&g_trace_mutex);
        return 1;
    }

    const char *path = getenv("LIBP2P_TRACE_FILE");
    if (!path || !*path)
    {
        atomic_store(&g_trace_state, TRACE_STATE_DISABLED);
        pthread_mutex_unlock(&g_trace_mutex);
        return 0;
    }

    if (strcmp(path, "stderr") == 0)
    {
        g_trace_fp = stderr;
    }
    else
    {
        g_trace_fp = fopen(path, "a");
    }

    if (!g_trace_fp)
    {
        atomic_store(&g_trace_state, TRACE_STATE_DISABLED);
        pthread_mutex_unlock(&g_trace_mutex);
        return 0;
    }

    setvbuf(g_trace_fp, NULL, _IOLBF, 0);
    atomic_store(&g_trace_state, TRACE_STATE_ENABLED);
    pthread_mutex_unlock(&g_trace_mutex);
    atexit(libp2p_debug_trace_shutdown);
    return 1;
}

static void trace_write(const char *tag, const char *fmt, va_list ap)
{
    if (!trace_open_if_needed())
        return;

    pthread_mutex_lock(&g_trace_mutex);
    FILE *fp = g_trace_fp ? g_trace_fp : stderr;

    struct timespec ts;
#if defined(CLOCK_REALTIME)
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    ts.tv_sec = time(NULL);
    ts.tv_nsec = 0;
#endif
    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tmv);

    fprintf(fp, "%s.%03ld pid=%ld tid=%lu %s: ", tbuf, ts.tv_nsec / 1000000, (long)getpid(), THREAD_ID(), tag ? tag : "trace");
    vfprintf(fp, fmt, ap);
    fputc('\n', fp);

    pthread_mutex_unlock(&g_trace_mutex);
}

void libp2p_debug_trace(const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    libp2p_debug_trace_v(tag, fmt, ap);
    va_end(ap);
}

void libp2p_debug_trace_v(const char *tag, const char *fmt, va_list ap)
{
    if (!fmt)
        return;
    va_list cp;
    va_copy(cp, ap);
    trace_write(tag, fmt, cp);
    va_end(cp);
}
