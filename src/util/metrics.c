#include "libp2p/metrics.h"

#include <stdlib.h>

struct libp2p_metrics
{
    libp2p_metrics_counter_fn counter_cb;
    libp2p_metrics_hist_fn hist_cb;
    void *ud;
};

int libp2p_metrics_new(libp2p_metrics_t **out)
{
    if (!out)
        return -1;
    libp2p_metrics_t *m = (libp2p_metrics_t *)calloc(1, sizeof(*m));
    if (!m)
        return -1;
    m->counter_cb = NULL; /* no-op until writer set */
    m->hist_cb = NULL;
    m->ud = NULL;
    *out = m;
    return 0;
}

void libp2p_metrics_free(libp2p_metrics_t *m)
{
    if (!m)
        return;
    free(m);
}

void libp2p_metrics_set_writer(libp2p_metrics_t *m, libp2p_metrics_counter_fn counter_cb, libp2p_metrics_hist_fn hist_cb, void *user_data)
{
    if (!m)
        return;
    if (counter_cb)
        m->counter_cb = counter_cb;
    if (hist_cb)
        m->hist_cb = hist_cb;
    m->ud = user_data;
}

int libp2p_metrics_inc_counter(libp2p_metrics_t *m, const char *name, const char *labels_json, double value)
{
    if (!m || !name)
        return -1;
    if (m->counter_cb)
        m->counter_cb(name, labels_json, value, m->ud);
    return 0;
}

int libp2p_metrics_observe_histogram(libp2p_metrics_t *m, const char *name, const char *labels_json, double value)
{
    if (!m || !name)
        return -1;
    if (m->hist_cb)
        m->hist_cb(name, labels_json, value, m->ud);
    return 0;
}
