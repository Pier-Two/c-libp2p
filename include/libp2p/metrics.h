#ifndef LIBP2P_METRICS_H
#define LIBP2P_METRICS_H

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Minimal metrics surface: counters and histograms with a pluggable writer.
 * See specs/unified_libp2p_api_host_runtime.md for the expected API.
 */

typedef struct libp2p_metrics libp2p_metrics_t;

/* Create/free a metrics object. Uses no-op writer by default. */
int libp2p_metrics_new(libp2p_metrics_t **out);
void libp2p_metrics_free(libp2p_metrics_t *m);

/* Pluggable writer callbacks for counters and histograms. */
typedef void (*libp2p_metrics_counter_fn)(const char *name, const char *labels_json, double value, void *ud);
typedef void (*libp2p_metrics_hist_fn)(const char *name, const char *labels_json, double value, void *ud);

/* Optional: set writer callbacks. Passing NULL keeps previous callback. */
void libp2p_metrics_set_writer(libp2p_metrics_t *m, libp2p_metrics_counter_fn counter_cb, libp2p_metrics_hist_fn hist_cb, void *user_data);

/* Public API for recording metrics. Returns 0 on success. */
int libp2p_metrics_inc_counter(libp2p_metrics_t *m, const char *name, const char *labels_json, double value);
int libp2p_metrics_observe_histogram(libp2p_metrics_t *m, const char *name, const char *labels_json, double value);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_METRICS_H */
