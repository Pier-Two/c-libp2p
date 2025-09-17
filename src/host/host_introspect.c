#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#include "host_internal.h"

/*
 * Internal snapshot helper: locks the host, builds a container with borrowed
 * protocol ID pointers, and unlocks before returning. The returned array
 * contains borrowed pointers valid while the host (and registrations) live.
 */
static int snapshot_protocol_ids(libp2p_host_t *h, const char ***out_ids, size_t *out_len)
{
    if (!h || !out_ids || !out_len)
        return LIBP2P_ERR_NULL_PTR;
    size_t count = 0;
    pthread_mutex_lock(&h->mtx);
    for (protocol_entry_t *e = h->protocols; e; e = e->next)
        if (e->def.protocol_id)
            count++;
    const char **arr = count ? (const char **)calloc(count, sizeof(*arr)) : NULL;
    if (count && !arr)
    {
        pthread_mutex_unlock(&h->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    size_t i = 0;
    for (protocol_entry_t *e = h->protocols; e; e = e->next)
        if (e->def.protocol_id)
            arr[i++] = e->def.protocol_id; /* borrowed */
    pthread_mutex_unlock(&h->mtx);
    *out_ids = arr;
    *out_len = count;
    return 0;
}

int libp2p_host_supported_protocols(const libp2p_host_t *host, const char ***out_ids, size_t *out_len)
{
    if (!host || !out_ids || !out_len)
        return LIBP2P_ERR_NULL_PTR;
    /* Cast host once to use its mutex for a read-only snapshot. No const-cast
     * of the mutex itself; we route through a non-const host pointer locally. */
    libp2p_host_t *h = (libp2p_host_t *)(uintptr_t)host;
    return snapshot_protocol_ids(h, out_ids, out_len);
}

void libp2p_host_free_supported_protocols(const char **ids, size_t len)
{
    (void)len;
    free((void *)ids);
}
