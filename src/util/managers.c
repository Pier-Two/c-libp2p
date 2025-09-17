/* Connection manager (resource manager removed for rust parity) */
#include "libp2p/conn_manager.h"
#include "peer_id/peer_id.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct libp2p_conn_mgr
{
    int low_water;
    int high_water;
    int grace_ms;
};

int libp2p_conn_mgr_new(int low_water, int high_water, int grace_ms, libp2p_conn_mgr_t **out)
{
    if (!out)
        return -1;
    libp2p_conn_mgr_t *cm = (libp2p_conn_mgr_t *)calloc(1, sizeof(*cm));
    if (!cm)
        return -1;
    cm->low_water = low_water;
    cm->high_water = high_water;
    cm->grace_ms = grace_ms;
    *out = cm;
    return 0;
}

void libp2p_conn_mgr_free(libp2p_conn_mgr_t *cm)
{
    if (!cm)
        return;
    free(cm);
}

/* Simple accessors so the host can integrate pruning/limits. */
int libp2p_conn_mgr_get_params(const libp2p_conn_mgr_t *cm, int *low_water, int *high_water, int *grace_ms)
{
    if (!cm)
        return -1;
    if (low_water)
        *low_water = cm->low_water;
    if (high_water)
        *high_water = cm->high_water;
    if (grace_ms)
        *grace_ms = cm->grace_ms;
    return 0;
}
