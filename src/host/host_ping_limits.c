#include <stdlib.h>
#include <string.h>

#include "host_internal.h"

static ping_count_entry_t *find_entry(const libp2p_host_t *host, const peer_id_t *peer)
{
    if (!host || !peer || !peer->bytes || peer->size == 0)
        return NULL;
    ping_count_entry_t *it = host->ping_counts;
    while (it)
    {
        if (peer_id_equals(&it->key, peer) == 1)
            return it;
        it = it->next;
    }
    return NULL;
}

static ping_count_entry_t *ensure_entry(libp2p_host_t *host, const peer_id_t *peer)
{
    ping_count_entry_t *e = find_entry(host, peer);
    if (e)
        return e;
    e = (ping_count_entry_t *)calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    /* deep copy key */
    e->key.bytes = (uint8_t *)malloc(peer->size);
    if (!e->key.bytes)
    {
        free(e);
        return NULL;
    }
    memcpy(e->key.bytes, peer->bytes, peer->size);
    e->key.size = peer->size;
    e->in_count = 0;
    e->out_count = 0;
    e->next = host->ping_counts;
    host->ping_counts = e;
    return e;
}

int libp2p__ping_counts_get(const libp2p_host_t *host, const peer_id_t *peer, int outbound)
{
    if (!host || !peer)
        return 0;
    /* Host mutex expected to be held by caller when used from hot paths, but
     * a best-effort read without locking is acceptable for conservative checks. */
    ping_count_entry_t *e = find_entry(host, peer);
    if (!e)
        return 0;
    return outbound ? e->out_count : e->in_count;
}

void libp2p__ping_counts_inc(libp2p_host_t *host, const peer_id_t *peer, int outbound)
{
    if (!host || !peer)
        return;
    pthread_mutex_lock(&host->mtx);
    ping_count_entry_t *e = ensure_entry(host, peer);
    if (e)
    {
        if (outbound)
            e->out_count++;
        else
            e->in_count++;
    }
    pthread_mutex_unlock(&host->mtx);
}

void libp2p__ping_counts_dec(libp2p_host_t *host, const peer_id_t *peer, int outbound)
{
    if (!host || !peer)
        return;
    pthread_mutex_lock(&host->mtx);
    ping_count_entry_t *e = find_entry(host, peer);
    if (e)
    {
        int *cnt = outbound ? &e->out_count : &e->in_count;
        if (*cnt > 0)
            (*cnt)--;
        /* Optional: prune empty entries */
        if (e->in_count == 0 && e->out_count == 0)
        {
            /* unlink */
            ping_count_entry_t **pp = &host->ping_counts;
            while (*pp)
            {
                if (*pp == e)
                {
                    *pp = e->next;
                    peer_id_destroy(&e->key);
                    free(e);
                    e = NULL;
                    break;
                }
                pp = &(*pp)->next;
            }
        }
    }
    pthread_mutex_unlock(&host->mtx);
}

void libp2p__ping_counts_free(libp2p_host_t *host)
{
    if (!host)
        return;
    ping_count_entry_t *it = host->ping_counts;
    while (it)
    {
        ping_count_entry_t *next = it->next;
        peer_id_destroy(&it->key);
        free(it);
        it = next;
    }
    host->ping_counts = NULL;
}
