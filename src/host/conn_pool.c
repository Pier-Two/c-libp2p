/**
 * @file conn_pool.c
 * @brief Connection pool implementation for libp2p host.
 *
 * This implementation provides connection reuse to solve the CPU issue where
 * multiple concurrent dials to the same peer create multiple QUIC connections,
 * each with its own network thread, causing ~800% CPU usage.
 */

#include "conn_pool.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "libp2p/errors.h"
#include "libp2p/log.h"
#include "protocol/quic/protocol_quic.h"
#include "transport/connection.h"

/* Default number of hash buckets */
#define CONN_POOL_DEFAULT_BUCKETS 64

/* Simple hash function for peer IDs */
static uint32_t peer_id_hash(const peer_id_t *pid, size_t num_buckets)
{
    if (!pid || !pid->bytes || pid->size == 0 || num_buckets == 0)
        return 0;

    /* FNV-1a hash */
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < pid->size; i++)
    {
        hash ^= pid->bytes[i];
        hash *= 16777619u;
    }
    return hash % (uint32_t)num_buckets;
}

/* Use peer_id_equals from peer_id.h */

/* Deep copy a peer ID */
static int peer_id_copy(const peer_id_t *src, peer_id_t *dst)
{
    if (!src || !dst)
        return -1;
    memset(dst, 0, sizeof(*dst));
    if (!src->bytes || src->size == 0)
        return 0;
    dst->bytes = (uint8_t *)malloc(src->size);
    if (!dst->bytes)
        return -1;
    memcpy(dst->bytes, src->bytes, src->size);
    dst->size = src->size;
    return 0;
}

/* Free the contents of a pooled connection entry */
static void pooled_conn_entry_free(libp2p_pooled_conn_t *entry)
{
    if (!entry)
        return;
    if (entry->peer_id.bytes)
    {
        peer_id_destroy(&entry->peer_id);
    }
    /* Note: We don't free the muxer/conn here - they're owned by the session
     * and will be cleaned up when the session closes. We just NULL them. */
    entry->muxer = NULL;
    entry->session = NULL;
    entry->conn = NULL;
    free(entry);
}

/* Free a pending dial entry */
static void dial_pending_free(libp2p_dial_pending_t *pending)
{
    if (!pending)
        return;
    if (pending->peer_id.bytes)
    {
        peer_id_destroy(&pending->peer_id);
    }
    pthread_cond_destroy(&pending->cond);
    free(pending);
}

libp2p_conn_pool_t *libp2p_conn_pool_new(size_t max_connections, time_t max_idle_secs)
{
    libp2p_conn_pool_t *pool = (libp2p_conn_pool_t *)calloc(1, sizeof(*pool));
    if (!pool)
        return NULL;

    if (pthread_mutex_init(&pool->lock, NULL) != 0)
    {
        free(pool);
        return NULL;
    }

    pool->num_buckets = CONN_POOL_DEFAULT_BUCKETS;
    pool->buckets = (libp2p_pooled_conn_t **)calloc(pool->num_buckets, sizeof(*pool->buckets));
    if (!pool->buckets)
    {
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }

    pool->count = 0;
    pool->pending_dials = NULL;
    pool->max_connections = max_connections;
    pool->max_idle_secs = max_idle_secs;

    LP_LOGD("CONN_POOL", "created pool=%p buckets=%zu max_conns=%zu max_idle=%ld",
            (void *)pool, pool->num_buckets, max_connections, (long)max_idle_secs);

    return pool;
}

void libp2p_conn_pool_free(libp2p_conn_pool_t *pool)
{
    if (!pool)
        return;

    pthread_mutex_lock(&pool->lock);

    /* Free all pooled connections */
    for (size_t i = 0; i < pool->num_buckets; i++)
    {
        libp2p_pooled_conn_t *entry = pool->buckets[i];
        while (entry)
        {
            libp2p_pooled_conn_t *next = entry->next;
            pooled_conn_entry_free(entry);
            entry = next;
        }
        pool->buckets[i] = NULL;
    }
    free(pool->buckets);
    pool->buckets = NULL;

    /* Free all pending dials and wake waiters */
    libp2p_dial_pending_t *pending = pool->pending_dials;
    while (pending)
    {
        libp2p_dial_pending_t *next = pending->next;
        pending->completed = 1;
        pending->success = 0;
        pthread_cond_broadcast(&pending->cond);
        dial_pending_free(pending);
        pending = next;
    }
    pool->pending_dials = NULL;

    pthread_mutex_unlock(&pool->lock);
    pthread_mutex_destroy(&pool->lock);

    LP_LOGD("CONN_POOL", "freed pool=%p", (void *)pool);
    free(pool);
}

libp2p_muxer_t *libp2p_conn_pool_get(libp2p_conn_pool_t *pool,
                                      const peer_id_t *peer_id,
                                      libp2p_pooled_conn_t **out_entry)
{
    if (!pool || !peer_id)
        return NULL;

    pthread_mutex_lock(&pool->lock);

    uint32_t bucket = peer_id_hash(peer_id, pool->num_buckets);
    libp2p_pooled_conn_t *entry = pool->buckets[bucket];

    while (entry)
    {
        if (peer_id_equals(&entry->peer_id, peer_id))
        {
            if (entry->is_closed || !entry->muxer)
            {
                /* Connection is dead, remove it */
                LP_LOGD("CONN_POOL", "get: found dead entry, removing");
                pthread_mutex_unlock(&pool->lock);
                libp2p_conn_pool_remove(pool, peer_id);
                return NULL;
            }

            /* Update last used time */
            entry->last_used = time(NULL);

            if (out_entry)
                *out_entry = entry;

            LP_LOGD("CONN_POOL", "get: found entry for peer, muxer=%p",
                    (void *)entry->muxer);

            pthread_mutex_unlock(&pool->lock);
            return entry->muxer;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

bool libp2p_conn_pool_dial_in_progress(libp2p_conn_pool_t *pool,
                                        const peer_id_t *peer_id)
{
    if (!pool || !peer_id)
        return false;

    pthread_mutex_lock(&pool->lock);

    libp2p_dial_pending_t *pending = pool->pending_dials;
    while (pending)
    {
        if (peer_id_equals(&pending->peer_id, peer_id) && !pending->completed)
        {
            pthread_mutex_unlock(&pool->lock);
            return true;
        }
        pending = pending->next;
    }

    pthread_mutex_unlock(&pool->lock);
    return false;
}

int libp2p_conn_pool_mark_dialing(libp2p_conn_pool_t *pool,
                                   const peer_id_t *peer_id)
{
    if (!pool || !peer_id)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_dial_pending_t *pending = (libp2p_dial_pending_t *)calloc(1, sizeof(*pending));
    if (!pending)
        return LIBP2P_ERR_INTERNAL;

    if (peer_id_copy(peer_id, &pending->peer_id) != 0)
    {
        free(pending);
        return LIBP2P_ERR_INTERNAL;
    }

    if (pthread_cond_init(&pending->cond, NULL) != 0)
    {
        peer_id_destroy(&pending->peer_id);
        free(pending);
        return LIBP2P_ERR_INTERNAL;
    }

    pending->completed = 0;
    pending->success = 0;

    pthread_mutex_lock(&pool->lock);
    pending->next = pool->pending_dials;
    pool->pending_dials = pending;
    pthread_mutex_unlock(&pool->lock);

    LP_LOGD("CONN_POOL", "mark_dialing: peer tracked");
    return 0;
}

libp2p_muxer_t *libp2p_conn_pool_wait_for_dial(libp2p_conn_pool_t *pool,
                                                const peer_id_t *peer_id,
                                                int timeout_ms)
{
    if (!pool || !peer_id)
        return NULL;

    pthread_mutex_lock(&pool->lock);

    /* Find the pending dial entry */
    libp2p_dial_pending_t *pending = pool->pending_dials;
    while (pending)
    {
        if (peer_id_equals(&pending->peer_id, peer_id))
            break;
        pending = pending->next;
    }

    if (!pending)
    {
        pthread_mutex_unlock(&pool->lock);
        return NULL;
    }

    /* Wait for completion */
    if (timeout_ms > 0)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000)
        {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        while (!pending->completed)
        {
            int rc = pthread_cond_timedwait(&pending->cond, &pool->lock, &ts);
            if (rc == ETIMEDOUT)
                break;
        }
    }
    else
    {
        while (!pending->completed)
        {
            pthread_cond_wait(&pending->cond, &pool->lock);
        }
    }

    int success = pending->success;
    pthread_mutex_unlock(&pool->lock);

    if (!success)
        return NULL;

    /* Dial succeeded - get the connection from the pool */
    return libp2p_conn_pool_get(pool, peer_id, NULL);
}

int libp2p_conn_pool_add(libp2p_conn_pool_t *pool,
                          const peer_id_t *peer_id,
                          libp2p_muxer_t *muxer,
                          libp2p_quic_session_t *session,
                          struct libp2p_connection *conn,
                          int is_inbound)
{
    if (!pool || !peer_id || !muxer)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_pooled_conn_t *entry = (libp2p_pooled_conn_t *)calloc(1, sizeof(*entry));
    if (!entry)
        return LIBP2P_ERR_INTERNAL;

    if (peer_id_copy(peer_id, &entry->peer_id) != 0)
    {
        free(entry);
        return LIBP2P_ERR_INTERNAL;
    }

    entry->muxer = muxer;
    entry->session = session;
    entry->conn = conn;
    entry->created_at = time(NULL);
    entry->last_used = entry->created_at;
    entry->is_inbound = is_inbound;
    entry->is_closed = 0;
    entry->next = NULL;

    pthread_mutex_lock(&pool->lock);

    /* Check if we already have a connection to this peer */
    uint32_t bucket = peer_id_hash(peer_id, pool->num_buckets);
    libp2p_pooled_conn_t *existing = pool->buckets[bucket];
    libp2p_pooled_conn_t *prev = NULL;

    while (existing)
    {
        if (peer_id_equals(&existing->peer_id, peer_id))
        {
            /* Tie-breaker: for duplicate connections, keep the one where
             * we are NOT the initiator (standard libp2p behavior: the peer
             * with the lower peer ID keeps their outbound connection).
             * For simplicity, we prefer the existing connection if alive. */
            if (!existing->is_closed && existing->muxer)
            {
                LP_LOGD("CONN_POOL", "add: already have connection to peer, dropping new");
                pthread_mutex_unlock(&pool->lock);
                pooled_conn_entry_free(entry);
                return 0;
            }
            /* Existing is dead, replace it */
            if (prev)
                prev->next = existing->next;
            else
                pool->buckets[bucket] = existing->next;
            pool->count--;
            pooled_conn_entry_free(existing);
            break;
        }
        prev = existing;
        existing = existing->next;
    }

    /* Add to bucket */
    entry->next = pool->buckets[bucket];
    pool->buckets[bucket] = entry;
    pool->count++;

    LP_LOGI("CONN_POOL", "add: added connection to pool, count=%zu muxer=%p inbound=%d",
            pool->count, (void *)muxer, is_inbound);

    pthread_mutex_unlock(&pool->lock);
    return 0;
}

void libp2p_conn_pool_dial_complete(libp2p_conn_pool_t *pool,
                                     const peer_id_t *peer_id,
                                     int success)
{
    if (!pool || !peer_id)
        return;

    pthread_mutex_lock(&pool->lock);

    /* Find and update the pending dial entry */
    libp2p_dial_pending_t *pending = pool->pending_dials;
    libp2p_dial_pending_t *prev = NULL;

    while (pending)
    {
        if (peer_id_equals(&pending->peer_id, peer_id))
        {
            pending->completed = 1;
            pending->success = success;
            pthread_cond_broadcast(&pending->cond);

            /* Remove from list */
            if (prev)
                prev->next = pending->next;
            else
                pool->pending_dials = pending->next;

            pthread_mutex_unlock(&pool->lock);

            LP_LOGD("CONN_POOL", "dial_complete: success=%d", success);

            /* Free after unlocking to avoid holding lock during free */
            dial_pending_free(pending);
            return;
        }
        prev = pending;
        pending = pending->next;
    }

    pthread_mutex_unlock(&pool->lock);
}

void libp2p_conn_pool_remove(libp2p_conn_pool_t *pool,
                              const peer_id_t *peer_id)
{
    if (!pool || !peer_id)
        return;

    pthread_mutex_lock(&pool->lock);

    uint32_t bucket = peer_id_hash(peer_id, pool->num_buckets);
    libp2p_pooled_conn_t *entry = pool->buckets[bucket];
    libp2p_pooled_conn_t *prev = NULL;

    while (entry)
    {
        if (peer_id_equals(&entry->peer_id, peer_id))
        {
            if (prev)
                prev->next = entry->next;
            else
                pool->buckets[bucket] = entry->next;
            pool->count--;

            LP_LOGD("CONN_POOL", "remove: removed entry, count=%zu", pool->count);

            pthread_mutex_unlock(&pool->lock);
            pooled_conn_entry_free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&pool->lock);
}

void libp2p_conn_pool_gc(libp2p_conn_pool_t *pool)
{
    if (!pool || pool->max_idle_secs == 0)
        return;

    time_t now = time(NULL);
    time_t cutoff = now - pool->max_idle_secs;

    pthread_mutex_lock(&pool->lock);

    for (size_t i = 0; i < pool->num_buckets; i++)
    {
        libp2p_pooled_conn_t *entry = pool->buckets[i];
        libp2p_pooled_conn_t *prev = NULL;

        while (entry)
        {
            libp2p_pooled_conn_t *next = entry->next;

            if (entry->last_used < cutoff || entry->is_closed)
            {
                if (prev)
                    prev->next = next;
                else
                    pool->buckets[i] = next;
                pool->count--;

                LP_LOGD("CONN_POOL", "gc: evicting stale entry, idle=%ld sec",
                        (long)(now - entry->last_used));

                pooled_conn_entry_free(entry);
            }
            else
            {
                prev = entry;
            }
            entry = next;
        }
    }

    pthread_mutex_unlock(&pool->lock);
}

void libp2p_conn_pool_touch(libp2p_conn_pool_t *pool, const peer_id_t *peer_id)
{
    if (!pool || !peer_id)
        return;

    pthread_mutex_lock(&pool->lock);

    uint32_t bucket = peer_id_hash(peer_id, pool->num_buckets);
    libp2p_pooled_conn_t *entry = pool->buckets[bucket];

    while (entry)
    {
        if (peer_id_equals(&entry->peer_id, peer_id))
        {
            entry->last_used = time(NULL);
            break;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&pool->lock);
}

size_t libp2p_conn_pool_size(const libp2p_conn_pool_t *pool)
{
    if (!pool)
        return 0;

    pthread_mutex_lock((pthread_mutex_t *)&pool->lock);
    size_t count = pool->count;
    pthread_mutex_unlock((pthread_mutex_t *)&pool->lock);

    return count;
}

bool libp2p_conn_pool_entry_is_alive(const libp2p_pooled_conn_t *entry)
{
    if (!entry)
        return false;
    if (entry->is_closed)
        return false;
    if (!entry->muxer)
        return false;

    /* For QUIC, check if session is still valid */
    if (entry->session)
    {
        /* The session's internal cnx is set to NULL when closed */
        /* We can't easily check this without the quic_internal.h header,
         * so we trust the is_closed flag and muxer presence */
    }

    return true;
}

