/**
 * @file conn_pool.h
 * @brief Connection pool for libp2p host - reuses QUIC connections per peer.
 *
 * This pool enables connection reuse across multiple protocol dials to the
 * same peer. Instead of creating 8+ QUIC connections when multiple protocols
 * dial concurrently (each spawning a separate network thread), the pool
 * ensures only one connection per peer exists, dramatically reducing CPU usage.
 *
 * Architecture:
 * - Hash map keyed by peer_id for O(1) connection lookup
 * - In-flight dial tracking to prevent concurrent dials to the same peer
 * - Thread-safe access with mutex protection
 * - Automatic cleanup on connection close
 */

#ifndef LIBP2P_CONN_POOL_H
#define LIBP2P_CONN_POOL_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "peer_id/peer_id.h"
#include "transport/muxer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct libp2p_host;
struct libp2p_connection;

/* Guard against duplicate typedef from protocol_quic.h */
#ifndef LIBP2P_QUIC_SESSION_TYPEDEF
#define LIBP2P_QUIC_SESSION_TYPEDEF
typedef struct libp2p_quic_session libp2p_quic_session_t;
#endif

/**
 * @brief A pooled connection entry storing the muxer and associated metadata.
 */
typedef struct libp2p_pooled_conn {
    peer_id_t peer_id;                 /**< Deep copy of the remote peer ID */
    libp2p_muxer_t *muxer;             /**< The muxer (QUIC or Yamux) for multiplexing streams */
    libp2p_quic_session_t *session;    /**< QUIC session (may be NULL for TCP) */
    struct libp2p_connection *conn;    /**< The underlying secured connection */
    time_t created_at;                 /**< When this connection was established */
    time_t last_used;                  /**< Last time a stream was opened on this connection */
    int is_inbound;                    /**< 1 if accepted, 0 if we dialed */
    int is_closed;                     /**< 1 if marked for cleanup */
    struct libp2p_pooled_conn *next;   /**< Linked list for hash bucket chaining */
} libp2p_pooled_conn_t;

/**
 * @brief Tracks an in-progress dial to prevent duplicate concurrent dials.
 */
typedef struct libp2p_dial_pending {
    peer_id_t peer_id;                 /**< Deep copy of the peer being dialed */
    pthread_cond_t cond;               /**< Condition variable for waiters */
    int completed;                     /**< 1 when dial finished (success or failure) */
    int success;                       /**< 1 if dial succeeded, 0 if failed */
    struct libp2p_dial_pending *next;  /**< Linked list */
} libp2p_dial_pending_t;

/**
 * @brief Connection pool for reusing connections per peer.
 */
typedef struct libp2p_conn_pool {
    pthread_mutex_t lock;              /**< Protects all pool state */

    /* Hash table for O(1) peer lookup (simple bucket-chaining) */
    libp2p_pooled_conn_t **buckets;    /**< Hash buckets */
    size_t num_buckets;                /**< Number of buckets */
    size_t count;                      /**< Current number of entries */

    /* In-flight dial tracking */
    libp2p_dial_pending_t *pending_dials;  /**< List of ongoing dials */

    /* Configuration */
    size_t max_connections;            /**< Max connections to cache (0 = unlimited) */
    time_t max_idle_secs;              /**< Max idle time before eviction (0 = never) */
} libp2p_conn_pool_t;

/**
 * @brief Create a new connection pool.
 *
 * @param max_connections Maximum connections to cache (0 for unlimited)
 * @param max_idle_secs Maximum idle time in seconds (0 for no eviction)
 * @return New pool or NULL on failure
 */
libp2p_conn_pool_t *libp2p_conn_pool_new(size_t max_connections, time_t max_idle_secs);

/**
 * @brief Free the connection pool and all cached connections.
 *
 * @param pool The pool to free
 */
void libp2p_conn_pool_free(libp2p_conn_pool_t *pool);

/**
 * @brief Look up an existing connection to a peer.
 *
 * If found and alive, returns the muxer. Caller does NOT own the muxer.
 *
 * @param pool The connection pool
 * @param peer_id The peer to look up
 * @param out_entry If not NULL, receives the full pooled connection entry
 * @return The muxer for the connection, or NULL if not found/dead
 */
libp2p_muxer_t *libp2p_conn_pool_get(libp2p_conn_pool_t *pool,
                                      const peer_id_t *peer_id,
                                      libp2p_pooled_conn_t **out_entry);

/**
 * @brief Check if a dial to this peer is already in progress.
 *
 * @param pool The connection pool
 * @param peer_id The peer ID to check
 * @return true if a dial is in progress
 */
bool libp2p_conn_pool_dial_in_progress(libp2p_conn_pool_t *pool,
                                        const peer_id_t *peer_id);

/**
 * @brief Mark that a dial to this peer is starting.
 *
 * @param pool The connection pool
 * @param peer_id The peer being dialed
 * @return 0 on success, error code on failure
 */
int libp2p_conn_pool_mark_dialing(libp2p_conn_pool_t *pool,
                                   const peer_id_t *peer_id);

/**
 * @brief Wait for an in-progress dial to complete.
 *
 * If another thread is dialing this peer, block until it finishes.
 * Returns the muxer if the dial succeeded, NULL otherwise.
 * Caller must hold the pool lock when calling.
 *
 * @param pool The connection pool
 * @param peer_id The peer being dialed
 * @param timeout_ms Maximum time to wait (0 = indefinite)
 * @return The muxer if dial succeeded, NULL otherwise
 */
libp2p_muxer_t *libp2p_conn_pool_wait_for_dial(libp2p_conn_pool_t *pool,
                                                const peer_id_t *peer_id,
                                                int timeout_ms);

/**
 * @brief Add a new connection to the pool after successful dial.
 *
 * Takes ownership of the muxer and session. The pool will free them when
 * the connection is removed.
 *
 * @param pool The connection pool
 * @param peer_id The remote peer ID
 * @param muxer The muxer for stream multiplexing
 * @param session The QUIC session (may be NULL for TCP)
 * @param conn The underlying connection
 * @param is_inbound 1 if this was an accepted connection, 0 if dialed
 * @return 0 on success, error code on failure
 */
int libp2p_conn_pool_add(libp2p_conn_pool_t *pool,
                          const peer_id_t *peer_id,
                          libp2p_muxer_t *muxer,
                          libp2p_quic_session_t *session,
                          struct libp2p_connection *conn,
                          int is_inbound);

/**
 * @brief Signal that a dial has completed (success or failure).
 *
 * Wakes up any threads waiting on this dial.
 *
 * @param pool The connection pool
 * @param peer_id The peer that was dialed
 * @param success 1 if dial succeeded, 0 if failed
 */
void libp2p_conn_pool_dial_complete(libp2p_conn_pool_t *pool,
                                     const peer_id_t *peer_id,
                                     int success);

/**
 * @brief Remove a connection from the pool.
 *
 * Called when a connection closes or errors.
 *
 * @param pool The connection pool
 * @param peer_id The peer to remove
 */
void libp2p_conn_pool_remove(libp2p_conn_pool_t *pool,
                              const peer_id_t *peer_id);

/**
 * @brief Remove stale connections that have been idle too long.
 *
 * @param pool The connection pool
 */
void libp2p_conn_pool_gc(libp2p_conn_pool_t *pool);

/**
 * @brief Update the last_used timestamp for a connection.
 *
 * @param pool The connection pool
 * @param peer_id The peer whose connection was used
 */
void libp2p_conn_pool_touch(libp2p_conn_pool_t *pool, const peer_id_t *peer_id);

/**
 * @brief Get the number of pooled connections.
 *
 * @param pool The connection pool
 * @return Number of connections in the pool
 */
size_t libp2p_conn_pool_size(const libp2p_conn_pool_t *pool);

/**
 * @brief Check if a connection is still alive/usable.
 *
 * @param entry The pooled connection to check
 * @return true if the connection appears healthy
 */
bool libp2p_conn_pool_entry_is_alive(const libp2p_pooled_conn_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_CONN_POOL_H */

