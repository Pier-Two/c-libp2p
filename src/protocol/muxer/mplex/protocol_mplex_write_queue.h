#ifndef LIBP2P_MPLEX_WRITE_QUEUE_H
#define LIBP2P_MPLEX_WRITE_QUEUE_H

#include "protocol_mplex_internal.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Initialize a write queue
 * @param queue The write queue to initialize
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_write_queue_init(libp2p_mplex_write_queue_t *queue);

/**
 * @brief Destroy a write queue
 * @param queue The write queue to destroy
 */
void libp2p_mplex_write_queue_destroy(libp2p_mplex_write_queue_t *queue);

/**
 * @brief Push a frame to the write queue
 * @param queue The write queue
 * @param frame The frame to push
 * @return LIBP2P_MPLEX_OK on success, error code on failure
 */
int libp2p_mplex_write_queue_push(libp2p_mplex_write_queue_t *queue, const libp2p_mplex_frame_t *frame);

/**
 * @brief Pop a frame from the write queue (non-blocking)
 * @param queue The write queue
 * @return Pointer to the popped frame, or NULL if queue is empty
 * @note The caller is responsible for freeing the returned frame
 */
libp2p_mplex_frame_t *libp2p_mplex_write_queue_pop(libp2p_mplex_write_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MPLEX_WRITE_QUEUE_H */
