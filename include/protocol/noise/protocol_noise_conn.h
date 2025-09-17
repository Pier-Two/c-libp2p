#ifndef PROTOCOL_NOISE_CONN_H
#define PROTOCOL_NOISE_CONN_H

#include "protocol/noise/protocol_noise_extensions.h"
#include "transport/connection.h"
#include <noise/protocol.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file protocol_noise_conn.h
 * @brief Helpers for wrapping a raw connection with Noise framing.
 */

/**
 * @brief Wrap a raw connection with Noise framing and cipher states.
 *
 * The returned connection takes ownership of @p raw on success and uses the
 * provided cipher states for encryption and decryption.
 *
 * @param raw             Raw connection to wrap.
 * @param send            Initialized sending cipher state.
 * @param recv            Initialized receiving cipher state.
 * @param max_plaintext   Maximum plaintext size allowed.
 * @param early_data      Optional early data buffer (may be NULL).
 * @param early_data_len  Length of @p early_data in bytes.
 * @param extensions      Optional extensions buffer (may be NULL).
 * @param extensions_len  Length of @p extensions in bytes.
 * @param parsed_ext      Optional parsed extensions (may be NULL).
 * @return Newly allocated Noise-wrapped connection or NULL on error.
 */
libp2p_conn_t *make_noise_conn(libp2p_conn_t *raw, NoiseCipherState *send, NoiseCipherState *recv, size_t max_plaintext, uint8_t *early_data,
                               size_t early_data_len, uint8_t *extensions, size_t extensions_len, noise_extensions_t *parsed_ext);

/**
 * @brief Retrieve early data associated with a Noise connection.
 *
 * @param c   Connection returned by make_noise_conn().
 * @param len Output length of the early data.
 * @return Pointer to the early data bytes or NULL if none.
 */
const uint8_t *noise_conn_get_early_data(const libp2p_conn_t *c, size_t *len);

/**
 * @brief Get the raw NoiseExtensions message from a connection.
 *
 * @param c   Connection returned by make_noise_conn().
 * @param len Output length of the extensions message.
 * @return Pointer to the extensions bytes or NULL if none.
 */
const uint8_t *noise_conn_get_extensions(const libp2p_conn_t *c, size_t *len);

/**
 * @brief Get the parsed NoiseExtensions structure from a connection.
 *
 * @param c Connection returned by make_noise_conn().
 * @return Parsed extensions or NULL if none are present.
 */
const noise_extensions_t *noise_conn_get_parsed_extensions(const libp2p_conn_t *c);

/* Debug helpers: annotate expected usage phase of the secured connection. */
void noise_conn_debug_set_phase(libp2p_conn_t *c, const char *phase);
const char *noise_conn_debug_get_phase(const libp2p_conn_t *c);

/* Test helpers used by the unit tests to introspect/debug counter limits. */
size_t noise_conn_debug_get_max_plaintext(const libp2p_conn_t *c);
void noise_conn_debug_set_send_count(libp2p_conn_t *c, uint64_t count);
void noise_conn_debug_set_recv_count(libp2p_conn_t *c, uint64_t count);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_NOISE_CONN_H */
