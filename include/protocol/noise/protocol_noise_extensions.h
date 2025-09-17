#ifndef PROTOCOL_NOISE_EXTENSIONS_H
#define PROTOCOL_NOISE_EXTENSIONS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file protocol_noise_extensions.h
 * @brief Parsing helpers for Noise protocol extensions.
 */

/**
 * @brief Parsed representation of the NoiseExtensions protobuf message.
 */
/* Registered Noise extension codepoints */
#define NOISE_EXT_WEBTRANSPORT_CERTHASHES 0x0A
#define NOISE_EXT_STREAM_MUXERS 0x12
#define NOISE_EXT_REGISTRY_MAX 1024

typedef struct noise_extensions
{
    uint8_t **webtransport_certhashes;
    size_t *webtransport_certhashes_lens;
    size_t num_webtransport_certhashes;

    char **stream_muxers;
    size_t num_stream_muxers;
} noise_extensions_t;

/**
 * @brief Parse a NoiseExtensions protobuf message.
 *
 * @param buf      Pointer to the serialized message bytes.
 * @param len      Length of @p buf in bytes.
 * @param out_ext  Output pointer receiving the parsed structure.
 * @return 0 on success, or -1 on failure.
 */
int parse_noise_extensions(const uint8_t *buf, size_t len, noise_extensions_t **out_ext);

/**
 * @brief Free a parsed NoiseExtensions structure.
 *
 * @param ext Structure to free (may be NULL).
 */
void noise_extensions_free(noise_extensions_t *ext);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_NOISE_EXTENSIONS_H */
