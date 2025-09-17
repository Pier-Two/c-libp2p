#ifndef BASE64_URL_PAD_H
#define BASE64_URL_PAD_H

#include <stddef.h>
#include <stdint.h>

#include "multiformats/multibase/multibase.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief The character used to represent Base64 URL format (RFC4648) with padding.
 */
#define BASE64_URL_PAD_CHARACTER 'U'

/**
 * @brief Encode data into Base64 URL format (RFC4648) with padding.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base64 URL padded string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer, or an error code.
 */
int multibase_base64_url_pad_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len);

/**
 * @brief Decode a Base64 URL padded encoded string (RFC4648) with padding.
 *
 * @param in The input Base64 URL padded encoded string.
 * @param data_len The length of the input encoded data.
 * @param out The buffer to store the decoded binary data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code.
 */
int multibase_base64_url_pad_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* BASE64_URL_PAD_H */