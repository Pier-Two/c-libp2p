#include <stdlib.h>
#include <string.h>

#include "../../../external/sha3/sha3.h"
#include "../../../external/wjcryptlib/lib/WjCryptLib_Sha256.h"
#include "../../../external/wjcryptlib/lib/WjCryptLib_Sha512.h"

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

/**
 * @brief Define the sizes of the SHA3 hash functions.
 */
#define SHA3_224_HASH_SIZE 28
#define SHA3_256_HASH_SIZE 32
#define SHA3_384_HASH_SIZE 48
#define SHA3_512_HASH_SIZE 64

/**
 * @brief Returns the expected digest size for the given hash function code.
 *
 * @param code The hash function code.
 * @return The digest size in bytes, or 0 if the code is unsupported.
 */
static size_t expected_digest_size(uint64_t code, size_t data_len)
{
    switch (code)
    {
        case MULTICODEC_SHA2_256:
            return SHA256_HASH_SIZE;
        case MULTICODEC_SHA2_512:
            return SHA512_HASH_SIZE;
        case MULTICODEC_SHA3_224:
            return SHA3_224_HASH_SIZE;
        case MULTICODEC_SHA3_256:
            return SHA3_256_HASH_SIZE;
        case MULTICODEC_SHA3_384:
            return SHA3_384_HASH_SIZE;
        case MULTICODEC_SHA3_512:
            return SHA3_512_HASH_SIZE;
        case MULTICODEC_IDENTITY:
            return data_len;
        default:
            return 0;
    }
}

/**
 * @brief Compute the digest for the provided data using the specified hash function.
 *
 * @param code The hash function code.
 * @param data The input data to be hashed.
 * @param data_len The length of the input data.
 * @param digest_out The buffer to store the computed digest.
 * @param digest_len Pointer to store the length of the computed digest.
 * @return int Error code indicating success or type of failure.
 */
static int compute_hash(uint64_t code, const uint8_t *data, size_t data_len, uint8_t *digest_out, size_t *digest_len)
{
    if (!data || !digest_out || !digest_len)
    {
        return MULTIHASH_ERR_NULL_POINTER;
    }

    switch (code)
    {
        case MULTICODEC_SHA2_256:
        {
            *digest_len = SHA256_HASH_SIZE;
            SHA256_HASH hash;
            Sha256Calculate(data, (uint32_t)data_len, &hash);
            memcpy(digest_out, hash.bytes, SHA256_HASH_SIZE);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA2_512:
        {
            *digest_len = SHA512_HASH_SIZE;
            SHA512_HASH hash;
            Sha512Context ctx;
            Sha512Initialise(&ctx);
            Sha512Update(&ctx, data, (uint32_t)data_len);
            Sha512Finalise(&ctx, &hash);
            memcpy(digest_out, hash.bytes, SHA512_HASH_SIZE);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_224:
        {
            *digest_len = SHA3_224_HASH_SIZE;
            sha3_224(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_256:
        {
            *digest_len = SHA3_256_HASH_SIZE;
            sha3_256(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_384:
        {
            *digest_len = SHA3_384_HASH_SIZE;
            sha3_384(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_512:
        {
            *digest_len = SHA3_512_HASH_SIZE;
            sha3_512(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_IDENTITY:
        {
            *digest_len = data_len;
            memcpy(digest_out, data, data_len);
            return MULTIHASH_SUCCESS;
        }
        default:
            return MULTIHASH_ERR_UNSUPPORTED_FUN;
    }
}

/**
 * @brief Encode a multihash.
 *
 * @param code The hash function code to be encoded.
 * @param data The input data to be hashed.
 * @param data_len The length of the input data.
 * @param out The buffer to write the encoded multihash to.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code.
 */
int multihash_encode(uint64_t code, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
{
    if (!data || !out)
    {
        return MULTIHASH_ERR_NULL_POINTER;
    }

    size_t expected_size = expected_digest_size(code, data_len);
    if (expected_size == 0 && code != MULTICODEC_IDENTITY)
    {
        return MULTIHASH_ERR_UNSUPPORTED_FUN;
    }

    uint8_t dummy;
    uint8_t *digest_buf = (expected_size > 0) ? malloc(expected_size) : &dummy;
    if (expected_size > 0 && !digest_buf)
    {
        return MULTIHASH_ERR_ALLOC_FAILURE;
    }

    size_t digest_len = 0;
    int hash_res = compute_hash(code, data, data_len, digest_buf, &digest_len);
    if (hash_res != MULTIHASH_SUCCESS)
    {
        if (expected_size > 0)
            free(digest_buf);
        return hash_res;
    }

    size_t written = 0;
    unsigned_varint_err_t err = unsigned_varint_encode(code, out, out_len, &written);
    if (err != UNSIGNED_VARINT_OK)
    {
        if (expected_size > 0)
            free(digest_buf);
        return err;
    }

    size_t written2 = 0;
    err = unsigned_varint_encode((uint64_t)digest_len, out + written, out_len - written, &written2);
    if (err != UNSIGNED_VARINT_OK)
    {
        if (expected_size > 0)
            free(digest_buf);
        return err;
    }

    size_t total = written + written2;
    if (total + digest_len > out_len)
    {
        if (expected_size > 0)
            free(digest_buf);
        return MULTIHASH_ERR_INVALID_INPUT;
    }

    memcpy(out + total, digest_buf, digest_len);
    total += digest_len;

    if (expected_size > 0)
        free(digest_buf);
    return (int)total;
}

/**
 * @brief Decode a multihash.
 *
 * @param in The input buffer containing the multihash.
 * @param in_len The length of the input buffer.
 * @param code Pointer to store the decoded function code.
 * @param digest The buffer to store the decoded digest.
 * @param digest_len Pointer to store the length of the decoded digest.
 * @return The number of bytes read from the input buffer, or an error code.
 */
int multihash_decode(const uint8_t *in, size_t in_len, uint64_t *code, uint8_t *digest, size_t *digest_len)
{
    if (!in || !code || !digest || !digest_len)
    {
        return MULTIHASH_ERR_NULL_POINTER;
    }

    uint64_t decoded_code = 0;
    size_t read1 = 0;
    unsigned_varint_err_t err = unsigned_varint_decode(in, in_len, &decoded_code, &read1);
    if (err != UNSIGNED_VARINT_OK)
    {
        return err;
    }

    uint64_t dlen = 0;
    size_t read2 = 0;
    err = unsigned_varint_decode(in + read1, in_len - read1, &dlen, &read2);
    if (err != UNSIGNED_VARINT_OK)
    {
        return err;
    }

    size_t offset = read1 + read2;
    if (offset + dlen > in_len)
    {
        return MULTIHASH_ERR_INVALID_INPUT;
    }
    if (dlen > *digest_len)
    {
        return MULTIHASH_ERR_DIGEST_TOO_LARGE;
    }

    memcpy(digest, in + offset, dlen);
    *digest_len = dlen;

    const char *codec_name = multicodec_name_from_code(decoded_code);
    if (!codec_name)
    {
        return MULTIHASH_ERR_UNSUPPORTED_FUN;
    }
    *code = decoded_code;

    return (int)(offset + dlen);
}
