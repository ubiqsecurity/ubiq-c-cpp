#include <ubiq/platform/internal/support.h>

#include <errno.h>

#include <openssl/evp.h>

int
ubiq_platform_base64_encode(
    char ** const obuf,
    const void * const ibuf, const size_t size)
{
    char * buf;
    int res;

    /*
     * the base64 encoding is 4/3rds the size of the unencoded data.
     * adding 2 bytes prior to the division by 3 rounds up the allocation
     * to handle any padding that is necessary. an extra byte is added
     * for the nul terminator.
     */

    res = -ENOMEM;
    buf = malloc(4 * ((size + 2) / 3) + 1);
    if (buf) {
        res = EVP_EncodeBlock(buf, ibuf, size);
        *obuf = buf;
    }

    return res;
}

int
ubiq_platform_base64_decode(
    void ** const obuf,
    const char * const ibuf, const size_t size)
{
    void * buf;
    int res;

    /*
     * output is surely smaller than input, so
     * allocating the input size should be plenty
     */
    res = -ENOMEM;
    buf = malloc(size);
    if (buf) {
        EVP_ENCODE_CTX * ctx;

        ctx = EVP_ENCODE_CTX_new();
        if (ctx) {
            int totl;

            EVP_DecodeInit(ctx);

            res = EVP_DecodeUpdate(ctx, buf, &totl, ibuf, size);
            if (res < 0) {
                res = INT_MIN;
            } else {
                int outl;

                res = EVP_DecodeFinal(ctx, (char *)buf + totl, &outl);
                res = (res < 0) ? INT_MIN : (totl + outl);
            }

            EVP_ENCODE_CTX_free(ctx);
        }

        if (res < 0) {
            free(buf);
        } else {
            *obuf = buf;
        }
    }

    return res;
}
