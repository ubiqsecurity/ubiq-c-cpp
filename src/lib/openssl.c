#include <ubiq/platform/internal/support.h>

#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

static struct ubiq_platform_algorithm * ubiq_platform_algorithms = NULL;
static size_t ubiq_platform_algorithms_n = 0;

/*
 * maps the openssl ciphers to the numeric id's that are
 * used in the ubiq headers to identify them.
 */
int
ubiq_platform_algorithm_init(
    void)
{
    const struct ubiq_platform_algorithm algos[] = {
        {
            .id = 0,
            .name = "aes-256-gcm",
            .cipher = (struct ubiq_platform_cipher *)EVP_aes_256_gcm(),
            .len = { .key = 32, .iv = 16, .tag = 16 }
        }, {
            .id = 1,
            .name = "aes-128-gcm",
            .cipher = (struct ubiq_platform_cipher *)EVP_aes_128_gcm(),
            .len = { .key = 16, .iv = 16, .tag = 16 }
        },
    };

    int err;

    err = -ENOMEM;
    ubiq_platform_algorithms = malloc(sizeof(algos));
    if (ubiq_platform_algorithms) {
        for (unsigned int i = 0; i < sizeof(algos) / sizeof(*algos); i++) {
            ubiq_platform_algorithms[i] = algos[i];
        }
        ubiq_platform_algorithms_n = sizeof(algos) / sizeof(*algos);
        err = 0;
    }

    return err;
}

void
ubiq_platform_algorithm_exit(
    void)
{
    ubiq_platform_algorithms_n = 0;
    free(ubiq_platform_algorithms);
}

int
ubiq_platform_algorithm_get_byid(
    const unsigned int i,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -EAGAIN;
    if (ubiq_platform_algorithms_n > 0) {
        err = -EINVAL;
        if (i < ubiq_platform_algorithms_n) {
            *algo = &ubiq_platform_algorithms[i];
            err = 0;
        }
    }

    return err;
}

int
ubiq_platform_algorithm_get_byname(
    const char * const name,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -EAGAIN;
    if (ubiq_platform_algorithms_n > 0) {
        err = -ENOENT;
        for (unsigned int i = 0; i < ubiq_platform_algorithms_n; i++) {
            if (strcasecmp(ubiq_platform_algorithms[i].name, name) == 0) {
                *algo = &ubiq_platform_algorithms[i];
                err = 0;
                break;
            }
        }
    }

    return err;
}

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

struct ubiq_platform_digest_context
{
    const EVP_MD * dig;
    EVP_MD_CTX * ctx;
};

int
ubiq_platform_digest_init(
    const char * const name,
    struct ubiq_platform_digest_context ** const _ctx)
{
    const EVP_MD * const dig = EVP_get_digestbyname(name);

    int err;

    err = -EINVAL;
    if (dig) {
        struct ubiq_platform_digest_context * ctx;

        err = -ENOMEM;
        ctx = malloc(sizeof(*ctx));
        if (ctx) {
            ctx->dig = dig;
            ctx->ctx = EVP_MD_CTX_new();

            if (ctx->ctx) {
                EVP_DigestInit_ex(ctx->ctx, ctx->dig, NULL);
                *_ctx = ctx;
                err = 0;
            } else {
                free(ctx);
            }
        }
    }

    return err;
}

void
ubiq_platform_digest_update(
    struct ubiq_platform_digest_context * const ctx,
    const void * const buf, const size_t len)
{
    EVP_DigestUpdate(ctx->ctx, buf, len);
}

int
ubiq_platform_digest_finalize(
    struct ubiq_platform_digest_context * const ctx,
    void ** _buf, size_t * const _len)
{
    void * buf;
    unsigned int len;
    int err;

    err = -ENOMEM;
    len = EVP_MD_size(ctx->dig);
    buf = malloc(len);
    if (buf) {
        EVP_DigestFinal_ex(ctx->ctx, buf, &len);
        EVP_MD_CTX_destroy(ctx->ctx);
        free(ctx);

        *_buf = buf;
        *_len = len;
        err = 0;
    }

    return err;
}

struct ubiq_platform_hmac_context
{
    const EVP_MD * dig;
    HMAC_CTX * ctx;
};

int
ubiq_platform_hmac_init(
    const char * const name,
    const void * const key, const size_t len,
    struct ubiq_platform_hmac_context ** const _ctx)
{
    const EVP_MD * const dig = EVP_get_digestbyname(name);

    int err;

    err = -EINVAL;
    if (dig) {
        struct ubiq_platform_hmac_context * ctx;

        err = -ENOMEM;
        ctx = malloc(sizeof(*ctx));
        if (ctx) {
            ctx->dig = dig;
            ctx->ctx = HMAC_CTX_new();

            if (ctx->ctx) {
                HMAC_Init_ex(ctx->ctx, key, len, ctx->dig, NULL);
                *_ctx = ctx;
                err = 0;
            } else {
                free(ctx);
            }
        }
    }

    return err;
}

void
ubiq_platform_hmac_update(
    struct ubiq_platform_hmac_context * const ctx,
    const void * const buf, const size_t len)
{
    HMAC_Update(ctx->ctx, buf, len);
}

int
ubiq_platform_hmac_finalize(
    struct ubiq_platform_hmac_context * const ctx,
    void ** _buf, size_t * const _len)
{
    void * buf;
    unsigned int len;
    int err;

    err = -ENOMEM;
    len = EVP_MD_size(ctx->dig);
    buf = malloc(len);
    if (buf) {
        HMAC_Final(ctx->ctx, buf, &len);
        HMAC_CTX_free(ctx->ctx);
        free(ctx);

        *_buf = buf;
        *_len = len;
        err = 0;
    }

    return err;
}
