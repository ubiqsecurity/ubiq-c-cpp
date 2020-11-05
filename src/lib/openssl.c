#include <ubiq/platform/internal/support.h>

#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

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
            .len = { .key = 32, .iv = 12, .tag = 16 }
        }, {
            .id = 1,
            .name = "aes-128-gcm",
            .cipher = (struct ubiq_platform_cipher *)EVP_aes_128_gcm(),
            .len = { .key = 16, .iv = 12, .tag = 16 }
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
ubiq_support_base64_encode(
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
ubiq_support_base64_decode(
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

struct ubiq_support_digest_context
{
    const EVP_MD * dig;
    EVP_MD_CTX * ctx;
};

int
ubiq_support_digest_init(
    const char * const name,
    struct ubiq_support_digest_context ** const _ctx)
{
    const EVP_MD * const dig = EVP_get_digestbyname(name);

    int err;

    err = -EINVAL;
    if (dig) {
        struct ubiq_support_digest_context * ctx;

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
ubiq_support_digest_update(
    struct ubiq_support_digest_context * const ctx,
    const void * const buf, const size_t len)
{
    EVP_DigestUpdate(ctx->ctx, buf, len);
}

int
ubiq_support_digest_finalize(
    struct ubiq_support_digest_context * const ctx,
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

struct ubiq_support_hmac_context
{
    const EVP_MD * dig;
    HMAC_CTX * ctx;
};

int
ubiq_support_hmac_init(
    const char * const name,
    const void * const key, const size_t len,
    struct ubiq_support_hmac_context ** const _ctx)
{
    const EVP_MD * const dig = EVP_get_digestbyname(name);

    int err;

    err = -EINVAL;
    if (dig) {
        struct ubiq_support_hmac_context * ctx;

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
ubiq_support_hmac_update(
    struct ubiq_support_hmac_context * const ctx,
    const void * const buf, const size_t len)
{
    HMAC_Update(ctx->ctx, buf, len);
}

int
ubiq_support_hmac_finalize(
    struct ubiq_support_hmac_context * const ctx,
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

int
ubiq_support_getrandom(
    void * const buf, const size_t len)
{
    return (RAND_bytes((unsigned char *)buf, len) == 1) ? 0 : INT_MIN;
}

struct ubiq_support_encryption_context
{
    const struct ubiq_platform_algorithm * algo;
    const EVP_CIPHER * cipher;
    EVP_CIPHER_CTX * ctx;
};

int
ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm * const algo,
    const void * const keybuf, const size_t keylen,
    const void * const ivbuf, const size_t ivlen,
    const void * const aadbuf, const size_t aadlen, /* aad */
    struct ubiq_support_encryption_context ** const _enc)
{
    const EVP_CIPHER * const cipher = EVP_get_cipherbyname(algo->name);
    int err;

    err = -EINVAL;
    if (cipher &&
        keylen == algo->len.key &&
        ivlen == algo->len.iv) {
        struct ubiq_support_encryption_context * enc;

        err = -ENOMEM;
        enc = malloc(sizeof(*enc));
        if (enc) {
            enc->algo = algo;
            enc->cipher = cipher;

            enc->ctx = EVP_CIPHER_CTX_new();
            if (enc->ctx) {
                err = 0;

                if (!EVP_EncryptInit_ex(
                        enc->ctx, enc->cipher, NULL, keybuf, ivbuf)) {
                    err = INT_MIN;
                }

                if (!err && algo->len.tag && aadlen) {
                    int outl;

                    if (!EVP_EncryptUpdate(
                            enc->ctx, NULL, &outl, aadbuf, aadlen)) {
                        err = INT_MIN;
                    }
                }

                if (err) {
                    EVP_CIPHER_CTX_free(enc->ctx);
                }
            }

            if (!err) {
                *_enc = enc;
            } else {
                free(enc);
            }
        }
    }

    return err;
}

int
ubiq_support_encryption_update(
    struct ubiq_support_encryption_context * const enc,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    unsigned int len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ptlen + EVP_CIPHER_CTX_block_size(enc->ctx);
    buf = malloc(len);
    if (buf) {
        if (EVP_EncryptUpdate(enc->ctx, buf, &len, ptbuf, ptlen)) {
            *ctbuf = buf;
            *ctlen = len;

            err = 0;
        } else {
            free(buf);
            err = INT_MIN;
        }
    }

    return err;
}

int
ubiq_support_encryption_finalize(
    struct ubiq_support_encryption_context * enc,
    void ** const ctbuf, size_t * const ctlen,
    void ** const tagbuf, size_t * const taglen)
{
    unsigned int len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = EVP_CIPHER_CTX_block_size(enc->ctx);
    buf = malloc(len);
    if (buf) {
        err = 0;

        if (!EVP_EncryptFinal_ex(enc->ctx, buf, &len)) {
            err = INT_MIN;
        }

        if (!err && enc->algo->len.tag) {
            void * tag;

            err = -ENOMEM;
            tag = malloc(enc->algo->len.tag);
            if (tag) {
                EVP_CIPHER_CTX_ctrl(enc->ctx,
                                    EVP_CTRL_AEAD_GET_TAG,
                                    enc->algo->len.tag, (char *)tag);
                *tagbuf = tag;
                *taglen = enc->algo->len.tag;

                err = 0;
            }
        }

        if (!err) {
            *ctbuf = buf;
            *ctlen = len;

            ubiq_support_encryption_destroy(enc);
        } else {
            free(buf);
        }
    }

    return err;
}

void ubiq_support_encryption_destroy(
    struct ubiq_support_encryption_context * const enc)
{
    EVP_CIPHER_CTX_free(enc->ctx);
    free(enc);
}
