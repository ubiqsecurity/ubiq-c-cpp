#include <ubiq/platform/internal/support.h>

#include <ubiq/platform/compat/sys/param.h>
#include <errno.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

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
    return (RAND_bytes((unsigned char *)buf, len) == 1) ? 0 : -ENODATA;
}

struct ubiq_support_cipher_context
{
    const struct ubiq_platform_algorithm * algo;
    const EVP_CIPHER * cipher;
    EVP_CIPHER_CTX * ctx;
};

static
int
ubiq_support_cipher_init(
    const struct ubiq_platform_algorithm * const algo,
    const size_t keylen, const size_t ivlen,
    struct ubiq_support_cipher_context ** _ctx)
{
    const EVP_CIPHER * const cipher = EVP_get_cipherbyname(algo->name);
    int err;

    err = -EINVAL;
    if (cipher &&
        keylen == algo->len.key &&
        ivlen == algo->len.iv) {
        struct ubiq_support_cipher_context * ctx;

        err = -ENOMEM;
        ctx = malloc(sizeof(*ctx));
        if (ctx) {
            ctx->algo = algo;
            ctx->cipher = cipher;

            ctx->ctx = EVP_CIPHER_CTX_new();
            if (ctx->ctx) {
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
ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context * const enc)
{
    EVP_CIPHER_CTX_free(enc->ctx);
    free(enc);
}

int
ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm * const algo,
    const void * const keybuf, const size_t keylen,
    const void * const ivbuf, const size_t ivlen,
    const void * const aadbuf, const size_t aadlen, /* aad */
    struct ubiq_support_cipher_context ** const _enc)
{
    struct ubiq_support_cipher_context * enc;
    int err;

    err = ubiq_support_cipher_init(algo, keylen, ivlen, &enc);
    if (!err) {
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
    }

    if (!err) {
        *_enc = enc;
    } else {
        ubiq_support_cipher_destroy(enc);
    }

    return err;
}

int
ubiq_support_encryption_update(
    struct ubiq_support_cipher_context * const enc,
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
    struct ubiq_support_cipher_context * enc,
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

            ubiq_support_cipher_destroy(enc);
        } else {
            free(buf);
        }
    }

    return err;
}

int
ubiq_support_decryption_init(
    const struct ubiq_platform_algorithm * const algo,
    const void * const keybuf, const size_t keylen,
    const void * const ivbuf, const size_t ivlen,
    const void * const aadbuf, const size_t aadlen, /* aad */
    struct ubiq_support_cipher_context ** const _dec)
{
    struct ubiq_support_cipher_context * dec;
    int err;

    err = ubiq_support_cipher_init(algo, keylen, ivlen, &dec);
    if (!err) {
        if (!EVP_DecryptInit_ex(
                dec->ctx, dec->cipher, NULL, keybuf, ivbuf)) {
            err = INT_MIN;
        }

        if (!err && algo->len.tag && aadlen) {
            int outl;

            if (!EVP_DecryptUpdate(
                    dec->ctx, NULL, &outl, aadbuf, aadlen)) {
                err = INT_MIN;
            }
        }
    }

    if (!err) {
        *_dec = dec;
    } else {
        ubiq_support_cipher_destroy(dec);
    }

    return err;
}

int
ubiq_support_decryption_update(
    struct ubiq_support_cipher_context * const dec,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    unsigned int len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ctlen + EVP_CIPHER_CTX_block_size(dec->ctx);
    buf = malloc(len);
    if (buf) {
        if (EVP_DecryptUpdate(dec->ctx, buf, &len, ctbuf, ctlen)) {
            *ptbuf = buf;
            *ptlen = len;

            err = 0;
        } else {
            free(buf);
            err = INT_MIN;
        }
    }

    return err;
}

int
ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context * const dec,
    const void * const tagbuf, const size_t taglen,
    void ** const ctbuf, size_t * const ctlen)
{
    int err;

    err = -EINVAL;
    if (taglen == dec->algo->len.tag) {
        void * buf;
        int len;

        if (taglen) {
            EVP_CIPHER_CTX_ctrl(
                dec->ctx, EVP_CTRL_GCM_SET_TAG, taglen, (char *)tagbuf);
        }

        len = EVP_CIPHER_CTX_block_size(dec->ctx);
        buf = malloc(len);
        err = -ENOMEM;
        if (buf) {
            if (EVP_DecryptFinal_ex(dec->ctx, buf, &len)) {
                *ctbuf = buf;
                *ctlen = len;
                ubiq_support_cipher_destroy(dec);
                err = 0;
            } else {
                free(buf);
                err = INT_MIN;
            }
        }
    }

    return err;
}

/*
 * openssl requires a callback to retrieve the password
 * for decrypting a private key. this function receives
 * the password in the void pointer and passes it through.
 */
static
int
get_password_callback(char * const buf, const int size,
                      const int rw,
                      void * const udata)
{
    const char * const pwstr = udata;
    const int pwlen = strlen(pwstr);
    const int len = MIN(size, pwlen);
    memcpy(buf, pwstr, len);
    return len;
}

int
ubiq_support_asymmetric_decrypt(
    const char * const prvpem, const char * const passwd,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    EVP_PKEY * prvkey;
    BIO * bp;
    int err;

    err = -ENOMEM;
    bp = BIO_new_mem_buf(prvpem, -1);
    if (bp) {
        err = -EACCES;
        prvkey = PEM_read_bio_PrivateKey(
            bp, NULL, get_password_callback, (void *)passwd);
        BIO_free(bp);

        if (prvkey) {
            EVP_PKEY_CTX * pctx;

            err = -ENOMEM;
            pctx = EVP_PKEY_CTX_new(prvkey, NULL);
            if (pctx) {
                void * buf;
                size_t len;

                EVP_PKEY_decrypt_init(pctx);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
                EVP_PKEY_decrypt(pctx, NULL, &len, NULL, 0);

                buf = malloc(len);
                if (buf) {
                    if (EVP_PKEY_decrypt(
                            pctx, buf, &len, ptbuf, ptlen) <= 0) {
                        free(buf);
                        err = -EACCES;
                    } else {
                        *ctbuf = buf;
                        *ctlen = len;
                        err = 0;
                    }
                }

                EVP_PKEY_CTX_free(pctx);
            }

            EVP_PKEY_free(prvkey);
        }
    }

    return err;
}
