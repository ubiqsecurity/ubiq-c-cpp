#include <ubiq/platform/internal/support.h>

#include <bcrypt.h>
#define STATUS_SUCCESS                  ((NTSTATUS)0L)

#include <stdint.h>

/* round X down to the nearest multiple of Y */
#define ROUNDDN(X, Y)                   (((X) / (Y)) * (Y))

int
ubiq_support_base64_encode(
    char ** const _str,
    const void * const buf, const size_t len)
{
    char * str;
    int res;
    DWORD out;

    /* call with NULL to determine number of output bytes */
    out = 0;
    CryptBinaryToStringA(buf, len,
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         NULL, &out);
    out++;

    res = -ENOMEM;
    str = malloc(out);
    if (str) {
        CryptBinaryToStringA(buf, len,
                             CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                             str, &out);
        *_str = str;
        res = out;
    }

    return res;
}

int
ubiq_support_base64_decode(
    void ** const _buf,
    const char * const str, const size_t len)
{
    void * buf;
    int res;
    DWORD out;

    /* call with NULL to determine number of output bytes */
    out = 0;
    CryptStringToBinaryA(str, len,
                         CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                         NULL, &out,
                         NULL, NULL);

    res = -ENOMEM;
    buf = malloc(out);
    if (buf) {
        CryptStringToBinaryA(str, len,
                             CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                             buf, &out,
                             NULL, NULL);
        *_buf = buf;
        res = out;
    }

    return res;
}

struct ubiq_support_hash_context
{
    struct {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE dig;
    } hnd;
    /*
     * private data structure allocated for
     * use by the windows api's.
     */
    struct {
        void * buf;
        size_t len;
    } obj;
};

/*
 * digests and hmacs are both initialized via this function.
 * when keylen is non-zero, the context is initialized as an
 * hmac. otherwise, it's initialized as a digest.
 */
static
int
ubiq_support_hash_init(
    const char * const name,
    const void * const keybuf, const size_t keylen,
    struct ubiq_support_hash_context ** const _ctx)
{
    static const
        struct windigest {
        const char * const name;
        const wchar_t * const ident;
    } digests[] = {
        /*
         * more algorithms can be added by adding them to this
         * list. the name must be compatible with other crypto
         * libraries, namely openssl. the order of the entries
         * in the list doesn't matter.
         */
        { .name = "sha512", .ident = BCRYPT_SHA512_ALGORITHM },
    };

    const struct windigest * digest;

    struct ubiq_support_hash_context * ctx;
    int err;

    /* find the digest structure for the named algorithm */
    digest = NULL;
    for (unsigned int i = 0;
         i < sizeof(digests) / sizeof(*digests);
         i++ ) {
        if (strcasecmp(name, digests[i].name) == 0) {
            digest = &digests[i];
            err = 0;
            break;
        }
    }

    err = -EINVAL;
    if (digest) {
        /* digest or hmac depending on keylen */
        const DWORD flag = keylen ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0;

        BCRYPT_ALG_HANDLE halg;

        /*
         * open the algorithm provider and determine the size
         * of the private space necessary for the chosen algorithm.
         * then allocate the hash context and the private space.
         */

        err = INT_MIN;
        if (BCryptOpenAlgorithmProvider(
                &halg, digest->ident,
                NULL,
                flag) == STATUS_SUCCESS) {
            DWORD objlen;
            ULONG out;

            if (BCryptGetProperty(
                    halg, BCRYPT_OBJECT_LENGTH,
                    (PUCHAR)&objlen, sizeof(objlen), &out,
                    0) == STATUS_SUCCESS) {
                err = -ENOMEM;
                ctx = malloc(sizeof(*ctx) + objlen);
                if (ctx) {
                    ctx->hnd.alg = halg;
                    ctx->hnd.dig = NULL;

                    ctx->obj.buf = ctx + 1;
                    ctx->obj.len = objlen;

                    err = 0;
                } else {
                    BCryptCloseAlgorithmProvider(halg, 0);
                }
            }
        }
    }

    /* get a handle to the algorithm, itself */
    if (!err &&
        BCryptCreateHash(
            ctx->hnd.alg,
            &ctx->hnd.dig,
            ctx->obj.buf, ctx->obj.len,
            (PUCHAR)keybuf, keylen,
            0) != STATUS_SUCCESS) {
        err = INT_MIN;
    }

    if (!err) {
        *_ctx = ctx;
    } else {
        if (ctx) {
            if (ctx->hnd.dig) {
                BCryptDestroyHash(ctx->hnd.dig);
            }

            BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
            free(ctx);
        }
    }

    return err;
}

static
void
ubiq_support_hash_update(
    struct ubiq_support_hash_context * const ctx,
    const void * const buf, const size_t len)
{
    BCryptHashData(ctx->hnd.dig, (PUCHAR)buf, len, 0);
}

static
int
ubiq_support_hash_finalize(
    struct ubiq_support_hash_context * const ctx,
    void ** const _buf, size_t * const _len)
{
    int err;

    ULONG copied;
    DWORD len;

    /*
     * determine the size of the output
     * allocate space for the output
     * get the final value of the hash
     * destroy the context
     */
    err = INT_MIN;
    if (BCryptGetProperty(
            ctx->hnd.alg,
            BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof(len),
            &copied,
            0) == STATUS_SUCCESS) {
        void * buf;

        err = -ENOMEM;
        buf = malloc(len);
        if (buf) {
            err = INT_MIN;
            if (BCryptFinishHash(
                    ctx->hnd.dig, buf, len, 0) == STATUS_SUCCESS) {
                *_buf = buf;
                *_len = len;

                BCryptDestroyHash(ctx->hnd.dig);
                BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
                /* sensitive data may reside in the context */
                memset(ctx, 0, sizeof(ctx) + ctx->obj.len);
                free(ctx);

                err = 0;
            } else {
                free(buf);
            }
        }
    }

    return err;
}

int
ubiq_support_digest_init(
    const char * const name,
    struct ubiq_support_hash_context ** const ctx)
{
    return ubiq_support_hash_init(name, NULL, 0, ctx);
}

void
ubiq_support_digest_update(
    struct ubiq_support_hash_context * const ctx,
    const void * const buf, const size_t len)
{
    ubiq_support_hash_update(ctx, buf, len);
}

int
ubiq_support_digest_finalize(
    struct ubiq_support_hash_context * const ctx,
    void ** const buf, size_t * const len)
{
    return ubiq_support_hash_finalize(ctx, buf, len);
}

int
ubiq_support_hmac_init(
    const char * const name,
    const void * const keybuf, const size_t keylen,
    struct ubiq_support_hash_context ** const ctx)
{
    return ubiq_support_hash_init(name, keybuf, keylen, ctx);
}

void
ubiq_support_hmac_update(
    struct ubiq_support_hash_context * const ctx,
    const void * const buf, const size_t len)
{
    ubiq_support_hash_update(ctx, buf, len);
}

int
ubiq_support_hmac_finalize(
    struct ubiq_support_hash_context * const ctx,
    void ** const buf, size_t * const len)
{
    return ubiq_support_hash_finalize(ctx, buf, len);
}

int
ubiq_support_getrandom(
    void * const buf, const size_t len)
{
    BCRYPT_ALG_HANDLE h;
    int err;

    /*
     * BCryptGenRandom() can be called without an algorithm provider
     * by specifying the BCRYPT_USE_SYSTEM_PREFERRED_RNG flag. However,
     * there is some concern in some corners of the interwebs that in
     * some version(s) of Windows that RNG might be the infamous Dual EC
     * DRBG. Instead, explicitly specify something different.
     */
    err = -ENODATA;
    if (BCryptOpenAlgorithmProvider(
            &h, BCRYPT_RNG_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
        if (BCryptGenRandom(h, (PUCHAR)buf, len, 0) == STATUS_SUCCESS) {
            err = 0;
        }

        BCryptCloseAlgorithmProvider(h, 0);
    }

    return 0;
}

/*
 * function type of BCryptEncrypt() and BCryptDecrypt()
 */
typedef
NTSTATUS
(__stdcall BCryptXxcryptFunc)(
    BCRYPT_KEY_HANDLE,
    PUCHAR, ULONG, /* input */
    VOID *, /* padding info */
    PUCHAR, ULONG, /* iv */
    PUCHAR, ULONG, ULONG *, /* output */
    ULONG /* flags */);

struct ubiq_support_cipher_context
{
    struct {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_KEY_HANDLE key;
    } hnd;

    /*
     * for block ciphers, the block size is
     * stored here. if the block size is
     * non-zero, then the blk and vec members
     * will populated.
     */
    size_t blksz;

    struct {
        /*
         * len indicates the number of bytes in use, not
         * necessarily the number of bytes allocated.
         *
         * in particular, for obj and aci, those numbers
         * are the same. for blk and vec, blksz indicates
         * the number allocated and len indicates the number
         * currently used.
         *
         * - obj is the private space used by the backend algorithm
         * - blk is the space used to store partial blocks during
         *   operation since windows only supports encrypting or
         *   decrypting whole blocks (except for the last one)
         * - vec is the scratch space used by windows to keep track
         *   of the current state of the initialization vector
         * - aci is the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO needed
         *   when using an authenticated mode like GCM
         *
         */
        void * buf;
        size_t len;
    } obj, blk, vec, aci;
};

void
ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context * const ctx)
{
    BCryptDestroyKey(ctx->hnd.key);
    BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
    /* sensitive data may reside in the context */
    memset(ctx, 0, (sizeof(*ctx) +
                    ctx->obj.len +
                    2 * ctx->blksz +
                    ctx->aci.len));
    free(ctx);
}

static
int
ubiq_support_cipher_init(
    const struct ubiq_platform_algorithm * const alg,
    const void * const keybuf, const size_t keylen,
    const void * const vecbuf, const size_t veclen,
    const void * const aadbuf, const size_t aadlen,
    BCryptXxcryptFunc * const crypt,
    struct ubiq_support_cipher_context ** const _ctx)
{
    static const
        struct wincipher {
        const char * const name;
        const wchar_t * const algo;
        const wchar_t * const mode;
    } ciphers[] = {
        /*
         * more algorithms can be added here. their order
         * is not important. however, their names must match
         * other supported crypto libraries, in particular
         * openssl
         *
         * note that the code currently only handles block ciphers.
         * it highly unlikely that stream ciphers will "just work"
         * by adding them here without modifications to the rest
         * of the code.
         *
         * the current implementation tries to be aware of the
         * differences between GCM and non-GCM modes of operation;
         * something like CBC *should* work, but it's untested.
         */
        {
            .name = "aes-256-gcm",
            .algo = BCRYPT_AES_ALGORITHM,
            .mode = BCRYPT_CHAIN_MODE_GCM
        }, {
            .name = "aes-128-gcm",
            .algo = BCRYPT_AES_ALGORITHM,
            .mode = BCRYPT_CHAIN_MODE_GCM
        },
    };

    const struct wincipher * cipher;

    struct ubiq_support_cipher_context * ctx;
    DWORD out;
    int err;

    ctx = NULL;

    err = -EINVAL;
    if (keylen == alg->len.key) {
        err = 0;
    }

    if (!err) {
        /* find the named cipher */
        err = -EINVAL;
        cipher = NULL;
        for (unsigned int i = 0;
             i < sizeof(ciphers) / sizeof(*cipher);
             i++) {
            if (strcasecmp(alg->name, ciphers[i].name) == 0) {
                cipher = &ciphers[i];
                err = 0;
                break;
            }
        }
    }

    if (!err) {
        BCRYPT_ALG_HANDLE halg;
        DWORD objsz, blksz, acisz;

        halg = NULL;
        if (BCryptOpenAlgorithmProvider(
                &halg, cipher->algo, NULL, 0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }

        /* set the chaining mode: gcm, cbc, etc. */
        if (!err &&
            BCryptSetProperty(
                halg, BCRYPT_CHAINING_MODE,
                (PUCHAR)cipher->mode, wcslen(cipher->mode) * *cipher->mode,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }

        /*
         * get the size required for the algorithm
         * implementation's private space
         */
        if (!err &&
            BCryptGetProperty(
                halg, BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&objsz, sizeof(objsz), &out,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }

        /* get the algorithm's block size */
        if (!err) {
            if (BCryptGetProperty(
                    halg, BCRYPT_BLOCK_LENGTH,
                    (PUCHAR)&blksz, sizeof(blksz), &out,
                    0) == STATUS_SUCCESS) {
                /*
                 * make sure the initialization vector
                 * isn't longer than the block size. in
                 * some cases (like GCM), the initialization
                 * vector/nonce may actually be shorter
                 */
                if (veclen > blksz) {
                    err = -EINVAL;
                }
            } else {
                err = INT_MIN;
            }
        }

        /*
         * for authenticated algorithms, determine the
         * amount of space necessary for parameters associated
         * with the algorithm
         */
        if (!err) {
            acisz = 0;

            if (alg->len.tag) {
                BCRYPT_AUTH_TAG_LENGTHS_STRUCT atl;

                /*
                 * in addition to the cipher mode info, space
                 * is allocated to store the current value of the
                 * mac/tag during the operation. this extra space
                 * is required to be at least that of the maximum
                 * possible size of the authentication tag
                 */
                if (BCryptGetProperty(
                        halg, BCRYPT_AUTH_TAG_LENGTH,
                        (PUCHAR)&atl, sizeof(atl), &out,
                        0) == STATUS_SUCCESS) {
                    acisz = atl.dwMaxLength +
                        sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
                } else {
                    err = INT_MIN;
                }
            }
        }

        /*
         * allocate the context structure. this is allocated as one
         * contiguous block of memory with pointers within in the
         * structure(s) pointing to the specific space for each
         * "substructure"
         */
        if (!err) {
            err = -ENOMEM;
            ctx = malloc(sizeof(*ctx) + objsz + 2 * blksz + acisz);
            if (ctx) {
                size_t off;

                memset(ctx, 0, sizeof(*ctx));

                ctx->hnd.alg = halg;
                ctx->hnd.key = NULL;

                /* private space for the algorithm implementation */
                ctx->obj.buf = ctx + 1;
                ctx->obj.len = objsz;

                /*
                 * off is used to keep track of the current number
                 * of bytes claimed by the structures below which
                 * may or may not be present.
                 */
                off = ctx->obj.len;

                ctx->blksz = blksz;
                if (ctx->blksz) {
                    /* scratch space for partial blocks */
                    ctx->blk.buf = (char *)ctx->obj.buf + off;
                    ctx->blk.len = 0;
                    off += ctx->blksz;

                    /* scratch space for iv state */
                    ctx->vec.buf = (char *)ctx->obj.buf + off;
                    ctx->vec.len = 0;
                    off += ctx->blksz;

                    /* store the initial iv/nonce value */
                    memcpy(ctx->vec.buf, vecbuf, veclen);
                    ctx->vec.len = veclen;
                }
                if (acisz) {
                    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * inf;

                    /* space for the authenticated cipher mode info */
                    ctx->aci.buf = (char *)ctx->obj.buf + off;
                    ctx->aci.len = acisz;
                    off += ctx->aci.len + alg->len.tag;

                    /*
                     * the documentation dictates that some
                     * fields be initialized by the
                     * BCRYPT_INIT_AUTH_MODE_INFO() macro.
                     */
                    inf = ctx->aci.buf;
                    memset(inf, 0, sizeof(*inf));
                    BCRYPT_INIT_AUTH_MODE_INFO(*inf);

                    /*
                     * the nonce is the first iv. even though it's not
                     * used in later calls, the pointer must remain set
                     * throughout the lifetime of the operation.
                     */
                    inf->pbNonce        = ctx->vec.buf;
                    inf->cbNonce        = ctx->vec.len;

                    /*
                     * the iv length should always be the block size
                     * after the initial encrypt/decrypt call
                     */
                    ctx->vec.len        = ctx->blksz;

                    /*
                     * auth data is set just before its use
                     * and set back to NULL again afterward
                     */
                    inf->pbAuthData     = NULL;
                    inf->cbAuthData     = 0;

                    /*
                     * the tag pointer isn't necessary until the final
                     * call that either generates or checks the value,
                     * but the size must be set throughout the operation
                     */
                    inf->pbTag          = NULL;
                    inf->cbTag          = alg->len.tag;

                    /*
                     * scratch space for the current state of the tag/mac
                     * during the operation. extra space was allocated after
                     * the end of the info structure for it
                     */
                    inf->pbMacContext   = (void *)(inf + 1);
                    inf->cbMacContext   = ctx->aci.len - sizeof(*inf);

                    /*
                     * cbAAD and cbData track the number of bytes of
                     * additional authenticated data and plain/ciphertext
                     * processed by the operation. they are initially set
                     * to 0, and then left alone. the windows api controls
                     * them once the operation has started.
                     */
                    inf->cbAAD          = 0;
                    inf->cbData         = 0;

                    /*
                     * the code performs the encryption/decryption across
                     * several calls and this usage is indicated by the
                     * "chain calls" flag. once the operation has started,
                     * flags should be individually added or removed with
                     * Boolean logic as the windows api sets its own flags
                     * in this field, also.
                     */
                    inf->dwFlags        = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
                }

                err = 0;
            }
        }

        if (err && halg) {
            BCryptCloseAlgorithmProvider(halg, 0);
        }
    }

    if (!err) {
        /*
         * despite the name, this function uses the key
         * specified by keybuf/keylen as opposed to generating
         * a new one.
         */
        if (BCryptGenerateSymmetricKey(
                ctx->hnd.alg,
                &ctx->hnd.key,
                ctx->obj.buf, ctx->obj.len,
                (PUCHAR)keybuf, keylen,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }
    }

    if (!err) {
        if (ctx->aci.buf && aadlen) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;
            ULONG out;

            /*
             * process additional authenticated data, if necessary
             */

            inf->pbAuthData = (void *)aadbuf;
            inf->cbAuthData = aadlen;

            err = ((*crypt)(ctx->hnd.key,
                            NULL, 0,
                            ctx->aci.buf,
                            ctx->vec.buf, ctx->vec.len,
                            NULL, 0, &out,
                            0) == STATUS_SUCCESS) ? 0 : INT_MIN;

            inf->pbAuthData = NULL;
            inf->cbAuthData = 0;
        } else if (!ctx->aci.buf && aadlen) {
            /*
             * can't specify additional authenticated
             * data without an authenticated algorithm
             */
            err = -EINVAL;
        }
    }

    if (!err) {
        *_ctx = ctx;
    } else {
        if (ctx) {
            if (ctx->hnd.key) {
                BCryptDestroyKey(ctx->hnd.key);
            }

            BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
            /* sensitive data may reside in the context */
            memset(ctx, 0, (sizeof(*ctx) +
                            ctx->obj.len +
                            2 * ctx->blksz +
                            ctx->aci.len));
            free(ctx);
        }
    }

    return err;
}

static
ubiq_support_cipher_update(
    struct ubiq_support_cipher_context * const ctx,
    BCryptXxcryptFunc * const crypt,
    const void * const ibuf, const size_t ilen,
    void ** const obuf, size_t * const olen)
{
    ULONG len, out;
    void * buf;
    int err;

    /*
     * for a block cipher the amount of data produced
     * will be `ilen` + `ctx->blk.len` rounded down
     * to the nearest multiple of block size because the
     * api's will only process block-sized chunks from
     * this function.
     *
     * excess input data will be buffered in ctx->blk.buf
     */
    err = -ENOMEM;
    len = ROUNDDN(ilen + ctx->blk.len, ctx->blksz);
    buf = malloc(len);
    if (buf) {
        /* indexes into the input and output buffers */
        struct {
            size_t i, o;
        } off;

        off.i = off.o = 0;
        err = 0;

        /*
         * if there is any data buffered from previous calls,
         * then the first priority is to fill that buffer so
         * that that data can be processed.
         *
         * if there is no data in the buffer, this step can
         * be skipped.
         */
        if (ctx->blk.len) {
            /*
             * move as much data as possible, but no more than the
             * buffer can hold, into the buffer.
             */
            const size_t copy = __min(ctx->blksz - ctx->blk.len, ilen);

            memcpy((char *)ctx->blk.buf + ctx->blk.len, ibuf, copy);
            ctx->blk.len += copy;
            off.i += copy;

            /* if the buffer is full, "crypt" it */
            if (ctx->blk.len == ctx->blksz) {
                ULONG out;

                if ((*crypt)(
                        ctx->hnd.key,
                        ctx->blk.buf, ctx->blk.len,
                        ctx->aci.buf,
                        ctx->vec.buf, ctx->vec.len,
                        (char *)buf + off.o, len - off.o, &out,
                        0) != STATUS_SUCCESS) {
                    err = INT_MIN;
                }

                /*
                 * reset the block length and adjust the
                 * output offset. if there was an error,
                 * this doesn't matter anyway, so no need
                 * to do something different for the
                 * error and non-error cases.
                 */
                ctx->blk.len = 0;
                off.o += out;
            }
        }

        /*
         * now that the buffer is empty, if the input contains
         * one or more full blocks of data, process those blocks
         */
        if (!err && (ilen - off.i) >= ctx->blksz) {
            const size_t clen = ROUNDDN(ilen - off.i, ctx->blksz);

            if ((*crypt)(
                    ctx->hnd.key,
                    (char *)ibuf + off.i, clen,
                    ctx->aci.buf,
                    ctx->vec.buf, ctx->vec.len,
                    (char *)buf + off.o, len - off.o, &out,
                    0) != STATUS_SUCCESS) {
                err = INT_MIN;
            }

            off.i += clen;
            off.o += clen;
        }

        /*
         * finally, any unprocessed input is copied to the internal
         * buffer space. given the logic above, the internal buffer
         * is known to be empty and the remaining input, if any,
         * contains fewer bytes than the block size
         */
        if (!err) {
            ctx->blk.len = ilen - off.i;
            memcpy(ctx->blk.buf, (char *)ibuf + off.i, ctx->blk.len);

            *obuf = buf;
            *olen = off.o;
        } else {
            free(buf);
        }
    }

    return err;
}

int
ubiq_support_cipher_finalize(
    struct ubiq_support_cipher_context * const ctx,
    BCryptXxcryptFunc * const crypt,
    void ** const obuf, size_t * const olen)
{
    DWORD len;
    void * buf;
    int err;

    /*
     * there is no plain text input to this function,
     * so the output size should be equivalent to the
     * number of bytes in the internal buffer
     */

    err = -ENOMEM;
    len = ctx->blk.len;
    buf = malloc(len);
    if (buf) {
        if (ctx->aci.buf) {
            /* this is the final call, so turn off the chaining flag */
            ((BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *)
             ctx->aci.buf)->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        }

        if ((*crypt)(
                ctx->hnd.key,
                ctx->blk.buf, ctx->blk.len,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                buf, len, &len,
                0) == STATUS_SUCCESS) {
            *obuf = buf;
            *olen = len;

            ubiq_support_cipher_destroy(ctx);

            err = 0;
        } else {
            free(buf);
            err = INT_MIN;
        }
    }

    return err;
}

int
ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm * const alg,
    const void * const keybuf, const size_t keylen,
    const void * const vecbuf, const size_t veclen,
    const void * const aadbuf, const size_t aadlen,
    struct ubiq_support_cipher_context ** const ctx)
{
    return ubiq_support_cipher_init(
        alg,
        keybuf, keylen, vecbuf, veclen, aadbuf, aadlen,
        &BCryptEncrypt,
        ctx);
}

int
ubiq_support_encryption_update(
    struct ubiq_support_cipher_context * const ctx,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    return ubiq_support_cipher_update(
        ctx, &BCryptEncrypt, ptbuf, ptlen, ctbuf, ctlen);
}

int
ubiq_support_encryption_finalize(
    struct ubiq_support_cipher_context * const ctx,
    void ** const ctbuf, size_t * const ctlen,
    void ** const tagbuf, size_t * const taglen)
{
    void * tbuf;
    size_t tlen;

    int err;

    tbuf = NULL;
    tlen = 0;

    err = 0;
    if (ctx->aci.buf) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;

        /*
         * for authenticated algorithms, allocate space for
         * the tag. a successful call to cipher_finalize()
         * will free the context structure, but this memory
         * will be updated by the call but not freed.
         */

        err = -ENOMEM;
        tbuf = malloc(inf->cbTag);
        if (tbuf) {
            inf->pbTag = tbuf;
            tlen = inf->cbTag;
            err = 0;
        }
    }

    if (!err) {
        err = ubiq_support_cipher_finalize(
            ctx, &BCryptEncrypt, ctbuf, ctlen);
    }

    if (!err) {
        *tagbuf = tbuf;
        *taglen = tlen;
    } else {
        free(tbuf);
    }

    return err;
}

int
ubiq_support_decryption_init(
    const struct ubiq_platform_algorithm * const alg,
    const void * const keybuf, const size_t keylen,
    const void * const vecbuf, const size_t veclen,
    const void * const aadbuf, const size_t aadlen,
    struct ubiq_support_cipher_context ** const ctx)
{
    return ubiq_support_cipher_init(
        alg,
        keybuf, keylen, vecbuf, veclen, aadbuf, aadlen,
        &BCryptDecrypt,
        ctx);
}

int
ubiq_support_decryption_update(
    struct ubiq_support_cipher_context * const ctx,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    return ubiq_support_cipher_update(
        ctx, &BCryptDecrypt, ctbuf, ctlen, ptbuf, ptlen);
}

int
ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context * const ctx,
    const void * const tagbuf, const size_t taglen,
    void ** const ptbuf, size_t * const ptlen)
{
    int err;

    err = 0;
    if (ctx->aci.buf) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;

        /*
         * for authenticated algorithms, verify that the supplied
         * tag length matches that required by the algorithm. if so,
         * make the supplied tag available to the finalize() call
         * for verification.
         */

        err = -EINVAL;
        if (inf->cbTag == taglen) {
            inf->pbTag = (PUCHAR)tagbuf;
            err = 0;
        }
    }

    if (!err) {
        err = ubiq_support_cipher_finalize(
            ctx, &BCryptDecrypt, ptbuf, ptlen);
    }

    return err;
}

/*
 * the ASN.1 code below was written very specifically to parse
 * the PKCS #5 PBES2 object (1.2.840.113549.1.5.13) described
 * in Appendix A.4 of RFC 8018. It tries to be somewhat generic,
 * but it was written to do one job, and will likely need some
 * work to extend it beyond that.
 */

/*
 * when the asn1scanf function parses/returns an array of
 * bytes/characters/etc., it is returned in this structure
 */
struct asn1vector
{
    const void * buf;
    unsigned int len;
};

/*
 * all of the parse functions do similar checking to start.
 * this function encompasses that checking.
 *
 * buf, len, and fmt are all modified by this function to
 * reflect the parsing performed by the function. the length
 * of the value being parsed is returned in vlen
 *
 * any errors are signaled by the return value which is 0 on
 * success and negative on error.
 */
static
int
asn1scanf_preamble(
    const uint8_t ** const buf, size_t * const len,
    const char ** const fmt,
    const char exfmt, const uint8_t exbuf,
    size_t * const vlen)
{
    /*
     * verify that the format character matches
     * the expected character associated with the
     * calling function
     */
    if (**fmt != exfmt) {
        return -EINVAL;
    }
    (*fmt)++;

    /*
     * verify that at least 2 bytes are available
     * in the asn.1 encoding: 1 for the type of object
     * and 1 for the length of the object
     */
    if (*len < 2) {
        return -EINVAL;
    }

    /*
     * verify that the object in the asn.1 matches
     * what is expected by the parsing function (and
     * which should correspond with the format, but
     * that is left to the calling function)
     */
    if (**buf != exbuf) {
        return -EINVAL;
    }
    (*buf)++; (*len)--;

    /*
     * verify that the upper bit of the length is not set.
     * if it is, it indicates that the length field itself
     * is longer than a single byte, which is not supported
     * by this code.
     */
    if ((**buf & 0x80)) {
        return -ENOTSUP;
    }

    /*
     * verify that at least the number of bytes specified
     * by the length field are available in the asn.1 data
     */
    if (**buf > *len - 1) {
        return -EINVAL;
    }

    /* return the length */
    *vlen = **buf;
    (*buf)++; (*len)--;

    return 0;
}

static
int
asn1scanf_octetstring(
    const uint8_t ** const buf, size_t * const len,
    const char ** const fmt, va_list * const ap)
{
    size_t vlen;
    int res;

    res = asn1scanf_preamble(buf, len, fmt, 'x', 0x04, &vlen);
    if (res == 0) {
        struct asn1vector * const s = va_arg(*ap, struct asn1vector *);

        s->len = vlen;
        s->buf = *buf;

        *buf += vlen;
        *len -= vlen;
    }

    return res;
}

static
int
asn1scanf_objectid(
    const uint8_t ** const buf, size_t * const len,
    const char ** const fmt, va_list * const ap)
{
    size_t vlen;
    int res;

    res = asn1scanf_preamble(buf, len, fmt, 'o', 0x06, &vlen);
    if (res == 0) {
        struct asn1vector * const s = va_arg(*ap, struct asn1vector *);

        s->len = vlen;
        s->buf = *buf;

        *buf += vlen;
        *len -= vlen;
    }

    return res;
}

static
int
asn1scanf_integer(
    const uint8_t ** const buf, size_t * const len,
    const char ** const fmt, va_list * const ap)
{
    size_t vlen;
    int res;

    res = asn1scanf_preamble(buf, len, fmt, 'i', 0x02, &vlen);
    if (res == 0) {
        res = -ENOTSUP;
        /*
         * integers greater than the size of an `int`
         * and negative values are not supported
         */
        if (vlen <= sizeof(int) && !((**buf) & 0x80)) {
            int * const i = va_arg(*ap, int *);

            /* integers are in big-endian order */
            *i = 0;
            for (unsigned int j = 0; j < vlen; j++) {
                *i <<= 8;
                *i  += (*buf)[j];
            }

            *buf += vlen;
            *len -= vlen;

            res = 0;
        }
    }

    return 0;
}

/*
 * an asn.1 sequence is sort of like a struct. it
 * is a grouping of objects which may themselves
 * be sequences
 */
static
int
asn1scanf_sequence(
    const uint8_t ** const buf, size_t * const len,
    const char ** const fmt, va_list * const ap)
{
    size_t vlen;
    int res;

    res = asn1scanf_preamble(buf, len, fmt, '(', 0x30, &vlen);
    if (res == 0) {
        while (res == 0 && **fmt != ')' && **fmt != '\0') {
            switch (**fmt) {
            case '(':
                res = asn1scanf_sequence(buf, len, fmt, ap);
                break;
            case 'x':
                res = asn1scanf_octetstring(buf, len, fmt, ap);
                break;
            case 'o':
                res = asn1scanf_objectid(buf, len, fmt, ap);
                break;
            case 'i':
                res = asn1scanf_integer(buf, len, fmt, ap);
                break;
            default:
                res = -EINVAL;
                break;
            }
        }

        if (res == 0) {
            if (**fmt == ')') {
                (*fmt)++;
            } else {
                res = -EINVAL;
            }
        }
    }

    return res;
}

/*
 * the scanf idea was born of finding the Crypto_ASN1 object
 * in the core-alljoyn code at https://github.com/alljoyn/core-alljoyn.
 * this code uses a similar syntax; however it borrows none of the
 * code from the there.
 *
 * this scanf function understands the following formats:
 * (): the parentheses denote a sequence. other formats, including
 *        more sequences can be specified between the parentheses. there
 *        is no argument associated with this format
 *  o: an OID. the argument is a pointer to an asn1vector. the encoded OID
 *     is returned; it is NOT parsed to a string.
 *  i: an integer. the argument is a pointer to an integer. the encoded
 *     integer must be fewer bytes than the system's `int` type and must
 *     NOT be negative.
 *  x: an octet/byte string. the argument is a pointer to an asn1vector.
 *     a pointer to the bytes and the number of bytes are returned in the
 *     structure.
 *
 * this function assumes that the format is a sequence.
 */
static
int
asn1scanf(
    const void * buf, size_t len,
    const char * fmt, ...)
{
    va_list ap;
    int res;

    va_start(ap, fmt);

    res = 0;
    while (res == 0 && *fmt != '\0') {
        switch (*fmt) {
        case '(':
            res = asn1scanf_sequence((const uint8_t **)&buf, &len, &fmt, &ap);
            break;
        default:
            res = -EINVAL;
            break;
        }
    }

    va_end(ap);

    return res;
}

/*
 * decrypt a cipher text using an RSA private key. this function
 * assumes that OAEP padding with SHA1 was used.
 *
 * the private key is specified by the prvblbbuf and prvblblen
 * parameters and prvblbbuf is in a format described by prvblbtyp.
 *
 * ctbuf and ctlen describe the data to be decrypted and the
 * plain text and its size are returned it ptbuf and ptlen on success.
 * the caller is responsible for freeing ptbuf.
 *
 * the function returns 0 on success and a negative value on failure.
 */
static
int
asymmetric_decrypt(
    const wchar_t * const prvblbtyp,
    const void * const prvblbbuf, const size_t prvblblen,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    BCRYPT_ALG_HANDLE halg;
    int res;

    res = INT_MIN;
    if (BCryptOpenAlgorithmProvider(
            &halg, BCRYPT_RSA_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
        BCRYPT_KEY_HANDLE hkey;

        if (BCryptImportKeyPair(
                halg,
                NULL, prvblbtyp, &hkey,
                (void *)prvblbbuf, prvblblen,
                0) == STATUS_SUCCESS) {
            BCRYPT_OAEP_PADDING_INFO inf;
            ULONG len;

            inf.pszAlgId = BCRYPT_SHA1_ALGORITHM;
            inf.pbLabel = NULL;
            inf.cbLabel = 0;

            /*
             * decrypt first with a NULL output buffer.
             * this returns the size necessary for the buffer.
             */
            if (BCryptDecrypt(
                    hkey,
                    (void *)ctbuf, ctlen,
                    &inf,
                    NULL, 0,
                    NULL, 0, &len,
                    BCRYPT_PAD_OAEP) == STATUS_SUCCESS) {
                void * buf;

                /*
                 * allocate the required buffer
                 * and decrypt again
                 */
                res = -ENOMEM;
                buf = malloc(len);
                if (buf) {
                    res = INT_MIN;
                    if (BCryptDecrypt(
                            hkey,
                            (void *)ctbuf, ctlen,
                            &inf,
                            NULL, 0,
                            buf, len, &len,
                            BCRYPT_PAD_OAEP) == STATUS_SUCCESS) {
                        *ptbuf = buf;
                        *ptlen = len;
                        res = 0;
                    } else {
                        free(buf);
                    }
                }
            }

            BCryptDestroyKey(hkey);
        }

        BCryptCloseAlgorithmProvider(halg, 0);
    }

    return res;
}

/*
 * the private key "blob" produced by this function
 * appears to be the following:
 *
 * PUBLICKEYSTRUC  publickeystruc;
 * RSAPUBKEY       rsapubkey;
 * BYTE            modulus[rsapubkey.bitlen/8];
 * BYTE            prime1[rsapubkey.bitlen/16];
 * BYTE            prime2[rsapubkey.bitlen/16];
 * BYTE            exponent1[rsapubkey.bitlen/16];
 * BYTE            exponent2[rsapubkey.bitlen/16];
 * BYTE            coefficient[rsapubkey.bitlen/16];
 * BYTE            privateExponent[rsapubkey.bitlen/8];
 *
 * which is described by microsoft docs in the section about
 * "RSA/Schannel Key BLOBs". This is apparently considered
 * a "legacy" format as the constant used to identify it for
 * import in the BCryptImportKeyPair() interface is
 * LEGACY_RSAPRIVATE_BLOB.
 */
static
int
decode_prvkey(
    const void * const prvkeybuf, const size_t prvkeylen,
    const wchar_t ** const prvblbtyp,
    void ** const prvblbbuf, size_t * const prvblblen)
{
    CRYPT_PRIVATE_KEY_INFO * inf;
    DWORD len;
    int res;

    /*
     * the input to this function is the data that is produced
     * by decrypting the encrypted portion of a private key.
     * this appears to be what windows regards as PKCS_PRIVATE_KEY_INFO.
     * this code assumes the information otherwise gleaned from the
     * structure and goes straight for the key itself.
     */

    res = INT_MIN;
    if (CryptDecodeObjectEx(
            PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            prvkeybuf, prvkeylen,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &inf, &len)) {
        /*
         * decode the key, first with a NULL
         * output buffer to get the size
         */
        if (CryptDecodeObject(
                PKCS_7_ASN_ENCODING,
                PKCS_RSA_PRIVATE_KEY,
                inf->PrivateKey.pbData, inf->PrivateKey.cbData,
                0,
                NULL, &len)) {
            void * blb;

            /*
             * then allocate the space, and get that key
             */
            res = -ENOMEM;
            blb = malloc(len);
            if (blb) {
                res = INT_MIN;
                if (CryptDecodeObject(
                        PKCS_7_ASN_ENCODING,
                        PKCS_RSA_PRIVATE_KEY,
                        inf->PrivateKey.pbData, inf->PrivateKey.cbData,
                        0,
                        blb, &len)) {
                    *prvblbtyp = LEGACY_RSAPRIVATE_BLOB;
                    *prvblbbuf = blb;
                    *prvblblen = len;
                    res = 0;
                } else {
                    free(blb);
                }
            }
        }

        LocalFree(inf);
    }

    return res;
}

static
int
decrypt_prvkey(
    const void * const enckeybuf, const size_t enckeylen,
    const char * const passwd,
    const char * const kdfoid,
    const void * const saltbuf, const size_t saltlen,
    const unsigned int iter,
    const char *algoid,
    const void * ivbuf, const size_t ivlen,
    void ** const prvkeybuf, size_t * const prvkeylen)
{
    BCRYPT_ALG_HANDLE halg;

    /* key and iv sizes assume aes256 */
    uint8_t key[32];
    uint8_t iv[16];

    int res;

    /*
     * verify that the key is derived with PBKDF2 and
     * the encryption is AES-256-CBC because that's
     * what this code assumes.
     */

    res = -ENOTSUP;
    if (strcmp(kdfoid, szOID_PKCS_5_PBKDF2) == 0 &&
        strcmp(algoid, szOID_NIST_AES256_CBC) == 0 &&
        ivlen == sizeof(iv)) {
        /* move the iv into a local buffer */
        memcpy(iv, ivbuf, ivlen);

        res = INT_MIN;
        if (BCryptOpenAlgorithmProvider(
                &halg,
                /*
                 * assume sha1. it's the default, and
                 * the asn.1 code currently doesn't parse
                 * out anything that might say different.
                 */
                BCRYPT_SHA1_ALGORITHM,
                NULL,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) == STATUS_SUCCESS) {
            if (BCryptDeriveKeyPBKDF2(
                    halg,
                    (char *)passwd, strlen(passwd),
                    (void *)saltbuf, saltlen,
                    iter,
                    key, sizeof(key),
                    0) == STATUS_SUCCESS) {
                res = 0;
            }

            BCryptCloseAlgorithmProvider(halg, 0);
        }
    }

    if (res == 0) {
        res = INT_MIN;
        /*
         * now that we've derived the key, decrypt the data
         */
        if (BCryptOpenAlgorithmProvider(
                &halg, BCRYPT_AES_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
            BCRYPT_KEY_HANDLE hkey;
            void * objbuf;
            DWORD objlen;
            ULONG v;

            hkey = NULL;
            objbuf = NULL;

            /*
             * set cbc mode, get the size of the
             * required private scratch space, and
             * allocate the space
             */
            if (BCryptSetProperty(
                    halg,
                    BCRYPT_CHAINING_MODE,
                    (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                    wcslen(BCRYPT_CHAIN_MODE_CBC) * sizeof(wchar_t),
                    0) == STATUS_SUCCESS &&
                BCryptGetProperty(
                    halg, BCRYPT_OBJECT_LENGTH,
                    (PUCHAR)&objlen, sizeof(objlen), &v,
                    0) == STATUS_SUCCESS) {
                res = -ENOMEM;
                objbuf = malloc(objlen);
            }

            /* import the key and perform the actual decryption */
            if (objbuf &&
                BCryptGenerateSymmetricKey(
                    halg, &hkey,
                    objbuf, objlen,
                    (PUCHAR)key, sizeof(key),
                    0) == STATUS_SUCCESS) {
                void * obuf;

                res = -ENOMEM;
                obuf = malloc(enckeylen);
                if (obuf) {
                    res = INT_MIN;
                    if (BCryptDecrypt(
                            hkey,
                            (void *)enckeybuf, enckeylen,
                            NULL,
                            iv, sizeof(iv),
                            obuf, enckeylen, &v,
                            BCRYPT_BLOCK_PADDING) == STATUS_SUCCESS) {
                        *prvkeybuf = obuf;
                        *prvkeylen = v;
                        res = 0;
                    } else {
                        free(obuf);
                    }
                }
            }

            if (hkey) {
                BCryptDestroyKey(hkey);
            }
            if (objbuf) {
                free(objbuf);
            }
            BCryptCloseAlgorithmProvider(halg, 0);
        }
    }

    return res;
}

static
int
decode_enckey(
    const void * const derbuf, const size_t derlen,
    const char ** const kdfoid,
    const void ** const saltbuf, size_t * const saltlen,
    unsigned int * const iter,
    const char ** const algoid,
    const void ** const ivbuf, size_t * const ivlen,
    const void ** const enckeybuf, size_t * const enckeylen)
{
    /*
     * these are some OID's that are expected to be found in the
     * asn.1 that has to be manually parsed.
     */

    /* 1.2.840.113549.1.5.12 */
    static const uint8_t pbOID_PKCS_5_PBKDF2[] =
        { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c };
    /* 2.16.840.1.101.3.4.1.42 */
    static const uint8_t pbOID_NIST_AES256_CBC[] =
        { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a };


    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO *inf;
    DWORD len;
    BOOL ret;
    int res;

    /*
     * decode the private key info. this produces an object that
     * contains asn.1 encoded information about how the private
     * key was encrypted and the encrypted private key.
     */

    res = INT_MIN;
    ret = CryptDecodeObjectEx(
        PKCS_7_ASN_ENCODING,
        PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
        derbuf, derlen,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        &inf, &len);
    if (ret) {
        res = -ENOTSUP;
        if (strcmp(inf->EncryptionAlgorithm.pszObjId,
                   szOID_PKCS_5_PBES2) == 0) {
            struct asn1vector kdf, alg, salt, iv;
            int _iter;

            /* extract the key derivation and encryption parameters */
            res = asn1scanf(inf->EncryptionAlgorithm.Parameters.pbData,
                            inf->EncryptionAlgorithm.Parameters.cbData,
                            "((o(xi))(ox))",
                            &kdf, &salt, &_iter, &alg, &iv);
            /*
             * verify that the parameters match what this code supports,
             * and then save them into the various parameters to be
             * returned to the caller
             */
            if (res == 0 &&
                sizeof(pbOID_PKCS_5_PBKDF2) == kdf.len &&
                memcmp(pbOID_PKCS_5_PBKDF2, kdf.buf, kdf.len) == 0 &&
                sizeof(pbOID_NIST_AES256_CBC) == alg.len &&
                memcmp(pbOID_NIST_AES256_CBC, alg.buf, alg.len) == 0) {
                /*
                 * the DECODE_NOCOPY_FLAG above means that all the pointers
                 * returned from the asn1scanf function actually point into
                 * the derbuf memory area. the pointers are valid as long
                 * as derbuf is valid and don't need to be individually freed
                 */
                *kdfoid = szOID_PKCS_5_PBKDF2;
                *saltbuf = salt.buf;
                *saltlen = salt.len;
                *iter = _iter;
                *algoid = szOID_NIST_AES256_CBC;
                *ivbuf = iv.buf;
                *ivlen = iv.len;
                *enckeybuf = inf->EncryptedPrivateKey.pbData;
                *enckeylen = inf->EncryptedPrivateKey.cbData;
            }
        }

        LocalFree(inf);
    }

    return res;
}

static
int
decode_pem(
    const char * const pemstr,
    void ** const derbuf, size_t * const derlen)
{
    DWORD prvlen;
    BOOL ret;
    int res;

    /*
     * pem is just a base64 encoding with a header
     * and footer. decode once with a NULL output
     * buffer to determine the length of the decoded
     * data. then allocate space for the output and
     * decode again.
     */

    res = INT_MIN;
    prvlen = 0;
    ret = CryptStringToBinaryA(pemstr, strlen(pemstr),
                               CRYPT_STRING_BASE64HEADER,
                               NULL, &prvlen,
                               NULL, NULL);
    if (ret) {
        BYTE * prvdec;

        res = -ENOMEM;
        prvdec = malloc(prvlen);
        if (prvdec) {
            ret = CryptStringToBinaryA(pemstr, strlen(pemstr),
                                       CRYPT_STRING_BASE64HEADER,
                                       prvdec, &prvlen,
                                       NULL, NULL);
            if (ret) {
                res = 0;
                *derbuf = prvdec;
                *derlen = prvlen;
            } else {
                free(prvdec);
            }
        }
    }

    return res;
}

int
ubiq_support_asymmetric_decrypt(
    const char * const prvpem, const char * const passwd,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    void * derbuf;
    size_t derlen;
    int res;

    /*
     * the derbuf returned by decode_pem must be maintained
     * until the end of this function as many of the later
     * functions parse it and return pointers into it which
     * are in turn further parsed by later functions.
     */
    res = decode_pem(prvpem, &derbuf, &derlen);
    if (res == 0) {
        const char * kdf, * alg;
        const void * enckeybuf, * saltbuf, * ivbuf;
        void * prvkeybuf;
        size_t enckeylen, saltlen, ivlen, prvkeylen;
        unsigned int iter;

        /*
         * get the encryption parameters and
         * the encrypted portion of the key
         */
        res = decode_enckey(derbuf, derlen,
                            &kdf, &saltbuf, &saltlen, &iter,
                            &alg, &ivbuf, &ivlen,
                            &enckeybuf, &enckeylen);
        if (res == 0) {
            /*
             * decrypt the private key, which produces
             * another asn.1 encoded data object
             */
            res = decrypt_prvkey(enckeybuf, enckeylen,
                                 passwd,
                                 kdf, saltbuf, saltlen, iter,
                                 alg, ivbuf, ivlen,
                                 &prvkeybuf, &prvkeylen);
            if (res == 0) {
                wchar_t * prvblbtyp;
                void * prvblbbuf;
                size_t prvblblen;

                /*
                 * decode the private key, which produces
                 * a "blob" which can be understood by
                 * windows' rsa key import function(s)
                 */
                res = decode_prvkey(prvkeybuf, prvkeylen,
                                    &prvblbtyp, &prvblbbuf, &prvblblen);
                if (res == 0) {
                    /* finally, use the private key to decrypt the data */
                    res = asymmetric_decrypt(
                        prvblbtyp, prvblbbuf, prvblblen,
                        ctbuf, ctlen,
                        ptbuf, ptlen);

                    memset(prvblbbuf, 0, prvblblen);
                    free(prvblbbuf);
                }

                memset(prvkeybuf, 0, prvkeylen);
                free(prvkeybuf);
            }
        }

        free(derbuf);
    }

    return res;
}
