#include <ubiq/platform/internal/support.h>

#include <bcrypt.h>
#define STATUS_SUCCESS                  ((NTSTATUS)0L)

int
ubiq_support_base64_encode(
    char ** const _str,
    const void * const buf, const size_t len)
{
    char * str;
    int res;
    DWORD out;

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
        res = 0;
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
        res = 0;
    }

    return res;
}

struct ubiq_support_digest_context
{
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE dig;
    struct {
        void * buf;
        size_t len;
    } obj;
};

static
int
ubiq_support_hash_init(
    const char * const name,
    const void * const keybuf, const size_t keylen,
    struct ubiq_support_digest_context ** const _ctx)
{
    static const
        struct {
        const char * const name;
        const wchar_t * const ident;
    } digests[] = {
        { .name = "sha512", .ident = BCRYPT_SHA512_ALGORITHM },
    };

    const wchar_t * ident;

    struct ubiq_support_digest_context * ctx;
    int err;

    err = -EINVAL;
    ident = NULL;
    for (unsigned int i = 0;
         i < sizeof(digests) / sizeof(*digests);
         i++ ) {
        if (strcasecmp(name, digests[i].name) == 0) {
            ident = digests[i].ident;
            err = 0;
            break;
        }
    }

    ctx = NULL;
    if (!err) {
        ctx = malloc(sizeof(*ctx));
        if (ctx) {
            ctx->alg = NULL;
            ctx->dig = NULL;
            ctx->obj.buf = NULL;
            ctx->obj.len = 0;
        } else {
            err = -ENOMEM;
        }
    }

    if (!err) {
        if (BCryptOpenAlgorithmProvider(
                &ctx->alg, ident,
                NULL,
                keylen ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }
    }

    if (!err) {
        ULONG copied;
        DWORD len;

        if (BCryptGetProperty(ctx->alg,
                              BCRYPT_OBJECT_LENGTH,
                              (PUCHAR)&len, sizeof(len),
                              &copied,
                              0) == STATUS_SUCCESS) {
            ctx->obj.len = len;
            ctx->obj.buf = malloc(len);
            if (!ctx->obj.buf) {
                err = -ENOMEM;
            }
        } else {
            err = INT_MIN;
        }
    }

    if (!err) {
        if (BCryptCreateHash(ctx->alg,
                             &ctx->dig,
                             ctx->obj.buf, ctx->obj.len,
                             (PUCHAR)keybuf, keylen,
                             0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }
    }

    if (!err) {
        *_ctx = ctx;
    } else {
        if (ctx) {
            if (ctx->dig) {
                BCryptDestroyHash(ctx->dig);
            }
            if (ctx->obj.buf) {
                free(ctx->obj.buf);
            }
            if (ctx->alg) {
                BCryptCloseAlgorithmProvider(ctx->alg, 0);
            }
            free(ctx);
        }
    }

    return err;
}

int
ubiq_support_digest_init(
    const char * const name,
    struct ubiq_support_digest_context ** const ctx)
{
    return ubiq_support_hash_init(name, NULL, 0, ctx);
}

void
ubiq_support_digest_update(
    struct ubiq_support_digest_context * const ctx,
    const void * const buf, const size_t len)
{
    BCryptHashData(ctx->dig, (PUCHAR)buf, len, 0);
}

int
ubiq_support_digest_finalize(
    struct ubiq_support_digest_context * const ctx,
    void ** const _buf, size_t * const _len)
{
    int err;

    ULONG copied;
    DWORD len;

    err = 0;
    if (BCryptGetProperty(ctx->alg,
                          BCRYPT_HASH_LENGTH,
                          (PUCHAR)&len, sizeof(len),
                          &copied,
                          0) != STATUS_SUCCESS) {
        err = INT_MIN;
    }

    if (!err) {
        void * buf;

        err = -ENOMEM;
        buf = malloc(len);
        if (buf) {
            err = INT_MIN;
            if (BCryptFinishHash(ctx->dig, buf, len, 0) == STATUS_SUCCESS) {
                *_buf = buf;
                *_len = len;

                BCryptDestroyHash(ctx->dig);
                free(ctx->obj.buf);
                BCryptCloseAlgorithmProvider(ctx->alg, 0);
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
ubiq_support_hmac_init(
    const char * const name,
    const void * const keybuf, const size_t keylen,
    struct ubiq_support_hmac_context ** const ctx)
{
    return ubiq_support_hash_init(
        name,
        keybuf, keylen,
        (struct ubiq_support_digest_context **)ctx);
}

void
ubiq_support_hmac_update(
    struct ubiq_support_hmac_context * const ctx,
    const void * const buf, const size_t len)
{
    ubiq_support_digest_update(
        (struct ubiq_support_digest_context *)ctx,
        buf, len);
}

int
ubiq_support_hmac_finalize(
    struct ubiq_support_hmac_context * const ctx,
    void ** const buf, size_t * const len)
{
    return ubiq_support_digest_finalize(
        (struct ubiq_support_digest_context *)ctx,
        buf, len);
}

int
ubiq_support_getrandom(
    void * const buf, const size_t len)
{
    BCRYPT_ALG_HANDLE h;
    int err;

    err = -ENODATA;
    h = NULL;
    BCryptOpenAlgorithmProvider(&h, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (h) {
        if (BCryptGenRandom(h, (PUCHAR)buf, len, 0) == STATUS_SUCCESS) {
            err = 0;
        }
        BCryptCloseAlgorithmProvider(h, 0);
    }

    return 0;
}

struct ubiq_support_cipher_context
{
    const struct ubiq_platform_algorithm * alg;

    struct {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_KEY_HANDLE key;
    } hnd;

    struct {
        void * buf;
        size_t len;
    } obj, vec, mac, aci;
};

static
int
ubiq_support_cipher_init(
    const struct ubiq_platform_algorithm * const alg,
    const void * const keybuf, const size_t keylen,
    const void * const vecbuf, const size_t veclen,
    struct ubiq_support_cipher_context ** const _ctx)
{
    static const
        struct wincipher {
        const char * const name;
        const wchar_t * const algo;
        const wchar_t * const mode;
    } ciphers[] = {
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
    DWORD val, len;
    int err;

    cipher = NULL;
    for (unsigned int i = 0;
         i < sizeof(ciphers) / sizeof(*cipher);
         i++) {
        if (strcasecmp(alg->name, ciphers[i].name) == 0) {
            cipher = &ciphers[i];
            break;
        }
    }
    err = (cipher && keylen == alg->len.key) ? 0 : -EINVAL;

    ctx = NULL;
    if (!err) {
        err = -ENOMEM;
        ctx = malloc(sizeof(*ctx));
        if (ctx) {
            ctx->alg = alg;

            ctx->hnd.alg = NULL;
            ctx->hnd.key = NULL;

            ctx->obj.buf =
                ctx->vec.buf =
                ctx->mac.buf =
                ctx->aci.buf = NULL;
            ctx->obj.len =
                ctx->vec.len =
                ctx->mac.len =
                ctx->aci.len = 0;

            err = 0;
        }
    }

    if (!err) {
        if (BCryptOpenAlgorithmProvider(
                &ctx->hnd.alg, cipher->algo, NULL, 0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }
    }

    if (!err) {
        if (BCryptSetProperty(
                ctx->hnd.alg, BCRYPT_CHAINING_MODE,
                (PUCHAR)cipher->mode, wcslen(cipher->mode) * *cipher->mode,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }
    }

    if (!err) {
        err = INT_MIN;
        if (BCryptGetProperty(
                ctx->hnd.alg, BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&val, sizeof(val), &len,
                0) == STATUS_SUCCESS) {
            ctx->obj.len = val;
            err = 0;
        }
    }

    if (!err) {
        err = INT_MIN;
        if (BCryptGetProperty(
                ctx->hnd.alg, BCRYPT_BLOCK_LENGTH,
                (PUCHAR)&val, sizeof(val), &len,
                0) == STATUS_SUCCESS) {
            ctx->vec.len = val;
            err = (veclen <= ctx->vec.len) ? 0 : -EINVAL;
        }
    }

    if (!err && alg->len.tag) {
        BCRYPT_AUTH_TAG_LENGTHS_STRUCT atl;
        err = INT_MIN;
        if (BCryptGetProperty(
                ctx->hnd.alg, BCRYPT_BLOCK_LENGTH,
                (PUCHAR)&atl, sizeof(atl), &len,
                0) == STATUS_SUCCESS) {
            ctx->mac.len = atl.dwMaxLength;
            ctx->aci.len = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);

            err = 0;
        }
    }

    if (!err) {
        err = -ENOMEM;
        ctx->obj.buf = malloc(
            ctx->obj.len + ctx->vec.len + ctx->mac.len + ctx->aci.len);
        if (ctx->obj.buf) {
            if (ctx->vec.len) {
                ctx->vec.buf = (char *)ctx->obj.buf + ctx->obj.len;
                memcpy(ctx->vec.buf, vecbuf, veclen);
            }
            if (ctx->mac.len) {
                ctx->mac.buf = (char *)ctx->vec.buf + ctx->vec.len;
            }
            if (ctx->aci.len) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * inf;

                ctx->aci.buf = (char *)ctx->mac.buf + ctx->mac.len;

                inf = ctx->aci.buf;
                memset(inf, 0, sizeof(*inf));
                BCRYPT_INIT_AUTH_MODE_INFO(*inf);

                inf->pbNonce        = NULL;
                inf->cbNonce        = 0;
                inf->pbAuthData     = NULL;
                inf->cbAuthData     = 0;
                inf->pbTag          = NULL;
                inf->cbTag          = 0;
                inf->pbMacContext   = ctx->mac.buf;
                inf->cbMacContext   = ctx->mac.len;
                inf->cbAAD          = 0;
                inf->cbData         = 0;
                inf->dwFlags        = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
            }

            err = 0;
        }
    }

    if (!err) {
        if (BCryptGenerateSymmetricKey(
                ctx->hnd.alg, &ctx->hnd.key,
                ctx->obj.buf, ctx->obj.len,
                (PUCHAR)keybuf, keylen,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }
    }

    if (!err) {
        *_ctx = ctx;
    } else if (ctx) {
        if (ctx->hnd.key) {
            BCryptDestroyKey(ctx->hnd.key);
        }
        if (ctx->obj.buf) {
            free(ctx->obj.buf);
        }
        if (ctx->hnd.alg) {
            BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
        }
        free(ctx);
    }

    return err;
}

void
ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context * const ctx)
{
    BCryptDestroyKey(ctx->hnd.key);
    free(ctx->obj.buf);
    BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
    free(ctx);
}

int
ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm * const alg,
    const void * const keybuf, const size_t keylen,
    const void * const vecbuf, const size_t veclen,
    const void * const aadbuf, const size_t aadlen,
    struct ubiq_support_cipher_context ** const _ctx)
{
    struct ubiq_support_cipher_context * ctx;
    int err;

    err = ubiq_support_cipher_init(
        alg, keybuf, keylen, vecbuf, veclen, &ctx);
    if (!err) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;
        ULONG out;

        if (inf) {
            inf->pbNonce    = (void *)vecbuf;
            inf->cbNonce    = veclen;
            inf->pbAuthData = (void *)aadbuf;
            inf->cbAuthData = aadlen;
        }

        err = INT_MIN;
        if (BCryptEncrypt(
                ctx->hnd.key,
                NULL, 0,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                NULL, 0, &out,
                0) == STATUS_SUCCESS) {
            if (inf) {
                inf->pbNonce    = NULL;
                inf->cbNonce    = 0;
                inf->pbAuthData = NULL;
                inf->cbAuthData = 0;
            }

            *_ctx = ctx;
            err = 0;
        } else {
            ubiq_support_cipher_destroy(ctx);
        }
    }

    return err;
}

int
ubiq_support_encryption_update(
    struct ubiq_support_cipher_context * const ctx,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    DWORD len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ptlen + ctx->vec.len;
    buf = malloc(len);
    if (buf) {
        if (BCryptEncrypt(
                ctx->hnd.key,
                (void *)ptbuf, ptlen,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                buf, len, &len,
                0) == STATUS_SUCCESS) {
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
    struct ubiq_support_cipher_context * const ctx,
    void ** const ctbuf, size_t * const ctlen,
    void ** const tagbuf, size_t * const taglen)
{
    DWORD len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ctx->vec.len;
    buf = malloc(len);
    if (buf) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;

        if (inf) {
            inf->cbTag          = ctx->alg->len.tag;
            inf->pbTag          = malloc(inf->cbTag);

            if (inf->pbTag) {
                inf->dwFlags   &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
                err = 0;
            }
        }

        if (!err &&
            BCryptEncrypt(
                ctx->hnd.key,
                NULL, 0,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                buf, len, &len,
                0) == STATUS_SUCCESS) {
            *ctbuf = buf;
            *ctlen = len;

            *tagbuf = inf->pbTag;
            *taglen = inf->cbTag;

            ubiq_support_cipher_destroy(ctx);

            err = 0;
        } else {
            if (inf && inf->pbTag) {
                free(inf->pbTag);
            }

            free(buf);
            err = INT_MIN;
        }
    }

    return err;
}

int
ubiq_support_decryption_init(
    const struct ubiq_platform_algorithm * const alg,
    const void * const keybuf, const size_t keylen,
    const void * const vecbuf, const size_t veclen,
    const void * const aadbuf, const size_t aadlen,
    struct ubiq_support_cipher_context ** const _ctx)
{
    struct ubiq_support_cipher_context * ctx;
    int err;

    err = ubiq_support_cipher_init(
        alg, keybuf, keylen, vecbuf, veclen, &ctx);
    if (!err) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;
        ULONG out;

        if (inf) {
            inf->pbNonce    = (void *)vecbuf;
            inf->cbNonce    = veclen;
            inf->pbAuthData = (void *)aadbuf;
            inf->cbAuthData = aadlen;
        }

        err = INT_MIN;
        if (BCryptDecrypt(
                ctx->hnd.key,
                NULL, 0,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                NULL, 0, &out,
                0) == STATUS_SUCCESS) {
            if (inf) {
                inf->pbNonce    = NULL;
                inf->cbNonce    = 0;
                inf->pbAuthData = NULL;
                inf->cbAuthData = 0;
            }

            *_ctx = ctx;
            err = 0;
        } else {
            ubiq_support_cipher_destroy(ctx);
        }
    }

    return err;
}

int
ubiq_support_decryption_update(
    struct ubiq_support_cipher_context * const ctx,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    DWORD len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ctlen + ctx->vec.len;
    buf = malloc(len);
    if (buf) {
        if (BCryptDecrypt(
                ctx->hnd.key,
                (void *)ctbuf, ctlen,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                buf, len, &len,
                0) == STATUS_SUCCESS) {
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
    struct ubiq_support_cipher_context * const ctx,
    const void * const tagbuf, const size_t taglen,
    void ** const ctbuf, size_t * const ctlen)
{
    DWORD len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ctx->vec.len;
    buf = malloc(len);
    if (buf) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;

        if (inf) {
            inf->pbTag          = (PUCHAR)tagbuf;
            inf->cbTag          = taglen;

            if (inf->pbTag) {
                inf->dwFlags   &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
                err = 0;
            }
        }

        if (!err &&
            BCryptDecrypt(
                ctx->hnd.key,
                NULL, 0,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                buf, len, &len,
                0) == STATUS_SUCCESS) {
            *ctbuf = buf;
            *ctlen = len;

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
ubiq_support_asymmetric_decrypt(
    const char * const prvpem, const char * const passwd,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    return -ENOTSUP;
}
