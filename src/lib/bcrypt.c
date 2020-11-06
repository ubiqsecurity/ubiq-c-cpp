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
__ubiq_support_digest_init(
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

    if (err) {
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
    return __ubiq_support_digest_init(name, NULL, 0, ctx);
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
    return __ubiq_support_digest_init(
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
