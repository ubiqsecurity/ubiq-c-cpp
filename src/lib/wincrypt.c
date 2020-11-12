#include <ubiq/platform/internal/support.h>

#include <bcrypt.h>
#define STATUS_SUCCESS                  ((NTSTATUS)0L)

#include <stdint.h>

#define MIN(x, y)                       (((x) < (y)) ? (x) : (y))

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

struct ubiq_support_digest_context
{
    struct {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE dig;
    } hnd;
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

    err = -EINVAL;
    if (ident) {
        const DWORD flag = keylen ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0;

        BCRYPT_ALG_HANDLE halg;

        err = INT_MIN;
        if (BCryptOpenAlgorithmProvider(
                &halg, ident,
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
    BCryptHashData(ctx->hnd.dig, (PUCHAR)buf, len, 0);
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
    if (BCryptGetProperty(ctx->hnd.alg,
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
            if (BCryptFinishHash(
                    ctx->hnd.dig, buf, len, 0) == STATUS_SUCCESS) {
                *_buf = buf;
                *_len = len;

                BCryptDestroyHash(ctx->hnd.dig);
                BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
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

    size_t blksz;
    struct {
        void * buf;
        size_t len;
    } obj, blk, vec, aci;
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
    DWORD out;
    int err;

    ctx = NULL;

    err = -EINVAL;
    if (keylen == alg->len.key) {
        err = 0;
    }

    if (!err) {
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

        if (!err &&
            BCryptSetProperty(
                halg, BCRYPT_CHAINING_MODE,
                (PUCHAR)cipher->mode, wcslen(cipher->mode) * *cipher->mode,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }

        if (!err &&
            BCryptGetProperty(
                halg, BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&objsz, sizeof(objsz), &out,
                0) != STATUS_SUCCESS) {
            err = INT_MIN;
        }

        if (!err) {
            if (BCryptGetProperty(
                    halg, BCRYPT_BLOCK_LENGTH,
                    (PUCHAR)&blksz, sizeof(blksz), &out,
                    0) == STATUS_SUCCESS) {
                if (veclen > blksz) {
                    err = -EINVAL;
                }
            } else {
                err = INT_MIN;
            }
        }

        if (!err) {
            acisz = 0;

            if (alg->len.tag) {
                BCRYPT_AUTH_TAG_LENGTHS_STRUCT atl;

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

        if (!err) {
            err = -ENOMEM;
            ctx = malloc(sizeof(*ctx) + objsz + 2 * blksz + acisz);
            if (ctx) {
                size_t off;

                ctx->alg     = alg;

                ctx->hnd.alg = halg;
                ctx->hnd.key = NULL;

                ctx->obj.buf = ctx + 1;
                ctx->obj.len = objsz;

                off = ctx->obj.len;

                if (blksz) {
                    ctx->blksz = blksz;

                    ctx->blk.buf = (char *)ctx->obj.buf + off;
                    ctx->blk.len = 0;
                    off += ctx->blksz;

                    ctx->vec.buf = (char *)ctx->obj.buf + off;
                    ctx->vec.len = 0;
                    off += ctx->blksz;

                    memcpy(ctx->vec.buf, vecbuf, veclen);
                    ctx->vec.len = veclen;
                }
                if (acisz) {
                    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * inf;

                    ctx->aci.buf = (char *)ctx->obj.buf + off;
                    ctx->aci.len = acisz;
                    off += ctx->aci.len;

                    inf = ctx->aci.buf;
                    memset(inf, 0, sizeof(*inf));
                    BCRYPT_INIT_AUTH_MODE_INFO(*inf);

                    inf->pbNonce        = ctx->vec.buf;
                    inf->cbNonce        = ctx->vec.len;

                    ctx->vec.len        = ctx->blksz;

                    inf->pbAuthData     = NULL;
                    inf->cbAuthData     = 0;
                    inf->pbTag          = NULL;
                    inf->cbTag          = alg->len.tag;
                    inf->pbMacContext   = (void *)(inf + 1);
                    inf->cbMacContext   = ctx->aci.len - sizeof(*inf);
                    inf->cbAAD          = 0;
                    inf->cbData         = 0;
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
        *_ctx = ctx;
    } else {
        if (ctx) {
            if (ctx->hnd.key) {
                BCryptDestroyKey(ctx->hnd.key);
            }

            BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
            free(ctx);
        }
    }

    return err;
}

void
ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context * const ctx)
{
    BCryptDestroyKey(ctx->hnd.key);
    BCryptCloseAlgorithmProvider(ctx->hnd.alg, 0);
    memset(ctx, 0, (sizeof(*ctx) +
                    ctx->obj.len +
                    2 * ctx->blksz +
                    ctx->aci.len));
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
        if (ctx->aci.buf && aadlen) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;
            ULONG out;

            inf->pbAuthData = (void *)aadbuf;
            inf->cbAuthData = aadlen;

            err = (BCryptEncrypt(
                       ctx->hnd.key,
                       NULL, 0,
                       ctx->aci.buf,
                       ctx->vec.buf, ctx->vec.len,
                       NULL, 0, &out,
                       0) == STATUS_SUCCESS) ? 0 : INT_MIN;

            inf->pbAuthData = NULL;
            inf->cbAuthData = 0;
        }

        if (!err) {
            *_ctx = ctx;
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
    ULONG len, out;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ptlen + ctx->blksz;
    buf = malloc(len);
    if (buf) {
        struct {
            size_t pt, ct;
        } off;

        off.pt = off.ct = 0;
        err = 0;

        if (ctx->blk.len) {
            const size_t copy = MIN(ctx->blksz - ctx->blk.len, ptlen);
            memcpy((char *)ctx->blk.buf + ctx->blk.len, ptbuf, copy);
            ctx->blk.len += copy;
            off.pt += copy;

            if (ctx->blk.len == ctx->blksz) {
                ULONG out;

                if (BCryptEncrypt(
                        ctx->hnd.key,
                        ctx->blk.buf, ctx->blk.len,
                        ctx->aci.buf,
                        ctx->vec.buf, ctx->vec.len,
                        (char *)buf + off.ct, len - off.ct, &out,
                        0) != STATUS_SUCCESS) {
                    err = INT_MIN;
                }

                memset(ctx->blk.buf, 0, ctx->blksz);
                ctx->blk.len = 0;

                off.ct += out;
            }
        }

        if (!err && (ptlen - off.pt) >= ctx->blksz) {
            const size_t enclen = ((ptlen - off.pt) / ctx->blksz) * ctx->blksz;

            if (BCryptEncrypt(
                    ctx->hnd.key,
                    (char *)ptbuf + off.pt, enclen,
                    ctx->aci.buf,
                    ctx->vec.buf, ctx->vec.len,
                    (char *)buf + off.ct, len - off.ct, &out,
                    0) != STATUS_SUCCESS) {
                err = INT_MIN;
            }

            off.pt += enclen;
            off.ct += enclen;
        }

        if (!err) {
            if (off.pt < ptlen) {
                ctx->blk.len = ptlen - off.pt;
                memcpy(ctx->blk.buf, (char *)ptbuf + off.pt, ctx->blk.len);
            }

            *ctbuf = buf;
            *ctlen = off.ct;
        } else {
            free(buf);
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
    len = ctx->blksz;
    buf = malloc(len);
    if (buf) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;

        if (inf) {
            inf->pbTag          = malloc(inf->cbTag);
            if (inf->pbTag) {
                inf->dwFlags   &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
                err = 0;
            }
        }

        if (!err &&
            BCryptEncrypt(
                ctx->hnd.key,
                ctx->blk.buf, ctx->blk.len,
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
        if (ctx->aci.buf && aadlen) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;
            ULONG out;

            inf->pbAuthData = (void *)aadbuf;
            inf->cbAuthData = aadlen;

            err = (BCryptDecrypt(
                       ctx->hnd.key,
                       NULL, 0,
                       ctx->aci.buf,
                       ctx->vec.buf, ctx->vec.len,
                       NULL, 0, &out,
                       0) == STATUS_SUCCESS) ? 0 : INT_MIN;

            inf->pbAuthData = NULL;
            inf->cbAuthData = 0;
        }

        if (!err) {
            *_ctx = ctx;
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
    ULONG len, out;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ctlen + ctx->blksz;
    buf = malloc(len);
    if (buf) {
        struct {
            size_t i, o;
        } off;

        off.i = off.o = 0;
        err = 0;

        if (ctx->blk.len) {
            const size_t copy = MIN(ctx->blksz - ctx->blk.len, ctlen);
            memcpy((char *)ctx->blk.buf + ctx->blk.len, ctbuf, copy);
            ctx->blk.len += copy;
            off.i += copy;

            if (ctx->blk.len == ctx->blksz) {
                ULONG out;

                if (BCryptDecrypt(
                        ctx->hnd.key,
                        ctx->blk.buf, ctx->blk.len,
                        ctx->aci.buf,
                        ctx->vec.buf, ctx->vec.len,
                        (char *)buf + off.o, len - off.o, &out,
                        0) != STATUS_SUCCESS) {
                    err = INT_MIN;
                }

                memset(ctx->blk.buf, 0, ctx->blksz);
                ctx->blk.len = 0;

                off.o += out;
            }
        }

        if (!err && (ctlen - off.i) >= ctx->blksz) {
            const size_t clen = ((ctlen - off.i) / ctx->blksz) * ctx->blksz;

            if (BCryptDecrypt(
                    ctx->hnd.key,
                    (char *)ctbuf + off.i, clen,
                    ctx->aci.buf,
                    ctx->vec.buf, ctx->vec.len,
                    (char *)buf + off.o, len - off.o, &out,
                    0) != STATUS_SUCCESS) {
                err = INT_MIN;
            }

            off.i += clen;
            off.o += clen;
        }

        if (!err) {
            if (off.i < ctlen) {
                ctx->blk.len = ctlen - off.i;
                memcpy(ctx->blk.buf, (char *)ctbuf + off.i, ctx->blk.len);
            }

            *ptbuf = buf;
            *ptlen = off.o;
        } else {
            free(buf);
        }
    }

    return err;
}

int
ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context * const ctx,
    const void * const tagbuf, const size_t taglen,
    void ** const ptbuf, size_t * const ptlen)
{
    DWORD len;
    void * buf;
    int err;

    err = -ENOMEM;
    len = ctx->blksz;
    buf = malloc(len);
    if (buf) {
        if (ctx->aci.buf) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO * const inf = ctx->aci.buf;

            err = -EINVAL;
            if (inf->cbTag == taglen) {
                inf->pbTag      = (PUCHAR)tagbuf;
                inf->dwFlags   &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
                err = 0;
            }
        }

        if (!err &&
            BCryptDecrypt(
                ctx->hnd.key,
                ctx->blk.buf, ctx->blk.len,
                ctx->aci.buf,
                ctx->vec.buf, ctx->vec.len,
                buf, len, &len,
                0) == STATUS_SUCCESS) {
            *ptbuf = buf;
            *ptlen = len;

            ubiq_support_cipher_destroy(ctx);

            err = 0;
        } else {
            free(buf);
            err = INT_MIN;
        }
    }

    return err;
}

struct asn1vector
{
    const void * buf;
    unsigned int len;
};

static
int
asn1scanf_preamble(
    const uint8_t ** const buf, size_t * const len,
    const char ** const fmt,
    const char exfmt, const uint8_t exbuf,
    size_t * const vlen)
{
    if (**fmt != exfmt) {
        return -EINVAL;
    }
    (*fmt)++;
    if (*len < 2) {
        return -EINVAL;
    }
    if (**buf != exbuf) {
        return -EINVAL;
    }
    (*buf)++; (*len)--;
    if ((**buf & 0x80)) {
        return -ENOTSUP;
    }
    if (**buf > *len - 1) {
        return -EINVAL;
    }
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
        int * const i = va_arg(*ap, int *);
        int j, l;

        for (j = 0, l = vlen - 1, *i = 0; l >= 0; l--, j++) {
            *i |= (*buf)[l] << (j * 8);
        }

        *buf += j;
        *len -= j;
    }

    return 0;
}

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

#define pbOID_PKCS_5_PBKDF2                     \
    (uint8_t[]){0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c}
#define pbOID_NIST_AES256_CBC                   \
    (uint8_t[]){0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a}

/*
 * base64 decode private key
 * decode der object
 * decode parameters
 * derive key
 * decrypt private key
 * use private key to decrypt ctbuf
 */

static
int
asymmetric_decrypt(const wchar_t * const prvblbtyp,
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

            if (BCryptDecrypt(
                    hkey,
                    (void *)ctbuf, ctlen,
                    &inf,
                    NULL, 0,
                    NULL, 0, &len,
                    BCRYPT_PAD_OAEP) == STATUS_SUCCESS) {
                void * buf;

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

static
int
decode_prvkey(const void * const prvkeybuf, const size_t prvkeylen,
              const wchar_t ** const prvblbtyp,
              void ** const prvblbbuf, size_t * const prvblblen)
{
    CRYPT_PRIVATE_KEY_INFO * inf;
    DWORD len;
    int res;

    res = INT_MIN;
    if (CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            prvkeybuf, prvkeylen,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &inf, &len)) {
        if (CryptDecodeObject(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                PKCS_RSA_PRIVATE_KEY,
                inf->PrivateKey.pbData, inf->PrivateKey.cbData,
                0,
                NULL, &len)) {
            void * blb;

            res = -ENOMEM;
            blb = malloc(len);
            if (blb) {
                res = INT_MIN;
                if (CryptDecodeObject(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
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
decrypt_der(const void * const enckeybuf, const size_t enckeylen,
            const char * const passwd,
            const char * const kdfoid,
            const void * const saltbuf, const size_t saltlen,
            const unsigned int iter,
            const char *algoid,
            const void * ivbuf, const size_t ivlen,
            void ** const prvkeybuf, size_t * const prvkeylen)
{
    BCRYPT_ALG_HANDLE halg;
    uint8_t key[32];
    uint8_t iv[16];
    int res;

    res = -EINVAL;
    if (strcmp(kdfoid, szOID_PKCS_5_PBKDF2) == 0 &&
        strcmp(algoid, szOID_NIST_AES256_CBC) == 0 &&
        ivlen == sizeof(iv)) {
        memcpy(iv, ivbuf, ivlen);

        res = INT_MIN;
        if (BCryptOpenAlgorithmProvider(
                &halg,
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
        if (BCryptOpenAlgorithmProvider(
                &halg, BCRYPT_AES_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
            BCRYPT_KEY_HANDLE hkey;
            void * objbuf;
            DWORD objlen;
            ULONG v;

            hkey = NULL;
            objbuf = NULL;

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
decode_der(const void * const derbuf, const size_t derlen,
           const char ** const kdfoid,
           const void ** const saltbuf, size_t * const saltlen,
           unsigned int * const iter,
           const char ** const algoid,
           const void ** const ivbuf, size_t * const ivlen,
           const void ** const enckeybuf, size_t * const enckeylen)
{
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO *inf;
    DWORD len;
    BOOL ret;
    int res;

    res = INT_MIN;
    ret = CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
        derbuf, derlen,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        &inf, &len);
    if (ret) {
        struct asn1vector kdf, alg, salt, iv;
        int _iter;

        res = asn1scanf(inf->EncryptionAlgorithm.Parameters.pbData,
                        inf->EncryptionAlgorithm.Parameters.cbData,
                        "((o(xi))(ox))",
                        &kdf, &salt, &_iter, &alg, &iv);
        if (res == 0 &&
            sizeof(pbOID_PKCS_5_PBKDF2) == kdf.len &&
            memcmp(pbOID_PKCS_5_PBKDF2, kdf.buf, kdf.len) == 0 &&
            sizeof(pbOID_NIST_AES256_CBC) == alg.len &&
            memcmp(pbOID_NIST_AES256_CBC, alg.buf, alg.len) == 0) {
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

        LocalFree(inf);
    }

    return res;
}

static
int
decode_pem(const char * const pemstr,
           void ** const derbuf, size_t * const derlen)
{
    DWORD prvlen;
    BOOL ret;
    int res;

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

    res = decode_pem(prvpem, &derbuf, &derlen);
    if (res == 0) {
        const char * kdf, * alg;
        const void * enckeybuf, * saltbuf, * ivbuf;
        void * prvkeybuf;
        size_t enckeylen, saltlen, ivlen, prvkeylen;
        unsigned int iter;

        res = decode_der(derbuf, derlen,
                         &kdf, &saltbuf, &saltlen, &iter,
                         &alg, &ivbuf, &ivlen,
                         &enckeybuf, &enckeylen);
        if (res == 0) {
            res = decrypt_der(enckeybuf, enckeylen,
                              passwd,
                              kdf, saltbuf, saltlen, iter,
                              alg, ivbuf, ivlen,
                              &prvkeybuf, &prvkeylen);
            if (res == 0) {
                wchar_t * prvblbtyp;
                void * prvblbbuf;
                size_t prvblblen;

                res = decode_prvkey(prvkeybuf, prvkeylen,
                                    &prvblbtyp, &prvblbbuf, &prvblblen);
                if (res == 0) {
                    res = asymmetric_decrypt(
                        prvblbtyp, prvblbbuf, prvblblen,
                        ctbuf, ctlen,
                        ptbuf, ptlen);

                    free(prvblbbuf);
                }

                free(prvkeybuf);
            }
        }

        free(derbuf);
    }

    return res;
}
