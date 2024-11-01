#include <ubiq/platform/internal/ffx.h>

#include <math.h>
#include <unistr.h>
#include <uniwidth.h>
#include <wchar.h>

/*
 * This function is intended to be used to create a context for
 * a specific algorithm. That is, the algorithm embeds the ffx_ctx
 * structure within a structure of its own. It then supplies the
 * total length of its structure as the @len parameter and the offset
 * to the ffx_ctx structure within as the @off parameter.
 *
 * The other parameters describe the limits/parameters of the algorithm.
 */
int ffx_ctx_create(void ** const _ctx,
                   const size_t len, const size_t off,
                   const uint8_t * const keybuf, const size_t keylen,
                   const uint8_t * const twkbuf, const size_t twklen,
                   const size_t maxtxtlen,
                   const size_t mintwklen, const size_t maxtwklen,
                   const unsigned int radix)
{
    struct ffx_ctx * ctx;
    const EVP_CIPHER * ciph;
    size_t mintxtlen;

    /* the key length determines the flavor of AES */
    switch (keylen) {
    case 16: ciph = EVP_aes_128_cbc(); break;
    case 24: ciph = EVP_aes_192_cbc(); break;
    case 32: ciph = EVP_aes_256_cbc(); break;
    default: ciph = NULL;              break;
    }
    if (!ciph) {
        return -EINVAL;
    }

    // /*
    //  * FF1 and FF3-1 support a radix up to 65536, but the
    //  * implementation becomes increasingly difficult and
    //  * less useful in practice after the limits below.
    //  */
    if (radix < 2 || radix > 255) {
        return -EINVAL;
    }

    /*
     * for both ff1 and ff3-1: radix**minlen >= 1000000
     *
     * therefore:
     *   minlen = ceil(log_radix(1000000))
     *          = ceil(log_10(1000000) / log_10(radix))
     *          = ceil(6 / log_10(radix))
     */
    mintxtlen = ceil((double)6 / log10(radix));
    if (mintxtlen < 2 || mintxtlen > maxtxtlen) {
        return -EOVERFLOW;
    }

    /*
     * make sure the default tweak falls within the
     * specified parameters for the algorithm
     *
     * a maxtwklen of 0 indicates that there is
     * no upper limit
     */
    if (mintwklen > maxtwklen ||
        twklen < mintwklen ||
        (maxtwklen > 0 && twklen > maxtwklen)) {
        return -EINVAL;
    }

    /*
     * allocate space and copy in the parameters
     *
     * the only way to fail at this point is if this
     * allocation or the allocation of the evp context
     * fails
     */
    *_ctx = malloc(len + twklen);
    if (*_ctx) {
        ctx = (void *)((uint8_t *)*_ctx + off);

        ctx->evp = EVP_CIPHER_CTX_new();
        if (ctx->evp) {
            static const uint8_t IV[16] = { 0 };

            ctx->radix = radix;
            ctx->custom_radix_str = NULL;
            ctx->u32_custom_radix_str = NULL;

            ctx->txtlen.min = mintxtlen;
            ctx->txtlen.max = maxtxtlen;

            ctx->twklen.min = mintwklen;
            ctx->twklen.max = maxtwklen;

            ctx->twk.buf = (uint8_t *)(ctx + 1);
            ctx->twk.len = twklen;
            memcpy(ctx->twk.buf, twkbuf, twklen);

            /*
             * allocate and initialize the EVP with the key. the
             * IV is a constant string of 0's for both ff1 and ff3-1
             */
            EVP_EncryptInit_ex(ctx->evp, ciph, NULL, keybuf, IV);
            /* don't do any padding */
            EVP_CIPHER_CTX_set_padding(ctx->evp, 0);
        } else {
            free(*_ctx);
            return -ENOMEM;
        }
    }

    return 0;
}

int ffx_ctx_create_custom_radix_str(void ** const _ctx,
                   const size_t len, const size_t off,
                   const uint8_t * const keybuf, const size_t keylen,
                   const uint8_t * const twkbuf, const size_t twklen,
                   const size_t maxtxtlen,
                   const size_t mintwklen, const size_t maxtwklen,
                   const uint8_t * const custom_radix_str) 
{
    // Get the number of bytes in the custom radix string
    size_t radix_len = strlen(custom_radix_str);
    // Get the number of UTF8 characters in the custom radix string
    size_t radix_u8_mbsnlen = u8_mbsnlen(custom_radix_str, radix_len);

    int x = ffx_ctx_create(_ctx, len, off,keybuf, keylen, twkbuf,twklen,maxtxtlen, mintwklen, maxtwklen, radix_u8_mbsnlen);
    if (!x) {
        struct ffx_ctx * ctx = (void *)((uint8_t *)*_ctx + off);

        // If the radix string contains multibyte values, then create the u32_version
        // else simply use the custom radix string.
        if (radix_len == radix_u8_mbsnlen) {
            ctx->custom_radix_str = strdup(custom_radix_str);
            ctx->u32_custom_radix_str = NULL;
        } else {
            uint32_t * tmp = NULL;
            size_t lengthp = 0;
            ctx->custom_radix_str = NULL;
            tmp = u8_to_u32(custom_radix_str, u8_strlen(custom_radix_str) + 1, NULL, &lengthp);
            if (tmp != NULL) {
                ctx->u32_custom_radix_str = tmp;
            }
        }
    }
    return x;

}

void ffx_ctx_destroy(void * const _ctx, const size_t off)
{
    struct ffx_ctx * const ctx = (void *)((uint8_t *)_ctx + off);
    EVP_CIPHER_CTX_free(ctx->evp);
    if (ctx->custom_radix_str) {
        free(ctx->custom_radix_str);
    }
    if (ctx->u32_custom_radix_str) {
        free(ctx->u32_custom_radix_str);
    }
    free(_ctx);
}

/*
 * reverse a sequence of bytes. @dst and @src may be
 * equal but may not overlap, otherwise
 */
uint8_t * ffx_revb(uint8_t * const dst,
                   const uint8_t * const src, const size_t len)
{
    size_t i;

    for (i = 0; i < len / 2; i++) {
        const uint8_t t = src[i];
        dst[i] = src[(len - 1) - i];
        dst[(len - 1)- i] = t;
    }

    /*
     * if length is odd, there will be a byte in the
     * middle untouched by the loop above
     */
    if (len % 2) {
        dst[i] = src[i];
    }

    return dst;
}

uint32_t * ffx_revu32(uint32_t * const dst,
                   const uint32_t * const src, const size_t len)
{
    size_t i;

    for (i = 0; i < len / 2; i++) {
        const uint32_t t = src[i];
        dst[i] = src[(len - 1) - i];
        dst[(len - 1)- i] = t;
    }

    /*
     * if length is odd, there will be a byte in the
     * middle untouched by the loop above
     */
    if (len % 2) {
        dst[i] = src[i];
    }

    return dst;
}


/*
 * convert a (big) integer, @n, to a string in the radix, @r,
 * with a length, @m. The caller must supply the space pointed
 * to by @str, and the number of bytes pointed to by @str is
 * indicated by @len, which must be at least @m + 2. (The
 * underlying number library sometimes overestimates the space
 * required to represent the string. The +2 includes 1 byte
 * for this overestimation and 1 byte for the nul terminator.)
 *
 * If, after conversion, the number of bytes necessary to
 * represent the @n is larger than @m, the function fails. if
 * the number of bytes is less than @m, the string is zero-padded
 * to the left.
 *
 * the function returns 0 on success
 */
int ffx_str(char * const str, const size_t len,
            const unsigned int m, const unsigned int r,
            const bigint_t * const n)
{
    int res;

    // TODO - this should be based on call to get zeroth character of std radix string for radix value
    char c = '0';
    if (r > 62) {
        c = '\x01';
    }

    res = -EINVAL;
    if (bigint_cmp_si(n, 0) >= 0) {
        res = __bigint_get_str_radix(str, len, r, n);
        if (res == 0) {
            const size_t len = strlen(str);

            if (len < m) {
                memmove(str + (m - len), str, len + 1);
                memset(str, c, m - len);
            } else if (len > m) {
                res = -EOVERFLOW;
            }
        }
    }

    return res;
}

/*
 * perform an aes-cbc encryption (with an IV of 0) of @src using
 * the supplied @ctx, storing the last block of output into @dst.
 * The number of bytes pointed to by @src is indicated by @len and
 * must be a multiple of 16. @dst and @src may point to the same
 * location but may not overlap, otherwise. @dst must point to a
 * location at least 16 bytes long
 */
int ffx_prf(struct ffx_ctx * const ctx,
            uint8_t * const dst,
            const uint8_t * const src, const size_t len)
{
    EVP_CIPHER_CTX * evp;
    int dstl;

    if (len % 16) {
        return -EINVAL;
    }

    /*
     * the key was already set into the context. we can just
     * copy the initialized structure into this new one
     * to avoid the overhead of initialization every time
     */
    evp = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_copy(evp, ctx->evp);

    /*
     * this function only returns the last encrypted block,
     * so do the encryption one block at a time so that the
     * result can be written to the destination (without
     * requiring that the destination location be as large
     * as the source)
     */
    for (unsigned int i = 0; i < len; i += 16) {
        EVP_EncryptUpdate(evp, dst, &dstl, &src[i], 16);
    }

    /*
     * final doesn't output anything since there is no padding;
     * however, the output length parameter must still be valid
     */
    EVP_EncryptFinal_ex(evp, NULL, &dstl);
    EVP_CIPHER_CTX_free(evp);

    return 0;
}



/*
 * perform an aes-ecb encryption of @src using the supplied @ctx.
 * @src and @dst must each be 16 bytes long. @src and @dst may
 * point to the same location or otherwise overlap
 */
int ffx_ciph(struct ffx_ctx * const ctx,
             uint8_t * const dst, const uint8_t * const src)
{
    return ffx_prf(ctx, dst, src, 16);
}
