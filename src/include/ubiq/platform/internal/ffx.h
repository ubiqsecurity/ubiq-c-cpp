#ifndef UBIQ_STRUCTURED_INTERNAL_FFX_H
#define UBIQ_STRUCTURED_INTERNAL_FFX_H

#include <sys/cdefs.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <ubiq/platform/internal/bn.h>
#include <ubiq/platform/internal/debug.h>

#include <openssl/evp.h>

__BEGIN_DECLS

uint8_t * ffx_revb(uint8_t * const dst,
                   const uint8_t * const src, const size_t len);

uint32_t * ffx_revu32(uint32_t * const dst,
                  const uint32_t * const src, const size_t len);

static inline
char * ffx_revs(char * const dst, const char * const src)
{
    const size_t len = strlen(src);
    char * const res =
        (char *)ffx_revb((uint8_t *)dst, (const uint8_t *)src, len);
    dst[len] = '\0';
    return res;
}

int ffx_str(char * const str, const size_t len,
            const unsigned int m, const unsigned int r, const bigint_t * n);


struct ffx_ctx
{
    EVP_CIPHER_CTX * evp;

    unsigned int radix;
    char * custom_radix_str; // Radix character set - Not null if custom radix string is supplied.
    // It is possible to have a custom radix string with a normally standard radix size (10,36,62, etc).
    // If the custom radix string is not null, need to perform string mapping regardless of radix value
    uint32_t * u32_custom_radix_str; // Only used in the custom radix string contains multibyte characters.
    struct {
        size_t min, max;
    } txtlen, twklen;
    struct {
        uint8_t * buf;
        size_t len;
    } twk;
};

int ffx_prf(struct ffx_ctx * const ctx,
            uint8_t * const dst, const uint8_t * const src, const size_t len);
int ffx_ciph(struct ffx_ctx * const ctx,
             uint8_t * const dst, const uint8_t * const src);

int ffx_ctx_create(void ** const _ctx,
                   const size_t len, const size_t off,
                   const uint8_t * const keybuf, const size_t keylen,
                   const uint8_t * const twkbuf, const size_t twklen,
                   const size_t maxtxtlen,
                   const size_t mintwklen, const size_t maxtwklen,
                   const unsigned int radix);

// Use a custom radix string.  radix string can be simple ascii7 or full utf8.  
// Either one is handled internally.
int ffx_ctx_create_custom_radix_str(void ** const _ctx,
    const size_t len, const size_t off,
    const uint8_t * const keybuf, const size_t keylen,
    const uint8_t * const twkbuf, const size_t twklen,
    const size_t maxtxtlen,
    const size_t mintwklen, const size_t maxtwklen,
    const uint8_t * const custom_radix_str);

void ffx_ctx_destroy(void * const ctx, const size_t off);

__END_DECLS

#endif
