#pragma once

#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

#pragma pack(push, 1)

/*
 * all fields in network byte order
 */

struct ubiq_platform_preamble
{
    uint8_t version;
};

#define UBIQ_HEADER_V0_FLAG_AAD (1 << 0)

struct ubiq_platform_header_v0
{
    struct ubiq_platform_preamble pre;
    uint8_t flags;
    uint8_t algorithm;
    uint8_t ivlen;
    uint16_t keylen;
    /*
     * iv (contains ivlen bytes)
     * key (contains keylen bytes)
     */
};

union ubiq_platform_header
{
    struct ubiq_platform_preamble pre;
    struct ubiq_platform_header_v0 v0;
};

#pragma pack(pop)

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
