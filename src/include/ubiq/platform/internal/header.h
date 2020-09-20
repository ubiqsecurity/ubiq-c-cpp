/*
 * Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Ubiq Security, Inc. The intellectual and technical concepts contained
 * herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
 * covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Ubiq Security, Inc.
 *
 * Your use of the software is expressly conditioned upon the terms
 * and conditions available at:
 *
 *     https://ubiqsecurity.com/legal
 *
 */

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
