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

__BEGIN_DECLS

#define UBIQ_SAMPLE_MAX_SIMPLE_SIZE     (50 * 1024 * 1024)

typedef enum
{
    UBIQ_SAMPLE_MODE_UNSPEC,
    UBIQ_SAMPLE_MODE_ENCRYPT,
    UBIQ_SAMPLE_MODE_DECRYPT,
} ubiq_sample_mode_t;

typedef enum
{
    UBIQ_SAMPLE_METHOD_UNSPEC,
    UBIQ_SAMPLE_METHOD_SIMPLE,
    UBIQ_SAMPLE_METHOD_PIECEWISE,
} ubiq_sample_method_t;

int
ubiq_sample_getopt(
    const int argc, char * const argv[],
    ubiq_sample_mode_t * const mode,
    ubiq_sample_method_t * const method,
    const char ** const infile, const char ** const outfile,
    const char ** const credfile, const char ** const profile);

__END_DECLS
