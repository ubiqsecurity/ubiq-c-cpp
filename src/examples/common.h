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
