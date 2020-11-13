#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS

int ubiq_platform_algorithm_init(void);
void ubiq_platform_algorithm_exit(void);

struct ubiq_platform_algorithm
{
    unsigned int id;
    const char * name;

    struct {
        unsigned int key, iv, tag;
    } len;
};

int
ubiq_platform_algorithm_get_byid(
    const unsigned int,
    const struct ubiq_platform_algorithm ** const);
int
ubiq_platform_algorithm_get_byname(
    const char * const,
    const struct ubiq_platform_algorithm ** const);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
