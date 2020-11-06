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
    unsigned int,
    const struct ubiq_platform_algorithm **);
int
ubiq_platform_algorithm_get_byname(
    const char *,
    const struct ubiq_platform_algorithm **);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
