#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

int ubiq_platform_algorithm_init(void);
void ubiq_platform_algorithm_exit(void);

struct ubiq_platform_cipher;
struct ubiq_platform_algorithm
{
    unsigned int id;

    const struct ubiq_platform_cipher * cipher;
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

int ubiq_platform_base64_encode(char **, const void *, size_t);
int ubiq_platform_base64_decode(void **, const char *, size_t);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
