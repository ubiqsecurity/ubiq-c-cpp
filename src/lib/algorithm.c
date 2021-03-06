#include <ubiq/platform/internal/algorithm.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const struct ubiq_platform_algorithm ubiq_platform_algorithms[] = {
    {
        .id = 0, .name = "aes-256-gcm",
        .len = { .key = 32, .iv = 12, .tag = 16 },
    }, {
        .id = 1, .name = "aes-128-gcm",
        .len = { .key = 16, .iv = 12, .tag = 16 },
    },
};

static const size_t ubiq_platform_algorithms_n =
    sizeof(ubiq_platform_algorithms) / sizeof(*ubiq_platform_algorithms);

int
ubiq_platform_algorithm_get_byid(
    const unsigned int i,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -EINVAL;
    if (i < ubiq_platform_algorithms_n) {
        *algo = &ubiq_platform_algorithms[i];
        err = 0;
    }

    return err;
}

int
ubiq_platform_algorithm_get_byname(
    const char * const name,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -ENOENT;
    for (unsigned int i = 0; i < ubiq_platform_algorithms_n; i++) {
        if (strcasecmp(ubiq_platform_algorithms[i].name, name) == 0) {
            *algo = &ubiq_platform_algorithms[i];
            err = 0;
            break;
        }
    }

    return err;
}
