#include <ubiq/platform/internal/algorithm.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

static struct ubiq_platform_algorithm * ubiq_platform_algorithms = NULL;
static size_t ubiq_platform_algorithms_n = 0;

/*
 * maps the openssl ciphers to the numeric id's that are
 * used in the ubiq headers to identify them.
 */
int
ubiq_platform_algorithm_init(
    void)
{
    const struct ubiq_platform_algorithm algos[] = {
        {
            .id = 0,
            .name = "aes-256-gcm",
            .len = { .key = 32, .iv = 12, .tag = 16 }
        }, {
            .id = 1,
            .name = "aes-128-gcm",
            .len = { .key = 16, .iv = 12, .tag = 16 }
        },
    };

    int err;

    err = -ENOMEM;
    ubiq_platform_algorithms = malloc(sizeof(algos));
    if (ubiq_platform_algorithms) {
        for (unsigned int i = 0; i < sizeof(algos) / sizeof(*algos); i++) {
            ubiq_platform_algorithms[i] = algos[i];
        }
        ubiq_platform_algorithms_n = sizeof(algos) / sizeof(*algos);
        err = 0;
    }

    return err;
}

void
ubiq_platform_algorithm_exit(
    void)
{
    ubiq_platform_algorithms_n = 0;
    free(ubiq_platform_algorithms);
}

int
ubiq_platform_algorithm_get_byid(
    const unsigned int i,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -EAGAIN;
    if (ubiq_platform_algorithms_n > 0) {
        err = -EINVAL;
        if (i < ubiq_platform_algorithms_n) {
            *algo = &ubiq_platform_algorithms[i];
            err = 0;
        }
    }

    return err;
}

int
ubiq_platform_algorithm_get_byname(
    const char * const name,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -EAGAIN;
    if (ubiq_platform_algorithms_n > 0) {
        err = -ENOENT;
        for (unsigned int i = 0; i < ubiq_platform_algorithms_n; i++) {
            if (strcasecmp(ubiq_platform_algorithms[i].name, name) == 0) {
                *algo = &ubiq_platform_algorithms[i];
                err = 0;
                break;
            }
        }
    }

    return err;
}
