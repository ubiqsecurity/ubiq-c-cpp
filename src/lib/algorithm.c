#include "ubiq/platform/internal/algorithm.h"
#include "ubiq/platform.h"

#include <string.h>
#include <errno.h>

static
struct ubiq_platform_algorithm *
ubiq_platform_algorithms = NULL;
static
size_t
ubiq_platform_algorithms_n = 0;

/*
 * maps the openssl ciphers to the numeric id's that are
 * used in the ubiq headers to identify them.
 */
int
ubiq_platform_algorithm_init(
    void)
{
    const struct ubiq_platform_algorithm algos[] = {
        { .cipher = EVP_aes_256_gcm(), .taglen = 16 },
        { .cipher = EVP_aes_128_gcm(), .taglen = 16 },
    };

    int err;

    err = -ENOMEM;
    ubiq_platform_algorithms = malloc(sizeof(algos));
    if (ubiq_platform_algorithms) {
        ubiq_platform_algorithms_n = sizeof(algos) / sizeof(*algos);

        for (unsigned int i = 0; i < ubiq_platform_algorithms_n; i++) {
            ubiq_platform_algorithms[i] = algos[i];
            ubiq_platform_algorithms[i].id = i;
        }

        err = 0;
    }

    return err;
}

void
ubiq_platform_algorithm_exit(
    void)
{
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
ubiq_platform_algorithm_get_bycipher(
    const EVP_CIPHER * const c,
    const struct ubiq_platform_algorithm ** const algo)
{
    int err;

    err = -EAGAIN;
    if (ubiq_platform_algorithms_n > 0) {
        err = -EINVAL;
        for (unsigned int i = 0; i < ubiq_platform_algorithms_n; i++) {
            if (ubiq_platform_algorithms[i].cipher == c) {
                *algo = &ubiq_platform_algorithms[i];

                err = 0;
                break;
            }
        }
    }

    return err;
}
