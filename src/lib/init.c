#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/request.h"

int ubiq_platform_init(void)
{
    int err;

    err = ubiq_platform_algorithm_init();
    if (!err) {
        err = ubiq_platform_http_init(UBIQ_PLATFORM_USER_AGENT);
        if (err) {
            ubiq_platform_algorithm_exit();
        }
    }

    return err;
}

void ubiq_platform_exit(void)
{
    ubiq_platform_http_exit();
    ubiq_platform_algorithm_exit();
}
