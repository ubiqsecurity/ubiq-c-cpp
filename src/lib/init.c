#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"

int ubiq_platform_init(void)
{
    int err;

    err = ubiq_platform_algorithm_init();
    if (!err) {
        ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
        err = ubiq_support_http_init();
        if (err) {
            ubiq_platform_algorithm_exit();
        }
    }

    return err;
}

void ubiq_platform_exit(void)
{
    ubiq_support_http_exit();
    ubiq_platform_algorithm_exit();
}
