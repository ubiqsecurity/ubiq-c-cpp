#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"

int ubiq_platform_init(void)
{
    if (!ubiq_support_user_agent) {
        ubiq_support_product = UBIQ_PRODUCT;
        ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
        ubiq_support_version = UBIQ_VERSION;
    }

    return ubiq_support_http_init();
}

void ubiq_platform_exit(void)
{
    ubiq_support_http_exit();
}
