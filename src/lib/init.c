#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"

int ubiq_platform_init(void)
{
    ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
    return ubiq_support_http_init();
}

void ubiq_platform_exit(void)
{
    ubiq_support_http_exit();
}
