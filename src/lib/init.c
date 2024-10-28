#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"
#include <errno.h>

static int library_init = 0;

int ubiq_platform_initialized(void) 
{
  return (1 == library_init);
}


int ubiq_platform_init(void)
{
    int ret = -EALREADY;
    if (!ubiq_support_user_agent) {
        ubiq_support_product = UBIQ_PRODUCT;
        ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
        ubiq_support_version = UBIQ_VERSION;
    }
    if (!ubiq_platform_initialized()) {
      library_init = 1;
      ret = ubiq_support_http_init();
    }
    return ret;
}

void ubiq_platform_exit(void)
{
    library_init = 0;
    ubiq_support_http_exit();
}

