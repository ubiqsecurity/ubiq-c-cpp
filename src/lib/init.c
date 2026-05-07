#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;


static int library_init = 0;

int ubiq_platform_initialized(void) 
{
  return (1 == library_init);
}


int ubiq_platform_init(void)
{
    static const char * csu = "ubiq_platform_init";
    UBIQ_DEBUG(debug_flag, printf("%s: start library_init(%d)\n", csu, library_init));

    int ret = -EALREADY;
    if (!ubiq_support_user_agent) {
        ubiq_support_product = UBIQ_PRODUCT;
        ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
        ubiq_support_version = UBIQ_VERSION;
    }
    if (!ubiq_platform_initialized()) {
      UBIQ_DEBUG(debug_flag, printf("%s: start !ubiq_platform_initialized(%d)\n", csu));
      library_init = 1;
      ret = ubiq_support_http_init();
    }
    setenv("TZ", "UTC", 0);
    UBIQ_DEBUG(debug_flag, printf("%s: end library_init(%d) res(%d)\n", csu, library_init, ret));

    return ret;
}

void ubiq_platform_exit(void)
{
    static const char * csu = "ubiq_platform_exit";
    UBIQ_DEBUG(debug_flag, printf("%s: start library_init(%d)\n", csu, library_init));

    library_init = 0;
    ubiq_support_http_exit();
    UBIQ_DEBUG(debug_flag, printf("%s: end library_init(%d)\n", csu, library_init));
}

