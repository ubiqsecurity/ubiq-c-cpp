#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"

#include <stdexcept>

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;


void ubiq::platform::init(void)
{
    static const char * csu = "ubiq::platform::init";
    UBIQ_DEBUG(debug_flag, printf("%s: start \n", csu));
    int res = 0;
    /*
     * override the name set by the C initialization function
     * defined as a compiler parameter in CMakeLists.txt
     */
    if (!ubiq_support_user_agent) {
        ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
        ubiq_support_product = UBIQ_PRODUCT;
        ubiq_support_version = UBIQ_VERSION;
    }

    if ((res = ubiq_platform_init()) != 0) {
        UBIQ_DEBUG(debug_flag, printf("%s: throwing exception res(%d) \n", csu, res));
        throw std::runtime_error("platform initialization failed");
    }
    UBIQ_DEBUG(debug_flag, printf("%s: end \n", csu));

}

void ubiq::platform::exit(void)
{
    static const char * csu = "ubiq::platform::exit";
    UBIQ_DEBUG(debug_flag, printf("%s: start \n", csu));
    ubiq_platform_exit();
    UBIQ_DEBUG(debug_flag, printf("%s: end \n", csu));
}

void ubiq::platform::initialized(void)
{
    if (!ubiq_platform_initialized()) {
        throw std::runtime_error("platform has not been initialized");
    }
}
