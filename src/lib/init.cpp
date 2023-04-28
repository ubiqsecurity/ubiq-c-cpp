#include "ubiq/platform.h"
#include "ubiq/platform/internal/support.h"

#include <stdexcept>

void ubiq::platform::init(void)
{
    /*
     * override the name set by the C initialization function
     * defined as a compiler parameter in CMakeLists.txt
     */
    if (!ubiq_support_user_agent) {
        ubiq_support_user_agent = UBIQ_PLATFORM_USER_AGENT;
        ubiq_support_product = UBIQ_PRODUCT;
        ubiq_support_version = UBIQ_VERSION;
    }

    if (ubiq_platform_init() != 0) {
        throw std::runtime_error("platform initialization failed");
    }

}

void ubiq::platform::exit(void)
{
    ubiq_platform_exit();
}
