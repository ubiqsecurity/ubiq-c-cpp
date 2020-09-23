#include "ubiq/platform.h"
#include "ubiq/platform/internal/request.h"

#include <stdexcept>

void ubiq::platform::init(void)
{
    if (ubiq_platform_init() != 0) {
        throw std::runtime_error("platform initialization failed");
    }

    /*
     * override the name set by the C initialization function
     *
     * defined as a compiler parameter in CMakeLists.txt
     */
    ubiq_platform_user_agent = UBIQ_PLATFORM_USER_AGENT;
}

void ubiq::platform::exit(void)
{
    ubiq_platform_exit();
}
