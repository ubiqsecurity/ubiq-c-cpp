#include "ubiq/platform.h"
#include "ubiq/platform/internal/algorithm.h"
#include "ubiq/platform/internal/request.h"

#include <curl/curl.h>

int ubiq_platform_init(void)
{
    CURLcode cc;

    cc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (cc != 0) {
        return INT_MIN;
    }

    /* defined as a compiler parameter in CMakeLists.txt */
    ubiq_platform_user_agent = UBIQ_PLATFORM_USER_AGENT;

    ubiq_platform_algorithm_init();

    return 0;
}

void ubiq_platform_exit(void)
{
    ubiq_platform_algorithm_exit();

    curl_global_cleanup();
}
