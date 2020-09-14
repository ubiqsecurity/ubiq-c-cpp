#include <gtest/gtest.h>

#include "ubiq/platform.h"

TEST(c_credentials, automatic)
{
    struct ubiq_platform_credentials * creds;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        ASSERT_NE(creds, nullptr);

        ubiq_platform_credentials_destroy(creds);
    }
}
