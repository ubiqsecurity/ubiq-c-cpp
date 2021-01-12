#include <gtest/gtest.h>

#include "ubiq/platform.h"

class cpp_encrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::encryption _enc;
};

void cpp_encrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_encrypt::TearDown(void)
{
}

TEST_F(cpp_encrypt, none)
{
    ASSERT_NO_THROW(
        _enc = ubiq::platform::encryption(_creds, 1));
}

TEST_F(cpp_encrypt, simple)
{
    std::string pt("ABC");
    std::vector<std::uint8_t> v;

    ASSERT_NO_THROW(
        v = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));
}

TEST(c_encrypt, simple)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_encrypt(creds, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    ubiq_platform_credentials_destroy(creds);

    if (res == 0) {
        free(ctbuf);
    }
}
