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

TEST_F(cpp_encrypt, get_usage)
{
    std::string usage;
    std::string pt("ABC");
    _enc = ubiq::platform::encryption(_creds, 1);

    ASSERT_NO_THROW(
        usage = _enc.get_copy_of_usage());

    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::vector<uint8_t> pre = _enc.begin();
    std::vector<uint8_t> mid = _enc.update(pt.data(), pt.size());
    std::vector<uint8_t> post = _enc.end();

    usage = _enc.get_copy_of_usage();

    EXPECT_NE(usage.compare("{\"usage\":[]}"), 0);

}



TEST(c_encrypt, simple)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    void * ctbuf = NULL;
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
