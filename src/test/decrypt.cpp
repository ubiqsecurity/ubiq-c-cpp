#include <gtest/gtest.h>

#include <cstring>

#include "ubiq/platform.h"

class cpp_decrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::decryption _dec;
};

void cpp_decrypt::SetUp(void)
{
    ASSERT_NO_THROW(
        _creds = ubiq::platform::credentials(
            std::string(), "test"));
}

void cpp_decrypt::TearDown(void)
{
}

TEST_F(cpp_decrypt, none)
{
    ASSERT_NO_THROW(
        _dec = ubiq::platform::decryption(_creds));
}

TEST_F(cpp_decrypt, simple)
{
    std::string pt("ABC");
    std::vector<std::uint8_t> ct, rec;

    ASSERT_NO_THROW(
        ct = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));
    ASSERT_NO_THROW(
        rec = ubiq::platform::decrypt(_creds, ct.data(), ct.size()));

    ASSERT_EQ(pt.size(), rec.size());
    EXPECT_EQ(0, std::memcmp(pt.data(), rec.data(), pt.size()));
}

TEST(c_decrypt, simple)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    void * ctbuf, * ptbuf;
    size_t ctlen, ptlen;
    int res;

    res = ubiq_platform_credentials_create_specific(NULL, "test", &creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_encrypt(
        creds, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        res = ubiq_platform_decrypt(
            creds, ctbuf, ctlen, &ptbuf, &ptlen);

        free(ctbuf);

        EXPECT_EQ(res, 0);

        if (res == 0) {
            EXPECT_EQ(strlen(pt), ptlen);
            EXPECT_EQ(0, memcmp(pt, ptbuf, ptlen));

            free(ptbuf);
        }
    }

    ubiq_platform_credentials_destroy(creds);
}
