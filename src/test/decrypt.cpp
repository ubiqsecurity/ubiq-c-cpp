#include <gtest/gtest.h>

#include <cstring>

#include "ubiq/platform.h"

class cpp_decrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    void encrypt_decrypt(const std::string &);

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

void
cpp_decrypt::encrypt_decrypt(
    const std::string & pt)
{
    std::vector<std::uint8_t> ct, rec;

    /* encrypt the data */
    ASSERT_NO_THROW(
        ct = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));

    /* decrypt the data */
    ASSERT_NO_THROW(
        rec = ubiq::platform::decrypt(_creds, ct.data(), ct.size()));

    /* verify that the recovered data matches the plain text */
    ASSERT_EQ(pt.size(), rec.size());
    EXPECT_EQ(0, std::memcmp(pt.data(), rec.data(), pt.size()));

    /*
     * flip the last byte of the cipher text (should be part of the tag),
     * and verify that an exception is thrown.
     */
    ct[ct.size() - 1] = ~ct[ct.size() - 1];
    ASSERT_ANY_THROW(
        ubiq::platform::decrypt(_creds, ct.data(), ct.size()));
}

TEST_F(cpp_decrypt, simple)
{
    encrypt_decrypt(std::string("ABC"));
}

TEST_F(cpp_decrypt, aes_block_size)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOP"));
}

TEST_F(cpp_decrypt, aes_block_size_2xm1)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ01234"));
}

TEST_F(cpp_decrypt, aes_block_size_2x)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
}

TEST_F(cpp_decrypt, aes_block_size_2xp1)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"));
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
