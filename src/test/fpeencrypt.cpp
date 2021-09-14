#include <gtest/gtest.h>

#include "ubiq/platform.h"

class cpp_fpe_encrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::encryption _enc;
};

void cpp_fpe_encrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_fpe_encrypt::TearDown(void)
{
}

TEST_F(cpp_fpe_encrypt, none)
{
    ASSERT_NO_THROW(
        _enc = ubiq::platform::encryption(_creds, 1));
}

TEST_F(cpp_fpe_encrypt, simple)
{
    std::string pt("ABC");
    std::vector<std::uint8_t> v;

    ASSERT_NO_THROW(
        v = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));
}

TEST(c_fpe_encrypt, simple)
{
    static const char * const pt = " 01121231231231231& 1 &231120001&-0-8-9";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt(creds,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt(creds,
      ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_encrypt, piecewise)
{
    static const char * const pt = " 01121231231231231& 1 &231120001&-0-8-9";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_encryption *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ctbuf2(nullptr);
    size_t ctlen2;
    char * ptbuf(nullptr);
    size_t ptlen;
    char * ptbuf2(nullptr);
    size_t ptlen2;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encryption_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf2, &ctlen2);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf2, ctlen2, &ptbuf2, &ptlen2);
    EXPECT_EQ(res, 0);
    //
    EXPECT_EQ(strcmp(pt, ptbuf),0);
    EXPECT_EQ(strcmp(pt, ptbuf2),0);

    EXPECT_EQ(ptlen, ctlen);

    ubiq_platform_fpe_encryption_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf2);
    free(ctbuf);
    free(ptbuf);
    free(ptbuf2);
}

TEST(c_fpe_encrypt, mixed_forward)
{
    static const char * const pt = " 01121231231231231& 1 &231120001&-0-8-9";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_encryption *enc;

    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt(creds,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_fpe_encryption_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strlen(pt), ptlen);
    EXPECT_EQ(ptlen, ctlen);
    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_fpe_encryption_destroy(enc);
    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_encrypt, mixed_backwards)
{
    static const char * const pt = " 01121231231231231& 1 &231120001&-0-8-9";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_encryption *enc;

    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encryption_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    ubiq_platform_fpe_encryption_destroy(enc);

    res = ubiq_platform_fpe_decrypt(creds,
      ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(ptlen, ctlen);
    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}
