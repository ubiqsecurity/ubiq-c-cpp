#include <gtest/gtest.h>

#include <cstring>

#include "ubiq/platform.h"

class cpp_fpe_decrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    void encrypt_decrypt(const std::string & ffsname, const std::string &pt);

    void encrypt_decrypt_bulk(
        const std::string & ffsname,
        const std::string & pt);

    ubiq::platform::credentials _creds;
    ubiq::platform::fpe::decryption _dec;
};

void cpp_fpe_decrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_fpe_decrypt::TearDown(void)
{
}

TEST_F(cpp_fpe_decrypt, none)
{
    ASSERT_NO_THROW(
        _dec = ubiq::platform::fpe::decryption(_creds));
}

void
cpp_fpe_decrypt::encrypt_decrypt(
    const std::string & ffsname,
    const std::string & pt)
{
    std::string ct, rec;

    /* encrypt the data */
    ASSERT_NO_THROW(
        ct = ubiq::platform::fpe_encrypt(_creds, ffsname, pt));

    /* decrypt the data */
    ASSERT_NO_THROW(
        rec = ubiq::platform::fpe_decrypt(_creds, ffsname,  ct));

    /* verify that the recovered data matches the plain text */
    ASSERT_EQ(pt.size(), rec.size());
    EXPECT_EQ(0, std::memcmp(pt.data(), rec.data(), pt.size()));

}

void
cpp_fpe_decrypt::encrypt_decrypt_bulk(
    const std::string & ffsname,
    const std::string & pt)
{
    std::string ct, rec, ct2, pt2;
    ubiq::platform::fpe::decryption dec;
    ubiq::platform::fpe::encryption enc;
    std::vector<std::uint8_t> tweak;

    enc =  ubiq::platform::fpe::encryption(_creds);
    dec =  ubiq::platform::fpe::decryption(_creds);

    /* encrypt the data */
    ASSERT_NO_THROW(
        ct = enc.encrypt(ffsname, pt));

    ASSERT_EQ(ct.size(), pt.size());

    ASSERT_NO_THROW(
        ct2 = enc.encrypt(ffsname, tweak, pt));

    ASSERT_EQ(ct.size(), ct2.size());
    EXPECT_EQ(0, std::memcmp(ct.data(), ct2.data(), ct.size()));

    /* decrypt the data */
    ASSERT_NO_THROW(
        rec = dec.decrypt( ffsname, ct));

    /* verify that the recovered data matches the plain text */
    ASSERT_EQ(pt.size(), rec.size());
    EXPECT_EQ(0, std::memcmp(pt.data(), rec.data(), pt.size()));

    ASSERT_NO_THROW(
        pt2 = dec.decrypt( ffsname, tweak, ct));

    ASSERT_EQ(pt2.size(), rec.size());
    EXPECT_EQ(0, std::memcmp(pt2.data(), rec.data(), pt2.size()));
}


TEST_F(cpp_fpe_decrypt, simple)
{
    encrypt_decrypt("ALPHANUM_SSN", "123 456 789");
}

TEST_F(cpp_fpe_decrypt, bulk)
{
    encrypt_decrypt_bulk("ALPHANUM_SSN", "123 456 789");
}


TEST_F(cpp_fpe_decrypt, bulk_generic_string)
{
    encrypt_decrypt_bulk("GENERIC_STRING", "1234567890ABCDEFGHIJKLMNOP");
}
