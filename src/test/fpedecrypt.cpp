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
        ct = ubiq::platform::fpe::encrypt(_creds, ffsname, pt));

    /* decrypt the data */
    ASSERT_NO_THROW(
        rec = ubiq::platform::fpe::decrypt(_creds, ffsname,  ct));

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
    encrypt_decrypt("ALPHANUM_SSN", "0123456789");
}

TEST_F(cpp_fpe_decrypt, bulk)
{
    encrypt_decrypt_bulk("ALPHANUM_SSN", "0123456789");
}



TEST(c_fpe_decrypt, piecewise_bad_char)
{

    char pt [] = "!!= J*K-42c(";
    static const char * const ffs_name = "ALPHANUM_SSN";

    pt[1] = 124;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, -EINVAL);
    if (res) {
      int err_num;
      char * err_msg = NULL;

      res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
      printf("error: %s\n", err_msg);
      free(err_msg);
    }

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
}


TEST(c_fpe_decrypt, piecewise_too_short)
{

    char pt [] = "!!!";
    static const char * const ffs_name = "ALPHANUM_SSN";


    struct ubiq_platform_credentials * creds(nullptr);
    struct ubiq_platform_fpe_enc_dec_obj *enc(nullptr);
    char * ctbuf(nullptr);
    size_t ctlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, -EINVAL);
    if (res) {
      int err_num;
      char * err_msg = NULL;

      res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
      printf("error: %s\n", err_msg);
      free(err_msg);
    }

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
}


TEST(c_fpe_decrypt, piecewise_all_zeroth)
{

    char pt [] = "!!!!!!!!!!!!!!!!!!";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
}

TEST(c_fpe_decrypt, piecewise_all_passthrough)
{

    char pt [] = "--------------------";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, -EINVAL);
    if (res) {
      int err_num;
      char * err_msg = NULL;

      res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
      printf("error: %s\n", err_msg);
      free(err_msg);
    }

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
}

TEST(c_fpe_decrypt, piecewise_leading_passthrough)
{

    char pt [] = "------------12-45-6789---------------";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    if (res) {
      int err_num;
      char * err_msg = NULL;

      res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
      printf("error: %s\n", err_msg);
      free(err_msg);
    } else {
        EXPECT_EQ(strlen(pt), ctlen);
    }

    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0,ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_decrypt, add_user_defined_metadata)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    struct ubiq_platform_fpe_enc_dec_obj *dec;
    char * buf(nullptr);
    char * ctbuf(nullptr);
    size_t ctlen;
    size_t len;

    int res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &dec);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_add_user_defined_metadata(NULL, NULL);
    EXPECT_NE(res, 0);

    char toolong[1050];
    memset(toolong, 'a', sizeof(toolong));
    toolong[sizeof(toolong)] = '\0';
    res = ubiq_platform_fpe_enc_dec_add_user_defined_metadata(dec, toolong);
    EXPECT_NE(res, 0);

    res = ubiq_platform_fpe_enc_dec_add_user_defined_metadata(dec, "not json");
    EXPECT_NE(res, 0);

    res = ubiq_platform_fpe_enc_dec_add_user_defined_metadata(dec, "{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}");
    EXPECT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res,0);

    res = ubiq_platform_fpe_decrypt_data(dec,
      ffs_name, NULL, 0, ctbuf, ctlen, &buf, &len);
    EXPECT_EQ(res,0);
    free(buf);

    // decrypt will have meta data
    res = ubiq_platform_fpe_enc_dec_get_copy_of_usage(dec, &buf, &len);
    EXPECT_EQ(res,0);
    EXPECT_NE(strcmp(buf, "{\"usage\":[]}"), 0);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_KEY"), nullptr);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_VALUE"), nullptr);
    EXPECT_NE(strstr(buf, "user_defined"), nullptr);
    
    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_fpe_enc_dec_destroy(dec);

    ubiq_platform_credentials_destroy(creds);
    free(buf);
    free(ctbuf);
}

TEST_F(cpp_fpe_decrypt, add_user_defined_metadata)
{
  std::string pt(";0123456-789ABCDEF|");
  std::string ffs_name("ALPHANUM_SSN");

  ubiq::platform::fpe::encryption enc = ubiq::platform::fpe::encryption(_creds);
  _dec = ubiq::platform::fpe::decryption(_creds);

  ASSERT_THROW(_dec.add_user_defined_metadata(""),std::system_error);
  ASSERT_THROW(_dec.add_user_defined_metadata("{"),std::system_error);
  ASSERT_NO_THROW(_dec.add_user_defined_metadata("{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}"));

  std::string ct = enc.encrypt(ffs_name, pt);
  std::string tmp = _dec.decrypt(ffs_name, ct);

  std::string usage = _dec.get_copy_of_usage();

  EXPECT_EQ(usage.find("{\"usage\":[]}"),  std::string::npos);
  EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_KEY"),  std::string::npos);
  EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_VALUE"),  std::string::npos);
  EXPECT_NE(usage.find("user_defined"),  std::string::npos);

}