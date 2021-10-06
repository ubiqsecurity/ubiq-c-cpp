#include <gtest/gtest.h>

#include "ubiq/platform.h"

class cpp_fpe_encrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::fpe::encryption _enc;
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
        _enc = ubiq::platform::fpe::encryption(_creds));
}

TEST_F(cpp_fpe_encrypt, simple)
{
    std::string pt("ABCDEFGHI");
    std::string ct, ct2;

    ASSERT_NO_THROW(
        ct = ubiq::platform::fpe::encrypt(_creds, "ALPHANUM_SSN", pt));

    ASSERT_NO_THROW(
        ct2 = ubiq::platform::fpe::encrypt(_creds, "ALPHANUM_SSN", std::vector<std::uint8_t>(), pt));

    EXPECT_EQ(ct, ct2);
}

TEST_F(cpp_fpe_encrypt, bulk)
{
    std::string pt("ABCDEFGHI");
    std::string ct, ct2;

    _enc = ubiq::platform::fpe::encryption(_creds);
    ASSERT_NO_THROW(
        ct = _enc.encrypt("ALPHANUM_SSN", pt));

    ASSERT_NO_THROW(
        ct2 = _enc.encrypt("ALPHANUM_SSN", std::vector<std::uint8_t>(), pt));

    EXPECT_EQ(ct, ct2);
}

TEST(c_fpe_encrypt, simple)
{
    static const char * const pt = " 01121231231231231& 1 &2311200 ";
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
    static const char * const pt = " 01121231231231231& 1 &2311200 ";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
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

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
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

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf2);
    free(ctbuf);
    free(ptbuf);
    free(ptbuf2);
}

TEST(c_fpe_encrypt, mixed_forward)
{
    static const char * const pt = " 01121231231231231& 1 &2311200 ";
//    static const char * const pt = "00001234567890";//234567890";
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

    res = ubiq_platform_fpe_encrypt(creds,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strlen(pt), ptlen);
    EXPECT_EQ(ptlen, ctlen);
    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_encrypt, mixed_backwards)
{
    static const char * const pt = " 01121231231231231& 1 &2311200 ";
//    static const char * const pt = "00001234567890";//234567890";
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
    EXPECT_EQ(strlen(pt), ctlen);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    res = ubiq_platform_fpe_decrypt(creds,
      ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(ptlen, ctlen);
    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_encrypt, 10_cycles)
{
    static const char * const pt = " 01121231231231231& 1 &2311200 ";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    for (int i = 0; i < 10; i++) {
      char * ctbuf(nullptr);
      size_t ctlen;
      char * ptbuf(nullptr);
      size_t ptlen;

      res = ubiq_platform_fpe_encrypt_data(enc,
        ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strlen(pt), ctlen);

      res = ubiq_platform_fpe_decrypt_data(enc,
         ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
      EXPECT_EQ(res, 0);

      EXPECT_EQ(ptlen, ctlen);
      EXPECT_EQ(strcmp(pt, ptbuf),0);
      free(ctbuf);
      free(ptbuf);
    }
    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);

}


TEST(c_fpe_encrypt, generic)
{
    static const char * const pt = " 1234567890ABCDEFGHIJKLMNOP";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "GENERIC_STRING";

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

TEST(c_fpe_encrypt, errmsg_null_object)
{
  int err_num;
  char * err_msg = NULL;
  int res;

  res = ubiq_platform_fpe_last_error(NULL, &err_num, &err_msg);
  ASSERT_EQ(res, -EINVAL);

}

TEST(c_fpe_encrypt, errmsg_notnull_object)
{
  int err_num;
  char * err_msg = NULL;
  int res;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj * enc;
    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_last_error(enc, &err_num, &err_msg);
    ASSERT_EQ(res, 0);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

}

TEST(c_fpe_encrypt, error_handling_invalid_ffs)
{

  static const char * const pt = " 01121231231231231& 1 &2311200 ";
  static const char * const ffs_name = "ALPHANUM_SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_fpe_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_encrypt_data(enc,
     "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  printf("error message %d %d %s\n",res, err_num, err_msg);

  ubiq_platform_fpe_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
  free(err_msg);
}

TEST(c_fpe_encrypt, error_handling_invalid_creds)
{

  static const char * const pt = " 01121231231231231& 1 &2311200 ";
  static const char * const ffs_name = "ALPHANUM_SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_fpe_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create_explicit(
      "invalid1", "invalid2",
      "invalid3",
      "https://koala.ubiqsecurity.com",
      &creds);

  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_encrypt_data(enc,
    "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  printf("error message %d %d %s\n",res, err_num, err_msg);

  ubiq_platform_fpe_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
  free(err_msg);
}

TEST(c_fpe_encrypt, error_handling_invalid_PT)
{

  static const char * const pt = " 123p";
  static const char * const ffs_name = "SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_fpe_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_encrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  printf("error message %d %d %s\n",res, err_num, err_msg);

  ubiq_platform_fpe_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
  free(err_msg);
}

TEST(c_fpe_encrypt, error_handling_invalid_PT_LEN)
{

  static const char * const short_pt = " 123";
  static const char * const long_pt = " 1234567890123123123123";
  static const char * const ffs_name = "SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_fpe_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_encrypt_data(enc,
    ffs_name, NULL, 0, short_pt, strlen(short_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  printf("error message %d %d %s\n",res, err_num, err_msg);

  res = ubiq_platform_fpe_encrypt_data(enc,
    ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  printf("error message %d %d %s\n",res, err_num, err_msg);

  ubiq_platform_fpe_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
  free(err_msg);
}
