#include <gtest/gtest.h>
#include <unistr.h>
#include <uniwidth.h>
#include <chrono>

#include "ubiq/platform.h"
#include <ubiq/platform/internal/credentials.h>

class cpp_fpe_encrypt_2 : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::fpe::encryption _enc;
    ubiq::platform::fpe::decryption _dec;
};

void cpp_fpe_encrypt_2::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_fpe_encrypt_2::TearDown(void)
{
}

TEST_F(cpp_fpe_encrypt_2, none)
{
  ASSERT_NO_THROW(
      _enc = ubiq::platform::fpe::encryption(_creds));
}



TEST_F(cpp_fpe_encrypt_2, bulk)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::string ct, ct2;

  _enc = ubiq::platform::fpe::encryption(_creds);
  ASSERT_NO_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  ASSERT_NO_THROW(
      ct2 = _enc.encrypt(ffs_name, std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct, ct2);
}

TEST_F(cpp_fpe_encrypt_2, bulk_search)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::vector<std::string> ct, ct2;

  _enc = ubiq::platform::fpe::encryption(_creds);
  _dec = ubiq::platform::fpe::decryption(_creds);
  ASSERT_NO_THROW(
      ct = _enc.encrypt_for_search(ffs_name, pt));

  ASSERT_NO_THROW(
      ct2 = _enc.encrypt_for_search(ffs_name, std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct, ct2);

  for (auto x : ct) {
    std::string ptbuf = _dec.decrypt(ffs_name, x);
    EXPECT_EQ(pt, ptbuf);
  }
}

TEST_F(cpp_fpe_encrypt_2, invalid_ffs)
{
  std::string pt("ABCDEFGHI");
  std::string ct;

  _enc = ubiq::platform::fpe::encryption(_creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt("ERROR FFS", pt));

  _dec = ubiq::platform::fpe::decryption(_creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt("ERROR FFS", pt));
}

TEST_F(cpp_fpe_encrypt_2, invalid_creds)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("ABCDEFGHI");
  std::string ct;

  ubiq::platform::credentials creds("a","b","c", "d");

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));
}

TEST_F(cpp_fpe_encrypt_2, invalid_PT_CT)
{
  std::string ffs_name("SSN");
  std::string pt(" 123456789$");
  std::string ct;


  _enc = ubiq::platform::fpe::encryption(_creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(_creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));
}

TEST_F(cpp_fpe_encrypt_2, invalid_LEN)
{
  std::string ffs_name("SSN");
  std::string shortpt(" 1234");
  std::string longpt(" 12345678901234567890");
  std::string ct;


  _enc = ubiq::platform::fpe::encryption(_creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, shortpt));
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, longpt));

 // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(_creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, shortpt));
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, longpt));
}

TEST_F(cpp_fpe_encrypt_2, invalid_specific_creds)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("123456789");
  std::string ct;

  ubiq::platform::credentials creds
  (
    std::string(ubiq_platform_credentials_get_papi(&(*_creds))).substr(1),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    ubiq_platform_credentials_get_host(&(*_creds)));

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    std::string(ubiq_platform_credentials_get_sapi(&(*_creds))).substr(1),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    ubiq_platform_credentials_get_host(&(*_creds)));

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    std::string(ubiq_platform_credentials_get_srsa(&(*_creds))).substr(1),
    ubiq_platform_credentials_get_host(&(*_creds)));

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  // Will add https prefix so error is different than others
  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    "pi.ubiqsecurity.com");

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  // won't recognize properly so url will different
  // an actually throw an exception

  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    "ps://api.ubiqsecurity.com");

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  // Completely wrong URL but a valid one
  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    "https://google.com");

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

}

TEST_F(cpp_fpe_encrypt_2, invalid_keynum)
{
  std::string ffs_name("SSN");
  std::string pt("0123456789");
  std::string ct;


  _enc = ubiq::platform::fpe::encryption(_creds);
  ASSERT_NO_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  ct[0] = '}';
  _dec = ubiq::platform::fpe::decryption(_creds);
  ASSERT_ANY_THROW(
      pt = _dec.decrypt(ffs_name, ct));
}

TEST(c_fpe_encrypt_2, piecewise)
{
    static const char * const pt = ";0123456-789ABCDEF|";
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

TEST(c_fpe_encrypt_2, piecewise_search)
{
    static const char * const pt = ";0123456-789ABCDEF|";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char ** ctbuf(nullptr);
    size_t ctcount(0);
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data_for_search(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    for (int i = 0; i < ctcount; i++) {
      char * ptbuf = NULL;
      size_t ptlen = 0;
      EXPECT_EQ(u8_width((uint8_t *)pt, strlen(pt),""), u8_width((uint8_t *)ctbuf[i], strlen(ctbuf[i]), ""));

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_fpe_decrypt_data(enc,
         ffs_name, NULL, 0, ctbuf[i], strlen(ctbuf[i]), &ptbuf, &ptlen);
      EXPECT_EQ(res, 0);

      EXPECT_EQ(strcmp(pt, ptbuf),0);
      free(ptbuf);
    }


    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    for (int i = 0; i < ctcount; i++) {
      free(ctbuf[i]);
    }
    free(ctbuf);
}

TEST(c_fpe_encrypt_2, 10_cycles)
{
    static const char * const pt = ";0123456-789ABCDEF|";
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


TEST(c_fpe_encrypt_2, error_handling_null_object)
{
  int err_num;
  char * err_msg = NULL;
  int res;

  res = ubiq_platform_fpe_get_last_error(NULL, &err_num, &err_msg);
  ASSERT_EQ(res, -EINVAL);

}

TEST(c_fpe_encrypt_2, error_handling_notnull_object)
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

    res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    ASSERT_EQ(res, 0);
    EXPECT_EQ(err_num, 0);
    EXPECT_TRUE(err_msg == NULL);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);
    free(err_msg);

}

TEST(c_fpe_encrypt_2, error_handling_invalid_ffs)
{

  static const char * const pt = ";0123456-789ABCDEF|";
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
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use same PT as CT for decrypt.  Should fail the same way
  res = ubiq_platform_fpe_decrypt_data(enc,
     "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  ubiq_platform_fpe_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);

}

TEST(c_fpe_encrypt_2, error_handling_invalid_creds)
{

  static const char * const pt = ";0123456-789ABCDEF|";
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
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use same PT as CT, should faild the same way
  res = ubiq_platform_fpe_decrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  ubiq_platform_fpe_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
}

TEST(c_fpe_encrypt_2, error_handling_invalid_PT_CT)
{

  static const char * const pt = " 123456789$";
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
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use same PT as invalid CT.  Should fail similarly
  res = ubiq_platform_fpe_decrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);


  ubiq_platform_fpe_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
}

TEST(c_fpe_encrypt_2, error_handling_invalid_LEN)
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
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  res = ubiq_platform_fpe_encrypt_data(enc,
    ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use PT as CT for decrypt.  Should fail the same way
  res = ubiq_platform_fpe_decrypt_data(enc,
    ffs_name, NULL, 0, short_pt, strlen(short_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  res = ubiq_platform_fpe_decrypt_data(enc,
    ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  ubiq_platform_fpe_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);

}


TEST(c_fpe_encrypt_2, error_handling_invalid_papi)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * err_msg = NULL;
    int err_num;
    int res = 0;

    res = ubiq_platform_credentials_create(&creds_orig);
    ASSERT_EQ(res, 0);

    // Alter the original credential value
    char * tmp_papi = strdup(ubiq_platform_credentials_get_papi(creds_orig));
    ASSERT_NE(tmp_papi, (char *)NULL);
    tmp_papi[strlen(tmp_papi) - 2] = '\0';

    res = ubiq_platform_credentials_create_explicit(
      tmp_papi,
      ubiq_platform_credentials_get_sapi(creds_orig),
      ubiq_platform_credentials_get_srsa(creds_orig),
      ubiq_platform_credentials_get_host(creds_orig),
      &creds
    );
    free(tmp_papi);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}

TEST(c_fpe_encrypt_2, error_handling_invalid_sapi)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * err_msg = NULL;
    int err_num;
    int res = 0;

    res = ubiq_platform_credentials_create(&creds_orig);
    ASSERT_EQ(res, 0);

    // Alter the original credential value
    char * tmp = strdup(ubiq_platform_credentials_get_sapi(creds_orig));
    ASSERT_NE(tmp, (char *)NULL);
    tmp[strlen(tmp) - 2] = '\0';

    res = ubiq_platform_credentials_create_explicit(
      ubiq_platform_credentials_get_papi(creds_orig),
      tmp,
      ubiq_platform_credentials_get_srsa(creds_orig),
      ubiq_platform_credentials_get_host(creds_orig),
      &creds
    );
    free(tmp);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);


    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}

TEST(c_fpe_encrypt_2, error_handling_invalid_rsa)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * err_msg = NULL;
    int err_num;
    int res = 0;

    res = ubiq_platform_credentials_create(&creds_orig);
    ASSERT_EQ(res, 0);

    // Alter the original credential value
    char * tmp = strdup(ubiq_platform_credentials_get_srsa(creds_orig));
    ASSERT_NE(tmp, (char *)NULL);
    tmp[strlen(tmp) - 2] = '\0';

    res = ubiq_platform_credentials_create_explicit(
      ubiq_platform_credentials_get_papi(creds_orig),
      ubiq_platform_credentials_get_sapi(creds_orig),
      tmp,
      ubiq_platform_credentials_get_host(creds_orig),
      &creds
    );
    free(tmp);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}

TEST(c_fpe_encrypt_2, error_handling_invalid_host)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * err_msg = NULL;
    int err_num;
    int res = 0;

    res = ubiq_platform_credentials_create(&creds_orig);
    ASSERT_EQ(res, 0);

    // Alter the original credential value
    char * tmp = strdup(ubiq_platform_credentials_get_host(creds_orig));
    ASSERT_NE(tmp, (char *)NULL);
    tmp[strlen(tmp) - 2] = '\0';

    res = ubiq_platform_credentials_create_explicit(
      ubiq_platform_credentials_get_papi(creds_orig),
      ubiq_platform_credentials_get_sapi(creds_orig),
      ubiq_platform_credentials_get_srsa(creds_orig),
      tmp,
      &creds
    );
    free(tmp);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}


TEST(c_fpe_encrypt_2, error_handling_invalid_keynum)
{

  static const char * const pt = "0123456789";
  static const char * const ffs_name = "SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_fpe_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  char * ptbuf(nullptr);
  size_t ptlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  // Encrypt should be fine
  res = ubiq_platform_fpe_encrypt_data(enc,
     ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_EQ(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_EQ(err_num, 0);
  EXPECT_TRUE(err_msg == NULL);
  free(err_msg);

  ctbuf[0] = '}'; // Invalid character for encoded key material

  res = ubiq_platform_fpe_decrypt_data(enc,
    ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
  EXPECT_NE(res, 0);
  ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);
  free(ptbuf);

  ubiq_platform_fpe_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);

}


TEST_F(cpp_fpe_encrypt_2, 1m)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::string ct, ct2;
  std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();

  _enc = ubiq::platform::fpe::encryption(_creds);


    ct = _enc.encrypt(ffs_name, pt);

    for (unsigned long i = 0; i < 10; i++) {
        auto start = std::chrono::steady_clock::now();

        ct = _enc.encrypt(ffs_name, pt);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }


    std::cerr << "\tSelect total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_fpe_encrypt_2, new)
{
    static const char * const pt = ";0123456-789ABCDEF|";
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



TEST(c_fpe_encrypt_2, prealloc)
{
    static const char * const pt = ";0123456-789ABCDEF|";
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

    // CTBUF has been allocated
    char ct_alloc[50];
    size_t len = 50;

    res = ubiq_platform_fpe_encrypt_data_prealloc(enc,
      ffs_name, NULL, 0, pt, strlen(pt), ct_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), len);
    EXPECT_EQ(strcmp(ctbuf, ct_alloc),0);

    len = strlen(pt);
    res = ubiq_platform_fpe_encrypt_data_prealloc(enc,
      ffs_name, NULL, 0, pt, strlen(pt), ct_alloc, &len);
    EXPECT_NE(res, 0);
    EXPECT_EQ(strlen(pt) + 1, len);

    // len should be correct from prior call (includes null terminator)
    res = ubiq_platform_fpe_encrypt_data_prealloc(enc,
      ffs_name, NULL, 0, pt, strlen(pt), ct_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), len);
    EXPECT_EQ(strcmp(ctbuf, ct_alloc),0);


    char pt_alloc[50];
    len = sizeof(pt_alloc);

    res = ubiq_platform_fpe_decrypt_data_prealloc(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, pt_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(ctbuf), len);
    EXPECT_EQ(strcmp(pt, pt_alloc),0);

    len = strlen(ctbuf);
    res = ubiq_platform_fpe_decrypt_data_prealloc(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, pt_alloc, &len);
    EXPECT_NE(res, 0);
    EXPECT_EQ(strlen(ctbuf) + 1, len);

    // len should be correct from prior call (includes null terminator)
    res = ubiq_platform_fpe_decrypt_data_prealloc(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, pt_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), len);
    EXPECT_EQ(strcmp(ctbuf, ct_alloc),0);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}


TEST(c_fpe_encrypt_2, prealloc_complex)
{
    static const char * const pt = "abcdefghijklmnop";
    static const char * const ffs_name = "UTF8_STRING_COMPLEX";

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
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ctbuf, strlen(ctbuf) ));

    // CTBUF has been allocated
    char ct_alloc[50];
    size_t len = 50;

    res = ubiq_platform_fpe_encrypt_data_prealloc(enc,
      ffs_name, NULL, 0, pt, strlen(pt), ct_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ct_alloc, strlen(ct_alloc) ));
    EXPECT_EQ(strcmp(ctbuf, ct_alloc),0);

    len--; // Force buffer to small failure
    res = ubiq_platform_fpe_encrypt_data_prealloc(enc,
      ffs_name, NULL, 0, pt, strlen(pt), ct_alloc, &len);
    EXPECT_NE(res, 0);

    // len should be right size from prior call
    res = ubiq_platform_fpe_encrypt_data_prealloc(enc,
      ffs_name, NULL, 0, pt, strlen(pt), ct_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ct_alloc, strlen(ct_alloc) ));
    EXPECT_EQ(strcmp(ctbuf, ct_alloc),0);


    char pt_alloc[50];
    len = sizeof(pt_alloc);

    res = ubiq_platform_fpe_decrypt_data_prealloc(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, pt_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt_alloc, strlen(pt_alloc)), u8_mbsnlen((uint8_t *)ct_alloc, strlen(ct_alloc) ));
    EXPECT_EQ(strcmp(pt, pt_alloc),0);

    len--;
    res = ubiq_platform_fpe_decrypt_data_prealloc(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, pt_alloc, &len);
    EXPECT_NE(res, 0);

    res = ubiq_platform_fpe_decrypt_data_prealloc(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, pt_alloc, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt_alloc, strlen(pt_alloc)), u8_mbsnlen((uint8_t *)ct_alloc, strlen(ct_alloc) ));
    EXPECT_EQ(strcmp(ctbuf, ct_alloc),0);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}
