#include <gtest/gtest.h>
#include <unistr.h>
#include <uniwidth.h>
#include <chrono>

#include "ubiq/platform.h"
#include <ubiq/platform/internal/credentials.h>

class cpp_fpe_encrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);
    void test_batch_rt(  
      const std::string &dataset_name,
      const std::string &pt,
      const std::string &expected_ct);

    void test_simple_rt(  
      const std::string &dataset_name,
      const std::string &pt,
      const std::string &expected_ct);

    void test_rt(  
      const std::string &dataset_name,
      const std::string &pt,
      const std::string &expected_ct);

    void search(  
      const std::string &dataset_name,
      const std::string &pt,
      const std::string &expected_ct);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::fpe::encryption _enc;
    ubiq::platform::fpe::decryption _dec;
};

void cpp_fpe_encrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_fpe_encrypt::TearDown(void)
{
}

void cpp_fpe_encrypt::search(
  const std::string &dataset_name,
  const std::string &pt,
  const std::string &expected_ct) {

  std::vector<std::string> ct, ct2;

  ASSERT_NO_THROW(
      ct = ubiq::platform::fpe::encrypt_for_search(_creds, dataset_name, pt));

  ASSERT_NO_THROW(
      ct2 = ubiq::platform::fpe::encrypt_for_search(_creds, dataset_name, std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct, ct2);

  // Expect that the supplied CT is found in one of the search keys - will work regardless of how many times the 
  // data has been rotated
  bool found_ct(false);
  for (auto x : ct) {
      found_ct = found_ct || (expected_ct == x);
      std::string ptbuf = ubiq::platform::fpe::decrypt(_creds, dataset_name, x);
      EXPECT_EQ(pt, ptbuf);
  }

  EXPECT_TRUE(found_ct);
}

void cpp_fpe_encrypt::test_simple_rt(
  const std::string &dataset_name,
  const std::string &pt,
  const std::string &expected_ct) {
  std::string ct;
  std::string rt;

  ASSERT_NO_THROW(
      ct = ubiq::platform::fpe::encrypt(_creds, dataset_name, pt));

  ASSERT_NO_THROW(
      rt = ubiq::platform::fpe::decrypt(_creds, dataset_name, ct));

  EXPECT_EQ(rt, pt);

  // Decrypt the expected value - will address issue when source data key has been rotated
  ASSERT_NO_THROW(
      rt = ubiq::platform::fpe::decrypt(_creds, dataset_name, expected_ct));
  EXPECT_EQ(rt, pt);

  std::vector<std::string> ct_arr, ct2_arr;
  ASSERT_NO_THROW(
      ct_arr = ubiq::platform::fpe::encrypt_for_search(_creds, dataset_name, pt));

  ASSERT_NO_THROW(
      ct2_arr = ubiq::platform::fpe::encrypt_for_search(_creds, dataset_name, std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct_arr, ct2_arr);

      // std::cout << "  pt: " << pt << std::endl;
  bool found_ct(false);
  for (auto x : ct_arr) {
      found_ct = found_ct || (expected_ct == x);
      std::string ptbuf = ubiq::platform::fpe::decrypt(_creds, dataset_name, x);
      // std::cout << "  ct: " << x << std::endl;
      // std::cout << "  ptbuf: " << ptbuf << std::endl;
      EXPECT_EQ(pt, ptbuf);
  }
  EXPECT_TRUE(found_ct);

}

void cpp_fpe_encrypt::test_batch_rt(
  const std::string &dataset_name,
  const std::string &pt,
  const std::string &expected_ct) {
  std::string ct;
  std::string rt;

  _enc = ubiq::platform::fpe::encryption(_creds);
  _dec = ubiq::platform::fpe::decryption(_creds);


  ASSERT_NO_THROW(
      ct = _enc.encrypt(dataset_name, pt));

  ASSERT_NO_THROW(
      rt = _dec.decrypt(dataset_name, ct));

  EXPECT_EQ(rt, pt);

  // Decrypt the expected value - will address issue when source data key has been rotated
  ASSERT_NO_THROW(
      rt = _dec.decrypt(dataset_name, expected_ct));
  EXPECT_EQ(rt, pt);

  std::vector<std::string> ct_arr, ct2_arr;
  ASSERT_NO_THROW(
      ct_arr = _enc.encrypt_for_search(dataset_name, pt));

  ASSERT_NO_THROW(
      ct2_arr = _enc.encrypt_for_search(dataset_name, pt));

  EXPECT_EQ(ct_arr, ct2_arr);

      // std::cout << "  pt: " << pt << std::endl;
  bool found_ct(false);
  for (auto x : ct_arr) {
      found_ct = found_ct || (expected_ct == x);
      std::string ptbuf = _dec.decrypt(dataset_name, x);
      // std::cout << "  ct: " << x << std::endl;
      // std::cout << "  ptbuf: " << ptbuf << std::endl;
      EXPECT_EQ(pt, ptbuf);
  }
  EXPECT_TRUE(found_ct);

}

void cpp_fpe_encrypt::test_rt(
  const std::string &dataset_name,
  const std::string &pt,
  const std::string &expected_ct) {

  test_simple_rt(dataset_name, pt, expected_ct);
  test_batch_rt(dataset_name, pt, expected_ct);

}

TEST_F(cpp_fpe_encrypt, none)
{
  ASSERT_NO_THROW(
      _enc = ubiq::platform::fpe::encryption(_creds));
}

TEST_F(cpp_fpe_encrypt, simple)
{
  std::string pt("0123456789");
  std::string ct, ct2;

  ASSERT_NO_THROW(
      ct = ubiq::platform::fpe::encrypt(_creds, "ALPHANUM_SSN", pt));

  ASSERT_NO_THROW(
      ct2 = ubiq::platform::fpe::encrypt(_creds, "ALPHANUM_SSN", std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct, ct2);
}


TEST_F(cpp_fpe_encrypt, ALPHANUM_SSN_rt)
{
  test_rt("ALPHANUM_SSN", ";0123456-789ABCDEF|", ";!!!E7`+-ai1ykOp8r|");
}

// TEST_F(cpp_fpe_encrypt, ALPHANUM_SSN_dev_rt)
// {
//   test_rt("ALPHANUM_SSN", "0123456789", "30003mA5by");
// }


TEST_F(cpp_fpe_encrypt, BIRTH_DATE_rt)
{
  test_rt("BIRTH_DATE", ";01\\02-1960|", ";!!\\!!-oKzi|");
}

TEST_F(cpp_fpe_encrypt, SSN_rt)
{
  test_rt("SSN", "-0-1-2-3-4-5-6-7-8-9-", "-0-0-0-0-1-I-L-8-j-D-");
}

TEST_F(cpp_fpe_encrypt, UTF8_STRING_COMPLEX_rt)
{
  test_rt("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ", "ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ");
}

TEST_F(cpp_fpe_encrypt, UTF8_STRING_COMPLEX_rt_1)
{
  test_rt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ", "にΪΪΪΪΪΪ3oeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはÏRϼĶufÝK3MXa");
}

// TEST_F(cpp_fpe_encrypt, UTF8_STRING_COMPLEX_dev_rt)
// {
//   test_rt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ", "にΪΪΪΪΪΪこm99Ì6qyLoĸϻÎ8mó4MogdϺϻ7ϼYBDTaKRはΫpññD7ÍϽĸϿBnϿog");
// }

// TEST_F(cpp_fpe_encrypt, UTF8_STRING_COMPLEX_dev_rt_1)
// {
//   test_rt("UTF8_STRING_COMPLEX","ÑÒÓķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶʔʕ", "ÑÒÓにΪΪΪΪΪΪこm99Ì6qyLoĸϻÎ8mó4MogdϺϻ7ϼYBDTaKRはΫpññD7ÍϽĸϿBnϿogʔʕ");
// }



TEST_F(cpp_fpe_encrypt, invalid_ffs)
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

TEST_F(cpp_fpe_encrypt, invalid_creds)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::string ct;

  ubiq::platform::credentials creds("a","b","c", "d");

  _enc = ubiq::platform::fpe::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  _dec = ubiq::platform::fpe::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));
}

TEST_F(cpp_fpe_encrypt, invalid_PT_CT)
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

TEST_F(cpp_fpe_encrypt, invalid_LEN)
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

TEST_F(cpp_fpe_encrypt, invalid_specific_creds)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt(" 123456789");
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

  ASSERT_ANY_THROW(_enc = ubiq::platform::fpe::encryption(creds));

  // Use same PT as invalid CT.  Should fail similarly
  ASSERT_ANY_THROW(_dec = ubiq::platform::fpe::decryption(creds));

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

TEST_F(cpp_fpe_encrypt, invalid_keynum)
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
// #endif


void c_test_simple_rt(
  const char * const dataset_name,
  const char * const pt,
  const char * const expected_ct) {

    struct ubiq_platform_credentials * creds;
    // struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;

    char ** ct_arr(nullptr);
    size_t ctcount(0);

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt(creds,
      dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ctbuf, strlen(ctbuf) ));

    res = ubiq_platform_fpe_decrypt(creds,
      dataset_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
    EXPECT_EQ(strcmp(pt, ptbuf),0);

    res = ubiq_platform_fpe_encrypt_for_search(creds,
      dataset_name, NULL, 0, pt, strlen(pt), &ct_arr, &ctcount);

    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    for (int i = 0; i < ctcount; i++) {

      found_ct = found_ct || (strcmp(ct_arr[i], expected_ct) == 0);

      char * ptbuf = NULL;
      size_t ptlen = 0;

      res = ubiq_platform_fpe_decrypt(creds,
        dataset_name, NULL, 0, (char *)ct_arr[i], strlen(ct_arr[i]), &ptbuf, &ptlen);
      EXPECT_EQ(res, 0) << "i (" << i << ")  ct_arr[i](" << ct_arr[i] << ")  ptbuf (" << ptbuf << ")" << std::endl;
      EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ct_arr[i], strlen(ct_arr[i]) ));
      EXPECT_EQ(strcmp(pt, ptbuf),0);

      // Decrypt each one and confirm results match PT
      free(ptbuf);
    }

    EXPECT_TRUE(found_ct);

    for (int i = 0; i < ctcount; i++) {
      free(ct_arr[i]);
    }
    free(ct_arr);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);

}

void c_test_batch_rt(
  const char * const dataset_name,
  const char * const pt,
  const char * const expected_ct) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;

    char ** ct_arr(nullptr);
    size_t ctcount(0);

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_encrypt_data(enc,
      dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ctbuf, strlen(ctbuf) ));

    res = ubiq_platform_fpe_decrypt_data(enc,
      dataset_name, NULL, 0, ctbuf, ctlen, &ptbuf, &ptlen);

    EXPECT_EQ(strcmp(pt, ptbuf),0);

    res = ubiq_platform_fpe_encrypt_data_for_search(enc,
      dataset_name, NULL, 0, pt, strlen(pt), &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    for (int i = 0; i < ctcount; i++) {

      found_ct = found_ct || (strcmp(ct_arr[i], expected_ct) == 0);

      char * ptbuf = NULL;
      size_t ptlen = 0;

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_fpe_decrypt_data(enc,
         dataset_name, NULL, 0, ct_arr[i], strlen(ct_arr[i]), &ptbuf, &ptlen);
      EXPECT_EQ(res, 0) << "i (" << i << ")  ct_arr[i](" << ct_arr[i] << ")  ptbuf (" << ptbuf << ")" << std::endl;

      EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ptbuf, strlen(ptbuf) ));

      EXPECT_EQ(strcmp(pt, ptbuf),0);
      free(ptbuf);
    }

    EXPECT_TRUE(found_ct);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    for (int i = 0; i < ctcount; i++) {
      free(ct_arr[i]);
    }
    free(ct_arr);


    free(ctbuf);
    free(ptbuf);

}

void c_test_rt(
  const char * const dataset_name,
  const char * const pt,
  const char * const expected_ct) {

  c_test_simple_rt(dataset_name, pt, expected_ct);
  c_test_batch_rt(dataset_name, pt, expected_ct);

}


TEST(c_fpe_encrypt, ALPHANUM_SSN_rt)
{
  c_test_rt("ALPHANUM_SSN", ";0123456-789ABCDEF|", ";!!!E7`+-ai1ykOp8r|");
}

TEST(c_fpe_encrypt, UTF8_STRING_COMPLEX_rt)
{
  c_test_rt("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ", "ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ");
}

TEST(c_fpe_encrypt, UTF8_STRING_COMPLEX_rt_1)
{
  c_test_rt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ", "にΪΪΪΪΪΪ3oeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはÏRϼĶufÝK3MXa");
}

TEST(c_fpe_encrypt, BIRTH_DATE_rt)
{
  c_test_rt("BIRTH_DATE", ";01\\02-1960|", ";!!\\!!-oKzi|");
}

TEST(c_fpe_encrypt, SSN_rt)
{
  c_test_rt("SSN", "-0-1-2-3-4-5-6-7-8-9-", "-0-0-0-0-1-I-L-8-j-D-");
}




TEST(c_fpe_encrypt, piecewise_bad_char)
{
    static const char * const pt = "123 456-7abc";
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
    // EXPECT_EQ(res, -EINVAL);
    // EXPECT_EQ(strlen(pt), ctlen);


    // EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_encrypt, 1m)
{
  static const char * const ffs_name = "ALPHANUM_SSN";
  static const char * const pt = "0123456789";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;

    char * ctbuf(nullptr);
    size_t ctlen;

    std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
    std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

    int res;
    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

        auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      free(ctbuf);
    auto end = std::chrono::steady_clock::now();
    first_call = (end - start);

    for (unsigned long i = 0; i < 1000000; i++) {
        auto start = std::chrono::steady_clock::now();
        res = ubiq_platform_fpe_encrypt_data(enc,
          ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
          free(ctbuf);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
    std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_fpe_encrypt, u32_1m)
{
  static const char * const ffs_name = "UTF8_STRING_COMPLEX";
  static const char * const pt = "は世界abcdefghijklmnop";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_fpe_enc_dec_obj *enc;

    char * ctbuf(nullptr);
    size_t ctlen(0);

    std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
    std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

    int res;
    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

        auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      free(ctbuf);
    auto end = std::chrono::steady_clock::now();
    first_call = (end - start);

    for (unsigned long i = 0; i < 1000000; i++) {
        auto start = std::chrono::steady_clock::now();
        res = ubiq_platform_fpe_encrypt_data(enc,
          ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
          free(ctbuf);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
    std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}


TEST(c_fpe_decrypt, 1m)
{
  static const char * const ffs_name = "ALPHANUM_SSN";
  static const char * const ct = ";!!!E7`+-ai1ykOp8r|";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_fpe_enc_dec_obj *enc;

  char * ptbuf(nullptr);
  size_t ptlen(0);

  std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
  std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

  int res;
  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

      auto start = std::chrono::steady_clock::now();
  res = ubiq_platform_fpe_decrypt_data(enc,
    ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
    free(ptbuf);
  auto end = std::chrono::steady_clock::now();
  first_call = (end - start);

    for (unsigned long i = 0; i < 1000000; i++) {
        auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
          free(ptbuf);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
    std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_fpe_encrypt, piecewise_cached)
{
    static const char * const pt = "0123456-789ABCDEF";
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

    free(ctbuf);

    res = ubiq_platform_fpe_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    // EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_fpe_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_fpe_encrypt, piecewise2)
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


TEST(c_fpe_encrypt, mixed_forward)
{
    static const char * const pt = ";0123456-789ABCDEF|";
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
    static const char * const pt = ";0123456-789ABCDEF|";
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


TEST(c_fpe_encrypt, error_handling_null_object)
{
  int err_num;
  char * err_msg = NULL;
  int res;

  res = ubiq_platform_fpe_get_last_error(NULL, &err_num, &err_msg);
  ASSERT_EQ(res, -EINVAL);

}

TEST(c_fpe_encrypt, error_handling_notnull_object)
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

TEST(c_fpe_encrypt, error_handling_invalid_ffs)
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

TEST(c_fpe_encrypt, error_handling_invalid_creds)
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

TEST(c_fpe_encrypt, error_handling_invalid_PT_CT)
{

  static const char * const pt =  "-0-1-2-3-4-5-6-7-8-9$";
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

TEST(c_fpe_encrypt, error_handling_invalid_LEN)
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


TEST(c_fpe_encrypt, error_handling_invalid_papi)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
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

TEST(c_fpe_encrypt, error_handling_invalid_sapi)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
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

TEST(c_fpe_encrypt, error_handling_invalid_rsa)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
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

TEST(c_fpe_encrypt, error_handling_invalid_host)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
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


TEST(c_fpe_encrypt, error_handling_invalid_keynum)
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


TEST_F(cpp_fpe_encrypt, 1m)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::string ct("");
  std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();

  _enc = ubiq::platform::fpe::encryption(_creds);


  ct = _enc.encrypt(ffs_name, pt);

  for (unsigned long i = 0; i < 1000000; i++) {
      auto start = std::chrono::steady_clock::now();

      ct = _enc.encrypt(ffs_name, pt);
      auto end = std::chrono::steady_clock::now();

      ubiq_times += (end - start);
  }


  std::cerr << "\tSelect total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_fpe_encrypt, new)
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
