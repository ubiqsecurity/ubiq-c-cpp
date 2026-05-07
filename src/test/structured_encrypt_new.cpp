#include <gtest/gtest.h>
#include <unistr.h>
#include <uniwidth.h>
#include <chrono>

#include "ubiq/platform.h"
#include <ubiq/platform/internal/credentials.h>
#include <ubiq/platform/internal/parsing.h>

class cpp_structured_encrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);
    // void test_batch_rt(  
    //   const std::string &dataset_name,
    //   const std::string &pt);

    void test_rt(  
      const std::string &dataset_name,
      const std::string &pt);

    void search(  
      const std::string &dataset_name,
      const std::string &pt);

    void test_rt(  
      const std::string &dataset_name,
      const int32_t &pt);

    void test_rt(  
      const std::string &dataset_name,
      const int64_t &pt);

    void test_rt(
      const std::string &dataset_name,
      const struct tm &pt);

    void test_datetime_rt(
      const std::string &dataset_name,
      const struct tm &pt);

  protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::structured::encryption _enc;
    ubiq::platform::structured::decryption _dec;
};

void cpp_structured_encrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_structured_encrypt::TearDown(void)
{
}

void cpp_structured_encrypt::search(
  const std::string &dataset_name,
  const std::string &pt) {

  std::vector<std::string> ct, ct2;
  std::string ct_tmp;

  _enc = ubiq::platform::structured::encryption(_creds);
  _dec = ubiq::platform::structured::decryption(_creds);

  ASSERT_NO_THROW(
      ct_tmp = _enc.encrypt(dataset_name, pt));


  ASSERT_NO_THROW(
      ct = _enc.encrypt_for_search(dataset_name, pt));

  ASSERT_NO_THROW(
      ct2 = _enc.encrypt_for_search(dataset_name, std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct, ct2);

  // Expect that the supplied CT is found in one of the search keys - will work regardless of how many times the 
  // data has been rotated
  bool found_ct(false);
  for (auto x : ct) {
      found_ct = found_ct || (ct_tmp == x);
      std::string ptbuf = _dec.decrypt(dataset_name, x);
      EXPECT_EQ(pt, ptbuf);
  }

  EXPECT_TRUE(found_ct);
}

void cpp_structured_encrypt::test_rt(
  const std::string &dataset_name,
  const std::string &pt) {
  std::string ct;
  std::string rt;

  _enc = ubiq::platform::structured::encryption(_creds);
  _dec = ubiq::platform::structured::decryption(_creds);

  ASSERT_NO_THROW(
      ct = _enc.encrypt(dataset_name, pt));

  ASSERT_NO_THROW(
      rt = _dec.decrypt(dataset_name, ct));

  EXPECT_EQ(rt, pt);

  std::vector<std::string> ct_arr, ct2_arr;
  ASSERT_NO_THROW(
      ct_arr = _enc.encrypt_for_search(dataset_name, pt));

  ASSERT_NO_THROW(
      ct2_arr = _enc.encrypt_for_search(dataset_name, std::vector<std::uint8_t>(), pt));

  EXPECT_EQ(ct_arr, ct2_arr);

  // std::cout << "  pt: " << pt << std::endl;
  bool found_ct(false);
  for (auto x : ct_arr) {
      found_ct = found_ct || (ct == x);
      std::string ptbuf = _dec.decrypt(dataset_name, x);
      // std::cout << "  ct: " << x << std::endl;
      // std::cout << "  ptbuf: " << ptbuf << std::endl;
      EXPECT_EQ(pt, ptbuf);
  }
  EXPECT_TRUE(found_ct);

}

void cpp_structured_encrypt::test_rt(
  const std::string &dataset_name,
  const int32_t &pt) {
  int32_t ct;
  int32_t rt;

  _enc = ubiq::platform::structured::encryption(_creds);
  _dec = ubiq::platform::structured::decryption(_creds);


  ASSERT_NO_THROW(
      ct = _enc.encryptInt(dataset_name, pt));

  ASSERT_NO_THROW(
      rt = _dec.decryptInt(dataset_name, ct));

  EXPECT_EQ(rt, pt);

  std::vector<int32_t> ct_arr;
  ASSERT_NO_THROW(
      ct_arr = _enc.encryptInt_for_search(dataset_name, pt));

  EXPECT_GT(ct_arr.size(), 0);

  bool found_ct(false);
  for (auto x : ct_arr) {
      found_ct = found_ct || (ct == x);
      int32_t ptbuf = _dec.decryptInt(dataset_name, x);
      EXPECT_EQ(pt, ptbuf);
  }
  EXPECT_TRUE(found_ct);

}


void cpp_structured_encrypt::test_rt(
  const std::string &dataset_name,
  const int64_t &pt) {
  int64_t ct;
  int64_t rt;

  _enc = ubiq::platform::structured::encryption(_creds);
  _dec = ubiq::platform::structured::decryption(_creds);


  ASSERT_NO_THROW(
      ct = _enc.encryptLong(dataset_name, pt));

  ASSERT_NO_THROW(
      rt = _dec.decryptLong(dataset_name, ct));

  EXPECT_EQ(rt, pt);

  std::vector<int64_t> ct_arr;
  ASSERT_NO_THROW(
      ct_arr = _enc.encryptLong_for_search(dataset_name, pt));

  EXPECT_GT(ct_arr.size(), 0);

  bool found_ct(false);
  for (auto x : ct_arr) {
      found_ct = found_ct || (ct == x);
      int64_t ptbuf = _dec.decryptLong(dataset_name, x);
      EXPECT_EQ(pt, ptbuf);
  }
  EXPECT_TRUE(found_ct);

}

void cpp_structured_encrypt::test_rt(
  const std::string &dataset_name,
  const struct tm &pt) {
  struct tm ct;
  struct tm rt;

  _enc = ubiq::platform::structured::encryption(_creds);
  _dec = ubiq::platform::structured::decryption(_creds);

  struct tm * pt_tmp = (struct tm *)calloc(1, sizeof(*pt_tmp));
  memcpy(pt_tmp, &pt, sizeof(struct tm));


  ASSERT_NO_THROW(
      ct = _enc.encryptDate(dataset_name, pt));

  ASSERT_NO_THROW(
      rt = _dec.decryptDate(dataset_name, ct));

  time_t p = mktime(pt_tmp);
  time_t rt_tmp = mktime(&rt);
  time_t ct_tmp = mktime(&ct);

  EXPECT_EQ(p, rt_tmp);

  std::vector<struct tm > ct_arr;
  ASSERT_NO_THROW(
      ct_arr = _enc.encryptDate_for_search(dataset_name, pt));

  EXPECT_GT(ct_arr.size(), 0);

  bool found_ct(false);
  for (auto x : ct_arr) {
      time_t x_tmp = mktime(&x);

      found_ct = found_ct || (ct_tmp == x_tmp);
      struct tm ptbuf = _dec.decryptDate(dataset_name, x);
      // EXPECT_EQ(pt, ptbuf);
      time_t tmp = mktime(&ptbuf);
      EXPECT_EQ(p, tmp);
  }
  EXPECT_TRUE(found_ct);
  free(pt_tmp);
}

void cpp_structured_encrypt::test_datetime_rt(
  const std::string &dataset_name,
  const struct tm &pt) {
  struct tm ct;
  struct tm rt;

  _enc = ubiq::platform::structured::encryption(_creds);
  _dec = ubiq::platform::structured::decryption(_creds);

  struct tm * pt_tmp = (struct tm *)calloc(1, sizeof(*pt_tmp));
  memcpy(pt_tmp, &pt, sizeof(struct tm));


  ASSERT_NO_THROW(
      ct = _enc.encryptDateTime(dataset_name, pt));

  ASSERT_NO_THROW(
      rt = _dec.decryptDateTime(dataset_name, ct));

  time_t p = mktime(pt_tmp);
  time_t rt_tmp = mktime(&rt);
  time_t ct_tmp = mktime(&ct);

  EXPECT_EQ(p, rt_tmp);

  std::vector<struct tm > ct_arr;
  ASSERT_NO_THROW(
      ct_arr = _enc.encryptDateTime_for_search(dataset_name, pt));

  EXPECT_GT(ct_arr.size(), 0);

  bool found_ct(false);
  for (auto x : ct_arr) {
      time_t x_tmp = mktime(&x);

      found_ct = found_ct || (ct_tmp == x_tmp);
      struct tm ptbuf = _dec.decryptDateTime(dataset_name, x);
      // EXPECT_EQ(pt, ptbuf);
      time_t tmp = mktime(&ptbuf);
      EXPECT_EQ(p, tmp);
  }
  EXPECT_TRUE(found_ct);
  free(pt_tmp);
}


TEST_F(cpp_structured_encrypt, none)
{
  ASSERT_NO_THROW(
      _enc = ubiq::platform::structured::encryption(_creds));
}




TEST_F(cpp_structured_encrypt, ALPHANUM_SSN_rt)
{
  test_rt("ALPHANUM_SSN", ";0123456-789ABCDEF|");
}

// TEST_F(cpp_structured_encrypt, ALPHANUM_SSN_dev_rt)
// {
//   test_rt("ALPHANUM_SSN", "0123456789", "30003mA5by");
// }


TEST_F(cpp_structured_encrypt, BIRTH_DATE_rt)
{
  test_rt("BIRTH_DATE", ";01\\02-1960|");
}

TEST_F(cpp_structured_encrypt, SSN_rt)
{
  test_rt("SSN", "-0-1-2-3-4-5-6-7-8-9-");
}

TEST_F(cpp_structured_encrypt, UTF8_STRING_COMPLEX_rt)
{
  test_rt("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ");
}

TEST_F(cpp_structured_encrypt, UTF8_STRING_COMPLEX_rt_1)
{
  test_rt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ");
}

// TEST_F(cpp_structured_encrypt, UTF8_STRING_COMPLEX_dev_rt)
// {
//   test_rt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ", "にΪΪΪΪΪΪこm99Ì6qyLoĸϻÎ8mó4MogdϺϻ7ϼYBDTaKRはΫpññD7ÍϽĸϿBnϿog");
// }

// TEST_F(cpp_structured_encrypt, UTF8_STRING_COMPLEX_dev_rt_1)
// {
//   test_rt("UTF8_STRING_COMPLEX","ÑÒÓķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶʔʕ", "ÑÒÓにΪΪΪΪΪΪこm99Ì6qyLoĸϻÎ8mó4MogdϺϻ7ϼYBDTaKRはΫpññD7ÍϽĸϿBnϿogʔʕ");
// }

TEST_F(cpp_structured_encrypt, integer32_rt)
{
  test_rt("integer32", 5);
}

TEST_F(cpp_structured_encrypt, integer32_rt_2)
{
  test_rt("integer32", 44151081);
}

TEST_F(cpp_structured_encrypt, integer64_rt)
{
  test_rt("integer64", 50L);
}

TEST_F(cpp_structured_encrypt, integer64_rt_2)
{
  test_rt("integer64", -1013971772118990L);
}

TEST_F(cpp_structured_encrypt, date_rt)
{
  time_t now = time(NULL);
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  localtime_r(&now, local);
  local->tm_hour = local->tm_min = local->tm_sec = 0;

  test_rt("date", *local);
  local->tm_year = 1600 - 1900;
  test_rt("date", *local);
  free(local);
}



TEST_F(cpp_structured_encrypt, date_rt_2)
{
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  ubiq_platform_parse_iso8601("1619-08-31T00:00Z", local);

  test_rt("date", *local);
  free(local);
}

TEST_F(cpp_structured_encrypt, datetime_rt)
{
  time_t now = time(NULL);
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  localtime_r(&now, local);
  test_datetime_rt("datetime", *local);

  local->tm_year = 1700 - 1900;
  test_datetime_rt("datetime", *local);

  ubiq_platform_parse_iso8601("1619-08-31T00:00Z", local);

  free(local);
}

TEST_F(cpp_structured_encrypt, datetime_rt_2)
{
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  ubiq_platform_parse_iso8601("1819-08-31T12:34:56Z", local);
  test_datetime_rt("datetime", *local);

  local->tm_year = 1700 - 1900;
  test_datetime_rt("datetime", *local);

  free(local);
}

TEST_F(cpp_structured_encrypt, token64_rt)
{
  test_rt("token64", "123");
}

TEST_F(cpp_structured_encrypt, token128_rt)
{
  test_rt("token128", "123");
}

TEST_F(cpp_structured_encrypt, generic_rt)
{
  test_rt("generic_string", "abcdefghijklmnop");
}

TEST_F(cpp_structured_encrypt, generic32_rt)
{
  test_rt("generic_string_32", "123");
}

TEST_F(cpp_structured_encrypt, generic64_rt)
{
  test_rt("generic_string_64", "123");
}

TEST_F(cpp_structured_encrypt, invalid_ffs)
{
  std::string pt("ABCDEFGHI");
  std::string ct;

  _enc = ubiq::platform::structured::encryption(_creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt("ERROR FFS", pt));

  _dec = ubiq::platform::structured::decryption(_creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt("ERROR FFS", pt));
}

TEST_F(cpp_structured_encrypt, invalid_creds)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::string ct;

  ubiq::platform::credentials creds("a","b","c", "d");

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  _dec = ubiq::platform::structured::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));
}

TEST_F(cpp_structured_encrypt, invalid_PT_CT)
{
  std::string ffs_name("SSN");
  std::string pt(" 123456789$");
  std::string ct;


  _enc = ubiq::platform::structured::encryption(_creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(_creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));
}

TEST_F(cpp_structured_encrypt, invalid_LEN)
{
  std::string ffs_name("SSN");
  std::string shortpt(" 1234");
  std::string longpt(" 12345678901234567890");
  std::string ct;


  _enc = ubiq::platform::structured::encryption(_creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, shortpt));
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, longpt));

 // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(_creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, shortpt));
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, longpt));
}

TEST_F(cpp_structured_encrypt, invalid_specific_creds)
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

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    std::string(ubiq_platform_credentials_get_sapi(&(*_creds))).substr(1),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    ubiq_platform_credentials_get_host(&(*_creds)));

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    std::string(ubiq_platform_credentials_get_srsa(&(*_creds))).substr(1),
    ubiq_platform_credentials_get_host(&(*_creds)));

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  // Will add https prefix so error is different than others
  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    "pi.ubiqsecurity.com");

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(creds);
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

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

  // Completely wrong URL but a valid one
  creds = ubiq::platform::credentials
  (
    ubiq_platform_credentials_get_papi(&(*_creds)),
    ubiq_platform_credentials_get_sapi(&(*_creds)),
    ubiq_platform_credentials_get_srsa(&(*_creds)),
    "https://google.com");

  _enc = ubiq::platform::structured::encryption(creds);
  ASSERT_ANY_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  // Use same PT as invalid CT.  Should fail similarly
  _dec = ubiq::platform::structured::decryption(creds);
  ASSERT_ANY_THROW(
      ct = _dec.decrypt(ffs_name, pt));

}

TEST_F(cpp_structured_encrypt, invalid_keynum)
{
  std::string ffs_name("SSN");
  std::string pt("0123456789");
  std::string ct;


  _enc = ubiq::platform::structured::encryption(_creds);
  ASSERT_NO_THROW(
      ct = _enc.encrypt(ffs_name, pt));

  ct[0] = '}';
  _dec = ubiq::platform::structured::decryption(_creds);
  ASSERT_ANY_THROW(
      pt = _dec.decrypt(ffs_name, ct));
}
// #endif

static
void c_test_batch_rt(
  const char * const dataset_name,
  const char * const pt) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;

    char ** ct_arr(nullptr);
    size_t ctcount(0);

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ctbuf, strlen(ctbuf) ));

    res = ubiq_platform_structured_decrypt_data(enc,
      dataset_name, NULL, 0, ctbuf, ctlen, &ptbuf, &ptlen);

    EXPECT_EQ(strcmp(pt, ptbuf),0);

    res = ubiq_platform_structured_encrypt_data_for_search(enc,
      dataset_name, NULL, 0, pt, strlen(pt), &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    for (int i = 0; i < ctcount; i++) {

      found_ct = found_ct || (strcmp(ct_arr[i], ctbuf) == 0);

      char * ptbuf = NULL;
      size_t ptlen = 0;

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_structured_decrypt_data(enc,
         dataset_name, NULL, 0, ct_arr[i], strlen(ct_arr[i]), &ptbuf, &ptlen);
      EXPECT_EQ(res, 0) << "i (" << i << ")  ct_arr[i](" << ct_arr[i] << ")  ptbuf (" << ptbuf << ")" << std::endl;

      EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ptbuf, strlen(ptbuf) ));

      EXPECT_EQ(strcmp(pt, ptbuf),0);
      free(ptbuf);
    }

    EXPECT_TRUE(found_ct);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    for (int i = 0; i < ctcount; i++) {
      free(ct_arr[i]);
    }
    free(ct_arr);


    free(ctbuf);
    free(ptbuf);

}

static
void c_test_rt(
  const char * const dataset_name,
  const char * const pt) {

  c_test_batch_rt(dataset_name, pt);

}


TEST(c_structured_encrypt, ALPHANUM_SSN_rt)
{
  c_test_rt("ALPHANUM_SSN", ";0123456-789ABCDEF|");
}

TEST(c_structured_encrypt, UTF8_STRING_COMPLEX_rt)
{
  c_test_rt("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ");
}

TEST(c_structured_encrypt, UTF8_STRING_COMPLEX_rt_1)
{
  c_test_rt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ");
}

TEST(c_structured_encrypt, BIRTH_DATE_rt)
{
  c_test_rt("BIRTH_DATE", ";01\\02-1960|");
}

TEST(c_structured_encrypt, SSN_rt)
{
  c_test_rt("SSN", "-0-1-2-3-4-5-6-7-8-9-");
}


TEST(c_structured_encrypt, date_random)
{
  struct tm pt;
  struct tm ct;
  struct tm pt2;
  int res = 0;

  srand(time(NULL));
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  time_t start = -62135596800; // date -d "01/01/0001" +%s
  
  time_t end    = 24264316800; // date -d "2738-11-28" +%s
  {
    struct tm end_tm;
    struct tm start_tm;
      char buffer1[30];
      char buffer2[30];
      struct tm *dt = gmtime_r(&start, &start_tm);
      dt = gmtime_r(&end, &end_tm);
      size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &start_tm);
      len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &end_tm);
      printf("START: %s   END: %s\n", buffer1, buffer2);
  }
                     
  long long range = end - start;
    // printf("range: %lld\n", range);

  for (size_t i = 0; !res && i < 250000; i++) {

    long long random_offset = ((long long)((((long long)rand() << 32 | rand()) % (range + 1)) / (60 * 60 *24))) * (60*60*24);
    // printf("offset: %lld\n", random_offset);
    time_t random_timestamp = (time_t)(start + random_offset);

    // pt.tm_year = rand() % (2738) - 1900 ;
    // if (pt.tm_year == -1900) { pt.tm_year = -1899;}
    // pt.tm_mon = rand() % 12;
    // pt.tm_mday = rand() % 31;
    // pt.tm_hour = pt.tm_min = pt.tm_sec = 0;
    // pt.tm_isdst = 0;
    // pt.tm_gmtoff = 0;
    struct tm *dt = gmtime_r(&random_timestamp, &pt);

  // {
  //     char buffer1[30];
  //     char buffer2[30];
  //     char buffer3[30];
  //     size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
  //     printf("PT: %d %s\n", pt.tm_year, buffer1);
  // }

    time_t rt_tmp = mktime(&pt);
    // printf("rt_tmp: %lld %d\n", rt_tmp, errno);
    res = ubiq_platform_structured_encrypt_date_data(enc, "date_2keys", NULL, 0, &pt, &ct);
    if (res) { printf("Encrypt Error:\n ");break; }
    res = ubiq_platform_structured_decrypt_date_data(enc, "date_2keys", NULL, 0, &ct, &pt2);
    if (res) { break; }
    
    time_t pt_tmp = mktime(&pt2);

    res = (pt_tmp != rt_tmp);
  }

  if (res) {
      char buffer1[30];
      char buffer2[30];
      char buffer3[30];
      size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
      len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &ct);
      len = strftime(buffer3, sizeof(buffer3), "%04Y-%m-%dT%H:%M:%SZ", &pt2);

      printf("PT: %s  CT: %s   PT2:  %s\n", buffer1, buffer2, buffer3);
  }
  if (res) {
    int err_num;
    char * err_msg = NULL;
    int res;

    res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error: %d %s\n", err_num, err_msg);

  }
  ASSERT_EQ(res, 0);



  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);
}

TEST(c_structured_encrypt, date_random_search)
{
  struct tm pt;
  struct tm * ct = NULL;
  struct tm pt2;
  int res = 0;


  srand(time(NULL));
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  time_t start = -62135596800; // date -d "01/01/0001" +%s
  
  time_t end    = 24264316800; // date -d "2738-11-28" +%s
  {
    struct tm end_tm;
    struct tm start_tm;
      char buffer1[30];
      char buffer2[30];
      struct tm *dt = gmtime_r(&start, &start_tm);
      dt = gmtime_r(&end, &end_tm);
      size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &start_tm);
      len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &end_tm);
      printf("START: %s   END: %s\n", buffer1, buffer2);
  }
                     
  long long range = end - start;

  for (size_t i = 0; !res && i < 250000; i++) {
    // pt.tm_year = -1899;//rand() % (2738) - 1900 ;
    // if (pt.tm_year == -1900) { pt.tm_year = -1899;}
    // pt.tm_mon = 0;//rand() % 12;
    // pt.tm_mday = 1;//rand() % 31;
    // pt.tm_hour = pt.tm_min = pt.tm_sec = 0;
    // pt.tm_isdst = 0;
    // pt.tm_gmtoff = 0;

    // {
    //     char buffer1[30];
    //     char buffer2[30];
    //     char buffer3[30];
    //     size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
    //     // printf("PT: %d %s\n", pt.tm_year, buffer1);
    // }

    long long random_offset = ((long long)((((long long)rand() << 32 | rand()) % (range + 1)) / (60 * 60 *24))) * (60*60*24);
    time_t random_timestamp = (time_t)(start + random_offset);
    struct tm *dt = gmtime_r(&random_timestamp, &pt);

    time_t rt_tmp = mktime(&pt);
    size_t arr_len = 5;
    // printf("rt_tmp: %lld %d\n", rt_tmp, errno);
    res = ubiq_platform_structured_encrypt_date_data_for_search(enc, "date_2keys", NULL, 0, &pt, &ct, &arr_len);
    if (res) { printf("Encrypt Error:\n ");break; }

    ASSERT_GT(arr_len, 1);
    for (size_t i = 0; i < arr_len; i++) {
      res = ubiq_platform_structured_decrypt_date_data(enc, "date_2keys", NULL, 0, &ct[i], &pt2);
      if (res) { 
        char buffer1[30];
        char buffer2[30];
        size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
        len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &ct[i]);
        printf("PT: %s  CT: %s  \n", buffer1, buffer2);
        break; }
    
      time_t pt_tmp = mktime(&pt2);

      res = (pt_tmp != rt_tmp);
    }
  }

  if (res) {
      char buffer1[30];
      char buffer2[30];
      char buffer3[30];
      size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
      len = strftime(buffer3, sizeof(buffer3), "%04Y-%m-%dT%H:%M:%SZ", &pt2);

      printf("PT: %s  CT: %s   PT2:  %s\n", buffer1, buffer2, buffer3);
  }
  if (res) {
    int err_num;
    char * err_msg = NULL;
    int res;

    res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error: %d %s\n", err_num, err_msg);

  }
  ASSERT_EQ(res, 0);



  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);
  free(ct);
}

TEST(c_structured_encrypt, date_2keys_all)
{
  struct tm pt;
  struct tm * ct = NULL;
  struct tm pt2;
  int res = 0;


  srand(time(NULL));
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

  // size_t days[12] = {31,29,}
  int endit = 0;

  for (size_t year = 1; !endit && !res && year <= 2738;/*38;*/ year++) {
    // size_t days = 364;
    // if (year % 4 == 0) {
    //   if (year % 100 == 0) {
    //     if (year % 400 == 0) {
    //       days += 1;
    //     }
    //   } else {
    //     days += 1;
    //   }
    // }
    if (year % 100 == 0) {
      printf("Year: %d\n", year);
    }

    for (size_t months = 0; !endit && !res && months <= 11; months++) {
      for (size_t days = 1; !endit && !res && days <= 31; days++) {

        pt.tm_year = year - 1900;
        pt.tm_mon = months;
        pt.tm_mday = days;

        if (year == 2738 && months == 10 && days == 29) {
          endit = 1;
          continue;
        }
      
        // pt.tm_year = -1899;//rand() % (2738) - 1900 ;
        // if (pt.tm_year == -1900) { pt.tm_year = -1899;}
        // pt.tm_mon = 0;//rand() % 12;
        // pt.tm_mday = 1;//rand() % 31;
        pt.tm_hour = pt.tm_min = pt.tm_sec = 0;
        pt.tm_isdst = 0;
        pt.tm_gmtoff = 0;

        time_t rt_tmp = mktime(&pt);
        // printf("rt_tmp: %lld %d\n", rt_tmp, errno);
        // {
        //     char buffer1[30];
        //     char buffer2[30];
        //     char buffer3[30];
        //     size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
        //     printf("PT: %d %s\n", pt.tm_year, buffer1);
        // }

        // time_t rt_tmp = mktime(&pt);
        size_t arr_len = 5;
        // printf("rt_tmp: %lld %d\n", rt_tmp, errno);
        res = ubiq_platform_structured_encrypt_date_data_for_search(enc, "date_2keys", NULL, 0, &pt, &ct, &arr_len);
        if (res) { printf("Encrypt Error:\n ");break; }

        ASSERT_GT(arr_len, 1);
        for (size_t i = 0; i < arr_len; i++) {
          res = ubiq_platform_structured_decrypt_date_data(enc, "date_2keys", NULL, 0, &ct[i], &pt2);
          if (res) { 
            char buffer1[30];
            char buffer2[30];
            size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
            len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &ct[i]);
            printf("PT: %s  CT: %s  \n", buffer1, buffer2);
            break; }
        
          time_t pt_tmp = mktime(&pt2);

          res = (pt_tmp != rt_tmp);
        }
      } // days
    } // months


    if (res) {
        char buffer1[30];
        char buffer2[30];
        char buffer3[30];
        size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
        len = strftime(buffer3, sizeof(buffer3), "%04Y-%m-%dT%H:%M:%SZ", &pt2);

        printf("PT: %s  CT: %s   PT2:  %s\n", buffer1, buffer2, buffer3);
    }
  } // years
  if (res) {
    int err_num;
    char * err_msg = NULL;
    int res;

    res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error: %d %s\n", err_num, err_msg);

  }
  ASSERT_EQ(res, 0);

  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);
  free(ct);
}

TEST(c_structured_encrypt, datetime_random)
{
  struct tm pt;
  struct tm ct;
  struct tm pt2;
  int res = 0;

  srand(time(NULL));
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

  time_t start = -9999999999; // 1653-02-10T06:13:21Z
  time_t end = 9999999999; // 2286-11-20T17:46:39Z
  long long range = end - start;

  // {
  //   struct tm end_tm;
  //   struct tm start_tm;
  //   char buffer1[30];
  //   char buffer2[30];
  //   struct tm *dt = gmtime_r(&start, &start_tm);
  //   dt = gmtime_r(&end, &end_tm);
  //   size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &start_tm);
  //   len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &end_tm);
  //   printf("START: %s   END: %s\n", buffer1, buffer2);
  // }

  for (size_t i = 0; !res && i < 250000; i++) {

    long long random_offset = ((long long)rand() << 32 | rand()) % (range + 1);
    
    // 5. Calculate the random timestamp
    time_t random_timestamp = (time_t)(start + random_offset);

    // 6. Convert and print the result
    struct tm *dt = gmtime_r(&random_timestamp, &pt);

  // {
  //     char buffer1[30];
  //     size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
  //     printf("PT: %d %s\n", pt.tm_year, buffer1);
  // }

    // time_t rt_tmp = mktime(&pt);
    // printf("rt_tmp: %lld %d\n", rt_tmp, errno);
    res = ubiq_platform_structured_encrypt_datetime_data(enc, "datetime", NULL, 0, &pt, &ct);
    if (res) { printf("Encrypt Error:\n ");break; }
    res = ubiq_platform_structured_decrypt_datetime_data(enc, "datetime", NULL, 0, &ct, &pt2);
    if (res) { break; }
    
    time_t pt_tmp = mktime(&pt2);

    res = (pt_tmp != random_timestamp);
  }

  if (res) {
      char buffer1[30];
      char buffer2[30];
      char buffer3[30];
      size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
      len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &ct);
      len = strftime(buffer3, sizeof(buffer3), "%04Y-%m-%dT%H:%M:%SZ", &pt2);

      printf("PT: %s  CT: %s   PT2:  %s\n", buffer1, buffer2, buffer3);
  }
  if (res) {
    int err_num;
    char * err_msg = NULL;
    int res;

    res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error: %d %s\n", err_num, err_msg);

  }
  ASSERT_EQ(res, 0);



  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);
}

TEST(c_structured_encrypt, datetime_random_search)
{
  struct tm pt;
  struct tm * ct = NULL;
  struct tm pt2;
  int res = 0;

  srand(time(NULL));
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

  long long start = -9999999999;
  long long end = 9999999999;
  long long range = end - start;

  for (size_t i = 0; !res && i < 1; i++) {

    long long random_offset = ((long long)rand() << 32 | rand()) % (range + 1);
    
    // 5. Calculate the random timestamp
    time_t random_timestamp = (time_t)(start + random_offset);

    // 6. Convert and print the result
    struct tm *dt = gmtime_r(&random_timestamp, &pt);

    // {
    //   char buffer1[30];
    //   size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
    //   printf("PT: %d %s\n", pt.tm_year, buffer1);
    // }

    // time_t rt_tmp = mktime(&pt);
    // printf("rt_tmp: %lld %d\n", rt_tmp, errno);
    size_t arr_len = 0;
    res = ubiq_platform_structured_encrypt_datetime_data_for_search(enc, "datetime", NULL, 0, &pt, &ct, &arr_len);
    if (res) { printf("Encrypt Error:\n ");break; }
    ASSERT_GT(arr_len, 1);

    for (size_t i = 0; i < arr_len; i++) {
      res = ubiq_platform_structured_decrypt_datetime_data(enc, "datetime", NULL, 0, &ct[i], &pt2);
      if (res) { 
          char buffer1[30];
          char buffer2[30];
          size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
          len = strftime(buffer2, sizeof(buffer2), "%04Y-%m-%dT%H:%M:%SZ", &ct[i]);
          printf("PT: %s  CT: %s  \n", buffer1, buffer2);
          break; 
      }

      time_t pt_tmp = mktime(&pt2);

      res = (pt_tmp != random_timestamp);
    } // for ct arr
  } // for datetimes

  if (res) {
      char buffer1[30];
      char buffer3[30];
      size_t len = strftime(buffer1, sizeof(buffer1), "%04Y-%m-%dT%H:%M:%SZ", &pt);
      len = strftime(buffer3, sizeof(buffer3), "%04Y-%m-%dT%H:%M:%SZ", &pt2);

      printf("PT: %s   PT2:  %s\n", buffer1,  buffer3);
  }
  if (res) {
    int err_num;
    char * err_msg = NULL;
    int res;

    res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error: %d %s\n", err_num, err_msg);
  }
  ASSERT_EQ(res, 0);
  free(ct);



  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

}


TEST(c_structured_encrypt, piecewise_bad_char)
{
    static const char * const pt = "123 456-7abc";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    if (res) {
    int err_num;
    char * err_msg = NULL;

    if (!enc) {
      int res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
      printf("Error: %d %s\n", err_num, err_msg);
    } else {
      printf("ENC is NULL\n");
    }
  }

    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    // EXPECT_EQ(res, -EINVAL);
    // EXPECT_EQ(strlen(pt), ctlen);


    // EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_structured_encrypt, 1m)
{
  static const char * const ffs_name = "ALPHANUM_SSN";
  static const char * const pt = "0123456789";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    char * ctbuf(nullptr);
    size_t ctlen;

    std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
    std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

    int res;
    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

        auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      free(ctbuf);
    auto end = std::chrono::steady_clock::now();
    first_call = (end - start);

    for (unsigned long i = 0; i < 1000000; i++) {
        auto start = std::chrono::steady_clock::now();
        res = ubiq_platform_structured_encrypt_data(enc,
          ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
          free(ctbuf);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
    std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_structured_encrypt, u32_1m)
{
  static const char * const ffs_name = "UTF8_STRING_COMPLEX";
  static const char * const pt = "は世界abcdefghijklmnop";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    char * ctbuf(nullptr);
    size_t ctlen(0);

    std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
    std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

    int res;
    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

        auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      free(ctbuf);
    auto end = std::chrono::steady_clock::now();
    first_call = (end - start);

    for (unsigned long i = 0; i < 1000000; i++) {
        auto start = std::chrono::steady_clock::now();
        res = ubiq_platform_structured_encrypt_data(enc,
          ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
          free(ctbuf);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
    std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}


TEST(c_structured_decrypt, 1m)
{
  static const char * const ffs_name = "ALPHANUM_SSN";
  static const char * const ct = ";!!!E7`+-ai1ykOp8r|";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;

  char * ptbuf(nullptr);
  size_t ptlen(0);

  std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
  std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

  int res;
  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

      auto start = std::chrono::steady_clock::now();
  res = ubiq_platform_structured_decrypt_data(enc,
    ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
    free(ptbuf);
  auto end = std::chrono::steady_clock::now();
  first_call = (end - start);

    for (unsigned long i = 0; i < 1000000; i++) {
        auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_decrypt_data(enc,
      ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
          free(ptbuf);
        auto end = std::chrono::steady_clock::now();

        ubiq_times += (end - start);
    }

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
    std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_structured_encrypt, piecewise_cached)
{
    static const char * const pt = "0123456-789ABCDEF";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char * ctbuf(nullptr);
    size_t ctlen;
    char * ptbuf(nullptr);
    size_t ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    free(ctbuf);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    // EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_structured_encrypt, piecewise2)
{
    static const char * const pt = ";0123456-789ABCDEF|";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf2, &ctlen2);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf2, ctlen2, &ptbuf2, &ptlen2);
    EXPECT_EQ(res, 0);
    //
    EXPECT_EQ(strcmp(pt, ptbuf),0);
    EXPECT_EQ(strcmp(pt, ptbuf2),0);

    EXPECT_EQ(ptlen, ctlen);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf2);
    free(ctbuf);
    free(ptbuf);
    free(ptbuf2);
}


TEST(c_structured_encrypt, 10_cycles)
{
    static const char * const pt = ";0123456-789ABCDEF|";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    for (int i = 0; i < 10; i++) {
      char * ctbuf(nullptr);
      size_t ctlen;
      char * ptbuf(nullptr);
      size_t ptlen;

      res = ubiq_platform_structured_encrypt_data(enc,
        ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strlen(pt), ctlen);

      res = ubiq_platform_structured_decrypt_data(enc,
         ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
      EXPECT_EQ(res, 0);

      EXPECT_EQ(ptlen, ctlen);
      EXPECT_EQ(strcmp(pt, ptbuf),0);
      free(ctbuf);
      free(ptbuf);
    }
    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);

}


TEST(c_structured_encrypt, error_handling_null_object)
{
  int err_num;
  char * err_msg = NULL;
  int res;

  res = ubiq_platform_structured_get_last_error(NULL, &err_num, &err_msg);
  ASSERT_EQ(res, -EINVAL);

}

TEST(c_structured_encrypt, error_handling_notnull_object)
{
  int err_num;
  char * err_msg = NULL;
  int res;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj * enc;
    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    ASSERT_EQ(res, 0);
    EXPECT_EQ(err_num, 0);
    EXPECT_TRUE(err_msg == NULL);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);
    free(err_msg);

}

TEST(c_structured_encrypt, error_handling_invalid_ffs)
{

  static const char * const pt = ";0123456-789ABCDEF|";
  static const char * const ffs_name = "ALPHANUM_SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_encrypt_data(enc,
     "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use same PT as CT for decrypt.  Should fail the same way
  res = ubiq_platform_structured_decrypt_data(enc,
     "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);

}

TEST(c_structured_encrypt, error_handling_invalid_creds)
{

  static const char * const pt = ";0123456-789ABCDEF|";
  static const char * const ffs_name = "ALPHANUM_SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;
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

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_encrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use same PT as CT, should faild the same way
  res = ubiq_platform_structured_decrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
}

TEST(c_structured_encrypt, error_handling_invalid_PT_CT)
{

  static const char * const pt =  "-0-1-2-3-4-5-6-7-8-9$";
  static const char * const ffs_name = "SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_encrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use same PT as invalid CT.  Should fail similarly
  res = ubiq_platform_structured_decrypt_data(enc,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);


  ubiq_platform_structured_enc_dec_destroy(enc);

  ubiq_platform_credentials_destroy(creds);

  free(ctbuf);
}

TEST(c_structured_encrypt, error_handling_invalid_LEN)
{
  static const char * const short_pt = " 123";
  static const char * const long_pt = " 1234567890123123123123";
  static const char * const ffs_name = "SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_encrypt_data(enc,
    ffs_name, NULL, 0, short_pt, strlen(short_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  res = ubiq_platform_structured_encrypt_data(enc,
    ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  // Use PT as CT for decrypt.  Should fail the same way
  res = ubiq_platform_structured_decrypt_data(enc,
    ffs_name, NULL, 0, short_pt, strlen(short_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  res = ubiq_platform_structured_decrypt_data(enc,
    ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);

  ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);

}


TEST(c_structured_encrypt, error_handling_invalid_papi)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_structured_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}

TEST(c_structured_encrypt, error_handling_invalid_sapi)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_structured_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);


    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}

TEST(c_structured_encrypt, error_handling_invalid_rsa)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_structured_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}

TEST(c_structured_encrypt, error_handling_invalid_host)
{
    static const char * const pt =  ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds_orig;
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    // Use PT as CT for decrypt.  Should fail the same way
    res = ubiq_platform_structured_decrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_NE(res, 0);
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    EXPECT_NE(err_num, 0);
    EXPECT_TRUE(err_msg != NULL);
    free(err_msg);
    free(ctbuf);

    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_credentials_destroy(creds_orig);
}


TEST(c_structured_encrypt, error_handling_invalid_keynum)
{

  static const char * const pt = "0123456789";
  static const char * const ffs_name = "SSN";

  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_structured_enc_dec_obj *enc;
  char * ctbuf(nullptr);
  size_t ctlen;
  char * ptbuf(nullptr);
  size_t ptlen;
  int res;

  char * err_msg = NULL;
  int err_num;

  res = ubiq_platform_credentials_create(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  ASSERT_EQ(res, 0);

  // Encrypt should be fine
  res = ubiq_platform_structured_encrypt_data(enc,
     ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
  EXPECT_EQ(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_EQ(err_num, 0);
  EXPECT_TRUE(err_msg == NULL);
  free(err_msg);

  ctbuf[0] = '}'; // Invalid character for encoded key material

  res = ubiq_platform_structured_decrypt_data(enc,
    ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
  EXPECT_NE(res, 0);
  ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  EXPECT_NE(err_num, 0);
  EXPECT_TRUE(err_msg != NULL);
  free(err_msg);
  free(ctbuf);
  free(ptbuf);

  ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);

}

TEST(c_structured_encrypt, load_cache_ssn)
{
  int res = 0;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);

    res = ubiq_platform_structured_load_cache_dataset(enc, "SSN");
    EXPECT_EQ(res, 0);

  ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);
}

TEST(c_structured_encrypt, load_cache_alphanum_ssn)
{
  int res = 0;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);

    res = ubiq_platform_structured_load_cache_dataset(enc, "ALPHANUM_SSN");
    EXPECT_EQ(res, 0);

  ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);
}

TEST(c_structured_encrypt, load_cache_2)
{
  int res = 0;
  char const * dataset_names[3];
  dataset_names[0] = "SSN";
  dataset_names[1] = "ALPHANUM_SSN";
  dataset_names[2] = "BAD";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);

    res = ubiq_platform_structured_load_cache_datasets(enc, dataset_names, 2);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_load_cache_datasets(enc, dataset_names, 3);
    EXPECT_EQ(res, 0);

    ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);
}

TEST(c_structured_encrypt, load_cache_3)
{
  int res = 0;
  char const * dataset_names[6];
  dataset_names[0] = "BAD2";
  dataset_names[1] = "SSN";
  dataset_names[2] = "BAD";
  dataset_names[3] = "ALPHANUM_SSN";
  dataset_names[4] = "BIRTH_DATE";
  dataset_names[5] = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;

    res = ubiq_platform_credentials_create(&creds);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);

    res = ubiq_platform_structured_load_cache_datasets(enc, dataset_names, 6);
    EXPECT_EQ(res, 0);

  ubiq_platform_structured_enc_dec_destroy(enc);
  ubiq_platform_credentials_destroy(creds);
}

TEST_F(cpp_structured_encrypt, 1m)
{
  std::string ffs_name("ALPHANUM_SSN");
  std::string pt("0123456789");
  std::string ct("");
  std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();

  _enc = ubiq::platform::structured::encryption(_creds);


  ct = _enc.encrypt(ffs_name, pt);

  for (unsigned long i = 0; i < 1000000; i++) {
      auto start = std::chrono::steady_clock::now();

      ct = _enc.encrypt(ffs_name, pt);
      auto end = std::chrono::steady_clock::now();

      ubiq_times += (end - start);
  }


  std::cerr << "\tSelect total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

}

TEST(c_structured_encrypt, new)
{
    static const char * const pt = ";0123456-789ABCDEF|";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf2, &ctlen2);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf2, ctlen2, &ptbuf2, &ptlen2);
    EXPECT_EQ(res, 0);
    //
    EXPECT_EQ(strcmp(pt, ptbuf),0);
    EXPECT_EQ(strcmp(pt, ptbuf2),0);

    EXPECT_EQ(ptlen, ctlen);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf2);
    free(ctbuf);
    free(ptbuf);
    free(ptbuf2);
}

TEST(c_structured_encrypt, new_2)
{
    static const char * const pt = "0123456-789";
//    static const char * const pt = "00001234567890";//234567890";
    static const char * const ffs_name = "ALPHANUM_SSN";
    static const char * const SSN = "SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
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

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf2, &ctlen2);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_decrypt_data(enc,
       ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strcmp(pt, ptbuf),0);

    EXPECT_EQ(ptlen, ctlen);

    free(ctbuf2);
    free(ctbuf);
    free(ptbuf);
    free(ptbuf2);

    res = ubiq_platform_structured_encrypt_data(enc,
      SSN, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strlen(pt), ctlen);

    res = ubiq_platform_structured_decrypt_data(enc,
       SSN, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strcmp(pt, ptbuf),0);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ctbuf);
    free(ptbuf);
}

TEST(c_structured_encrypt, get_usage)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char * buf(nullptr);
    char * buf2(nullptr);
    char * ctbuf(nullptr);
    size_t ctlen;
    size_t len;
    size_t len2;

    int res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res,0);
    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res,0);

    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf2, &len);
    EXPECT_EQ(res,0);
    EXPECT_NE(strcmp(buf, buf2), 0);

    free(ctbuf);
    free(buf);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res,0);

    // Second encrypt will have different usage string
    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res,0);
    EXPECT_NE(strcmp(buf, buf2), 0);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);
    free(buf);
    free(buf2);
    free(ctbuf);
}

TEST(c_structured_encrypt, get_usage_enc_dec)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char * buf(nullptr);
    char * buf2(nullptr);
    char * ctbuf(nullptr);
    char * ptbuf(nullptr);
    size_t ctlen;
    size_t len;
    size_t len2;

    int res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res,0);
    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res,0);

    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf2, &len);
    EXPECT_EQ(res,0);
    EXPECT_NE(strcmp(buf, buf2), 0);

    free(buf);

    res = ubiq_platform_structured_decrypt_data(enc,
      ffs_name, NULL, 0, ctbuf, ctlen, &ptbuf, &len);
    EXPECT_EQ(res,0);

    // Second encrypt will have different usage string
    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res,0);
    EXPECT_GT(strlen(buf), strlen(buf2));

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);
    free(buf);
    free(buf2);
    free(ctbuf);
    free(ptbuf);
}

TEST_F(cpp_structured_encrypt, get_usage)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    _enc = ubiq::platform::structured::encryption(_creds);
    std::string usage = _enc.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::string ct = _enc.encrypt(ffs_name, pt);
    std::string usage2 = _enc.get_copy_of_usage();
    EXPECT_NE(usage.compare(usage2), 0);

    ct = _enc.encrypt(ffs_name, pt);
    std::string usage3 = _enc.get_copy_of_usage();
    EXPECT_NE(usage3.compare(usage2), 0);
}


TEST_F(cpp_structured_encrypt, get_usage_enc_dec)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const dataset_name = "ALPHANUM_SSN";

    _enc = ubiq::platform::structured::encryption(_creds);
    _dec = ubiq::platform::structured::decryption(_creds);

    std::string usage = _enc.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::string usage2 = _dec.get_copy_of_usage();
    EXPECT_EQ(usage.compare(usage2), 0);

    std::string ct = _enc.encrypt(dataset_name, pt);
    std::string ptbuf = _dec.decrypt(dataset_name, ct);

    // Encrypt and Decrypt usage strings should be same length
    usage = _enc.get_copy_of_usage();
    EXPECT_GT(usage.length(),usage2.length());

    usage2 = _dec.get_copy_of_usage();
    EXPECT_EQ(usage.length(),usage2.length());
}


TEST(c_structured_encrypt, add_user_defined_metadata)
{
    static const char * const pt = ";0123456-789ABCDEF|";
    static const char * const ffs_name = "ALPHANUM_SSN";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char * buf(nullptr);
    char * ctbuf(nullptr);
    size_t ctlen;
    size_t len;
    size_t len2;

    int res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(NULL, NULL);
    EXPECT_NE(res, 0);

    char toolong[1050];
    memset(toolong, 'a', sizeof(toolong));
    toolong[sizeof(toolong)] = '\0';
    res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, toolong);
    EXPECT_NE(res, 0);

    res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, "not json");
    EXPECT_NE(res, 0);

    res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, "{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}");
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_data(enc,
      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res,0);

    free(buf);

    // Second encrypt will have different usage string
    res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res,0);
    EXPECT_NE(strcmp(buf, "{\"usage\":[]}"), 0);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_KEY"), nullptr);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_VALUE"), nullptr);
    EXPECT_NE(strstr(buf, "user_defined"), nullptr);
    
    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);
    free(buf);
    free(ctbuf);
}

TEST_F(cpp_structured_encrypt, add_user_defined_metadata)
{
  std::string pt(";0123456-789ABCDEF|");
  std::string ffs_name("ALPHANUM_SSN");

  _enc = ubiq::platform::structured::encryption(_creds);

  ASSERT_THROW(_enc.add_user_defined_metadata(""),std::system_error);
  ASSERT_THROW(_enc.add_user_defined_metadata("{"),std::system_error);
  ASSERT_NO_THROW(_enc.add_user_defined_metadata("{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}"));

  std::string ct = _enc.encrypt(ffs_name, pt);

  std::string usage = _enc.get_copy_of_usage();

  EXPECT_EQ(usage.find("{\"usage\":[]}"),  std::string::npos);
  EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_KEY"),  std::string::npos);
  EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_VALUE"),  std::string::npos);
  EXPECT_NE(usage.find("user_defined"),  std::string::npos);

}
