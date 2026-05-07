#include <gtest/gtest.h>
#include <unistr.h>
#include <uniwidth.h>
#include <chrono>

#include "ubiq/platform.h"
#include <ubiq/platform/internal/credentials.h>
#include <ubiq/platform/internal/parsing.h>


static
void c_test_rt(
  const char * const dataset_name,
  const char32_t * const pt) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    char32_t * ctbuf(nullptr);
    size_t ctlen;
    char32_t * ptbuf(nullptr);
    size_t ptlen;

    char32_t ** ct_arr(nullptr);
    size_t ctcount(0);

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_u32data(enc,
      dataset_name, NULL, 0, pt, u32_strlen((uint32_t*)pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_structured_decrypt_u32data(enc,
      dataset_name, NULL, 0, ctbuf, ctlen, &ptbuf, &ptlen);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strcmp32(pt, ptbuf),0);

    res = ubiq_platform_structured_encrypt_u32data_for_search(enc,
      dataset_name, NULL, 0, pt, u32_strlen((uint32_t*)pt), &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);
    free(ptbuf);
    bool found_ct(false);
    for (int i = 0; i < ctcount; i++) {

      found_ct = found_ct || (u32_strcmp((uint32_t*)ct_arr[i], (uint32_t*)ctbuf) == 0);

      char32_t * ptbuf = NULL;
      size_t ptlen = 0;

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_structured_decrypt_u32data(enc,
         dataset_name, NULL, 0, ct_arr[i], u32_strlen((uint32_t*)ct_arr[i]), &ptbuf, &ptlen);
      EXPECT_EQ(res, 0) << "i (" << i << ")  ct_arr[i](" << ct_arr[i] << ")  ptbuf (" << ptbuf << ")" << std::endl;

      EXPECT_EQ(u32_strcmp((uint32_t*)pt, (uint32_t*)ptbuf),0);
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
    

}

void c_test_rt(
  const char * const dataset_name,
  const int32_t pt) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    int32_t ct = 0;
    int32_t pt_tmp = 0;

    int32_t * ct_arr(nullptr);
    size_t ctcount(0);

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_int_data(enc,
      dataset_name, NULL, 0, pt, &ct);
    EXPECT_EQ(res, 0);
    
    // // EXPECT_EQ(u8_mbsnlen((uint8_t *)pt, strlen(pt)), u8_mbsnlen((uint8_t *)ctbuf, strlen(ctbuf) ));

    res = ubiq_platform_structured_decrypt_int_data(enc,
      dataset_name, NULL, 0, ct, &pt_tmp);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(pt, pt_tmp);

    res = ubiq_platform_structured_encrypt_int_data_for_search(enc,
      dataset_name, NULL, 0, pt, &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    for (int i = 0; i < ctcount; i++) {
      found_ct = (found_ct || ct_arr[i] == ct);

    //   char * ptbuf = NULL;
    //   size_t ptlen = 0;

    //   // Decrypt each one and confirm results match PT
      res = ubiq_platform_structured_decrypt_int_data(enc,
         dataset_name, NULL, 0, ct_arr[i], &pt_tmp);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(pt_tmp, pt) << "i (" << i << ")  ct_arr[i](" << ct_arr[i] << ")  pt_tmp (" << pt_tmp << ")" << std::endl;

    }
    free(ct_arr);
    EXPECT_TRUE(found_ct);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

}


void c_test_rt(
  const char * const dataset_name,
  const int64_t pt) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    int64_t ct = 0;
    int64_t pt_tmp = 0;

    int64_t * ct_arr(nullptr);
    size_t ctcount(0);

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_long_data(enc,
      dataset_name, NULL, 0, pt, &ct);
    EXPECT_EQ(res, 0);
    
    res = ubiq_platform_structured_decrypt_long_data(enc,
      dataset_name, NULL, 0, ct, &pt_tmp);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(pt, pt_tmp);

    res = ubiq_platform_structured_encrypt_long_data_for_search(enc,
      dataset_name, NULL, 0, pt, &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    for (int i = 0; i < ctcount; i++) {

      found_ct = (found_ct || ct_arr[i] == ct);

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_structured_decrypt_long_data(enc,
         dataset_name, NULL, 0, ct_arr[i], &pt_tmp);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(pt_tmp, pt) << "i (" << i << ")  ct_arr[i](" << ct_arr[i] << ")  pt_tmp (" << pt_tmp << ")" << std::endl;
    }
    EXPECT_TRUE(found_ct);
    free(ct_arr);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

}


void c_test_rt(
  const char * const dataset_name,
  struct tm * pt) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    struct tm * ct = NULL;
    struct tm * pt_tmp = NULL;

    struct tm * ct_arr(nullptr);
    size_t ctcount(0);

    ct = (struct tm *)calloc(1, sizeof(*ct));
    pt_tmp = (struct tm *)calloc(1, sizeof(*pt_tmp));

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_date_data(enc,
      dataset_name, NULL, 0, pt, ct);
    EXPECT_EQ(res, 0);
    
    res = ubiq_platform_structured_decrypt_date_data(enc,
      dataset_name, NULL, 0, ct, pt_tmp);
    EXPECT_EQ(res, 0);

    time_t p = mktime(pt);
    time_t p_tmp = mktime(pt_tmp);
    EXPECT_EQ(p, p_tmp);


    res = ubiq_platform_structured_encrypt_date_data_for_search(enc,
      dataset_name, NULL, 0, pt, &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    time_t c = mktime(ct);
    for (int i = 0; i < ctcount; i++) {
      time_t c_tmp = mktime(&ct_arr[i]);

      found_ct = found_ct || (c == c_tmp);

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_structured_decrypt_date_data(enc,
         dataset_name, NULL, 0, &ct_arr[i], pt_tmp);
      EXPECT_EQ(res, 0) << "i (" << i << ")  ct_arr[i](" << asctime(&ct_arr[i]) << ")  ptbuf (" << asctime(pt_tmp) << ")" << std::endl;

      time_t p = mktime(pt);
      time_t p_tmp = mktime(pt_tmp);
      EXPECT_EQ(p, p_tmp);

    }

    EXPECT_TRUE(found_ct);

    free(ct_arr);
    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ct);
    free(pt_tmp);
    // free(ptbuf);

}


void c_test_batch_datetime_rt(
  const char * const dataset_name,
  struct tm * pt) {

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc;
    struct tm * ct = NULL;
    struct tm * pt_tmp = NULL;

    struct tm * ct_arr(nullptr);
    size_t ctcount(0);

    ct = (struct tm *)calloc(1, sizeof(*ct));
    pt_tmp = (struct tm *)calloc(1, sizeof(*pt_tmp));

    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_enc_dec_create(creds, &enc);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_encrypt_datetime_data(enc,
      dataset_name, NULL, 0, pt, ct);
    EXPECT_EQ(res, 0);
    
    res = ubiq_platform_structured_decrypt_datetime_data(enc,
      dataset_name, NULL, 0, ct, pt_tmp);
    EXPECT_EQ(res, 0);

    time_t p = mktime(pt);
    time_t p_tmp = mktime(pt_tmp);
    EXPECT_EQ(p, p_tmp);

    res = ubiq_platform_structured_encrypt_datetime_data_for_search(enc,
      dataset_name, NULL, 0, pt, &ct_arr, &ctcount);
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(ctcount >= 0);

    bool found_ct(false);
    time_t c = mktime(ct);
    for (int i = 0; i < ctcount; i++) {
      time_t c_tmp = mktime(&ct_arr[i]);

      found_ct = found_ct || (c == c_tmp);

      // Decrypt each one and confirm results match PT
      res = ubiq_platform_structured_decrypt_datetime_data(enc,
         dataset_name, NULL, 0, &ct_arr[i], pt_tmp);
      EXPECT_EQ(res, 0) << "i (" << i << ")  ct_arr[i](" << asctime(&ct_arr[i]) << ")  ptbuf (" << asctime(pt_tmp) << ")" << std::endl;

      time_t p = mktime(pt);
      time_t p_tmp = mktime(pt_tmp);
      EXPECT_EQ(p, p_tmp);

    }

    EXPECT_TRUE(found_ct);

    free(ct_arr);

    ubiq_platform_structured_enc_dec_destroy(enc);

    ubiq_platform_credentials_destroy(creds);

    free(ct);
    free(pt_tmp);
    // free(ptbuf);

}


TEST(c_structured_encrypt_pipeline, ALPHANUM_SSN_rt)
{
  c_test_rt("ALPHANUM_SSN", U";0123456-789ABCDEF|");
}

TEST(c_structured_encrypt_pipeline, UTF8_STRING_COMPLEX_rt)
{
  c_test_rt("UTF8_STRING_COMPLEX", U"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ");
}

TEST(c_structured_encrypt_pipeline, UTF8_STRING_COMPLEX_rt_1)
{
  c_test_rt("UTF8_STRING_COMPLEX", U"ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ");
}

TEST(c_structured_encrypt_pipeline, BIRTH_DATE_rt)
{
  c_test_rt("BIRTH_DATE", U";01\\02-1960|");
}

TEST(c_structured_encrypt_pipeline, SSN_rt)
{
  c_test_rt("SSN", U"-0-1-2-3-4-5-6-7-8-9-");
}

TEST(c_structured_encrypt_pipeline, integer32_rt)
{
  c_test_rt("integer32", 5);
}

TEST(c_structured_encrypt_pipeline, integer32_rt_2)
{
  c_test_rt("integer32", 44151081);
}

TEST(c_structured_encrypt_pipeline, integer64_rt)
{
  c_test_rt("integer64", 50L);
}

TEST(c_structured_encrypt_pipeline, integer64_rt_2)
{
  c_test_rt("integer64", -1013971772118990L);
}

TEST(c_structured_encrypt_pipeline, token64_rt)
{
  c_test_rt("token64", U"123");
}

TEST(c_structured_encrypt_pipeline, token128_rt)
{
  c_test_rt("token128", U"123");
}

TEST(c_structured_encrypt_pipeline, generic_rt)
{
  c_test_rt("generic_string", U"abcdefghijklmnop");
}

TEST(c_structured_encrypt_pipeline, generic32_rt)
{
  c_test_rt("generic_string_32", U"123");
}

TEST(c_structured_encrypt_pipeline, generic64_rt)
{
  c_test_rt("generic_string_64", U"123");
}

TEST(c_structured_encrypt_pipeline, date_rt)
{
  time_t now = time(NULL);
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  localtime_r(&now, local);
  local->tm_hour = local->tm_min = local->tm_sec = 0;

  c_test_rt("date", local);
  local->tm_year = 1600 - 1900;
  c_test_rt("date", local);
  free(local);
}

TEST(c_structured_encrypt_pipeline, date_rt_2)
{
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  ubiq_platform_parse_iso8601("1619-08-31T00:00Z", local);

  c_test_rt("date", local);
  free(local);
}

TEST(c_structured_encrypt_pipeline, datetime_rt)
{
  time_t now = time(NULL);
  struct tm * local = (struct tm *) calloc(1, sizeof(struct tm));
  localtime_r(&now, local);

  c_test_batch_datetime_rt("datetime", local);
  local->tm_year = 1700 - 1900;
  c_test_batch_datetime_rt("datetime", local);
  free(local);
}



// TEST(c_structured_encrypt, piecewise_bad_char)
// {
//     static const char * const pt = "123 456-7abc";
// //    static const char * const pt = "00001234567890";//234567890";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_old_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * ptbuf(nullptr);
//     size_t ptlen;
//     int res;

//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     // EXPECT_EQ(res, -EINVAL);
//     // EXPECT_EQ(strlen(pt), ctlen);


//     // EXPECT_EQ(strcmp(pt, ptbuf),0);

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     free(ctbuf);
//     free(ptbuf);
// }

// TEST(c_structured_encrypt, 1m)
// {
//   static const char * const ffs_name = "ALPHANUM_SSN";
//   static const char * const pt = "0123456789";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;

//     char * ctbuf(nullptr);
//     size_t ctlen;

//     std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
//     std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

//     int res;
//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//         auto start = std::chrono::steady_clock::now();
//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//       free(ctbuf);
//     auto end = std::chrono::steady_clock::now();
//     first_call = (end - start);

//     for (unsigned long i = 0; i < 1000000; i++) {
//         auto start = std::chrono::steady_clock::now();
//         res = ubiq_platform_structured_encrypt_data(enc,
//           ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//           free(ctbuf);
//         auto end = std::chrono::steady_clock::now();

//         ubiq_times += (end - start);
//     }

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
//     std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

// }

// TEST(c_structured_encrypt, u32_1m)
// {
//   static const char * const ffs_name = "UTF8_STRING_COMPLEX";
//   static const char * const pt = "は世界abcdefghijklmnop";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;

//     char * ctbuf(nullptr);
//     size_t ctlen(0);

//     std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
//     std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

//     int res;
//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//         auto start = std::chrono::steady_clock::now();
//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//       free(ctbuf);
//     auto end = std::chrono::steady_clock::now();
//     first_call = (end - start);

//     for (unsigned long i = 0; i < 1000000; i++) {
//         auto start = std::chrono::steady_clock::now();
//         res = ubiq_platform_structured_encrypt_data(enc,
//           ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//           free(ctbuf);
//         auto end = std::chrono::steady_clock::now();

//         ubiq_times += (end - start);
//     }

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
//     std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

// }


// TEST(c_structured_decrypt, 1m)
// {
//   static const char * const ffs_name = "ALPHANUM_SSN";
//   static const char * const ct = ";!!!E7`+-ai1ykOp8r|";

//   struct ubiq_platform_credentials * creds;
//   struct ubiq_platform_structured_enc_dec_obj *enc;

//   char * ptbuf(nullptr);
//   size_t ptlen(0);

//   std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();
//   std::chrono::duration<double, std::nano> first_call = std::chrono::steady_clock::duration::zero();

//   int res;
//   res = ubiq_platform_credentials_create(&creds);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//   ASSERT_EQ(res, 0);

//       auto start = std::chrono::steady_clock::now();
//   res = ubiq_platform_structured_decrypt_data(enc,
//     ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
//     free(ptbuf);
//   auto end = std::chrono::steady_clock::now();
//   first_call = (end - start);

//     for (unsigned long i = 0; i < 1000000; i++) {
//         auto start = std::chrono::steady_clock::now();
//     res = ubiq_platform_structured_decrypt_data(enc,
//       ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
//           free(ptbuf);
//         auto end = std::chrono::steady_clock::now();

//         ubiq_times += (end - start);
//     }

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     std::cerr << "\t first: " << std::chrono::duration<double, std::milli>(first_call).count() << " ms " << std::endl;
//     std::cerr << "\t total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

// }

// TEST(c_structured_encrypt, piecewise_cached)
// {
//     static const char * const pt = "0123456-789ABCDEF";
// //    static const char * const pt = "00001234567890";//234567890";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * ptbuf(nullptr);
//     size_t ptlen;
//     int res;

//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res, 0);
//     EXPECT_EQ(strlen(pt), ctlen);

//     free(ctbuf);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res, 0);
//     EXPECT_EQ(strlen(pt), ctlen);

//     // EXPECT_EQ(strcmp(pt, ptbuf),0);

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     free(ctbuf);
//     free(ptbuf);
// }

// TEST(c_structured_encrypt, piecewise2)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
// //    static const char * const pt = "00001234567890";//234567890";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * ctbuf2(nullptr);
//     size_t ctlen2;
//     char * ptbuf(nullptr);
//     size_t ptlen;
//     char * ptbuf2(nullptr);
//     size_t ptlen2;
//     int res;

//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res, 0);
//     EXPECT_EQ(strlen(pt), ctlen);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf2, &ctlen2);
//     EXPECT_EQ(res, 0);

//     res = ubiq_platform_structured_decrypt_data(enc,
//        ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
//     EXPECT_EQ(res, 0);

//     res = ubiq_platform_structured_decrypt_data(enc,
//        ffs_name, NULL, 0, (char *)ctbuf2, ctlen2, &ptbuf2, &ptlen2);
//     EXPECT_EQ(res, 0);
//     //
//     EXPECT_EQ(strcmp(pt, ptbuf),0);
//     EXPECT_EQ(strcmp(pt, ptbuf2),0);

//     EXPECT_EQ(ptlen, ctlen);

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     free(ctbuf2);
//     free(ctbuf);
//     free(ptbuf);
//     free(ptbuf2);
// }


// TEST(c_structured_encrypt, 10_cycles)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
// //    static const char * const pt = "00001234567890";//234567890";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;

//     int res;

//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     for (int i = 0; i < 10; i++) {
//       char * ctbuf(nullptr);
//       size_t ctlen;
//       char * ptbuf(nullptr);
//       size_t ptlen;

//       res = ubiq_platform_structured_encrypt_data(enc,
//         ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//       EXPECT_EQ(res, 0);
//       EXPECT_EQ(strlen(pt), ctlen);

//       res = ubiq_platform_structured_decrypt_data(enc,
//          ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
//       EXPECT_EQ(res, 0);

//       EXPECT_EQ(ptlen, ctlen);
//       EXPECT_EQ(strcmp(pt, ptbuf),0);
//       free(ctbuf);
//       free(ptbuf);
//     }
//     ubiq_platform_structured_enc_dec_destroy(enc);
//     ubiq_platform_credentials_destroy(creds);

// }


// TEST(c_structured_encrypt, error_handling_null_object)
// {
//   int err_num;
//   char * err_msg = NULL;
//   int res;

//   res = ubiq_platform_structured_get_last_error(NULL, &err_num, &err_msg);
//   ASSERT_EQ(res, -EINVAL);

// }

// TEST(c_structured_encrypt, error_handling_notnull_object)
// {
//   int err_num;
//   char * err_msg = NULL;
//   int res;

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj * enc;
//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     ASSERT_EQ(res, 0);
//     EXPECT_EQ(err_num, 0);
//     EXPECT_TRUE(err_msg == NULL);

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);
//     free(err_msg);

// }

// TEST(c_structured_encrypt, error_handling_invalid_ffs)
// {

//   static const char * const pt = ";0123456-789ABCDEF|";
//   static const char * const ffs_name = "ALPHANUM_SSN";

//   struct ubiq_platform_credentials * creds;
//   struct ubiq_platform_structured_enc_dec_obj *enc;
//   char * ctbuf(nullptr);
//   size_t ctlen;
//   int res;

//   char * err_msg = NULL;
//   int err_num;

//   res = ubiq_platform_credentials_create(&creds);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_encrypt_data(enc,
//      "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   // Use same PT as CT for decrypt.  Should fail the same way
//   res = ubiq_platform_structured_decrypt_data(enc,
//      "ERROR_MSG", NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   ubiq_platform_structured_enc_dec_destroy(enc);
//   ubiq_platform_credentials_destroy(creds);

// }

// TEST(c_structured_encrypt, error_handling_invalid_creds)
// {

//   static const char * const pt = ";0123456-789ABCDEF|";
//   static const char * const ffs_name = "ALPHANUM_SSN";

//   struct ubiq_platform_credentials * creds;
//   struct ubiq_platform_structured_enc_dec_obj *enc;
//   char * ctbuf(nullptr);
//   size_t ctlen;
//   int res;

//   char * err_msg = NULL;
//   int err_num;

//   res = ubiq_platform_credentials_create_explicit(
//       "invalid1", "invalid2",
//       "invalid3",
//       "https://koala.ubiqsecurity.com",
//       &creds);

//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_encrypt_data(enc,
//     ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   // Use same PT as CT, should faild the same way
//   res = ubiq_platform_structured_decrypt_data(enc,
//     ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   ubiq_platform_structured_enc_dec_destroy(enc);

//   ubiq_platform_credentials_destroy(creds);

//   free(ctbuf);
// }

// TEST(c_structured_encrypt, error_handling_invalid_PT_CT)
// {

//   static const char * const pt =  "-0-1-2-3-4-5-6-7-8-9$";
//   static const char * const ffs_name = "SSN";

//   struct ubiq_platform_credentials * creds;
//   struct ubiq_platform_structured_enc_dec_obj *enc;
//   char * ctbuf(nullptr);
//   size_t ctlen;
//   int res;

//   char * err_msg = NULL;
//   int err_num;

//   res = ubiq_platform_credentials_create(&creds);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_encrypt_data(enc,
//     ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   // Use same PT as invalid CT.  Should fail similarly
//   res = ubiq_platform_structured_decrypt_data(enc,
//     ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);


//   ubiq_platform_structured_enc_dec_destroy(enc);

//   ubiq_platform_credentials_destroy(creds);

//   free(ctbuf);
// }

// TEST(c_structured_encrypt, error_handling_invalid_LEN)
// {
//   static const char * const short_pt = " 123";
//   static const char * const long_pt = " 1234567890123123123123";
//   static const char * const ffs_name = "SSN";

//   struct ubiq_platform_credentials * creds;
//   struct ubiq_platform_structured_enc_dec_obj *enc;
//   char * ctbuf(nullptr);
//   size_t ctlen;
//   int res;

//   char * err_msg = NULL;
//   int err_num;

//   res = ubiq_platform_credentials_create(&creds);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_encrypt_data(enc,
//     ffs_name, NULL, 0, short_pt, strlen(short_pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   res = ubiq_platform_structured_encrypt_data(enc,
//     ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   // Use PT as CT for decrypt.  Should fail the same way
//   res = ubiq_platform_structured_decrypt_data(enc,
//     ffs_name, NULL, 0, short_pt, strlen(short_pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   res = ubiq_platform_structured_decrypt_data(enc,
//     ffs_name, NULL, 0, long_pt, strlen(long_pt), &ctbuf, &ctlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);

//   ubiq_platform_structured_enc_dec_destroy(enc);
//   ubiq_platform_credentials_destroy(creds);

// }


// TEST(c_structured_encrypt, error_handling_invalid_papi)
// {
//     static const char * const pt =  ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds_orig;
//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * err_msg = NULL;
//     int err_num;
//     int res = 0;

//     res = ubiq_platform_credentials_create(&creds_orig);
//     ASSERT_EQ(res, 0);

//     // Alter the original credential value
//     char * tmp_papi = strdup(ubiq_platform_credentials_get_papi(creds_orig));
//     ASSERT_NE(tmp_papi, (char *)NULL);
//     tmp_papi[strlen(tmp_papi) - 2] = '\0';

//     res = ubiq_platform_credentials_create_explicit(
//       tmp_papi,
//       ubiq_platform_credentials_get_sapi(creds_orig),
//       ubiq_platform_credentials_get_srsa(creds_orig),
//       ubiq_platform_credentials_get_host(creds_orig),
//       &creds
//     );
//     free(tmp_papi);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     // Use PT as CT for decrypt.  Should fail the same way
//     res = ubiq_platform_structured_decrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     ubiq_platform_structured_enc_dec_destroy(enc);
//     ubiq_platform_credentials_destroy(creds);
//     ubiq_platform_credentials_destroy(creds_orig);
// }

// TEST(c_structured_encrypt, error_handling_invalid_sapi)
// {
//     static const char * const pt =  ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds_orig;
//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * err_msg = NULL;
//     int err_num;
//     int res = 0;

//     res = ubiq_platform_credentials_create(&creds_orig);
//     ASSERT_EQ(res, 0);

//     // Alter the original credential value
//     char * tmp = strdup(ubiq_platform_credentials_get_sapi(creds_orig));
//     ASSERT_NE(tmp, (char *)NULL);
//     tmp[strlen(tmp) - 2] = '\0';

//     res = ubiq_platform_credentials_create_explicit(
//       ubiq_platform_credentials_get_papi(creds_orig),
//       tmp,
//       ubiq_platform_credentials_get_srsa(creds_orig),
//       ubiq_platform_credentials_get_host(creds_orig),
//       &creds
//     );
//     free(tmp);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     // Use PT as CT for decrypt.  Should fail the same way
//     res = ubiq_platform_structured_decrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);


//     ubiq_platform_structured_enc_dec_destroy(enc);
//     ubiq_platform_credentials_destroy(creds);
//     ubiq_platform_credentials_destroy(creds_orig);
// }

// TEST(c_structured_encrypt, error_handling_invalid_rsa)
// {
//     static const char * const pt =  ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds_orig;
//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * err_msg = NULL;
//     int err_num;
//     int res = 0;

//     res = ubiq_platform_credentials_create(&creds_orig);
//     ASSERT_EQ(res, 0);

//     // Alter the original credential value
//     char * tmp = strdup(ubiq_platform_credentials_get_srsa(creds_orig));
//     ASSERT_NE(tmp, (char *)NULL);
//     tmp[strlen(tmp) - 2] = '\0';

//     res = ubiq_platform_credentials_create_explicit(
//       ubiq_platform_credentials_get_papi(creds_orig),
//       ubiq_platform_credentials_get_sapi(creds_orig),
//       tmp,
//       ubiq_platform_credentials_get_host(creds_orig),
//       &creds
//     );
//     free(tmp);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     // Use PT as CT for decrypt.  Should fail the same way
//     res = ubiq_platform_structured_decrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     ubiq_platform_structured_enc_dec_destroy(enc);
//     ubiq_platform_credentials_destroy(creds);
//     ubiq_platform_credentials_destroy(creds_orig);
// }

// TEST(c_structured_encrypt, error_handling_invalid_host)
// {
//     static const char * const pt =  ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds_orig;
//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * err_msg = NULL;
//     int err_num;
//     int res = 0;

//     res = ubiq_platform_credentials_create(&creds_orig);
//     ASSERT_EQ(res, 0);

//     // Alter the original credential value
//     char * tmp = strdup(ubiq_platform_credentials_get_host(creds_orig));
//     ASSERT_NE(tmp, (char *)NULL);
//     tmp[strlen(tmp) - 2] = '\0';

//     res = ubiq_platform_credentials_create_explicit(
//       ubiq_platform_credentials_get_papi(creds_orig),
//       ubiq_platform_credentials_get_sapi(creds_orig),
//       ubiq_platform_credentials_get_srsa(creds_orig),
//       tmp,
//       &creds
//     );
//     free(tmp);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     // Use PT as CT for decrypt.  Should fail the same way
//     res = ubiq_platform_structured_decrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_NE(res, 0);
//     ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//     EXPECT_NE(err_num, 0);
//     EXPECT_TRUE(err_msg != NULL);
//     free(err_msg);
//     free(ctbuf);

//     ubiq_platform_structured_enc_dec_destroy(enc);
//     ubiq_platform_credentials_destroy(creds);
//     ubiq_platform_credentials_destroy(creds_orig);
// }


// TEST(c_structured_encrypt, error_handling_invalid_keynum)
// {

//   static const char * const pt = "0123456789";
//   static const char * const ffs_name = "SSN";

//   struct ubiq_platform_credentials * creds;
//   struct ubiq_platform_structured_enc_dec_obj *enc;
//   char * ctbuf(nullptr);
//   size_t ctlen;
//   char * ptbuf(nullptr);
//   size_t ptlen;
//   int res;

//   char * err_msg = NULL;
//   int err_num;

//   res = ubiq_platform_credentials_create(&creds);
//   ASSERT_EQ(res, 0);

//   res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//   ASSERT_EQ(res, 0);

//   // Encrypt should be fine
//   res = ubiq_platform_structured_encrypt_data(enc,
//      ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//   EXPECT_EQ(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_EQ(err_num, 0);
//   EXPECT_TRUE(err_msg == NULL);
//   free(err_msg);

//   ctbuf[0] = '}'; // Invalid character for encoded key material

//   res = ubiq_platform_structured_decrypt_data(enc,
//     ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
//   EXPECT_NE(res, 0);
//   ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
//   EXPECT_NE(err_num, 0);
//   EXPECT_TRUE(err_msg != NULL);
//   free(err_msg);
//   free(ctbuf);
//   free(ptbuf);

//   ubiq_platform_structured_enc_dec_destroy(enc);
//   ubiq_platform_credentials_destroy(creds);

// }


// TEST_F(cpp_structured_encrypt, 1m)
// {
//   std::string ffs_name("ALPHANUM_SSN");
//   std::string pt("0123456789");
//   std::string ct("");
//   std::chrono::duration<double, std::nano> ubiq_times = std::chrono::steady_clock::duration::zero();

//   _enc = ubiq::platform::structured::encryption(_creds);


//   ct = _enc.encrypt(ffs_name, pt);

//   for (unsigned long i = 0; i < 1000000; i++) {
//       auto start = std::chrono::steady_clock::now();

//       ct = _enc.encrypt(ffs_name, pt);
//       auto end = std::chrono::steady_clock::now();

//       ubiq_times += (end - start);
//   }


//   std::cerr << "\tSelect total: " << std::chrono::duration<double, std::milli>(ubiq_times).count() << " ms " << std::endl;

// }

// TEST(c_structured_encrypt, new)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
// //    static const char * const pt = "00001234567890";//234567890";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * ctbuf2(nullptr);
//     size_t ctlen2;
//     char * ptbuf(nullptr);
//     size_t ptlen;
//     char * ptbuf2(nullptr);
//     size_t ptlen2;
//     int res;

//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res, 0);
//     EXPECT_EQ(strlen(pt), ctlen);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf2, &ctlen2);
//     EXPECT_EQ(res, 0);

//     res = ubiq_platform_structured_decrypt_data(enc,
//        ffs_name, NULL, 0, (char *)ctbuf, ctlen, &ptbuf, &ptlen);
//     EXPECT_EQ(res, 0);

//     res = ubiq_platform_structured_decrypt_data(enc,
//        ffs_name, NULL, 0, (char *)ctbuf2, ctlen2, &ptbuf2, &ptlen2);
//     EXPECT_EQ(res, 0);
//     //
//     EXPECT_EQ(strcmp(pt, ptbuf),0);
//     EXPECT_EQ(strcmp(pt, ptbuf2),0);

//     EXPECT_EQ(ptlen, ctlen);

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);

//     free(ctbuf2);
//     free(ctbuf);
//     free(ptbuf);
//     free(ptbuf2);
// }

// TEST(c_structured_encrypt, get_usage)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * buf(nullptr);
//     char * buf2(nullptr);
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     size_t len;
//     size_t len2;

//     int res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res,0);

//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf2, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_NE(strcmp(buf, buf2), 0);

//     free(ctbuf);
//     free(buf);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res,0);

//     // Second encrypt will have different usage string
//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_NE(strcmp(buf, buf2), 0);

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);
//     free(buf);
//     free(buf2);
//     free(ctbuf);
// }

// TEST(c_structured_encrypt, get_usage_enc_dec)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * buf(nullptr);
//     char * buf2(nullptr);
//     char * ctbuf(nullptr);
//     char * ptbuf(nullptr);
//     size_t ctlen;
//     size_t len;
//     size_t len2;

//     int res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res,0);

//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf2, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_NE(strcmp(buf, buf2), 0);

//     free(buf);

//     res = ubiq_platform_structured_decrypt_data(enc,
//       ffs_name, NULL, 0, ctbuf, ctlen, &ptbuf, &len);
//     EXPECT_EQ(res,0);

//     // Second encrypt will have different usage string
//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_GT(strlen(buf), strlen(buf2));

//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);
//     free(buf);
//     free(buf2);
//     free(ctbuf);
//     free(ptbuf);
// }

// TEST_F(cpp_structured_encrypt, get_usage)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     _enc = ubiq::platform::structured::encryption(_creds);
//     std::string usage = _enc.get_copy_of_usage();
//     EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

//     std::string ct = _enc.encrypt(ffs_name, pt);
//     std::string usage2 = _enc.get_copy_of_usage();
//     EXPECT_NE(usage.compare(usage2), 0);

//     ct = _enc.encrypt(ffs_name, pt);
//     std::string usage3 = _enc.get_copy_of_usage();
//     EXPECT_NE(usage3.compare(usage2), 0);
// }


// TEST_F(cpp_structured_encrypt, get_usage_enc_dec)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
//     static const char * const dataset_name = "ALPHANUM_SSN";

//     _enc = ubiq::platform::structured::encryption(_creds);
//     _dec = ubiq::platform::structured::decryption(_creds);

//     std::string usage = _enc.get_copy_of_usage();
//     EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

//     std::string usage2 = _dec.get_copy_of_usage();
//     EXPECT_EQ(usage.compare(usage2), 0);

//     std::string ct = _enc.encrypt(dataset_name, pt);
//     std::string ptbuf = _dec.decrypt(dataset_name, ct);

//     // Encrypt and Decrypt usage strings should be same length
//     usage = _enc.get_copy_of_usage();
//     EXPECT_GT(usage.length(),usage2.length());

//     usage2 = _dec.get_copy_of_usage();
//     EXPECT_EQ(usage.length(),usage2.length());
// }


// TEST(c_structured_encrypt, add_user_defined_metadata)
// {
//     static const char * const pt = ";0123456-789ABCDEF|";
//     static const char * const ffs_name = "ALPHANUM_SSN";

//     struct ubiq_platform_credentials * creds;
//     struct ubiq_platform_structured_enc_dec_obj *enc;
//     char * buf(nullptr);
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     size_t len;
//     size_t len2;

//     int res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_create(creds, &enc);
//     ASSERT_EQ(res, 0);

//     res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(NULL, NULL);
//     EXPECT_NE(res, 0);

//     char toolong[1050];
//     memset(toolong, 'a', sizeof(toolong));
//     toolong[sizeof(toolong)] = '\0';
//     res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, toolong);
//     EXPECT_NE(res, 0);

//     res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, "not json");
//     EXPECT_NE(res, 0);

//     res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, "{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}");
//     EXPECT_EQ(res, 0);

//     res = ubiq_platform_structured_encrypt_data(enc,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res,0);

//     free(buf);

//     // Second encrypt will have different usage string
//     res = ubiq_platform_structured_enc_dec_get_copy_of_usage(enc, &buf, &len);
//     EXPECT_EQ(res,0);
//     EXPECT_NE(strcmp(buf, "{\"usage\":[]}"), 0);
//     EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_KEY"), nullptr);
//     EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_VALUE"), nullptr);
//     EXPECT_NE(strstr(buf, "user_defined"), nullptr);
    
//     ubiq_platform_structured_enc_dec_destroy(enc);

//     ubiq_platform_credentials_destroy(creds);
//     free(buf);
//     free(ctbuf);
// }

// TEST_F(cpp_structured_encrypt, add_user_defined_metadata)
// {
//   std::string pt(";0123456-789ABCDEF|");
//   std::string ffs_name("ALPHANUM_SSN");

//   _enc = ubiq::platform::structured::encryption(_creds);

//   ASSERT_THROW(_enc.add_user_defined_metadata(""),std::system_error);
//   ASSERT_THROW(_enc.add_user_defined_metadata("{"),std::system_error);
//   ASSERT_NO_THROW(_enc.add_user_defined_metadata("{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}"));

//   std::string ct = _enc.encrypt(ffs_name, pt);

//   std::string usage = _enc.get_copy_of_usage();

//   EXPECT_EQ(usage.find("{\"usage\":[]}"),  std::string::npos);
//   EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_KEY"),  std::string::npos);
//   EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_VALUE"),  std::string::npos);
//   EXPECT_NE(usage.find("user_defined"),  std::string::npos);

// }