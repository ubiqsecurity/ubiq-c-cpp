#include <gtest/gtest.h>

#include "ubiq/platform.h"
#include "ubiq/platform/internal/ffs_cache.h"


class cpp_ffs_cache: public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    void * _ffs_tree;
    ubiq::platform::credentials _creds;
    ubiq::platform::encryption _enc;
};

void cpp_ffs_cache::SetUp(void)
{
  ASSERT_TRUE(0 == create_ffs_cache(&_ffs_tree));
  ASSERT_TRUE(NULL != _ffs_tree);
}

void cpp_ffs_cache::TearDown(void)
{
  destroy_ffs_cache(_ffs_tree);
}

TEST_F(cpp_ffs_cache, find)
{
//  char * const data = (char *)calloc(25, sizeof(char));
//  strcpy(data, "test");
  const char * key = "key";

  ASSERT_EQ(find_element(_ffs_tree, key),(char *) NULL);
}

TEST_F(cpp_ffs_cache, add)
{
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, "testtest");
  const char * key = "key       ";

  ASSERT_EQ(find_element(_ffs_tree, key),(char *) NULL);
  ASSERT_EQ(add_element(_ffs_tree, key, data, &free),0);
  const char * x= find_element(_ffs_tree, key);
  ASSERT_EQ(strcmp(find_element(_ffs_tree, key),data),0);

  ASSERT_EQ(find_element(_ffs_tree, "wrong-key"),(char *) NULL);
//  free(data);
}

// TEST_F(cpp_fpe_encrypt, simple)
// {
//     std::string pt("ABC");
//     std::vector<std::uint8_t> v;
//
//     ASSERT_NO_THROW(
//         v = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));
// }
//
// TEST(c_fpe_encrypt, simple)
// {
//     static const char * const pt = " 01121231231231231& 1 &231120001&-0-8-9";
// //    static const char * const pt = "00001234567890";//234567890";
//     static const char * const ffs_name = "ALPHANUM_SSN";
//
//     struct ubiq_platform_credentials * creds;
//     char * ctbuf(nullptr);
//     size_t ctlen;
//     char * ptbuf(nullptr);
//     size_t ptlen;
//     int res;
//
//     res = ubiq_platform_credentials_create(&creds);
//     ASSERT_EQ(res, 0);
//
//     res = ubiq_platform_fpe_encrypt(creds,
//       ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
//     EXPECT_EQ(res, 0);
//
//     res = ubiq_platform_fpe_decrypt(creds,
//       ffs_name, NULL, 0, (char *)ctbuf, strlen(ctbuf), &ptbuf, &ptlen);
//     EXPECT_EQ(res, 0);
//
//     EXPECT_EQ(strcmp(pt, ptbuf),0);
//
//     ubiq_platform_credentials_destroy(creds);
//
//     free(ctbuf);
//     free(ptbuf);
// }
