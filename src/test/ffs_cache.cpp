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
  const char * key = "key";

  ASSERT_EQ(find_element(_ffs_tree, key),(void *) NULL);
}

TEST_F(cpp_ffs_cache, add)
{
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, "testtest");
  const char * key = "key       ";

  ASSERT_EQ(find_element(_ffs_tree, key),(void *) NULL);
  ASSERT_EQ(add_element(_ffs_tree, key, data, &free),0);
//  const void * x= find_element(_ffs_tree, key);
  ASSERT_EQ(strcmp((char *)find_element(_ffs_tree, key),data),0);

  ASSERT_EQ(find_element(_ffs_tree, "wrong-key"),(void *) NULL);
}


TEST_F(cpp_ffs_cache, add_many)
{
  char * keys[10];
  for (int i = 0; i < 10; i++) {
    char * const data = (char *)calloc(25, sizeof(char));
    snprintf(data, 25, "test %d data", i);
    keys[i] = (char *) calloc(25, sizeof(char));
    snprintf(keys[i], 25, "key %d data", i);

    ASSERT_EQ(find_element(_ffs_tree, keys[i]),(void *) NULL);
    ASSERT_EQ(add_element(_ffs_tree, keys[i], data, &free),0);
    const void * x= find_element(_ffs_tree, keys[i]);
    ASSERT_EQ(strcmp((char *)find_element(_ffs_tree, keys[i]),data),0);

    ASSERT_EQ(find_element(_ffs_tree, "wrong-key"),(char *) NULL);
  }

  // Random search for first and last and make sure data not the same
  ASSERT_TRUE(find_element(_ffs_tree, keys[0]) != (void *)NULL);
  ASSERT_TRUE(find_element(_ffs_tree, keys[9]) != (void *)NULL);
  ASSERT_TRUE(strcmp((char *)find_element(_ffs_tree, keys[0]),(char *)find_element(_ffs_tree, keys[9])) != 0);
  for (int i = 0; i < 10; i++) {
    free(keys[i]);
  }
}
