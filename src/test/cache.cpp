#include <gtest/gtest.h>

#include "ubiq/platform.h"
#include "ubiq/platform/internal/cache.h"


class cpp_ffs_cache: public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq_platform_cache * _ffs_tree;
    ubiq::platform::credentials _creds;
    ubiq::platform::encryption _enc;
};

void cpp_ffs_cache::SetUp(void)
{
  ASSERT_TRUE(0 == ubiq_platform_cache_create(&_ffs_tree));
  ASSERT_TRUE(NULL != _ffs_tree);
}

void cpp_ffs_cache::TearDown(void)
{
  ubiq_platform_cache_destroy(_ffs_tree);
}

TEST_F(cpp_ffs_cache, find)
{
  const char * key = "key";

  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, key),(void *) NULL);
}

TEST_F(cpp_ffs_cache, add)
{
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, "testtest");
  const char * key = "key       ";

  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, key, 24*60*60*3, data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, key),data),0);
//  const void * x= ubiq_platform_cache_find_element(_ffs_tree, key);

  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, "wrong-key"),(void *) NULL);
}

TEST_F(cpp_ffs_cache, add_expired)
{
  #define data3 "data add_expired"
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, data3);
  const char * key = "key       ";

  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, key, 1, data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, key),data3),0);
  sleep(2);
  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, key),(void *) NULL);
//  const void * x= ubiq_platform_cache_find_element(_ffs_tree, key);

  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, "wrong-key"),(void *) NULL);
}

TEST_F(cpp_ffs_cache, add_again)
{
  #define data1 "data 1"
  #define data2 "data 2"
  const char * first_key = "key1";
  char * first_data = (char *)calloc(25, sizeof(char));
  char * second_data = (char *)calloc(25, sizeof(char));

  snprintf(first_data, 25, data1);
  snprintf(second_data, 25, data2);

  // Attempt to add a second identical record when unexpired, get original data

  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, first_key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, first_key,  24*60*60*3, first_data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key),first_data),0);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, first_key,  24*60*60*3, second_data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key),data1),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key),data1),0);
  ASSERT_TRUE(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key), data2) != 0);
}

TEST_F(cpp_ffs_cache, add_again_expired)
{
  #define data1 "data 1"
  #define data2 "data 2"
  const char * first_key = "key1";
  char * first_data = (char *)calloc(25, sizeof(char));
  char * second_data = (char *)calloc(25, sizeof(char));

  snprintf(first_data, 25, data1);
  snprintf(second_data, 25, data2);

  // Attempt to add a second identical record when unexpired, get original data
  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, first_key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, first_key,  2, first_data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key),data1),0);
  sleep(3);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, first_key,  24*60*60*3, second_data, &free),0);
  ASSERT_TRUE(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key),data1) != 0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, first_key),data2),0);
}

TEST_F(cpp_ffs_cache, add_bad_duration)
{
  #define data1 "data 1"
  #define data2 "data 2"
  const char * first_key = "key1";
  char * first_data = (char *)calloc(25, sizeof(char));

  snprintf(first_data, 25, data1);

  // Attempt to add a second identical record when unexpired, get original data
  ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, first_key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, first_key,  -1, first_data, &free), -EINVAL);

  // Not added, so need to free own memory
  free(first_data);

}


TEST_F(cpp_ffs_cache, add_many)
{
  char * keys[10];
  for (int i = 0; i < 10; i++) {
    char * const data = (char *)calloc(25, sizeof(char));
    snprintf(data, 25, "test %d data", i);
    keys[i] = (char *) calloc(25, sizeof(char));
    snprintf(keys[i], 25, "key %d data", i);

    ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, keys[i]),(void *) NULL);
    ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, keys[i], 0, data, &free),0);
    const void * x= ubiq_platform_cache_find_element(_ffs_tree, keys[i]);
    ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, keys[i]),data),0);

    ASSERT_EQ(ubiq_platform_cache_find_element(_ffs_tree, "wrong-key"),(char *) NULL);
  }

  // Random search for first and last and make sure data not the same
  ASSERT_TRUE(ubiq_platform_cache_find_element(_ffs_tree, keys[0]) != (void *)NULL);
  ASSERT_TRUE(ubiq_platform_cache_find_element(_ffs_tree, keys[9]) != (void *)NULL);
  ASSERT_TRUE(strcmp((char *)ubiq_platform_cache_find_element(_ffs_tree, keys[0]),(char *)ubiq_platform_cache_find_element(_ffs_tree, keys[9])) != 0);
  for (int i = 0; i < 10; i++) {
    free(keys[i]);
  }
}


static
void
action(const void *nodep, VISIT which, void *__closure)
{
  int debug_flag = 1;
  static const char * const csu = "cache.cpp::action";


  // struct cache_element * e = NULL;

  char * e = NULL;

   switch (which) {
  case leaf:
    e = *(char **) nodep;

    // printf("leaf key (%p): \n", e->key);
    // printf("leaf data (%s): \n", e->data;

    // printf("%s leaf nodep (%p): \n", csu, (char *)nodep);
    // printf("%s leaf e (%p): \n", csu, e);
    // printf("%s leaf e (%s): \n", csu, e);

    // printf("leaf data (%s): \n", e);
    // printf("leaf data (%s): \n", *e);

    // printf("leaf data: (%s}\n", data);
    (*(int *)__closure)++;
    break;

  case preorder:
    // printf("preorder: \n");
    break;
  case postorder:
    e = *(char **) nodep;
    // printf("postorder nodep (%p): \n", (char *)nodep);
    // printf("postorder *nodep (%p): \n", *(char *)nodep);
    // printf("postorder *(char **)nodep (%p): \n", (char **)nodep);
    // printf("postorder **(char ***)nodep (%p): \n", **(char ***)nodep);
    (*(int *)__closure)++;
    break;
  case endorder:
    // printf("endorder: \n");
    break;


  default:
    // printf("not leaf: \n");
    break;
  }

}


TEST_F(cpp_ffs_cache, walk_r)
{
  char * keys[10];
  for (int i = 0; i < 10; i++) {
    char * const data = (char *)calloc(25, sizeof(char));
    // printf("data %p\n", data);
    snprintf(data, 25, "test %d data", i);
    keys[i] = (char *) calloc(25, sizeof(char));
    snprintf(keys[i], 25, "key %d data", i);

    // printf("key: '%s'  data: %p '%s'\n", keys[i], data, data);



    ASSERT_EQ(ubiq_platform_cache_add_element(_ffs_tree, keys[i], 0, data, &free),0);
  }

  int count = 0;

   ubiq_platform_cache_walk_r(_ffs_tree, action, (void *)&count);

  // printf("after ubiq_platform_cache_walk_r %d\n", count);

  // // Random search for first and last and make sure data not the same
  for (int i = 0; i < 10; i++) {
    free(keys[i]);
  }
}