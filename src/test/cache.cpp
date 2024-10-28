#include <gtest/gtest.h>

#include "ubiq/platform.h"
#include "ubiq/platform/internal/cache.h"


class cpp_cache: public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq_platform_cache * _cache;
};

void cpp_cache::SetUp(void)
{
  ASSERT_TRUE(0 == ubiq_platform_cache_create(55, 24*60*60*3, &_cache));
  ASSERT_TRUE(NULL != _cache);
}

void cpp_cache::TearDown(void)
{
  ubiq_platform_cache_destroy(_cache);
}

TEST_F(cpp_cache, create)
{
  const char * key = "key";
  unsigned int count = 0;

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, key),(void *) NULL);
  EXPECT_EQ(ubiq_platform_cache_get_element_count(_cache, &count),0);
  EXPECT_EQ(count, 0);
}



TEST_F(cpp_cache, add)
{
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, "testtest");
  const char * key = "key       ";

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, key, data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, key),data),0);
//  const void * x= ubiq_platform_cache_find_element(_cache, key);

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, "wrong-key"),(void *) NULL);
}

TEST_F(cpp_cache, add_ttl_1)
{
  #define data3 "data add_expired"
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, data3);
  const char * key = "key       ";

  // Destroy cache and then rebuild with ttl as 1 second
  ubiq_platform_cache_destroy(_cache);
  ASSERT_TRUE(0 == ubiq_platform_cache_create(55, 1, &_cache));

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, key, data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, key),data3),0);
  sleep(2);
  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, key),(void *) NULL);
//  const void * x= ubiq_platform_cache_find_element(_cache, key);

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, "wrong-key"),(void *) NULL);
}

TEST_F(cpp_cache, add_ttl_0)
{
  #define data3 "data add_expired"
  char * const data = (char *)calloc(25, sizeof(char));
  strcpy(data, data3);
  const char * key = "key       ";

  // Destroy cache and then rebuild with ttl as 0 second
  ubiq_platform_cache_destroy(_cache);
  ASSERT_TRUE(0 == ubiq_platform_cache_create(55, 0, &_cache));

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, key),(void *) NULL);
  // Gets added but will already be considered expired for next find.
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, key, data, &free),0);
  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, key),(void *) NULL);

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, "wrong-key"),(void *) NULL);
}

TEST_F(cpp_cache, add_again)
{
  #define data1 "data 1"
  #define data2 "data 2"
  const char * first_key = "key1";
  char * first_data = (char *)calloc(25, sizeof(char));
  char * second_data = (char *)calloc(25, sizeof(char));

  snprintf(first_data, 25, data1);
  snprintf(second_data, 25, data2);

  // Attempt to add a second identical record when unexpired, get original data

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, first_key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, first_key, first_data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key),first_data),0);
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, first_key, second_data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key),data1),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key),data1),0);
  ASSERT_TRUE(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key), data2) != 0);
}

TEST_F(cpp_cache, add_again_expired)
{
  #define data1 "data 1"
  #define data2 "data 2"
  const char * first_key = "key1";
  char * first_data = (char *)calloc(25, sizeof(char));
  char * second_data = (char *)calloc(25, sizeof(char));

  snprintf(first_data, 25, data1);
  snprintf(second_data, 25, data2);

  // Destroy cache and then rebuild with ttl as 1 second
  ubiq_platform_cache_destroy(_cache);
  ASSERT_TRUE(0 == ubiq_platform_cache_create(55, 2, &_cache));

  // Attempt to add a second identical record when unexpired, get original data
  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, first_key),(void *) NULL);
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, first_key,  first_data, &free),0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key),data1),0);
  sleep(3);
  ASSERT_EQ(ubiq_platform_cache_add_element(_cache, first_key,  second_data, &free),0);
  ASSERT_TRUE(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key),data1) != 0);
  ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, first_key),data2),0);
}

TEST_F(cpp_cache, add_bad_duration)
{
  #define data1 "data 1"
  #define data2 "data 2"
  const char * first_key = "key1";
  char * first_data = (char *)calloc(25, sizeof(char));

  snprintf(first_data, 25, data1);

  ubiq_platform_cache_destroy(_cache);
  ASSERT_TRUE(0 == ubiq_platform_cache_create(55, 2, &_cache));

  ASSERT_EQ(ubiq_platform_cache_find_element(_cache, first_key),(void *) NULL);

  ubiq_platform_cache_destroy(_cache);
  ASSERT_FALSE(0 == ubiq_platform_cache_create(55, -1, &_cache));

  // Not added, so need to free own memory
  free(first_data);

}


TEST_F(cpp_cache, add_many)
{

  char * keys[10];
  for (int i = 0; i < 10; i++) {
    char * const data = (char *)calloc(25, sizeof(char));
    snprintf(data, 25, "test %d data", i);
    keys[i] = (char *) calloc(25, sizeof(char));
    snprintf(keys[i], 25, "key %d data", i);

    ASSERT_EQ(ubiq_platform_cache_find_element(_cache, keys[i]),(void *) NULL);
    ASSERT_EQ(ubiq_platform_cache_add_element(_cache, keys[i], data, &free),0);
    const void * x= ubiq_platform_cache_find_element(_cache, keys[i]);
    ASSERT_EQ(strcmp((char *)ubiq_platform_cache_find_element(_cache, keys[i]),data),0);

    ASSERT_EQ(ubiq_platform_cache_find_element(_cache, "wrong-key"),(char *) NULL);
  }

  // Random search for first and last and make sure data not the same
  ASSERT_TRUE(ubiq_platform_cache_find_element(_cache, keys[0]) != (void *)NULL);
  ASSERT_TRUE(ubiq_platform_cache_find_element(_cache, keys[9]) != (void *)NULL);
  ASSERT_TRUE(strcmp((char *)ubiq_platform_cache_find_element(_cache, keys[0]),(char *)ubiq_platform_cache_find_element(_cache, keys[9])) != 0);
  for (int i = 0; i < 10; i++) {
    free(keys[i]);
  }
}


static
void
action(const void *nodep, void *__closure)
{
    //  printf("action data start\n");

  int debug_flag = 1;
  static const char * const csu = "cache.cpp::action";

  // printf("action data(%p)\n", nodep);
  // struct cache_element * e = NULL;

  // char * e = NULL;

  // e = *(char **) nodep;
  (*(int *)__closure)++;
}


TEST_F(cpp_cache, walk_r)
{
  ubiq_platform_cache_destroy(_cache);
  ASSERT_TRUE(0 == ubiq_platform_cache_create(55, 0, &_cache));

  char * keys[10];
  for (int i = 0; i < 10; i++) {
    char * const data = (char *)calloc(25, sizeof(char));
    // printf("data %p\n", data);
    snprintf(data, 25, "test %d data", i);
    keys[i] = (char *) calloc(25, sizeof(char));
    snprintf(keys[i], 25, "key %d data", i);

    // printf("key: '%s'  data: %p '%s'\n", keys[i], data, data);

    ASSERT_EQ(ubiq_platform_cache_add_element(_cache, keys[i], data, &free),0);
    // TTL is 0 so should not be found BUT, walk will find it.
  }

  int count = 0;

  // Walking does not check expiration
  ubiq_platform_cache_walk_r(_cache, action, (void *)&count);

  EXPECT_EQ(count, 10);

  // Walk did not remove items
  for (int i = 0; i < 10; i++) {
      ASSERT_EQ(ubiq_platform_cache_find_element(_cache, keys[i]), (void *)NULL);
  }

  // // Random search for first and last and make sure data not the same
  for (int i = 0; i < 10; i++) {
    free(keys[i]);
  }
}