#include <gtest/gtest.h>
#include <string.h>

#include "ubiq/platform.h"
#include "ubiq/platform/internal/hashtable.h"


class cpp_htable_cache: public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq_platform_hashtable * _htable;
};

void cpp_htable_cache::SetUp(void)
{
  ASSERT_TRUE(0 == ubiq_platform_ht_create(50, &_htable));
  ASSERT_TRUE(NULL != _htable);
}

void cpp_htable_cache::TearDown(void)
{
  ubiq_platform_ht_destroy(_htable, &free);
}

TEST_F(cpp_htable_cache, get_empty)
{
  const char * const key = "key";

  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 0);
  EXPECT_EQ(ubiq_platform_ht_get(_htable, key),(void *) NULL);
}


// Using ASSERT to check on values that could cause a segfault later if invalid
TEST_F(cpp_htable_cache, get_and_remove)
{
  const char orig_value[] = "This is the value";
  const char second_value[] = "This is the second value";
  char  key[] = "key";
  char * value = strdup(orig_value);
  char * value2 = strdup(second_value);
  char * existing_value = NULL;
  
  // Put and verify it exists
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key, value, (void **)(void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  char * x = (char * )ubiq_platform_ht_get(_htable, key);
  ASSERT_NE((char *)NULL, x);
  EXPECT_EQ(strcmp(x, orig_value), 0);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 1);

  // Put new value and verify old value was returned
  EXPECT_EQ(ubiq_platform_ht_put(_htable, key, value2, (void **)&existing_value), 0);
  ASSERT_NE((char *)NULL, existing_value);
  EXPECT_EQ(strcmp(existing_value, orig_value), 0);
  free(existing_value);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 1);

  // Get current value and verify it is new value
  x = (char *)ubiq_platform_ht_get(_htable, key);
  ASSERT_NE((char*) NULL, x);
  EXPECT_EQ(strcmp(x, second_value), 0);

  // remove element
  x = (char *)ubiq_platform_ht_remove(_htable, key);
  ASSERT_NE((char*) NULL, x);
  EXPECT_EQ(strcmp(x, second_value), 0);
  free(x);

  // Verify get returns NULL
  x = (char *)ubiq_platform_ht_get(_htable, key);
  EXPECT_EQ((char*) NULL, x);

  // Verify remove returns NULL
  x = (char *)ubiq_platform_ht_remove(_htable, key);
  ASSERT_EQ((char*) NULL, x);

  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 0);

}


TEST_F(cpp_htable_cache, list_keys_and_values)
{
  const char first_value[] = "This is the value";
  const char second_value[] = "This is the second value";
  char  key1[] = "key";
  char  key2[] = "key2";
  char * value1 = strdup(first_value);
  char * value2 = strdup(second_value);
  char * existing_value = NULL;
  
  // Put and verify it exists
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key1, value1,(void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key2, value2,(void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 2);

  // Get the list of keys.  Make sure keys[0] != keys[1]
  // Make sure one of the keys matches key1 and one matches key2
  char * keys[2];
  EXPECT_EQ(0, ubiq_platform_ht_list_keys(_htable, keys, 2));
  EXPECT_NE(strcmp(keys[0], keys[1]), 0);
  EXPECT_TRUE((strcmp(keys[0], key1) == 0) || (strcmp(keys[0], key2) == 0 ));
  EXPECT_TRUE((strcmp(keys[0], key1) == 0) || (strcmp(keys[0], key2) == 0 ));

  // Get the list of values.  Make sure values[0] != values[1]
  // Make sure one of the values matches value1 and one matches value2
  void * values[2];
  EXPECT_EQ(0, ubiq_platform_ht_list_values(_htable, values, 2));
  EXPECT_NE(strcmp((char*)values[0], (char *)values[1]), 0);
  EXPECT_TRUE((strcmp((char *)values[0], value1) == 0) || (strcmp((char *)values[0], value2) == 0 ));
  EXPECT_TRUE((strcmp((char *)values[0], value1) == 0) || (strcmp((char *)values[0], value2) == 0 ));
}

TEST_F(cpp_htable_cache, clear)
{
  const char first_value[] = "This is the value";
  const char second_value[] = "This is the second value";
  char  key1[] = "key";
  char  key2[] = "key2";
  char * value1 = strdup(first_value);
  char * value2 = strdup(second_value);
  char * existing_value = NULL;

  // Put and verify it exists
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key1, value1, (void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key2, value2, (void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 2);

  EXPECT_EQ(ubiq_platform_ht_clear(_htable, free), 0);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 0);

  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key1, (void *)"value1", (void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key2, (void *)"value2", (void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 2);

  // memory doesn't need to be managed but needs to be cleared before DESTROY in class which uses free
  EXPECT_EQ(ubiq_platform_ht_clear(_htable, NULL), 0);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 0);
}


TEST_F(cpp_htable_cache, iterate)
{
  const char first_value[] = "This is the value";
  const char second_value[] = "This is the second value";
  char  key1[] = "key";
  char  key2[] = "key2";
  char * value1 = strdup(first_value);
  char * value2 = strdup(second_value);
  char * existing_value = NULL;
  
  // Put and verify it exists
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key1, value1, (void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(0, ubiq_platform_ht_put(_htable, key2, value2, (void **)&existing_value));
  EXPECT_EQ(existing_value, (char *)NULL);
  EXPECT_EQ(ubiq_platform_ht_element_count(_htable), 2);


  ubiq_platform_hash_elem_itr *it = NULL;
	ASSERT_EQ(ubiq_platform_ht_create_iterator(_htable, &it), 0);
	const char* k = ubiq_platform_ht_iterate_keys(it);

  int found[] = {0,0};

  while (k != NULL) {
    if (strcmp(k, key1) == 0) {
      found[0]++;
    } else     if (strcmp(k, key2) == 0) {
      found[1]++;
    } 
    k = ubiq_platform_ht_iterate_keys(it);
  }
  ubiq_platform_ht_destroy_iterator(it);

  // Expect both keys to have been found once
  EXPECT_EQ(found[0],1);
  EXPECT_EQ(found[1],1);

  // Iterate values
	ASSERT_EQ(ubiq_platform_ht_create_iterator(_htable, &it), 0);
	void* v = ubiq_platform_ht_iterate_values(it);

  int vfound[] = {0,0};

  while (v != NULL) {
    if (strcmp((char *)v, value1) == 0) {
      vfound[0]++;
    } else     if (strcmp((char *)v, value2) == 0) {
      vfound[1]++;
    } 
    v = ubiq_platform_ht_iterate_values(it);
  }
  ubiq_platform_ht_destroy_iterator(it);

  // Expect both values to have been found once
  EXPECT_EQ(vfound[0],1);
  EXPECT_EQ(vfound[1],1);


}
