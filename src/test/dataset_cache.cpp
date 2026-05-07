#include <gtest/gtest.h>
#include <ubiq/platform/internal/dataset_cache.h>

#include <ubiq/platform/configuration.h>
#include <ubiq/platform/credentials.h>
#include <ubiq/platform/internal/parsing.h>

static int create_dataset(char const * const name, cJSON ** const dataset_json) {
  int res = -EINVAL;
  std::string s;

  ubiq_platform_dataset_t * d = nullptr;

  s = "{" \
  "\"input_character_set\": \"0123456789\"," \
  "\"output_character_set\": \"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\"," \
  "\"min_input_length\": 10" \
  "}";

  cJSON *j = cJSON_ParseWithLength(s.data(), s.length());
  if (j != NULL && !cJSON_IsNull(j)) {
    res = 0;
  } else {
    res = -1;
    cJSON_Delete(j);
    j = NULL;
  }

  if (!res && name) {
    cJSON_AddStringToObject(j, "name", name);
  }

  if (!res) {
    *dataset_json = j;
  } else {
    cJSON_Delete(j);
  }


  return res;   
}


TEST(dataset_cache, valid)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_dataset_cache_t * cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds;
    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_dataset_cache_create(
      creds, config, &error_buf, &cache);
    EXPECT_EQ(res, 0);
    ASSERT_NE(cache, nullptr);

    ubiq_platform_dataset_cache_destroy(cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}

TEST(dataset_cache, add)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_dataset_cache_t * cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds;
    cJSON * dataset_json = nullptr;
    ubiq_platform_dataset_t const * dataset = nullptr;
    
    int res;

    res = create_dataset("test", &dataset_json);
    ASSERT_EQ(res, 0);
    ASSERT_NE(dataset_json, nullptr);

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_dataset_cache_create(
      creds, config, &error_buf, &cache);
    EXPECT_EQ(res, 0);
    ASSERT_NE(cache, nullptr);

    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);

    res = ubiq_platform_dataset_cache_add_dataset(cache, dataset_json, &dataset);
    EXPECT_EQ(res, 0);
    cJSON_Delete(dataset_json);

    res = ubiq_platform_dataset_cache_get_dataset(cache, "test", &dataset);
    EXPECT_EQ(res,0);
    EXPECT_NE(dataset, nullptr);
    EXPECT_EQ( strcmp(ubiq_platform_dataset_get_name(dataset), "test"), 0);


    ubiq_platform_dataset_cache_destroy(cache);
    // ubiq_platform_configuration_destroy(config);
    // ubiq_platform_credentials_destroy(creds);
}

TEST(dataset_cache, fetching)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_dataset_cache_t * cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds;
    ubiq_platform_dataset_t const * dataset = nullptr;
    ubiq_platform_dataset_t const * dataset2 = nullptr;
    
    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_dataset_cache_create(
      creds, config, &error_buf, &cache);
    EXPECT_EQ(res, 0);
    ASSERT_NE(cache, nullptr);

    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);

    // Should not already exist, so has to fetch from server
    res = ubiq_platform_dataset_cache_get_dataset(cache, "SSN", &dataset);
    EXPECT_EQ(res,0);
    EXPECT_NE(dataset, nullptr);
    EXPECT_EQ( strcmp(ubiq_platform_dataset_get_name(dataset), "SSN"), 0);

    // Should already exist and should return the same pointer
    res = ubiq_platform_dataset_cache_get_dataset(cache, "SSN", &dataset2);
    EXPECT_EQ(res,0);
    EXPECT_NE(dataset2, nullptr);
    EXPECT_EQ( strcmp(ubiq_platform_dataset_get_name(dataset2), "SSN"), 0);
    EXPECT_EQ(dataset, dataset2);


    ubiq_platform_dataset_cache_destroy(cache);
    // ubiq_platform_configuration_destroy(config);
    // ubiq_platform_credentials_destroy(creds);
}
