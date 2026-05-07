#include <gtest/gtest.h>
#include <ubiq/platform/internal/structured_key_cache.h>

#include <ubiq/platform/configuration.h>
#include <ubiq/platform/credentials.h>


TEST(structured_key_cache, valid)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;

    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);


    res = ubiq_platform_structured_key_cache_create(
      creds, config, &error_buf, &key_cache);
    EXPECT_EQ(res, 0);
    ASSERT_NE(key_cache, nullptr);

    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}


TEST(structured_key_cache, get_key_encrypt)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_structured_key_t * key = nullptr;
    ubiq_platform_structured_key_t * key2 = nullptr;

    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_key_cache_create(
      creds, config, &error_buf, &key_cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(key_cache, nullptr);

    res = ubiq_platform_structured_key_cache_get_structured_key(key_cache,
      "SSN", -1, &key);
    EXPECT_EQ(res, 0);
    EXPECT_NE(key, nullptr);

    res = ubiq_platform_structured_key_cache_get_structured_key(key_cache,
      "SSN", key->key_number, &key2);
    EXPECT_EQ(res, 0);
    EXPECT_NE(key2, nullptr);
    EXPECT_EQ(key->key_number, key2->key_number);


    ubiq_platform_structured_key_cache_structured_key_destroy(key);
    ubiq_platform_structured_key_cache_structured_key_destroy(key2);
    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}

TEST(structured_key_cache, get_key_decrypt)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_structured_key_t * key = nullptr;
    ubiq_platform_structured_key_t * key2 = nullptr;

    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_structured_key_cache_create(
      creds, config, &error_buf, &key_cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(key_cache, nullptr);

    res = ubiq_platform_structured_key_cache_get_structured_key(key_cache,
      "SSN", 3, &key); // Latest in the key rotation
    EXPECT_EQ(res, 0);
    EXPECT_NE(key, nullptr);

    res = ubiq_platform_structured_key_cache_get_structured_key(key_cache,
      "SSN", -1, &key2);
    EXPECT_EQ(res, 0);
    EXPECT_NE(key2, nullptr);
    EXPECT_EQ(key->key_number, key2->key_number);


    ubiq_platform_structured_key_cache_structured_key_destroy(key);
    ubiq_platform_structured_key_cache_structured_key_destroy(key2);
    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}
