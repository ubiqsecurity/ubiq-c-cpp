#include <gtest/gtest.h>
#include <ubiq/platform/internal/ff1_cache.h>

#include <ubiq/platform/configuration.h>
#include <ubiq/platform/credentials.h>


TEST(ff1_cache, valid)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_ff1_cache_t * ff1_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_dataset_cache_t * dataset_cache = nullptr;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;

    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_dataset_cache_create(
      creds, config, &error_buf, &dataset_cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(dataset_cache, nullptr);

    res = ubiq_platform_structured_key_cache_create(
      creds, config, &error_buf, &key_cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(key_cache, nullptr);


    res = ubiq_platform_ff1_cache_create(
      creds, config, dataset_cache, key_cache, &error_buf, &ff1_cache);
    EXPECT_EQ(res, 0);
    ASSERT_NE(ff1_cache, nullptr);

    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_dataset_cache_destroy(dataset_cache);
    ubiq_platform_ff1_cache_destroy(ff1_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}

TEST(ff1_cache, get)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_ff1_cache_t * ff1_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_dataset_cache_t * dataset_cache = nullptr;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;

    int res;

    res = ubiq_platform_configuration_create(
      &config);
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_NE(creds, nullptr);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_dataset_cache_create(
      creds, config, &error_buf, &dataset_cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(dataset_cache, nullptr);

    res = ubiq_platform_structured_key_cache_create(
      creds, config, &error_buf, &key_cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(key_cache, nullptr);


    res = ubiq_platform_ff1_cache_create(
      creds, config, dataset_cache, key_cache, &error_buf, &ff1_cache);
    EXPECT_EQ(res, 0);
    ASSERT_NE(ff1_cache, nullptr);

    int key_number = -1;
    struct ff1_ctx * ff1_ctx = nullptr;
    struct ff1_ctx * ff1_ctx2 = nullptr;
    ubiq_platform_ff1_cache_get_ff1_ctx(ff1_cache,
        "SSN",
        &key_number,
        &ff1_ctx);
    EXPECT_NE(key_number, -1);
    EXPECT_NE(ff1_ctx, nullptr);

    key_number = -1;
    ubiq_platform_ff1_cache_get_ff1_ctx(ff1_cache,
        "SSN",
        &key_number,
        &ff1_ctx2);
    EXPECT_NE(ff1_ctx, ff1_ctx2);

    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_dataset_cache_destroy(dataset_cache);
    ubiq_platform_ff1_cache_destroy(ff1_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}
