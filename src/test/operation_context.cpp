#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "ubiq/platform.h"
#include "ubiq/platform/internal/operation_context.h"
#include "ubiq/platform/internal/cache.h"

TEST(c_oc, create_destroy_valid)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_operation_context_t * ctx;
    int res;

    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        ASSERT_NE(ctx, nullptr);

        ubiq_platform_operation_context_destroy(ctx);
    }
}

TEST(c_oc, test_hash_valid)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_operation_context_t * ctx;
    int res;

    const char32_t * key1 = U"key1-23456®23456Ñ23456Á23456";
    const char32_t * value1 = U"value1-23456®23456Ñ23456Á23456";

    const char32_t * key2 = U"key2-23456®23456Ñ23456Á23456";
    const char32_t * value2 = U"value2-23456®23456Ñ23456Á23456";

    const char32_t * value3 = U"value3-23456®23456Ñ23456Á23456";

    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    ASSERT_EQ(res, 0);

    ASSERT_EQ(ubiq_platform_operation_context_put_data_value(ctx, key1, value1), 0);
    ASSERT_EQ(ubiq_platform_operation_context_put_data_value(ctx, key2, value2), 0);

    const char32_t * value = ubiq_platform_operation_context_get_data_value(ctx, key1);
    ASSERT_EQ(u32_strcmp((const uint32_t*)value, (const uint32_t*)value1),0);
    value = ubiq_platform_operation_context_get_data_value(ctx, key2);
    ASSERT_EQ(u32_strcmp((const uint32_t*)value, (const uint32_t*)value2),0);

    ASSERT_EQ(ubiq_platform_operation_context_put_data_value(ctx, key2, value3), 0);
    value = ubiq_platform_operation_context_get_data_value(ctx, key2);
    ASSERT_EQ(u32_strcmp((const uint32_t*)value, (const uint32_t*)value3),0);

    value = ubiq_platform_operation_context_get_data_value(ctx, key1);
    ASSERT_EQ(u32_strcmp((const uint32_t*)value, (const uint32_t*)value1),0);

    if (res == 0) {
        ASSERT_NE(ctx, nullptr);

        ubiq_platform_operation_context_destroy(ctx);
    }
}

TEST(c_oc, set_values)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_operation_context_t * ctx;
    int res;

    const char32_t * current = U"key1-23456®23456Ñ23456Á23456";
    const char32_t * original = U"value1-23456®23456Ñ23456Á23456";

    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(ubiq_platform_operation_context_set_current_value(ctx, current), 0);
    EXPECT_EQ(ubiq_platform_operation_context_set_original_value(ctx, original), 0);

    const char32_t * value = ubiq_platform_operation_context_get_current_value(ctx);
    EXPECT_EQ(u32_strcmp((const uint32_t*)value, (const uint32_t*)current),0);
    value = ubiq_platform_operation_context_get_original_value(ctx);
    EXPECT_EQ(u32_strcmp((const uint32_t*)value, (const uint32_t*)original),0);

    if (res == 0) {
        EXPECT_NE(ctx, nullptr);

        ubiq_platform_operation_context_destroy(ctx);
    }
}

TEST(c_oc, tweak)
{
    ubiq_platform_error_t error_buf;
    uint8_t t[5] = {1,2,3,4,5};

    ubiq_platform_operation_context_t * ctx;
    int res;

    const char32_t * current = U"key1-23456®23456Ñ23456Á23456";
    const char32_t * original = U"value1-23456®23456Ñ23456Á23456";

    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    ASSERT_EQ(res, 0);

    EXPECT_NE(ctx, nullptr);
    const ubiq_platform_tweak_t * tweak = nullptr;
    EXPECT_NE((tweak = ubiq_platform_operation_context_get_user_supplied_tweak(ctx)), nullptr);
    EXPECT_EQ(tweak->buf, nullptr);

    EXPECT_EQ(ubiq_platform_operation_context_set_user_supplied_tweak(ctx, t, 5),0);
    
    EXPECT_NE((tweak = ubiq_platform_operation_context_get_user_supplied_tweak(ctx)), nullptr);
    EXPECT_EQ(memcmp(t, tweak->buf, tweak->len),0);

    if (res == 0) {
        EXPECT_NE(ctx, nullptr);

        ubiq_platform_operation_context_destroy(ctx);
    }
}

TEST(c_oc, keyNumber)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_operation_context_t * ctx = nullptr;
    int res;

    int keyNumber = 5;
    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    ASSERT_EQ(res, 0);

    ASSERT_NE(ctx, nullptr);

    EXPECT_EQ(ubiq_platform_operation_context_get_key_number(ctx), -1);

    EXPECT_EQ(ubiq_platform_operation_context_set_key_number(ctx, keyNumber), 0);
    EXPECT_EQ(ubiq_platform_operation_context_get_key_number(ctx), keyNumber);

    if (res == 0) {
        EXPECT_NE(ctx, nullptr);

        ubiq_platform_operation_context_destroy(ctx);
    }
}

// TEST(c_oc, isEncrypt)
// {

//     ubiq_platform_operation_context_t * ctx = nullptr;
//     int res;

//     res = ubiq_platform_operation_context_create(&ctx);
//     ASSERT_EQ(res, 0);
//     ASSERT_NE(ctx, nullptr);

//     EXPECT_EQ(ubiq_platform_operation_context_get_is_encrypt(ctx), -1);

//     EXPECT_EQ(ubiq_platform_operation_context_set_is_encrypt(ctx, 1), 0);
//     EXPECT_EQ(ubiq_platform_operation_context_get_is_encrypt(ctx), 1);

//     EXPECT_EQ(ubiq_platform_operation_context_set_is_encrypt(ctx, 0), 0);
//     EXPECT_EQ(ubiq_platform_operation_context_get_is_encrypt(ctx), 0);

//     if (res == 0) {
//         EXPECT_NE(ctx, nullptr);

//         ubiq_platform_operation_context_destroy(ctx);
//     }
// }

TEST(c_oc, ffxCache)
{
    ubiq_platform_error_t error_buf;

    ubiq_platform_operation_context_t * ctx = nullptr;
    int res = 0;

    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_dataset_cache_t * dataset_cache = nullptr;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;

    ubiq_platform_ff1_cache_t * ff1Cache = nullptr;
    ubiq_platform_ff1_cache_t * ff1Cache2 = nullptr;

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
      creds, config, dataset_cache, key_cache, &error_buf, &ff1Cache);
    ASSERT_EQ(res, 0);
    ASSERT_NE(ff1Cache, nullptr);

    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    ASSERT_EQ(res, 0);
    ASSERT_NE(ctx, nullptr);


    // ASSERT_EQ(ubiq_platform_cache_create(500, ttl, &ffxCache),0);
    EXPECT_EQ(ubiq_platform_operation_context_set_ffx_cache(ctx, ff1Cache), 0);
    EXPECT_NE(ff1Cache2 = ubiq_platform_operation_context_get_ffx_cache(ctx), nullptr);

    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_dataset_cache_destroy(dataset_cache);
    ubiq_platform_ff1_cache_destroy(ff1Cache);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_configuration_destroy(config);


}