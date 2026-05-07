#include <gtest/gtest.h>
#include <ubiq/platform/internal/ff1_cache.h>
#include <ubiq/platform/internal/encrypt_operation.h>
#include <ubiq/platform/internal/decrypt_operation.h>
#include <ubiq/platform/internal/parsing.h>
#include <ubiq/platform/internal/structured_private.h>

#include <ubiq/platform/configuration.h>
#include <ubiq/platform/credentials.h>


TEST(encrypt_operation, getType)
{
  ubiq_platform_operation_t * const t = ubiq_platform_encrypt_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_ENCRYPT);

  ubiq_platform_encrypt_operation_delete(t);
}

TEST(encrypt_operation, invoke)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_ff1_cache_t * ff1_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_dataset_cache_t * dataset_cache = nullptr;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;
    // ubiq_platform_operation_t * const enc = nullptr;
    ubiq_platform_dataset_t const * dataset = nullptr;
    char32_t * out = nullptr;
    int res = 0;

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

    res = ubiq_platform_dataset_cache_get_dataset(dataset_cache, "SSN", &dataset);
    ASSERT_EQ(res, 0);
    ASSERT_NE(dataset, nullptr);

    ubiq_platform_operation_t * const enc = ubiq_platform_encrypt_operation_create();
    ASSERT_NE(enc, nullptr);



    ubiq_platform_operation_context_t * ctx = nullptr;
    res = ubiq_platform_operation_context_create(&error_buf, &ctx);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_dataset(ctx, dataset);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_key_number(ctx, -1);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_ffx_cache(ctx, ff1_cache);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, U"123456789");
    EXPECT_EQ(res, 0);

    res = enc->invoke(ctx, &out);
    printf("out: %S\n", out);
    EXPECT_EQ(res, 0);

    free(out);

    ubiq_platform_encrypt_operation_delete(enc);
    ubiq_platform_operation_context_destroy(ctx);

    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_dataset_cache_destroy(dataset_cache);
    ubiq_platform_ff1_cache_destroy(ff1_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}

TEST(encrypt_operation, invoke_encrypt_decrypt)
{
    ubiq_platform_error_t error_buf;
    ubiq_platform_ff1_cache_t * ff1_cache = nullptr;
    struct ubiq_platform_configuration * config = nullptr;
    struct ubiq_platform_credentials * creds = nullptr;
    ubiq_platform_dataset_cache_t * dataset_cache = nullptr;
    ubiq_platform_structured_key_cache_t * key_cache = nullptr;
    // ubiq_platform_operation_t * const enc = nullptr;
    ubiq_platform_dataset_t const * dataset = nullptr;
    char32_t * ct = nullptr;
    char32_t * pt = nullptr;
    char32_t const * orig = U"123456789";
    int res = 0;

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

    res = ubiq_platform_dataset_cache_get_dataset(dataset_cache, "SSN", &dataset);
    ASSERT_EQ(res, 0);
    ASSERT_NE(dataset, nullptr);

    ubiq_platform_operation_t * const enc = ubiq_platform_encrypt_operation_create();
    ASSERT_NE(enc, nullptr);

    ubiq_platform_operation_t * const dec = ubiq_platform_decrypt_operation_create();
    ASSERT_NE(enc, nullptr);

    ubiq_platform_operation_context_t * ctx = nullptr;
    res = ubiq_platform_operation_context_create(&error_buf, &ctx);

    res = ubiq_platform_operation_context_set_dataset(ctx, dataset);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_key_number(ctx, -1);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_ffx_cache(ctx, ff1_cache);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, orig);
    EXPECT_EQ(res, 0);

    res = enc->invoke(ctx, &ct);
    printf("out: %S\n", ct);
    
    EXPECT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, ct);
    EXPECT_EQ(res, 0);
    res = ubiq_platform_operation_context_set_is_encrypt(ctx, 0);
    EXPECT_EQ(res, 0);

    res = dec->invoke(ctx, &pt);
    printf("pt: %S\n", pt);

    EXPECT_EQ(res, 0);
    EXPECT_EQ(strcmp32(pt, orig), 0);

    free(ct);
    free(pt);

    ubiq_platform_decrypt_operation_delete(dec);
    ubiq_platform_encrypt_operation_delete(enc);
    ubiq_platform_operation_context_destroy(ctx);

    ubiq_platform_structured_key_cache_destroy(key_cache);
    ubiq_platform_dataset_cache_destroy(dataset_cache);
    ubiq_platform_ff1_cache_destroy(ff1_cache);
    ubiq_platform_configuration_destroy(config);
    ubiq_platform_credentials_destroy(creds);
}
