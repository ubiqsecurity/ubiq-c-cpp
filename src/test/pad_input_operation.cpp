#include <gtest/gtest.h>
#include <ubiq/platform/internal/pad_input_operation.h>
#include <ubiq/platform/internal/unpad_input_operation.h>
#include <ubiq/platform/internal/operation_context.h>
#include <ubiq/platform/internal/dataset.h>
#include <ubiq/platform/internal/parsing.h>

#include <unistr.h>

static int create_operation_context(int include_padding_char, ubiq_platform_operation_context_t ** const ctx, ubiq_platform_dataset_t ** d2) {
  ubiq_platform_error_t error_buf;
  int res = -EINVAL;
  std::string s;

  ubiq_platform_operation_context_t * oc = nullptr;
  ubiq_platform_dataset_t * d = nullptr;

  res = ubiq_platform_operation_context_create(&error_buf, &oc);
  if (res) { 
    return res;
  }

  s = "{\"name\": \"testing\"," \
  "\"input_character_set\": \"0123456789\"," \
  "\"output_character_set\": \"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\"," \
  "\"min_input_length\": 10" \
  "}";
  // "\"end\":\"end\"}";
//  "\"passthrough_character_set\": \"-\"," \
//  "\"passthrough_rules\": [{\"type\":\"passthrough\", \"priority\":1,\"value\":\"-\"}]," \
//  "\"data_type\": \"date\"," \

  // printf("s: %s\n", s.data());

  cJSON *j = cJSON_ParseWithLength(s.data(), s.length());
  if (j != NULL && !cJSON_IsNull(j)) {
    res = 0;
  } else {
    res = -1;
    cJSON_Delete(j);
    j = NULL;
  }

  if (!res && include_padding_char) {
    cJSON_AddStringToObject(j, "input_pad_character", "*");
  }

  if (!res) {
    res = ubiq_platform_dataset_create(j, &d);
    // printf("%s res(%d)\n","ubiq_platform_dataset_create", res);
  }
  cJSON_Delete(j);

  if (!res) {
    res = ubiq_platform_operation_context_set_current_value(oc, U"123-456");
    // printf("%s res(%d)\n","ubiq_platform_operation_context_set_current_value", res);
  }

  if (!res) {
    res = ubiq_platform_operation_context_set_dataset(oc, d);
    // printf("%s res(%d)\n","ubiq_platform_operation_context_set_dataset", res);
  }
  if (!res) {
    *ctx = oc;
    *d2 = d;
  } else {
    ubiq_platform_dataset_destroy(d);

    ubiq_platform_operation_context_destroy(oc);
  }


  return res;   
}


TEST(pad_input, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_pad_input_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_PAD_INPUT);

  ubiq_platform_pad_input_operation_delete(t);
}

TEST(pad_input, simple)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;
  res = create_operation_context(1, &ctx, &dataset);
  ASSERT_EQ(res, 0);

  ubiq_platform_operation_t * const t = ubiq_platform_pad_input_operation_create();

  char32_t * out = NULL;

  res = t->invoke(ctx, &out);
  EXPECT_EQ(res, 0);

  // printf("out: %S\n", out);
  EXPECT_EQ(strcmp32(out, U"***123-456"), 0);
  free(out);
  ubiq_platform_pad_input_operation_delete(t);
  ubiq_platform_operation_context_destroy(ctx);
  ubiq_platform_dataset_destroy(dataset);
}

TEST(pad_input, simple_none_needed)
{
  int res = 0;
  char32_t const * const original = U"1234567890";
  char32_t const * const original_template = U"xxxx-xxx-xxx";
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;
  res = create_operation_context(1, &ctx, &dataset);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_set_current_value(ctx, original);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE, original_template);
  ASSERT_EQ(res, 0);

  ubiq_platform_operation_t * const t = ubiq_platform_pad_input_operation_create();
  {
    char32_t * out = NULL;

    res = t->invoke(ctx, &out);
    EXPECT_EQ(res, 0);

    // printf("out: %S\n", out);
    EXPECT_EQ(strcmp32(out, original), 0);
    free(out);
  }
  {
    char32_t const * out = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
    EXPECT_EQ(strcmp32(out, original_template), 0);
  }

  ubiq_platform_pad_input_operation_delete(t);
  ubiq_platform_operation_context_destroy(ctx);
  ubiq_platform_dataset_destroy(dataset);
  
}


TEST(pad_input, simple_pad_both)
{
  int res = 0;
  char32_t const * const original = U"123-456";
  char32_t const * const expected = U"***123-456";
  char32_t const * const original_template = U"xxx-xxx";
  char32_t const * const expected_template = U"***xxx-xxx";
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;
  res = create_operation_context(1, &ctx, &dataset);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_set_current_value(ctx, original);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE, original_template);
  ASSERT_EQ(res, 0);

  ubiq_platform_operation_t * const t = ubiq_platform_pad_input_operation_create();
  {
    char32_t * out = NULL;

    int x = t->invoke(ctx, &out);

    // printf("out: %S\n", out);
    EXPECT_EQ(strcmp32(out, expected), 0);
    free(out);
  }
  {
    char32_t const * out = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
    EXPECT_EQ(strcmp32(out, expected_template), 0);
  }

  ubiq_platform_pad_input_operation_delete(t);
  ubiq_platform_operation_context_destroy(ctx);
  ubiq_platform_dataset_destroy(dataset);
  
}

TEST(pad_input, unpad)
{
  int res = 0;
  char32_t const * const original = U"123-456";
  char32_t const * const expected = U"***123-456";
  char32_t const * const original_template = U"xxx-xxx";
  char32_t const * const expected_template = U"***xxx-xxx";
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;
  res = create_operation_context(1, &ctx, &dataset);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_set_current_value(ctx, original);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE, original_template);
  ASSERT_EQ(res, 0);

  ubiq_platform_operation_t * const t = ubiq_platform_pad_input_operation_create();
  ASSERT_NE(t, nullptr);
  {
    char32_t * out = NULL;

    res = t->invoke(ctx, &out);
    EXPECT_EQ(res, 0);
    
    // printf("out: %S\n", out);
    EXPECT_EQ(strcmp32(out, expected), 0);
    res = ubiq_platform_operation_context_set_current_value(ctx, out);
    EXPECT_EQ(res, 0);
    free(out);
  }
  {
    char32_t const * out = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
    EXPECT_EQ(strcmp32(out, expected_template), 0);
  }

  ubiq_platform_operation_t * const unpad = ubiq_platform_unpad_input_operation_create();
  ASSERT_NE(unpad, nullptr);
  {
    char32_t * out = NULL;

    res = unpad->invoke(ctx, &out);
    EXPECT_EQ(res, 0);
    
    EXPECT_EQ(strcmp32(out, original), 0);
    free(out);
  }
  {
    char32_t const * out = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
    EXPECT_EQ(strcmp32(out, original_template), 0);
  }


  ubiq_platform_unpad_input_operation_delete(unpad);
  ubiq_platform_pad_input_operation_delete(t);
  ubiq_platform_operation_context_destroy(ctx);
  ubiq_platform_dataset_destroy(dataset);
  
}

TEST(pad_input, no_padding_character)
{
  int res = 0;
  char32_t const * const original = U"123-456";
  char32_t const * const original_template = U"xxx-xxx";
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;
  res = create_operation_context(0, &ctx, &dataset);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_set_current_value(ctx, original);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE, original_template);
  ASSERT_EQ(res, 0);

  ubiq_platform_operation_t * const t = ubiq_platform_pad_input_operation_create();
  ASSERT_NE(t, nullptr);
  {
    char32_t * out = NULL;

    res = t->invoke(ctx, &out);
    EXPECT_EQ(res, 0);
    
    // printf("out: %S\n", out);
    EXPECT_EQ(strcmp32(out, original), 0);
    res = ubiq_platform_operation_context_set_current_value(ctx, out);
    EXPECT_EQ(res, 0);
    free(out);
  }
  {
    char32_t const * out = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
    EXPECT_EQ(strcmp32(out, original_template), 0);
  }

  ubiq_platform_operation_t * const unpad = ubiq_platform_unpad_input_operation_create();
  ASSERT_NE(unpad, nullptr);
  {
    char32_t * out = NULL;

    res = unpad->invoke(ctx, &out);
    EXPECT_EQ(res, 0);
    
    EXPECT_EQ(strcmp32(out, original), 0);
    free(out);
  }
  {
    char32_t const * out = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
    EXPECT_EQ(strcmp32(out, original_template), 0);
  }


  ubiq_platform_unpad_input_operation_delete(unpad);
  ubiq_platform_pad_input_operation_delete(t);
  ubiq_platform_operation_context_destroy(ctx);
  ubiq_platform_dataset_destroy(dataset);
  
}
