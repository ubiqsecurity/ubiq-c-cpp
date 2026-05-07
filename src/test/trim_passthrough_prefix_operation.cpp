#include <gtest/gtest.h>
#include <ubiq/platform/internal/trim_passthrough_prefix_operation.h>
#include <ubiq/platform/internal/expand_passthrough_prefix_operation.h>
#include <ubiq/platform/internal/operation_context.h>
#include <ubiq/platform/internal/dataset.h>
#include <ubiq/platform/internal/parsing.h>

#include <unistr.h>

static int create_operation_context(
  int const prefix_length,
  ubiq_platform_operation_context_t ** const ctx, 
  ubiq_platform_dataset_t ** d2) {
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
  "\"input_character_set\": \"abc123\"," \
  "\"output_character_set\": \"xyz456\"," \
  "\"min_input_length\": 4" \
  "}";

  cJSON *j = cJSON_ParseWithLength(s.data(), s.length());
  if (j != NULL && !cJSON_IsNull(j)) {
    res = 0;
  } else {
    res = -1;
    cJSON_Delete(j);
    j = NULL;
  }

  if (!res && prefix_length >= 0) {
    cJSON * p = cJSON_CreateObject();
    cJSON_AddStringToObject(p, "type", "prefix");
    cJSON_AddNumberToObject(p, "value", prefix_length);
    cJSON_AddNumberToObject(p, "priority", 1);
    cJSON * a = cJSON_AddArrayToObject(j, "passthrough_rules");
    cJSON_AddItemToArray(a, p);
  }

  if (!res) {
    res = ubiq_platform_dataset_create(j, &d);
  }
  cJSON_Delete(j);

  if (!res) {
    res = ubiq_platform_operation_context_set_dataset(oc, d);
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


TEST(operation_trim_passthrough_prefix, getType)
{
  ubiq_platform_operation_t * const t = ubiq_platform_trim_passthrough_prefix_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_TRIM_PASSTHROUGH_PREFIX);

  ubiq_platform_trim_passthrough_prefix_operation_delete(t);
}

TEST(operation_trim_passthrough_prefix, invoke)
{
  ubiq_platform_operation_t * const t = ubiq_platform_trim_passthrough_prefix_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  free(out);
  ubiq_platform_trim_passthrough_prefix_operation_delete(t);
}


TEST(operation_trim_passthrough_prefix, simple)
{

  typedef struct  {
    char32_t original[100];
    char32_t expected[100];
    char32_t prefix[100];
    int prefix_length;
  } data_t;

   data_t data[] = { 
    {U"abc-123", U"abc-123", U"", -1},
    {U"abc-123", U"abc-123", U"", 0},
    {U"abc-123", U"-123", U"abc", 3},
    {U"abc-123", U"123", U"abc-", 4}
  };

  int res = 0;

  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  for (int i = 0; i < sizeof(data) / sizeof(data_t); i++) {

    res = create_operation_context(data[i].prefix_length, &ctx, &dataset);
    ASSERT_EQ(res, 0);
    ASSERT_NE(ctx, nullptr);
    ASSERT_NE(dataset, nullptr);

    ubiq_platform_operation_t * const t = ubiq_platform_trim_passthrough_prefix_operation_create();
    ubiq_platform_operation_t * const expand = ubiq_platform_expand_passthrough_prefix_operation_create();
    ASSERT_NE(t, nullptr);
    ASSERT_NE(expand, nullptr);

    res = ubiq_platform_operation_context_set_current_value(ctx, data[i].original);
    ASSERT_EQ(res, 0);

    {
      char32_t * out = NULL;

      res = t->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, data[i].expected), 0);

      if (data[i].prefix_length > 0) {
        char32_t const * const tmp = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PREFIX);
        EXPECT_EQ(strcmp32(tmp, data[i].prefix), 0);
      }
      res = ubiq_platform_operation_context_set_current_value(ctx, out);
      free(out);

    }
    {
      char32_t * out = NULL;

      res = expand->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, data[i].original), 0);

      free(out);
    }
      
    ubiq_platform_expand_passthrough_prefix_operation_delete(expand);
    ubiq_platform_trim_passthrough_prefix_operation_delete(t);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}
