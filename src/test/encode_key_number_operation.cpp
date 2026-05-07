#include <gtest/gtest.h>
#include <ubiq/platform/internal/encode_key_number_operation.h>
#include <ubiq/platform/internal/decode_key_number_operation.h>
#include <ubiq/platform/internal/operation_context.h>
#include <ubiq/platform/internal/dataset.h>
#include <ubiq/platform/internal/parsing.h>

#include <unistr.h>

static int create_operation_context(
  const size_t key_number, 
  const int encoding_bits, 
  ubiq_platform_operation_context_t ** const ctx, 
  ubiq_platform_dataset_t ** d2) {
  int res = -EINVAL;
  std::string s;

  ubiq_platform_operation_context_t * oc = nullptr;
  ubiq_platform_dataset_t * d = nullptr;

  res = ubiq_platform_operation_context_create(nullptr, &oc);
  if (res) { 
    return res;
  }

  s = "{\"name\": \"testing\"," \
  "\"input_character_set\": \"0123456789\"," \
  "\"output_character_set\": \"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\"," \
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

  if (!res && encoding_bits > 0) {
    cJSON_AddNumberToObject(j, "msb_encoding_bits", encoding_bits);
  }

  if (!res) {
    res = ubiq_platform_dataset_create(j, &d);
    // printf("%s res(%d)\n","ubiq_platform_dataset_create", res);
  }
  cJSON_Delete(j);

  if (!res) {
    res = ubiq_platform_operation_context_set_current_value(oc, U"0000");
    // printf("%s res(%d)\n","ubiq_platform_operation_context_set_current_value", res);
  }

  if (!res) {
    res = ubiq_platform_operation_context_set_dataset(oc, d);
    // printf("%s res(%d)\n","ubiq_platform_operation_context_set_dataset", res);
  }

  if (!res) {
    res = ubiq_platform_operation_context_set_key_number(oc, key_number);
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


TEST(encode_key_number, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_encode_key_number_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_ENCODE_KEY_NUMBER);

  ubiq_platform_encode_key_number_operation_delete(t);
}

TEST(encode_key_number, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_encode_key_number_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  free(out);
  ubiq_platform_encode_key_number_operation_delete(t);
}



TEST(encode_key_number, simple_zero_msb)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const originals[] = {U"0000", U"1ZZZ"};
  char32_t const * const expected[] = {U"1000", U"2ZZZ"};

  for (int i = 0; i < sizeof(originals) / sizeof(char32_t*); i++) {
    res = create_operation_context(1,0, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, originals[i]);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const encode = ubiq_platform_encode_key_number_operation_create();
    ASSERT_NE(encode, nullptr);
    {
      char32_t * out = NULL;

      res = encode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, expected[i]), 0);

      free(out);
    }
    ubiq_platform_encode_key_number_operation_delete(encode);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}

TEST(encode_key_number, simple_3_msb)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const originals[] = {U"0000", U"1ZZZ"};
  char32_t const * const expected[] = {U"O000", U"PZZZ"};

  for (int i = 0; i < sizeof(originals) / sizeof(char32_t*); i++) {
    res = create_operation_context(3,3, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, originals[i]);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const encode = ubiq_platform_encode_key_number_operation_create();
    ASSERT_NE(encode, nullptr);
    {
      char32_t * out = NULL;

      res = encode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, expected[i]), 0);

      free(out);
    }
    ubiq_platform_encode_key_number_operation_delete(encode);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}

TEST(encode_key_number, simple_rt)
{
  typedef struct  {
    char32_t original[100];
    char32_t expected[100];
    size_t key_number;
    size_t msb;
  } data_t;

  data_t data[] = { 
    {U"0ZZZ", U"OZZZ", 3, 3},
    {U"5123", U"T123", 3, 3},
    {U"0ZZZ", U"WZZZ", 4, 3},
    {U"0000", U"1000", 1, 0}
  };

  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  for (int i = 0; i < sizeof(data) / sizeof(data_t); i++) {
    res = create_operation_context(data[i].key_number, data[i].msb, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, data[i].original);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const encode = ubiq_platform_encode_key_number_operation_create();
    ubiq_platform_operation_t * const decode = ubiq_platform_decode_key_number_operation_create();
    ASSERT_NE(encode, nullptr);
    ASSERT_NE(decode, nullptr);
    {
      char32_t * out = NULL;

      res = encode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, data[i].expected), 0);
      res = ubiq_platform_operation_context_set_current_value(ctx, out);

      free(out);
    }
    // Set the key number, verify it, and then decode and make sure key number is updated.
    res = ubiq_platform_operation_context_set_key_number(ctx, 0);
    ASSERT_EQ(res, 0);
    ASSERT_EQ(ubiq_platform_operation_context_get_key_number(ctx), 0);
    {
      char32_t * out = NULL;

      res = decode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, data[i].original), 0);
      EXPECT_EQ(ubiq_platform_operation_context_get_key_number(ctx), data[i].key_number);

      free(out);
    }

    ubiq_platform_encode_key_number_operation_delete(encode);
    ubiq_platform_decode_key_number_operation_delete(decode);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}
