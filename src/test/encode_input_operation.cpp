#include <gtest/gtest.h>
#include <ubiq/platform/internal/encode_input_operation.h>
#include <ubiq/platform/internal/decode_input_operation.h>
#include <ubiq/platform/internal/operation_context.h>
#include <ubiq/platform/internal/dataset.h>
#include <ubiq/platform/internal/parsing.h>

#include <unistr.h>

static int create_operation_context(char const * const input_encoding, ubiq_platform_operation_context_t ** const ctx, ubiq_platform_dataset_t ** d2) {
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

  if (!res && input_encoding) {
    cJSON_AddStringToObject(j, "input_encoding", input_encoding);
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



TEST(encode_input, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_encode_input_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_ENCODE_INPUT);

  ubiq_platform_encode_input_operation_delete(t);
}

TEST(encode_input, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_encode_input_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  free(out);
  ubiq_platform_encode_input_operation_delete(t);
}

TEST(encode_input, simple)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const original = U"1234567890";
  char32_t const * const expected = U"1234567890";

  res = create_operation_context(nullptr, &ctx, &dataset);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_operation_context_set_current_value(ctx, original);
  ASSERT_EQ(res, 0);

  ubiq_platform_operation_t * const t = ubiq_platform_encode_input_operation_create();
  ASSERT_NE(t, nullptr);
  {
    char32_t * out = NULL;

    res = t->invoke(ctx, &out);
    EXPECT_EQ(res, 0);
    // EXPECT_EQ(strcmp32(out, expected), 0);

    free(out);
  }
  ubiq_platform_encode_input_operation_delete(t);
  ubiq_platform_operation_context_destroy(ctx);
  ubiq_platform_dataset_destroy(dataset);
}

TEST(encode_input, simple_base64)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const originals[] = {U"AA", U"abcde1234567890"};
  char32_t const * const expected[] = {U"QUE=", U"YWJjZGUxMjM0NTY3ODkw"};

  for (int i = 0; i < sizeof(originals) / sizeof(char32_t*); i++) {
 
    res = create_operation_context(ENCODING_BASE64, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, originals[i]);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const t = ubiq_platform_encode_input_operation_create();
    ASSERT_NE(t, nullptr);
    {
      char32_t * out = NULL;

      res = t->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, expected[i]), 0);

      free(out);
    }
    ubiq_platform_encode_input_operation_delete(t);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}

TEST(encode_input, simple_base64_rt)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const originals[] = {U"A", U"1234567890abcde"};
  char32_t const * const expected[] = {U"QQ==", U"MTIzNDU2Nzg5MGFiY2Rl"};

  for (int i = 0; i < sizeof(originals) / sizeof(char32_t*); i++) {
 
    res = create_operation_context(ENCODING_BASE64, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, originals[i]);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const encode = ubiq_platform_encode_input_operation_create();
    ubiq_platform_operation_t * const decode = ubiq_platform_decode_input_operation_create();
    ASSERT_NE(encode, nullptr);
    ASSERT_NE(decode, nullptr);
    {
      char32_t * out = NULL;

      res = encode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, expected[i]), 0);
      res = ubiq_platform_operation_context_set_current_value(ctx, out);

      free(out);
    }
    {
      char32_t * out = NULL;

      res = decode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, originals[i]), 0);

      free(out);
    }
    ubiq_platform_decode_input_operation_delete(decode);
    ubiq_platform_encode_input_operation_delete(encode);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}

TEST(encode_input, simple_base32)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const originals[2] = {U"A", U"1234567890abcde"};
  char32_t const * const expected[2] = {U"IE======", U"GEZDGNBVGY3TQOJQMFRGGZDF"};

  for (int i = 0; i < sizeof(originals) / sizeof(char32_t*); i++) {

    res = create_operation_context(ENCODING_BASE32, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, originals[i]);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const t = ubiq_platform_encode_input_operation_create();
    ASSERT_NE(t, nullptr);
    {
      char32_t * out = NULL;

      res = t->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, expected[i]), 0);

      free(out);
    }
    ubiq_platform_encode_input_operation_delete(t);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}

TEST(encode_input, simple_base32_rt)
{
  int res = 0;
  ubiq_platform_operation_context_t * ctx = nullptr;
  ubiq_platform_dataset_t * dataset = nullptr;

  char32_t const * const originals[] = {U"AA", U"abcde1234567890"};
  char32_t const * const expected[] = {U"IFAQ====", U"MFRGGZDFGEZDGNBVGY3TQOJQ"};

  for (int i = 0; i < sizeof(originals) / sizeof(char32_t*); i++) {
    res = create_operation_context(ENCODING_BASE32, &ctx, &dataset);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_operation_context_set_current_value(ctx, originals[i]);
    ASSERT_EQ(res, 0);

    ubiq_platform_operation_t * const encode = ubiq_platform_encode_input_operation_create();
    ubiq_platform_operation_t * const decode = ubiq_platform_decode_input_operation_create();
    ASSERT_NE(encode, nullptr);
    ASSERT_NE(decode, nullptr);
    {
      char32_t * out = NULL;

      res = encode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, expected[i]), 0);
      res = ubiq_platform_operation_context_set_current_value(ctx, out);

      free(out);
    }
    {
      char32_t * out = NULL;

      res = decode->invoke(ctx, &out);
      EXPECT_EQ(res, 0);
      EXPECT_EQ(strcmp32(out, originals[i]), 0);

      free(out);
    }
    ubiq_platform_decode_input_operation_delete(decode);
    ubiq_platform_encode_input_operation_delete(encode);
    ubiq_platform_operation_context_destroy(ctx);
    ubiq_platform_dataset_destroy(dataset);
  }
}
