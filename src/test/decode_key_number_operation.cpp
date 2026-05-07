#include <gtest/gtest.h>
#include <ubiq/platform/internal/decode_key_number_operation.h>

#include <unistr.h>

TEST(decode_key_number, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_decode_key_number_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_DECODE_KEY_NUMBER);

  ubiq_platform_decode_key_number_operation_delete(t);
}

TEST(decode_key_number, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_decode_key_number_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  printf("out: %S\n", out);
  free(out);
  ubiq_platform_decode_key_number_operation_delete(t);
}
