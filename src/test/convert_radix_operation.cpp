#include <gtest/gtest.h>
#include <ubiq/platform/internal/convert_radix_operation.h>

#include <unistr.h>

TEST(operation_radix, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_convert_radix_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_CONVERT_RADIX);

  ubiq_platform_convert_radix_operation_delete(t);
}

TEST(operation_radix, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_convert_radix_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  printf("out: %S\n", out);
  free(out);
  ubiq_platform_convert_radix_operation_delete(t);
}
