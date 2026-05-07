#include <gtest/gtest.h>
#include <ubiq/platform/internal/unpad_input_operation.h>

#include <unistr.h>

TEST(unpad_input, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_unpad_input_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_PAD_INPUT);

  ubiq_platform_unpad_input_operation_delete(t);
}

TEST(unpad_input, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_unpad_input_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  printf("out: %S\n", out);
  free(out);
  ubiq_platform_unpad_input_operation_delete(t);
}
