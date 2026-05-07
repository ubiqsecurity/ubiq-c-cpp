#include <gtest/gtest.h>
#include <ubiq/platform/internal/expand_passthrough_prefix_operation.h>

#include <unistr.h>

TEST(operation_expand_passthrough_prefix, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_expand_passthrough_prefix_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_EXPAND_PASSTHROUGH_PREFIX);

  ubiq_platform_expand_passthrough_prefix_operation_delete(t);
}

TEST(operation_expand_passthrough_prefix, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_expand_passthrough_prefix_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  printf("out: %S\n", out);
  free(out);
  ubiq_platform_expand_passthrough_prefix_operation_delete(t);
}
