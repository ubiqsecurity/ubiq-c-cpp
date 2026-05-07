#include <gtest/gtest.h>
#include <ubiq/platform/internal/expand_passthrough_suffix_operation.h>

#include <unistr.h>

TEST(operation_expand_passthrough_suffix, getType)
{

  ubiq_platform_operation_t * const t = ubiq_platform_expand_passthrough_suffix_operation_create();

  operation_class_t x = t->getType();
  EXPECT_EQ(x, OPERATION_EXPAND_PASSTHROUGH_SUFFIX);

  ubiq_platform_expand_passthrough_suffix_operation_delete(t);
}

TEST(operation_expand_passthrough_suffix, invoke)
{

  ubiq_platform_operation_t * const t = ubiq_platform_expand_passthrough_suffix_operation_create();

  ubiq_platform_operation_context_t * ctx = NULL;
  char32_t * out = NULL;

  int x = t->invoke(ctx, &out);

  printf("out: %S\n", out);
  free(out);
  ubiq_platform_expand_passthrough_suffix_operation_delete(t);
}
