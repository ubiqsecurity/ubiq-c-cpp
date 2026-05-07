#include <gtest/gtest.h>
#include <ubiq/platform/internal/structured_pipeline.h>
#include <ubiq/platform/internal/decode_input_operation.h>

#include <unistr.h>

TEST(structured_pipeline, valid)
{

  ubiq_platform_structured_pipeline_t * pipeline = nullptr;

  int res = ubiq_platform_structured_pipeline_create(5,&pipeline);
  EXPECT_EQ(res,0);
  EXPECT_NE(pipeline, nullptr);

  ubiq_platform_structured_pipeline_destroy(pipeline);
}

TEST(structured_pipeline, add_operation)
{

  ubiq_platform_structured_pipeline_t * pipeline = nullptr;

  int res = ubiq_platform_structured_pipeline_create(10, &pipeline);
  ASSERT_EQ(res,0);
  ASSERT_NE(pipeline, nullptr);

  ubiq_platform_operation_t * const dec = ubiq_platform_decode_input_operation_create();
  ASSERT_NE(dec, nullptr);

  res = ubiq_platform_structured_pipeline_add_operation(pipeline, dec, 0);
  ASSERT_EQ(res,0);

  ubiq_platform_operation_t * const dec2 = ubiq_platform_decode_input_operation_create();
  ASSERT_NE(dec2, nullptr);

  res = ubiq_platform_structured_pipeline_add_operation(pipeline, dec2, -1);
  ASSERT_EQ(res,0);
  for (int i=0; i< 50; i++) {
    ubiq_platform_operation_t * const dec3 = ubiq_platform_decode_input_operation_create();
    ASSERT_NE(dec3, nullptr);

    res = ubiq_platform_structured_pipeline_add_operation(pipeline, dec3, 0);
    ASSERT_EQ(res,0);
  }
  ubiq_platform_structured_pipeline_destroy(pipeline);
}

