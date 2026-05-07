#include "ubiq/platform.h"


#include "ubiq/platform/internal/convert_radix_operation.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/bn.h"

#include <stdlib.h>
#include <string.h>
#include <unistr.h>


/**************************************************************************************
 *
 * Defines
 *
**************************************************************************************/
// #define UBIQ_DEBUG_ON // UNCOMMENT to Enable UBIQ_DEBUG macro


#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;


/**************************************************************************************
 *
 * Constants
 *
**************************************************************************************/

/**************************************************************************************
 *
 * Structures
 *
************************************** ************************************************/





/**************************************************************************************
 *
 * Static functions body
 *
**************************************************************************************/


static
int invoke(ubiq_platform_operation_context_t * ctx, char32_t ** const output) {
  int res = -EINVAL;

  if (ctx) {
    const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
    if (dataset) {
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      char32_t const * const input_chars = ubiq_platform_dataset_get_input_characters(dataset);
      char32_t const * const output_chars = ubiq_platform_dataset_get_output_characters(dataset);
      char32_t * output_str = calloc(u32_strlen((uint32_t *)current_value) + 1, sizeof(char32_t));
      if (ubiq_platform_operation_context_get_is_encrypt(ctx)) {
        res = ubiq_platform_u32_str_convert_u32_radix(current_value, input_chars, output_chars, 0, 1, output_str);
      } else {
        res = ubiq_platform_u32_str_convert_u32_radix(current_value, output_chars, input_chars, 0, 1, output_str);
      }
      if (!res) {
        *output = output_str;
      } else {
        free(output_str);
      }
    } // dataset
  } // ctx

  // char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
  // char32_t * output_str = calloc(u32_strlen((uint32_t *)current_value) + 1, sizeof(char32_t));

  // const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
  // const char32_t * const input_chars = ubiq_platform_dataset_get_input_characters(dataset);
  // const char32_t * const output_chars = ubiq_platform_dataset_get_output_characters(dataset);
  // if (ubiq_platform_operation_context_get_is_encrypt(ctx)) {
  //   res = ubiq_platform_u32_str_convert_u32_radix(current_value, input_chars, output_chars, output_str);
  // } else {
  //   res = ubiq_platform_u32_str_convert_u32_radix(current_value, output_chars, input_chars, output_str);
  // }
  // if (!res) {
  //   *output = output_str;
  // }
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_CONVERT_RADIX;
}

ubiq_platform_operation_t * const ubiq_platform_convert_radix_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_convert_radix_operation_delete;
  return s;
}

void ubiq_platform_convert_radix_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
