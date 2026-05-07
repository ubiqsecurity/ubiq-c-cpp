#include "ubiq/platform.h"


#include "ubiq/platform/internal/trim_passthrough_suffix_operation.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/support.h"
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
 *g
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
    uint32_t * out = NULL;
    const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
    if (dataset) {
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      size_t const suffix_length = ubiq_platform_dataset_get_passthrough_suffix_length(dataset);
      if (suffix_length == 0) {
        if (NULL != (out = u32_strdup(current_value))) {
          *output = out;
          res = 0;
        } else {
          res = -ENOMEM;
        }
      } else {
        size_t len = u32_strlen(current_value);
        uint32_t * const suffix_str = calloc(suffix_length + 1, sizeof(uint32_t));
        u32_strcpy(suffix_str, current_value + len - suffix_length);
        res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_SUFFIX, suffix_str);
        free(suffix_str);
        if (!res) {
          out = calloc(len - suffix_length + 1, sizeof(uint32_t));
          u32_strncpy(out, current_value, len - suffix_length);
          *output = out;
        }
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_TRIM_PASSTHROUGH_SUFFIX;
}

ubiq_platform_operation_t * const ubiq_platform_trim_passthrough_suffix_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->destroy = &ubiq_platform_trim_passthrough_suffix_operation_delete;
  return s;
}

void ubiq_platform_trim_passthrough_suffix_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
