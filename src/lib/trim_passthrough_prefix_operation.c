#include "ubiq/platform.h"


#include "ubiq/platform/internal/trim_passthrough_prefix_operation.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/support.h"
#include <stdlib.h>
#include <string.h>
#include <unistr.h>
#include <stdio.h>


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

static int debug_flag = 0;


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
      size_t const prefix_length = ubiq_platform_dataset_get_passthrough_prefix_length(dataset);
      if (prefix_length == 0) {
        if (NULL != (out = u32_strdup(current_value))) {
          *output = out;
          res = 0;
        } else {
          res = -ENOMEM;
        }
      } else {
        uint32_t * const prefix_str = calloc(prefix_length + 1, sizeof(uint32_t));
        UBIQ_DEBUG(debug_flag, printf("current_value(%S) prefix_length(%d)\n", current_value, prefix_length));
        u32_strncpy(prefix_str, current_value, prefix_length);
        res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PREFIX, prefix_str); // dataset
        free(prefix_str);
        if (!res) {
          out = u32_strdup(current_value + prefix_length);
          *output = out;
        }
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_TRIM_PASSTHROUGH_PREFIX;
}

ubiq_platform_operation_t * const ubiq_platform_trim_passthrough_prefix_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_trim_passthrough_prefix_operation_delete;
  return s;
}

void ubiq_platform_trim_passthrough_prefix_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
