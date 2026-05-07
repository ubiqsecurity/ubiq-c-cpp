#include "ubiq/platform.h"


#include "ubiq/platform/internal/expand_passthrough_suffix_operation.h"
#include "ubiq/platform/internal/dataset.h"
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
    uint32_t * out = NULL;
    const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
    if (dataset) {
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      char32_t const * const suffix_str = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_SUFFIX);

      if (suffix_str == NULL) {
        if (NULL != (out = u32_strdup(current_value))) {
          res = 0;
          *output = out;
        } else {
          res = -ENOMEM;
        }
      } else {
        if (NULL != (out = calloc(u32_strlen(current_value) + u32_strlen(suffix_str) + 1, sizeof(uint32_t)))) {
          u32_strcpy(out, current_value);
          u32_strcat(out, suffix_str);
          res = 0;
          *output = out;
        } else {
          res = -ENOMEM;
        }
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_EXPAND_PASSTHROUGH_SUFFIX;
}

ubiq_platform_operation_t * const ubiq_platform_expand_passthrough_suffix_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_expand_passthrough_suffix_operation_delete;
  return s;
}

void ubiq_platform_expand_passthrough_suffix_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
