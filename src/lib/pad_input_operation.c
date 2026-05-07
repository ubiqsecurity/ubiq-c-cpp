#include "ubiq/platform.h"


#include "ubiq/platform/internal/pad_input_operation.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
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

static int debug_flag = 0;


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
      char32_t const pad_char = ubiq_platform_dataset_get_input_pad_char(dataset);
      size_t const input_min_length = ubiq_platform_dataset_get_input_min_length(dataset);
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      if (pad_char == '\0') {
        out = u32_strdup(current_value);
        res = 0;
        // NOP
      } else {
        res = 0;
        res = ubiq_platform_pad_left(pad_char, input_min_length, current_value, &out);
        uint32_t const * const template = ubiq_platform_operation_context_get_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE);
        if (template != NULL) {
          uint32_t * padded_template = NULL;
          res = ubiq_platform_pad_left(pad_char, input_min_length, template, &padded_template);
          if (!res) {
            res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE, padded_template);
            free(padded_template);
          }
        } else {
          res = 0;
        }
      }
      if (!res && out) {
        *output = out;
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_PAD_INPUT;
}

ubiq_platform_operation_t * const ubiq_platform_pad_input_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_pad_input_operation_delete;
  return s;
}

void ubiq_platform_pad_input_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
