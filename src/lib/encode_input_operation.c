#include "ubiq/platform.h"


#include "ubiq/platform/internal/encode_input_operation.h"
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
      char const * const encoding = ubiq_platform_dataset_get_input_encoding(dataset);
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      if (encoding == NULL || *encoding == '\0') {
        // NOP
        *output = u32_strdup(current_value);
        res = 0;
      } else if (strcmp(encoding, ENCODING_BASE64) == 0) {
        UBIQ_DEBUG(debug_flag, printf("current_value: %S\n", current_value));
        res = ubiq_support_u32_base64_encode(&out, current_value);
        UBIQ_DEBUG(debug_flag, printf("res(%d) out: %S\n", res, out));
        if (!res) {
          *output = out;
        }
      } else if (strcmp(encoding, ENCODING_BASE32) == 0) {
        res = ubiq_support_u32_base32_encode(&out, current_value);
        if (!res) {
          *output = out;
        }
      } else {
        // leave RES as an error
      }
        
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_ENCODE_INPUT;
}

ubiq_platform_operation_t * const ubiq_platform_encode_input_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_encode_input_operation_delete;
  return s;
}

void ubiq_platform_encode_input_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
