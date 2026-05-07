#include "ubiq/platform.h"


#include "ubiq/platform/internal/decode_input_operation.h"
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
        res = 0;
        *output = u32_strdup(current_value);
      } else if (strcmp(encoding, ENCODING_BASE64) == 0) {
        res = ubiq_support_u32_base64_decode(&out, current_value);
        if (!res) {
          *output = out;
        }
      } else if (strcmp(encoding, ENCODING_BASE32) == 0) {
        res = ubiq_support_u32_base32_decode(&out, current_value);
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
  return OPERATION_DECODE_INPUT;
}

ubiq_platform_operation_t * const ubiq_platform_decode_input_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_decode_input_operation_delete;
  return s;
}

void ubiq_platform_decode_input_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
