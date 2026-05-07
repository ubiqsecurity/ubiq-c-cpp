#include "ubiq/platform.h"


#include "ubiq/platform/internal/encode_key_number_operation.h"
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
      char32_t const * const output_character_set = ubiq_platform_dataset_get_output_characters(dataset);
      unsigned int const msb_encoding_bits = ubiq_platform_dataset_get_msb_encoding_bits(dataset);
      unsigned int const key_number = ubiq_platform_operation_context_get_key_number(ctx);
      out = u32_strdup(current_value);
      res = ubiq_platform_encode_keynum(output_character_set, msb_encoding_bits, key_number, out);
      if (!res) {
        *output = out;
      } else {
        free(out);
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_ENCODE_KEY_NUMBER;
}

ubiq_platform_operation_t * const ubiq_platform_encode_key_number_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_encode_key_number_operation_delete;
  return s;
}

void ubiq_platform_encode_key_number_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
