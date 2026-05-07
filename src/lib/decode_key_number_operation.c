#include "ubiq/platform.h"


#include "ubiq/platform/internal/decode_key_number_operation.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
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
  static const char * const csu = "decode_key_number_operation.invoke";
  int res = -EINVAL;

  if (ctx) {
    uint32_t * out = NULL;
    const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
    if (dataset) {
      unsigned int key_number = 0;
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      char32_t const * const output_character_set = ubiq_platform_dataset_get_output_characters(dataset);
      unsigned int const msb_encoding_bits = ubiq_platform_dataset_get_msb_encoding_bits(dataset);
      out = u32_strdup(current_value);
      res = ubiq_platform_decode_keynum(output_character_set, msb_encoding_bits, &key_number, out);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_decode_keynum res(%d)\n",csu, res));
      if (!res) {
        *output = out;
        res = ubiq_platform_operation_context_set_key_number(ctx, key_number);
      } else {
        CTX_CAPTURE_ERROR(ctx, res, "Unable to decode key number");
        free(out);
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_DECODE_KEY_NUMBER;
}

ubiq_platform_operation_t * const ubiq_platform_decode_key_number_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_decode_key_number_operation_delete;
  return s;
}

void ubiq_platform_decode_key_number_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
