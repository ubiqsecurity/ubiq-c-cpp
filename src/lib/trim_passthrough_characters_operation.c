#include "ubiq/platform.h"


#include "ubiq/platform/internal/trim_passthrough_characters_operation.h"
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
  int debug_flag = 1;
  int res = -EINVAL;

  if (ctx) {
    const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
    if (dataset) {
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      char32_t const * const passthrough_characters = ubiq_platform_dataset_get_passthrough_characters(dataset);
      UBIQ_DEBUG(debug_flag, printf("passthrough_characters: %S\n", passthrough_characters));
      char32_t template_char = '\0';
      size_t len = u32_strlen(current_value);
      UBIQ_DEBUG(debug_flag, printf("len(%d)\n", len));
      char32_t * const trimmed = calloc(len + 1, sizeof(uint32_t));
      char32_t * const template = calloc(len + 1, sizeof(uint32_t));
      if (ubiq_platform_operation_context_get_is_encrypt(ctx)) {
        template_char = ubiq_platform_dataset_get_output_characters(dataset)[0];
        UBIQ_DEBUG(debug_flag, printf("Encrypt template_char(%C)\n", template_char));
      } else {
        template_char = ubiq_platform_dataset_get_input_characters(dataset)[0];
        UBIQ_DEBUG(debug_flag, printf("Debug template_char(%C)\n", template_char));
      }
      char32_t * trimmed_ptr = trimmed;
      char32_t * template_ptr = template;

      for (int i = 0; i < len; i++) {
        uint32_t const c = current_value[i];
        UBIQ_DEBUG(debug_flag, printf("i(%d) c(%C)\n", i, c));
        const uint32_t * pos = u32_strchr(passthrough_characters, c);
        if (pos) {
          *template_ptr++ = c;
        } else {
          *trimmed_ptr++ = c;
          *template_ptr++ = template_char;
        }
      }
      *output = trimmed;
      res = ubiq_platform_operation_context_put_data_value(ctx, OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE, template);
      free(template);
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_TRIM_PASSTHROUGH_CHARACTERS;
}

ubiq_platform_operation_t * const ubiq_platform_trim_passthrough_characters_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_trim_passthrough_characters_operation_delete;
  return s;
}

void ubiq_platform_trim_passthrough_characters_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
