#include "ubiq/platform.h"


#include "ubiq/platform/internal/encrypt_operation.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/parsing.h"
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
    static const char * const csu = "encrypt_operation.invoke";

  if (ctx) {

    if (!ubiq_platform_operation_context_get_is_encrypt(ctx)) {
      UBIQ_DEBUG(debug_flag, printf("ubiq_platform_operation_context_get_is_encrypt false\n"));
      CTX_CAPTURE_ERROR(ctx, res, "Encrypt operation is not allowed in a decryption pipeline ");
      return res;
    } 

    uint32_t * out = NULL;
    const ubiq_platform_dataset_t * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_operation_context_get_dataset NULL?(%d)\n", dataset == NULL));
    if (dataset) {
      char32_t const * const current_value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("current_value (%S)\n", current_value));
      char32_t const * const input_chars = ubiq_platform_dataset_get_input_characters(dataset);
      UBIQ_DEBUG(debug_flag, printf("input_chars (%S)\n", input_chars));
      size_t len = u32_strlen((uint32_t const *) current_value);
      UBIQ_DEBUG(debug_flag, printf("len (%d) input_min_length(%d)\n", len, ubiq_platform_dataset_get_input_min_length(dataset)));
      if (len < ubiq_platform_dataset_get_input_min_length(dataset)) {
        CTX_CAPTURE_ERROR(ctx, res, "Input length is less than the dataset's minimum input length");
        return res;
      }
      UBIQ_DEBUG(debug_flag, printf("len (%d) input_max_length(%d)\n", len, ubiq_platform_dataset_get_input_max_length(dataset)));
      if (len > ubiq_platform_dataset_get_input_max_length(dataset)) {
        CTX_CAPTURE_ERROR(ctx, res, "Input length is greater than the dataset's maximum input length");
        return res;
      }
      char32_t const * ptr = current_value;
      while (*ptr != U'\0') {
        const uint32_t * pos = u32_strchr(input_chars, *ptr);
        if (!pos) {
          UBIQ_DEBUG(debug_flag, printf("Input string has an invalid character (%C)\n", *ptr));
          CTX_CAPTURE_ERROR(ctx, res, "Input string has an invalid character");
          return res;
        }
        ptr++;
      }

      struct ff1_ctx * ff1_ctx = NULL;
      ubiq_platform_ff1_cache_t * const ff1_cache = ubiq_platform_operation_context_get_ffx_cache(ctx);
      ubiq_platform_dataset_t const * const dataset = ubiq_platform_operation_context_get_dataset(ctx);
      ubiq_platform_tweak_t const * const tweak = ubiq_platform_operation_context_get_user_supplied_tweak(ctx);
      int key_number = ubiq_platform_operation_context_get_key_number(ctx);
      UBIQ_DEBUG(debug_flag, printf("key_number (%d)\n", key_number));

      res = ubiq_platform_ff1_cache_get_ff1_ctx(ff1_cache,
          ubiq_platform_dataset_get_name(dataset),
          &key_number,
          &ff1_ctx);
      UBIQ_DEBUG(debug_flag, printf("ubiq_platform_ff1_cache_get_ff1_ctx key_number(%d) res(%d) \n", key_number, res));
      if (!res && ff1_ctx) {
        char * utf8_pt = NULL;
        res = convert_utf32_to_utf8(current_value, (uint8_t**)&utf8_pt);
        UBIQ_DEBUG(debug_flag, printf("utf8_pt (%s) res(%d)\n", utf8_pt, res));
        UBIQ_DEBUG(debug_flag, printf("tweak NULL?(%d)\n", tweak == NULL));
        UBIQ_DEBUG(debug_flag, printf("tweak_len(%d)\n",  tweak->len));
        char * utf8_ct = calloc(1, strlen(utf8_pt) * 3); // magic number to account for multi-byte
        res = ff1_encrypt(ff1_ctx, utf8_ct, utf8_pt, 
            tweak->buf, tweak->len);
        UBIQ_DEBUG(debug_flag, printf("ff1_encrypt utf8_ct(%s) res(%d) \n", utf8_ct, res));
        if (!res) {
          res = convert_utf8_to_utf32(utf8_ct, output);
          ubiq_platform_operation_context_set_key_number(ctx, key_number);
        }
        free(utf8_pt);
        free(utf8_ct);
      }
    } // dataset
  } //ctx
  return res;
}

static operation_class_t getType(void) {
  return OPERATION_ENCRYPT;
}

ubiq_platform_operation_t * const ubiq_platform_encrypt_operation_create(void) {
  ubiq_platform_operation_t * s = calloc(1, sizeof(ubiq_platform_operation_t));
  s->invoke = &invoke;
  s->getType = &getType;
  s->ctx = s;
  s->destroy = &ubiq_platform_encrypt_operation_delete;
  return s;
}

void ubiq_platform_encrypt_operation_delete(ubiq_platform_operation_t * const op) {
  free(op);
}
