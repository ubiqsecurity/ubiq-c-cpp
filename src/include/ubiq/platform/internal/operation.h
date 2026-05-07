#pragma once

#include <unistr.h>
#include <uchar.h>

#include "ubiq/platform/internal/operation_context.h"


__BEGIN_DECLS

typedef enum operation_class {
  OPERATION_CONVERT_RADIX=0, 
  OPERATION_DECODE_INPUT,
  OPERATION_DECODE_KEY_NUMBER,
  OPERATION_DECRYPT,
  OPERATION_ENCODE_INPUT,
  OPERATION_ENCODE_KEY_NUMBER,
  OPERATION_ENCRYPT,
  OPERATION_EXPAND_PASSTHROUGH_CHARACTERS,
  OPERATION_EXPAND_PASSTHROUGH_PREFIX,
  OPERATION_EXPAND_PASSTHROUGH_SUFFIX,
  OPERATION_PAD_INPUT,
  OPERATION_TRIM_PASSTHROUGH_CHARACTERS,
  OPERATION_TRIM_PASSTHROUGH_PREFIX,
  OPERATION_TRIM_PASSTHROUGH_SUFFIX,
  OPERATION_UNPAD_INPUT
   }  operation_class_t ;

typedef struct ubiq_platform_operation ubiq_platform_operation_t;

typedef struct ubiq_platform_operation {
  ubiq_platform_operation_t * ctx;
  int (*invoke)(ubiq_platform_operation_context_t * ctx, char32_t ** const output);
  operation_class_t (*getType)(void);
  void (*destroy)(ubiq_platform_operation_t * const);
} ubiq_platform_operation_t;

ubiq_platform_operation_t * const ubiq_platform_convert_radix_operation_create(void);

void ubiq_platform_convert_radix_operation_delete(ubiq_platform_operation_t * const op);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
