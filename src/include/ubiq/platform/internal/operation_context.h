#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include "ubiq/platform/internal/ff1_cache.h"
#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS

#define CTX_CAPTURE_ERROR(ctx, res, msg) ({ if (res) { ubiq_platform_operation_context_capture_error(ctx, res, msg);}})

extern const char32_t * const OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE;
extern const char32_t * const OPERATION_CONTEXT_SUFFIX;
extern const char32_t * const OPERATION_CONTEXT_PREFIX;


struct ubiq_platform_operation_context ;
typedef struct ubiq_platform_operation_context ubiq_platform_operation_context_t;

typedef struct ubiq_platform_dataset ubiq_platform_dataset_t;

typedef struct ubiq_platform_tweak {
          uint8_t * buf; // will be bytes
          size_t len; // in bytes
} ubiq_platform_tweak_t;

int ubiq_platform_operation_context_create(
  ubiq_platform_error_t * const error_buffer,
  ubiq_platform_operation_context_t ** const ctx);

void ubiq_platform_operation_context_destroy(ubiq_platform_operation_context_t * const ctx);

ubiq_platform_ff1_cache_t * const ubiq_platform_operation_context_get_ffx_cache(const ubiq_platform_operation_context_t * const ctx);

ubiq_platform_dataset_t const * const ubiq_platform_operation_context_get_dataset(const ubiq_platform_operation_context_t * const ctx);

int const ubiq_platform_operation_context_get_key_number(const ubiq_platform_operation_context_t * const ctx);

int const ubiq_platform_operation_context_set_key_number(ubiq_platform_operation_context_t * const ctx, const int keyNumber);

ubiq_platform_tweak_t const * const ubiq_platform_operation_context_get_user_supplied_tweak(const ubiq_platform_operation_context_t * const ctx);

int ubiq_platform_operation_context_set_user_supplied_tweak(ubiq_platform_operation_context_t * const ctx, const uint8_t * const tweak, const size_t tweaklen);

int const ubiq_platform_operation_context_get_is_encrypt(const ubiq_platform_operation_context_t * const ctx);

int ubiq_platform_operation_context_set_is_encrypt(ubiq_platform_operation_context_t * const ctx, int isEncrypt);

char32_t const * const ubiq_platform_operation_context_get_original_value(const ubiq_platform_operation_context_t * const ctx);

char32_t const * const ubiq_platform_operation_context_get_current_value(const ubiq_platform_operation_context_t * const ctx);

char32_t const * const ubiq_platform_operation_context_get_data_value(const ubiq_platform_operation_context_t * const ctx, char32_t const * const key);

int ubiq_platform_operation_context_put_data_value(const ubiq_platform_operation_context_t * const ctx, char32_t const * const key, char32_t const * const value);

int ubiq_platform_operation_context_set_ffx_cache(ubiq_platform_operation_context_t * const ctx, ubiq_platform_ff1_cache_t * const cache);

int ubiq_platform_operation_context_set_dataset(ubiq_platform_operation_context_t * const ctx, ubiq_platform_dataset_t const * const dataset);

int ubiq_platform_operation_context_set_current_value(ubiq_platform_operation_context_t * const ctx, char32_t const * const value);

int ubiq_platform_operation_context_set_original_value(ubiq_platform_operation_context_t * const ctx, char32_t const * const value);

void ubiq_platform_operation_context_capture_error(ubiq_platform_operation_context_t * const ctx, int const res, char const * const msg);

// Have dataset, have key_number, so can get the ctx_cache_element
// int const ubiq_platform_operation_context_get_ffx_ctx(
//     const ubiq_platform_operation_context_t * const ctx,
//     ctx_cache_element_t ** const ffx_ctx);


// // Deep copy
// int ubiq_platform_credentials_clone(
//   const struct ubiq_platform_credentials * const src,
//   struct ubiq_platform_credentials ** const creds);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
