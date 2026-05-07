#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/internal/ff1.h>
#include <ubiq/platform/internal/dataset_cache.h>
#include <ubiq/platform/internal/structured_key_cache.h>
#include <ubiq/platform/internal/dataset.h>

__BEGIN_DECLS


struct ubiq_platform_ff1_cache ;
typedef struct ubiq_platform_ff1_cache ubiq_platform_ff1_cache_t;

void ubiq_platform_ff1_cache_destroy(ubiq_platform_ff1_cache_t * const ctx);

int ubiq_platform_ff1_cache_create(
  const struct ubiq_platform_credentials * const creds, 
  const struct ubiq_platform_configuration * const cfg,
  ubiq_platform_dataset_cache_t * const dataset_cache, // Saves a copy - do not free
  ubiq_platform_structured_key_cache_t * const key_cache,
  ubiq_platform_error_t * const error_buffer,
  ubiq_platform_ff1_cache_t ** const ctx_cache);

int ubiq_platform_ff1_cache_get_ff1_ctx(
  ubiq_platform_ff1_cache_t * const ctx_cache,
  const char * const dataset_name,
  int * const key_number,
  struct ff1_ctx ** ff1_ctx);

int ubiq_platform_ff1_cache_load_def_keys(
    ubiq_platform_ff1_cache_t * const ctx_cache,
    char const ** const dataset_names, size_t const count);

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
