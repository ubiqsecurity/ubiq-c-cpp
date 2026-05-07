#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/internal/dataset.h>

__BEGIN_DECLS


struct ubiq_platform_dataset_cache ;
typedef struct ubiq_platform_dataset_cache ubiq_platform_dataset_cache_t;

void ubiq_platform_dataset_cache_destroy(ubiq_platform_dataset_cache_t * const cache);

int ubiq_platform_dataset_cache_create(
  const struct ubiq_platform_credentials * const creds, 
  const struct ubiq_platform_configuration * const cfg,
  ubiq_platform_error_t * const error,
  ubiq_platform_dataset_cache_t ** const cache);

int ubiq_platform_dataset_cache_get_dataset(
  ubiq_platform_dataset_cache_t * const cache,
  const char * const dataset_name,
  ubiq_platform_dataset_t const ** const dataset);

int ubiq_platform_dataset_cache_add_dataset(
  ubiq_platform_dataset_cache_t * const cache,
  cJSON const * const dataset_json,
  ubiq_platform_dataset_t const ** const dataset);

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
