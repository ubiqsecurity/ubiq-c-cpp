#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/internal/dataset.h>
__BEGIN_DECLS


struct ubiq_platform_structured_key_cache ;
typedef struct ubiq_platform_structured_key_cache ubiq_platform_structured_key_cache_t;

typedef struct structured_key {
        void * buf;
        size_t len;
        unsigned int key_number;
} ubiq_platform_structured_key_t;

typedef struct ubiq_key {
     void * buf;
     size_t len;
} ubiq_key_t;

void ubiq_platform_structured_key_cache_destroy(ubiq_platform_structured_key_cache_t * const ctx);

int ubiq_platform_structured_key_cache_create(
  const struct ubiq_platform_credentials * const creds, 
  const struct ubiq_platform_configuration * const cfg,
  ubiq_platform_error_t * const error_buffer,
  ubiq_platform_structured_key_cache_t ** const key_cache);

// Will be decrypted
int ubiq_platform_structured_key_cache_get_structured_key(
  ubiq_platform_structured_key_cache_t * const key_cache,
  const char * const dataset_name,
  int const key_number,
  ubiq_platform_structured_key_t ** const key);

void ubiq_platform_structured_key_cache_structured_key_destroy(
  ubiq_platform_structured_key_t * const key);

int ubiq_platform_structured_key_cache_add_key(
  ubiq_platform_structured_key_cache_t * const key_cache,
  const char * const dataset_name,
  int const key_number,
  int const current_key_flag,
  char const * const wrapped_data_key);

  // When keys are set from external sources, this allows it to be
  // set
  int ubiq_platform_structured_key_cache_set_encrypted_private_key(
    ubiq_platform_structured_key_cache_t * const key_cache,
    char const * const encrypted_private_key);


// int ubiq_platform_structured_key_cache_get_ff1_ctx(
//   ubiq_platform_structured_key_cache_t * const ctx_cache,
//   const char * const dataset_name,
//   int * const key_number,
//   struct ff1_ctx ** ff1_ctx);

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
