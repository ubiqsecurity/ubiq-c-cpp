#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS

struct ubiq_platform_cache ;

int
ubiq_platform_cache_create(
  struct ubiq_platform_cache ** const ubiq_cache);

void
ubiq_platform_cache_destroy(
  struct ubiq_platform_cache * const ubiq_cache);

int
ubiq_platform_cache_add_element(
  struct ubiq_platform_cache * ubiq_cache,
  const char * const key,
  const time_t duration,
  void * data,
  void (*free_ptr)(void *)
);

const void *
ubiq_platform_cache_find_element(
  struct ubiq_platform_cache const *  ubiq_cache,
  const char * const key
);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
