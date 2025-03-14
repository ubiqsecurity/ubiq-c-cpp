#pragma once

#include <ubiq/platform/compat/cdefs.h>


__BEGIN_DECLS

struct ubiq_platform_cache ;

int
ubiq_platform_cache_create(
  unsigned int capacity,
  const time_t ttl_seconds,
  struct ubiq_platform_cache ** const ubiq_cache);

void
ubiq_platform_cache_destroy(
  struct ubiq_platform_cache * const ubiq_cache);

int
ubiq_platform_cache_add_element(
  struct ubiq_platform_cache * ubiq_cache,
  const char * const key,
  void * data,
  void (*free_ptr)(void *)
);

const void *
ubiq_platform_cache_find_element(
  struct ubiq_platform_cache const *  ubiq_cache,
  const char * const key
);

int
ubiq_platform_cache_get_element_count(
  struct ubiq_platform_cache * ubiq_cache,
  unsigned int * count
);


void
ubiq_platform_cache_walk_r(
  struct ubiq_platform_cache * ubiq_cache,
  void (* action) (const void *__nodep, 
			       void *__closure) ,
  void *__closure);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
