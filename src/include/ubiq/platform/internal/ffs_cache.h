#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS


int
create_ffs_cache(void ** const ffs_cache);

void
destroy_ffs_cache(void * const ffs_cache);

int
add_element(
  void * f,
  const char * const key,
  char * ffs,
  void (*free_ptr)(void *)
);

const char *
find_element(
  void const *  f,
  const char * const key
);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
