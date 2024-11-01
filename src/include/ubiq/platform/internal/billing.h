#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <search.h>

__BEGIN_DECLS

struct ubiq_billing_ctx ;

typedef enum {ENCRYPTION = 0, DECRYPTION = 1} ubiq_billing_action_type;

int
ubiq_billing_ctx_create(
  struct ubiq_billing_ctx ** ctx,
  const char * const host,
  const char *const papi, 
  const char *const sapi,
  const struct ubiq_platform_configuration * const cfg
  );

void
ubiq_billing_ctx_destroy(struct ubiq_billing_ctx * const ctx);


// Will insert / update as needed
int
ubiq_billing_add_billing_event(
  struct ubiq_billing_ctx * const e,
  const char * const api_key,
  const char * const dataset_name,
  const char * const dataset_group_name,
  const ubiq_billing_action_type billing_action,
  unsigned long count,
  unsigned int key_number);

int 
ubiq_billing_get_copy_of_usage( struct ubiq_billing_ctx * const e,
                char ** const buffer, size_t * const buffer_len);

int
ubiq_billing_add_user_defined_metadata( struct ubiq_billing_ctx * const e,
                        const char * const jsonString);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
