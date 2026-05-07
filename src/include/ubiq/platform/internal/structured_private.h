#pragma once

#include "dataset.h"

__BEGIN_DECLS

UBIQ_PLATFORM_API
ubiq_platform_error_t * const ubiq_platform_structured_get_error_buffer(
  struct ubiq_platform_structured_enc_dec_obj * const enc
);

UBIQ_PLATFORM_API
ubiq_platform_dataset_t const * const ubiq_platform_structured_get_dataset(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  char const * const dataset_name
);

__END_DECLS

