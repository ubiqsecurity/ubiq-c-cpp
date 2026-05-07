#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include <ubiq/platform/compat/cdefs.h>
#include "ubiq/platform/internal/operation_context.h"

__BEGIN_DECLS

typedef struct ubiq_platform_decryption_pipeline ubiq_platform_decryption_pipeline_t;

ubiq_platform_decryption_pipeline_t * const ubiq_platform_decryption_pipeline_create(
  ubiq_platform_dataset_t const * const dataset);

int ubiq_platform_decryption_pipeline_invoke(
  ubiq_platform_decryption_pipeline_t * const pipeline,
  ubiq_platform_operation_context_t * const context);

void ubiq_platform_decryption_pipeline_delete(ubiq_platform_decryption_pipeline_t * const op);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
