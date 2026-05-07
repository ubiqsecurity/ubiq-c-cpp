#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include <ubiq/platform/compat/cdefs.h>
#include "ubiq/platform/internal/operation.h"
#include "ubiq/platform/internal/operation_context.h"

__BEGIN_DECLS

struct ubiq_platform_structured_pipeline;
typedef struct ubiq_platform_structured_pipeline ubiq_platform_structured_pipeline_t;

// struct ubiq_platform_operation;

// typedef struct ubiq_platform_operation ubiq_platform_operation_t;


int ubiq_platform_structured_pipeline_create(size_t const initial_capacity, ubiq_platform_structured_pipeline_t ** const pipeline);

void ubiq_platform_structured_pipeline_destroy(ubiq_platform_structured_pipeline_t * const pipeline);

int ubiq_platform_structured_pipeline_add_operation(
  ubiq_platform_structured_pipeline_t * const pipeline, 
  ubiq_platform_operation_t * const operation,
  size_t const position); // 0 means beginning, MAX_INT or -1 means end;

int ubiq_platform_structured_pipeline_invoke(
  ubiq_platform_structured_pipeline_t * const pipeline, 
  ubiq_platform_operation_context_t * const context); // ctx current value will have the results

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
