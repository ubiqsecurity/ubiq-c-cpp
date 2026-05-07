#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>

#include <ubiq/platform/compat/cdefs.h>
#include "ubiq/platform/internal/operation.h"
#include "ubiq/platform/internal/operation_context.h"

__BEGIN_DECLS

ubiq_platform_operation_t * const ubiq_platform_unpad_input_operation_create(void);

void ubiq_platform_unpad_input_operation_delete(ubiq_platform_operation_t * const op);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
