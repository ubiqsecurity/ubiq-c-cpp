#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

int ubiq_platform_base64_encode(char **, const void *, size_t);
int ubiq_platform_base64_decode(void **, const char *, size_t);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
