#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS

/*
 * COND is the condition/expression being tested.
 * DESC is a description of what's being tested, but it needs
 *   to be formatted as a type name, so it can't have quotes
 *   or spaces or the like.
 */
#define STATIC_ASSERT(COND, DESC)                               \
    typedef char static_assertion__##DESC[2 * (!!(COND)) - 1]

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
