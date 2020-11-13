#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <limits.h>

#include <ubiq/platform/encrypt.h>
#include <ubiq/platform/decrypt.h>

/* C interfaces */
__BEGIN_DECLS

/*
 * Library initialization and tear-down
 *
 * These are necessary for non-static initialization of this
 * library and libraries upon which this code depends.
 *
 * The init() function should be called at program startup,
 * and the exit() function should be called just prior to
 * program shutdown/exit.
 */
UBIQ_PLATFORM_API
int ubiq_platform_init(void);
UBIQ_PLATFORM_API
void ubiq_platform_exit(void);

__END_DECLS

/* C++ interfaces */
#if defined(__cplusplus)

#include <string>
#include <vector>

namespace ubiq {
    namespace platform {
        /*
         * Library initialization and tear-down.
         *
         * These simply call through to the C versions.
         */
        UBIQ_PLATFORM_API
        void init(void);
        UBIQ_PLATFORM_API
        void exit(void);
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
