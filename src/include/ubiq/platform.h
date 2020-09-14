/*
 * Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Ubiq Security, Inc. The intellectual and technical concepts contained
 * herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
 * covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Ubiq Security, Inc.
 *
 * Your use of the software is expressly conditioned upon the terms
 * and conditions available at:
 *
 *     https://ubiqsecurity.com/legal
 *
 */

#pragma once

#include <sys/cdefs.h>

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
int ubiq_platform_init(void);
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
        void init(void);
        void exit(void);
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
