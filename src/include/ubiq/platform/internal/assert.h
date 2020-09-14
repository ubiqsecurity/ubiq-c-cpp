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
