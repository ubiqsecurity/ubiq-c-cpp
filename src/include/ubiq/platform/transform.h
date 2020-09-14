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

#if defined(__cplusplus)

#include <vector>

#include <ubiq/platform/transform.h>

namespace ubiq {
    namespace platform {
        /*
         * The transform object is an abstract class that serves
         * as the base class for the encryption and decryption
         * objects, unifying their interfaces.
         */
        class transform
        {
        public:
            virtual ~transform(void) = default;
            transform(void) = default;

            transform(const transform &) = delete;
            transform(transform &&) = default;

            transform & operator =(const transform &) = delete;
            transform & operator =(transform &&) = default;

            /*
             * Once constructed the, transform object works by calling
             * begin() followed by some number of calls to update() and
             * calling end() once all data has been passed to update().
             */

            virtual
            std::vector<std::uint8_t>
            begin(void) = 0;
            virtual
            std::vector<std::uint8_t>
            update(const void * buf, std::size_t len) = 0;
            virtual
            std::vector<std::uint8_t>
            end(void) = 0;
        };
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
