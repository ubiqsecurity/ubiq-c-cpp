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

        class fpe_encrypt_transform
        {
        public:
            virtual ~fpe_encrypt_transform(void) = default;
            fpe_encrypt_transform(void) = default;

            fpe_encrypt_transform(const fpe_encrypt_transform &) = delete;
            fpe_encrypt_transform(fpe_encrypt_transform &&) = default;

            fpe_encrypt_transform & operator =(const fpe_encrypt_transform &) = delete;
            fpe_encrypt_transform & operator =(fpe_encrypt_transform &&) = default;

            /*
             * Once constructed the, transform object works by calling
             * begin() followed by some number of calls to update() and
             * calling end() once all data has been passed to update().
             */

            virtual
            std::string
            encrypt(
              const std::string & ffs_name,
              const std::string & pt
            ) = 0;

            virtual
            std::string
            encrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & pt
            ) = 0;
        };
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
