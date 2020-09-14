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
#include <stddef.h>

#include <ubiq/platform/credentials.h>

__BEGIN_DECLS

/*
 * Encrypt a single buffer, outputting the entire cipher text at once
 *
 * Given a (valid) set of credentials and a plain text buffer and size,
 * this function obtains a new data key from the Ubiq service and uses
 * it and the assigned algorithm to encrypt the plain text buffer.
 *
 * A pointer to the encrypted cipher text is returned in *ctbuf and the
 * number of bytes of cipher text is returned in *ctlen.
 *
 * The function returns 0 on success or a negative error number on failure.
 * In the case of success, *ctbuf will point to memory allocated with
 * malloc(3), and the caller is responsible for releasing the memory with
 * free(3).
 */
int
ubiq_platform_encrypt(
    const struct ubiq_platform_credentials * creds,
    const void * ptbuf, const size_t ptlen,
    void ** ctbuf, size_t * ctlen);

/* Opaque encryption object */
struct ubiq_platform_encryption;

/*
 * Create an encryption object that can be used to encrypt some number
 * of separate plain texts under the same key.
 *
 * Given a (valid) set of credentials and a desired number of uses of the
 * newly obtained key, this function will obtain a new data key from the
 * Ubiq service with permission to use it some number of times with the
 * assigned algorithm. The number of times the key may be used may be
 * reduced by the server.
 *
 * This function returns 0 on success or a negative error number on failure.
 * In the case of success, the encryption object is returned in *enc, and
 * must be destroyed by ubiq_platform_encryption_destroy() to avoid leaking
 * resources.
 */
int
ubiq_platform_encryption_create(
    const struct ubiq_platform_credentials * creds,
    unsigned int uses,
    struct ubiq_platform_encryption ** enc);

/*
 * Destroy an encryption object.
 *
 * This function releases resources associated with a previously created
 * encryption object. The most recent call on the object must either be
 * ubiq_platform_encryption_create() or ubiq_platform_encryption_end().
 */
void
ubiq_platform_encryption_destroy(
    struct ubiq_platform_encryption * enc);

/*
 * Begin encryption of a plain text using the specified encryption object.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to the initial portion of the
 * cipher text in *ctbuf and the number of bytes pointed to by that pointer
 * in *ctlen. The caller is responsible for freeing that pointer using
 * free(3).
 */
int
ubiq_platform_encryption_begin(
    struct ubiq_platform_encryption * enc,
    void ** ctbuf, size_t * ctlen);

/*
 * Encrypt a portion of plain text.
 *
 * This function should be called repeatedly to process the plain text. Each
 * call may generate some amount of cipher text.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the cipher text
 * in *ctbuf and the number of bytes pointed to by that pointer in *ctlen.
 * The caller is responsible for freeing that pointer using free(3).
 */
int
ubiq_platform_encryption_update(
    struct ubiq_platform_encryption * enc,
    const void * ptbuf, const size_t ptlen,
    void ** ctbuf, size_t * ctlen);

/*
 * Complete an encryption of a plain text.
 *
 * Once all of the plain text has been processed by the calls to update(),
 * this function must be called to finalize the encryption.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the cipher text
 * in *ctbuf and the number of bytes pointed to by that pointer in *ctlen.
 * The caller is responsible for freeing that pointer using free(3).
 *
 * After this function is called, the caller can call begin() again to start
 * an encryption a different plain text under the same key or destroy() to
 * release the encryption object.
 */
int
ubiq_platform_encryption_end(
    struct ubiq_platform_encryption * enc,
    void ** ctbuf, size_t * ctlen);

__END_DECLS

#if defined(__cplusplus)

#include <memory>
#include <string>
#include <vector>

#include <ubiq/platform/transform.h>

namespace ubiq {
    namespace platform {
        std::vector<std::uint8_t>
        encrypt(const credentials & creds,
                const void * ptbuf, std::size_t ptlen);

        class encryption : public transform
        {
        public:
            virtual ~encryption(void) = default;

            /*
             * The default constructor creates an empty encryption object.
             * This object cannot be used to perform an encryption, and
             * the constructor is provided for convenience.
             */
            encryption(void) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_encryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
            encryption(const credentials & creds, unsigned int uses);

            encryption(const encryption &) = delete;
            encryption(encryption &&) = default;

            encryption & operator =(const encryption &) = delete;
            encryption & operator =(encryption &&) = default;

            /*
             * This function is equivalent to ubiq_platform_encryption_begin();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            virtual
            std::vector<std::uint8_t>
            begin(void)
                override;
            /*
             * This function is equivalent to ubiq_platform_encryption_update();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            virtual
            std::vector<std::uint8_t>
            update(const void * ptbuf, std::size_t ptlen)
                override;
            /*
             * This function is equivalent to ubiq_platform_encryption_end();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            virtual
            std::vector<std::uint8_t>
            end(void)
                override;

        private:
            std::shared_ptr<::ubiq_platform_encryption> _enc;
        };
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
