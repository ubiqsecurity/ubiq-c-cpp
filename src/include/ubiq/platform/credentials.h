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

__BEGIN_DECLS

struct ubiq_platform_credentials;

/*
 * Create an object containing credentials for accessing the Ubiq service.
 *
 * This function will try environment followed by ~/.ubiq/credentials in
 * locating the credentials to be used. Missing variables in the environment
 * will be populated by merging those that are found with the 'default'
 * profile from ~/.ubiq/credentials
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, `*creds` will be populated with a pointer to the created
 * object. This object must be destroyed to avoid resource leakage.
 */
int
ubiq_platform_credentials_create(
    struct ubiq_platform_credentials ** creds);

/*
 * Load credentials from a specific profile in a specific file.
 *
 * The environment cannot override. One or the other or both of path and
 * profile may be specified as NULL. If the profile is specified and found
 * and does not contain a complete set of credentials, it will be merged with
 * the 'default' profile (if present). The server, if still not specified
 * after performing the above steps, may still be overridden by the
 * environment.
 *
 * Unnamed profiles are ignored.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, `*creds` will be populated with a pointer to the created
 * object. This object must be destroyed to avoid resource leakage.
 */
int
ubiq_platform_credentials_create_specific(
    const char * const path, const char * const profile,
    struct ubiq_platform_credentials ** creds);

/*
 * Create a credentials object from  explicitly specified credentials.
 *
 * `papi` is the access key id.
 * `sapi` is the secret signing key.
 * `srsa` is the secret crypto access key.
 * `host` is the api server name and port. This parameter may be NULL.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, `*creds` will be populated with a pointer to the created
 * object. This object must be destroyed to avoid resource leakage.
 */
int
ubiq_platform_credentials_create_explicit(
    const char * const papi, const char * const sapi,
    const char * const srsa,
    const char * const host,
    struct ubiq_platform_credentials ** creds);

/*
 * Destroy a previously created credentials object.
 */
void
ubiq_platform_credentials_destroy(
    struct ubiq_platform_credentials * creds);

__END_DECLS

#if defined(__cplusplus)

#include <string>
#include <memory>

namespace ubiq {
    namespace platform {
        class credentials
        {
        public:
            virtual ~credentials(void) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_credentials_create(). It does NOT throw an
             * exception on failure and will leave the object in an
             * "invalid" state.
             */
            credentials(void);
            /*
             * This constructor is equivalent to
             * ubiq_platform_credentials_create_specific(). It will throw
             * an exception if it cannot form a complete/valid set of
             * credentials. One or the other or both of `path` and `profile`
             * may be specified as empty strings which corresponds to passing
             * NULL for both parameters to
             * ubiq_platform_credentials_create_specific().
             */
            credentials(
                const std::string & path, const std::string & profile);
            /*
             * This constructor is equivalent to
             * ubiq_platform_credentials_create_explicit(). It will throw
             * an exception if the object cannot be properly constructed.
             */
            credentials(
                const std::string & papi, const std::string & sapi,
                const std::string & srsa,
                const std::string & host = std::string());

            credentials(const credentials &) = default;
            credentials(credentials &) =  default;

            credentials & operator =(const credentials &) = default;
            credentials & operator =(credentials &&) = default;

            /*
             * Gives access to the underlying C object
             */
            const ::ubiq_platform_credentials & operator *(void) const;

            /*
             * Determines if the object contains a set of credentials.
             */
            operator bool(void) const;

        private:
            std::shared_ptr<const ::ubiq_platform_credentials> _cred;
        };
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
