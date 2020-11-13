#pragma once

#include <ubiq/platform/compat/cdefs.h>
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
UBIQ_PLATFORM_API
int
ubiq_platform_credentials_create(
    struct ubiq_platform_credentials ** const creds);

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
UBIQ_PLATFORM_API
int
ubiq_platform_credentials_create_specific(
    const char * const path, const char * const profile,
    struct ubiq_platform_credentials ** const creds);

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
UBIQ_PLATFORM_API
int
ubiq_platform_credentials_create_explicit(
    const char * const papi, const char * const sapi,
    const char * const srsa,
    const char * const host,
    struct ubiq_platform_credentials ** const creds);

/*
 * Destroy a previously created credentials object.
 */
UBIQ_PLATFORM_API
void
ubiq_platform_credentials_destroy(
    struct ubiq_platform_credentials * const creds);

__END_DECLS

#if defined(__cplusplus)

#include <string>
#include <memory>

namespace ubiq {
    namespace platform {
        class credentials
        {
        public:
            UBIQ_PLATFORM_API
            virtual ~credentials(void) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_credentials_create(). It does NOT throw an
             * exception on failure and will leave the object in an
             * "invalid" state.
             */
            UBIQ_PLATFORM_API
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
            UBIQ_PLATFORM_API
            credentials(
                const std::string & path, const std::string & profile);
            /*
             * This constructor is equivalent to
             * ubiq_platform_credentials_create_explicit(). It will throw
             * an exception if the object cannot be properly constructed.
             */
            UBIQ_PLATFORM_API
            credentials(
                const std::string & papi, const std::string & sapi,
                const std::string & srsa,
                const std::string & host = std::string());

            UBIQ_PLATFORM_API
            credentials(const credentials &) = default;
            UBIQ_PLATFORM_API
            credentials(credentials &&) =  default;

            UBIQ_PLATFORM_API
            credentials & operator =(const credentials &) = default;
            UBIQ_PLATFORM_API
            credentials & operator =(credentials &&) = default;

            /*
             * Gives access to the underlying C object
             */
            UBIQ_PLATFORM_API
            const ::ubiq_platform_credentials & operator *(void) const;

            /*
             * Determines if the object contains a set of credentials.
             */
            UBIQ_PLATFORM_API
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
