#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

struct ubiq_platform_configuration;

/*
 * Create an object containing configuration for accessing the Ubiq service.
 *
 * This function will try environment followed by ~/.ubiq/configuration in
 * locating the configuration to be used. Missing variables in the environment
 * will be populated by merging those that are found with the 'default'
 * profile from ~/.ubiq/configuration
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, `*config` will be populated with a pointer to the created
 * object. This object must be destroyed to avoid resource leakage.
 */
UBIQ_PLATFORM_API
int
ubiq_platform_configuration_create(
  struct ubiq_platform_configuration ** const config);

/*
 * Load configuration from a specific profile in a specific file.
 *
 * The environment cannot override. One or the other or both of path and
 * profile may be specified as NULL. If the profile is specified and found
 * and does not contain a complete set of configuration, it will be merged with
 * the 'default' profile (if present). The server, if still not specified
 * after performing the above steps, may still be overridden by the
 * environment.
 *
 * Unnamed profiles are ignored.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, `*config` will be populated with a pointer to the created
 * object. This object must be destroyed to avoid resource leakage.
 */
UBIQ_PLATFORM_API
int
ubiq_platform_configuration_load_configuration(
    const char * const path,
    struct ubiq_platform_configuration ** const config);

/*
 * Create a configuration object from  explicitly specified configuration.
 *
 * `papi` is the access key id.
 * `sapi` is the secret signing key.
 * `srsa` is the secret crypto access key.
 * `host` is the api server name and port. This parameter may be NULL.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, `*config` will be populated with a pointer to the created
 * object. This object must be destroyed to avoid resource leakage.
 */
UBIQ_PLATFORM_API
int
ubiq_platform_configuration_create_explicit(
    const int event_reporting_wake_interval,
    const int event_reporting_minimum_count,
    const int event_reporting_flush_interval,
    const int event_reporting_trap_exceptions,
    struct ubiq_platform_configuration ** const config);

/*
 * Destroy a previously created configuration object.
 */
UBIQ_PLATFORM_API
void
ubiq_platform_configuration_destroy(
    struct ubiq_platform_configuration * const config);

__END_DECLS

#if defined(__cplusplus)

#include <string>
#include <memory>

namespace ubiq {
    namespace platform {
        class configuration
        {
        public:
            UBIQ_PLATFORM_API
            virtual ~configuration(void) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_configuration_create(). It does NOT throw an
             * exception on failure and will leave the object in an
             * "invalid" state.
             */
            UBIQ_PLATFORM_API
            configuration(void);
            /*
             * This constructor is equivalent to
             * ubiq_platform_configuration_create_specific(). It will throw
             * an exception if it cannot form a complete/valid set of
             * configuration. One or the other or both of `path` and `profile`
             * may be specified as empty strings which corresponds to passing
             * NULL for both parameters to
             * ubiq_platform_configuration_create_specific().
             */
            UBIQ_PLATFORM_API
            configuration(
                const std::string & path);
            /*
             * This constructor is equivalent to
             * ubiq_platform_configuration_create_explicit(). It will throw
             * an exception if the object cannot be properly constructed.
             */
            UBIQ_PLATFORM_API
            configuration(
              const int event_reporting_wake_interval,
              const int event_reporting_minimum_count,
              const int event_reporting_flush_interval,
              const int event_reporting_trap_exceptions);

            UBIQ_PLATFORM_API
            configuration(const configuration &) = default;
            UBIQ_PLATFORM_API
            configuration(configuration &&) =  default;

            UBIQ_PLATFORM_API
            configuration & operator =(const configuration &) = default;
            UBIQ_PLATFORM_API
            configuration & operator =(configuration &&) = default;

            /*
             * Gives access to the underlying C object
             */
            UBIQ_PLATFORM_API
            const ::ubiq_platform_configuration & operator *(void) const;

            /*
             * Determines if the object contains a set of configuration.
             */
            UBIQ_PLATFORM_API
            operator bool(void) const;

        private:
            std::shared_ptr<const ::ubiq_platform_configuration> _config;
        };
    }
}

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
