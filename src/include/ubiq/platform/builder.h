#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include <ubiq/platform.h>
#include <ubiq/platform/credentials.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS


struct ubiq_platform_builder;

UBIQ_PLATFORM_API
int
ubiq_platform_builder_create(
  struct ubiq_platform_builder ** const builder
);

UBIQ_PLATFORM_API
void
ubiq_platform_builder_destroy(
  struct ubiq_platform_builder * const builder
);

UBIQ_PLATFORM_API
int
ubiq_platform_builder_set_credentials_file(
  struct ubiq_platform_builder * const builder,
  const char * filename,
  const char * profile
);

UBIQ_PLATFORM_API
int
ubiq_platform_builder_set_credentials(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_credentials * const creds
);

UBIQ_PLATFORM_API
int
ubiq_platform_builder_set_configuration(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_configuration * const config
);

UBIQ_PLATFORM_API
int
ubiq_platform_builder_build_structured(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_structured_enc_dec_obj ** structured
);

UBIQ_PLATFORM_API
int
ubiq_platform_builder_build_unstructured_encrypt(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_encryption ** encrypt
);

UBIQ_PLATFORM_API
int
ubiq_platform_builder_build_unstructured_decrypt(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_decryption ** decrypt
);


// Future Consideration - Decide if we want builder_destroy for each of the encrypt / decrypt objects
// so we have a better matched set of build / destroy functions.
// Currently using the ubiq_platform_*_destroy which don't match the builder or
// or ubiq_platform_*_create functions.

__END_DECLS


#if defined(__cplusplus)

#include <string>


namespace ubiq {
    namespace platform {

        class builder
        {
        public:
            UBIQ_PLATFORM_API
            virtual ~builder(void) = default;

            UBIQ_PLATFORM_API
            builder(void);

            UBIQ_PLATFORM_API
            builder & with(const credentials & creds);

            UBIQ_PLATFORM_API
            builder & with(const configuration & cfg);

            builder(const builder &) = delete;
            UBIQ_PLATFORM_API
            builder(builder &&) = default;

            builder & operator =(const builder &) = delete;

            UBIQ_PLATFORM_API
            builder & operator =(builder &&) = default;

            UBIQ_PLATFORM_API
            virtual
            encryption 
            buildUnstructuredEncryption(void);

            UBIQ_PLATFORM_API
            virtual
            decryption 
            buildUnstructuredDecryption(void);

            UBIQ_PLATFORM_API
            virtual
            structured::encryption 
            buildStructuredEncryption(void);

            UBIQ_PLATFORM_API
            virtual
            structured::decryption 
            buildStructuredDecryption(void);

            UBIQ_PLATFORM_API
            const ::ubiq_platform_builder & operator *(void) const;

            UBIQ_PLATFORM_API
            operator bool(void) const;

        private:
          std::shared_ptr<::ubiq_platform_builder> _builder;

        };

    } // platform
} // ubiq

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */


