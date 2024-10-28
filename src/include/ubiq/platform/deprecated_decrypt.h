#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>
#include <stdint.h>

#include <ubiq/platform/credentials.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const void * const ctbuf, const size_t ctlen,
    char ** const ptbuf, size_t * const ptlen);



__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen
);

/**
 * @brief Decrypt data using a pre-allocated buffer of data for the results.
 * 
 * @param enc handle to the Encrypt / Decrypt object
 * @param ffs_name name of the Dataset to use when decrypting the data.
 * @param tweak array of bytes to use for tweak 
 * @param tweaklen length of the tweak
 * @param ctbuf buffer containing the cipher text.  String should be NULL terminated.
 * @param ctlen number of bytes of data in the cipher text not including the NULL
 * terminator.
 * @param ptbuf pre-allocated buffer large enough to contain the
 * decrypted data including the NULL terminator.
 * @param ptlen indicates the size of allocated buffer.  Will be set to the number of 
 * bytes of the ptbuf returned or necessary space if ptbuf is not long enough
 * @return integer, 0 on success or negative error number on failure. 
 */

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_decrypt_data_prealloc(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char * const ptbuf, size_t * const ptlen
);

__END_DECLS

#if defined(__cplusplus)

#include <memory>
#include <string>
#include <vector>

#include <ubiq/platform/transform.h>


namespace ubiq {
    namespace platform {
        namespace fpe {

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          decrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::string & ct);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          decrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::vector<std::uint8_t> & tweak,
                  const std::string & ct);



          class decryption
          {
          public:
            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual ~decryption(void) = default;

            /*
             * The default constructor creates an empty decryption object.
             * This object cannot be used to perform an decryption, and
             * the constructor is provided for convenience.
             */
            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            decryption(void) = default;

            decryption(const decryption &) = delete;

            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            decryption(decryption &&) = default;

            decryption & operator =(const decryption &) = delete;

            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            decryption & operator =(decryption &&) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_encryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            decryption(const credentials & creds);

            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::string
            decrypt(
              const std::string & ffs_name,
              const std::string & pt
            ) ;

            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::string
            decrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & pt
            ) ;

            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::string
            get_copy_of_usage(void);

            __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            void
            add_user_defined_metadata(const std::string & jsonString);

          private:
            std::shared_ptr<::ubiq_platform_fpe_enc_dec_obj> _dec;
          };
        } // fpe
    } // platform
} // ubiq

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */
