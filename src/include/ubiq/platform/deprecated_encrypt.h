#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>
#include <stdint.h>

#include <ubiq/platform/credentials.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS


struct ubiq_platform_fpe_enc_dec_obj;

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char ** const ctbuf, size_t * const ctlen);

// ctbuf is array of NULL terminated UTF8 strings
// length is not returned since each ctbuf element may be different number of
// bytes due to multi-byte characters
__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_encrypt_for_search(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char *** const ctbuf, size_t * const count);


/*
 * *******************************************
 *                  FPE
 * *******************************************
 */

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc);

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_enc_dec_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc);
/**
 * @brief Encrypt data using a pre-allocated byffer of data for the results.
 * 
 * @param enc handle to the Encrypt / Decrypt object
 * @param ffs_name name of the Dataset to use when encrypting the data.
 * @param tweak array of bytes to use for tweak 
 * @param tweaklen length of the tweak
 * @param ptbuf buffer containing the plain text.  String should be NULL terminated.
 * @param ptlen number of bytes of data in the plain text not including the NULL
 * terminator.
 * @param ctbuf pre-allocated buffer large enough to contain the
 * cipher text including the NULL terminator.
 * @param ctlen indicates the size of allocated buffer.  Will be set to the number of 
 * bytes of the ctbuf returned or necessary space if ctbuf is not long enough
 * @return integer, 0 on success or negative error number on failure. 
 */
__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_encrypt_data_prealloc(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char * const ctbuf, size_t * const ctlen
);

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen
);

// ctbuf is array of NULL terminated UTF8 strings
// length is not returned since each ctbuf element may be different number of
// bytes due to multi-byte characters

/**
 * @brief Perform encryption on the same plain text using many different key numbers to find a cipher text 
 * that may match a database
 * 
 * @param enc handle to the Encrypt / Decrypt object
 * @param ffs_name name of the Dataset to use when encrypting the data.
 * @param tweak array of bytes to use for tweak 
 * @param tweaklen length of the tweak
 * @param ptbuf buffer containing the plain text.  String should be NULL terminated.
 * @param ptlen number of bytes of data in the plain text not including the NULL
 * terminator.
 * @param ctbuf - array of buffers for the search results
 * @param ctbuflen - indicates the size each array element in the allocated buffer.  Will be set to the number of 
 * bytes of the longest cipher text value or the number of bytes required, including the NULL terminator
 * @param count the number of array elements allocated in ctbuf.  Will be set to the number of cipher text values returned.
 * If count is not large enough for all cipher text values, an error will be returned and this value will be set to the neccessary value.
 * @return integer, 0 on success or negative error number on failure. 
 */
__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_encrypt_data_for_search_prealloc(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctbuflen, size_t * const count
);

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_encrypt_data_for_search(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char *** const ctbuf, size_t * const count
);

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
void
ubiq_platform_fpe_enc_dec_destroy(
    struct ubiq_platform_fpe_enc_dec_obj * const e);

// Get details regarding last error message if
// available.  Must free the errmsg string when
// done.
__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_get_last_error(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  int * const err_num,
  char ** const err_msg
);

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_enc_dec_get_copy_of_usage(
    struct ubiq_platform_fpe_enc_dec_obj * const obj,
    char ** const buffer, size_t * const buffer_len);

__attribute__ ((deprecated)) 
UBIQ_PLATFORM_API
int
ubiq_platform_fpe_enc_dec_add_user_defined_metadata(
    struct ubiq_platform_fpe_enc_dec_obj * const obj,
    const char * const jsonString);


__END_DECLS

#if defined(__cplusplus)

#include <memory>
#include <string>
#include <vector>

#include <ubiq/platform/transform.h>


namespace ubiq {
    namespace platform {
        namespace fpe {

          // Simple
          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          encrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          encrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::vector<std::string>
          encrypt_for_search(const credentials & creds,
                  const std::string & ffs_name,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::vector<std::string>
          encrypt_for_search(const credentials & creds,
                  const std::string & ffs_name,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          encrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::vector<std::uint8_t> & tweak,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          encrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::vector<std::uint8_t> & tweak,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::vector<std::string>
          encrypt_for_search(const credentials & creds,
                  const std::string & ffs_name,
                  const std::vector<std::uint8_t> & tweak,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::vector<std::string>
          encrypt_for_search(const credentials & creds,
                  const std::string & ffs_name,
                  const std::vector<std::uint8_t> & tweak,
                  const std::string & pt);

          __attribute__ ((deprecated)) 
          UBIQ_PLATFORM_API
          std::string
          get_error(struct ubiq_platform_fpe_enc_dec_obj * const enc);


          // Bulk
          class encryption
          {
          public:

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual ~encryption(void) = default;

            /*
             * The default constructor creates an empty encryption object.
             * This object cannot be used to perform an encryption, and
             * the constructor is provided for convenience.
             */
          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            encryption(void) = default;

            encryption(const encryption &) = delete;

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            encryption(encryption &&) = default;

            encryption & operator =(const encryption &) = delete;

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            encryption & operator =(encryption &&) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_encryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            encryption(const credentials & creds);

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            encryption(const credentials & creds,
            configuration & cfg
            );

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::string
            encrypt(
              const std::string & ffs_name,
              const std::string & pt
            ) ;

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::string>
            encrypt_for_search(
              const std::string & ffs_name,
              const std::string & pt
            ) ;

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::string
            encrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & pt
            ) ;

          __attribute__ ((deprecated)) 
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::string>
            encrypt_for_search(
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
            std::shared_ptr<::ubiq_platform_fpe_enc_dec_obj> _enc;
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
