#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>
#include <stdint.h>

#include <ubiq/platform/credentials.h>
#include <ubiq/platform/configuration.h>

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
UBIQ_PLATFORM_API
int
ubiq_platform_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen);


/* Opaque encryption object */
struct ubiq_platform_encryption;

struct ubiq_platform_structured_enc_dec_obj;

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
UBIQ_PLATFORM_API
int
ubiq_platform_encryption_create(
    const struct ubiq_platform_credentials * const creds,
    const unsigned int uses,
    struct ubiq_platform_encryption ** const enc);

UBIQ_PLATFORM_API
int
ubiq_platform_encryption_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * cfg,
    const unsigned int uses,
    struct ubiq_platform_encryption ** const enc);

/*
 * Destroy an encryption object.
 *
 * This function releases resources associated with a previously created
 * encryption object. The most recent call on the object must either be
 * ubiq_platform_encryption_create() or ubiq_platform_encryption_end().
 */
UBIQ_PLATFORM_API
void
ubiq_platform_encryption_destroy(
    struct ubiq_platform_encryption * const enc);

/*
 * Begin encryption of a plain text using the specified encryption object.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to the initial portion of the
 * cipher text in *ctbuf and the number of bytes pointed to by that pointer
 * in *ctlen. The caller is responsible for freeing that pointer using
 * free(3).
 */
UBIQ_PLATFORM_API
int
ubiq_platform_encryption_begin(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen);

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
UBIQ_PLATFORM_API
int
ubiq_platform_encryption_update(
    struct ubiq_platform_encryption * const enc,
    const void * ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen);

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
UBIQ_PLATFORM_API
int
ubiq_platform_encryption_end(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen);

UBIQ_PLATFORM_API
int
ubiq_platform_encryption_add_user_defined_metadata(
    struct ubiq_platform_encryption * const enc,
    const char * const jsonString);

UBIQ_PLATFORM_API
int
ubiq_platform_encryption_get_copy_of_usage(
    struct ubiq_platform_encryption * const enc,
    char ** const buffer, size_t * const buffer_len);

/*
 * *******************************************
 *                  Structured
 * *******************************************
 */

// Piecewise functions
UBIQ_PLATFORM_API
int
ubiq_platform_structured_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_structured_enc_dec_obj ** const enc);

// Piecewise functions
UBIQ_PLATFORM_API
int
ubiq_platform_structured_enc_dec_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_structured_enc_dec_obj ** const enc);
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
UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char * const ctbuf, size_t * const ctlen
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
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
UBIQ_PLATFORM_API
int
ubiq_platform_encrypt_data_for_search_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctbuflen, size_t * const count
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char *** const ctbuf, size_t * const count
);

UBIQ_PLATFORM_API
void
ubiq_platform_structured_enc_dec_destroy(
    struct ubiq_platform_structured_enc_dec_obj * const e);

// Get details regarding last error message if
// available.  Must free the errmsg string when
// done.
UBIQ_PLATFORM_API
int
ubiq_platform_structured_get_last_error(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  int * const err_num,
  char ** const err_msg
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_enc_dec_get_copy_of_usage(
    struct ubiq_platform_structured_enc_dec_obj * const obj,
    char ** const buffer, size_t * const buffer_len);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_enc_dec_add_user_defined_metadata(
    struct ubiq_platform_structured_enc_dec_obj * const obj,
    const char * const jsonString);

__END_DECLS

#if defined(__cplusplus)

#include <memory>
#include <string>
#include <vector>

#include <ubiq/platform/transform.h>

namespace ubiq {
    namespace platform {

      class builder;

        UBIQ_PLATFORM_API
        std::vector<std::uint8_t>
        encrypt(const credentials & creds,
                const void * ptbuf, std::size_t ptlen);

        class encryption : public transform
        {
        public:
            UBIQ_PLATFORM_API
            virtual ~encryption(void) = default;

            /*
             * The default constructor creates an empty encryption object.
             * This object cannot be used to perform an encryption, and
             * the constructor is provided for convenience.
             */
            UBIQ_PLATFORM_API
            encryption(void) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_encryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
            UBIQ_PLATFORM_API
            encryption(const credentials & creds, unsigned int uses);

            UBIQ_PLATFORM_API
            encryption(const credentials & creds, 
            const configuration & cfg,
            unsigned int uses);

            encryption(const encryption &) = delete;
            UBIQ_PLATFORM_API
            encryption(encryption &&) = default;

            encryption & operator =(const encryption &) = delete;
            UBIQ_PLATFORM_API
            encryption & operator =(encryption &&) = default;

            /*
             * This function is equivalent to ubiq_platform_encryption_begin();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            begin(void)
                override;
            /*
             * This function is equivalent to ubiq_platform_encryption_update();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            update(const void * ptbuf, std::size_t ptlen)
                override;
            /*
             * This function is equivalent to ubiq_platform_encryption_end();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            end(void)
                override;

            UBIQ_PLATFORM_API
            std::string
            get_copy_of_usage(void);

            UBIQ_PLATFORM_API
            virtual
            void
            add_user_defined_metadata(const std::string & jsonString);

        private:
            UBIQ_PLATFORM_API
            encryption(::ubiq_platform_encryption * e);

            std::shared_ptr<::ubiq_platform_encryption> _enc;
            friend class builder;
        };


        namespace structured {


          UBIQ_PLATFORM_API
          std::string
          get_error(struct ubiq_platform_structured_enc_dec_obj * const enc);

          // Bulk
          class encryption
          {
          public:

            UBIQ_PLATFORM_API
            virtual ~encryption(void) = default;

            /*
             * The default constructor creates an empty encryption object.
             * This object cannot be used to perform an encryption, and
             * the constructor is provided for convenience.
             */
            UBIQ_PLATFORM_API
            encryption(void) = default;

            encryption(const encryption &) = delete;
            UBIQ_PLATFORM_API
            encryption(encryption &&) = default;
            encryption & operator =(const encryption &) = delete;
            UBIQ_PLATFORM_API
            encryption & operator =(encryption &&) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_encryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
            UBIQ_PLATFORM_API
            encryption(const credentials & creds);

            UBIQ_PLATFORM_API
            encryption(const credentials & creds,
            const configuration & cfg
            );

            UBIQ_PLATFORM_API
            virtual
            std::string
            encrypt(
              const std::string & ffs_name,
              const std::string & pt
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::vector<std::string>
            encrypt_for_search(
              const std::string & ffs_name,
              const std::string & pt
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::string
            encrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & pt
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::vector<std::string>
            encrypt_for_search(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & pt
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::string
            get_copy_of_usage(void);

            UBIQ_PLATFORM_API
            virtual
            void
            add_user_defined_metadata(const std::string & jsonString);


          protected:

          private:
            UBIQ_PLATFORM_API
            encryption(::ubiq_platform_structured_enc_dec_obj * e);

            std::shared_ptr<::ubiq_platform_structured_enc_dec_obj> _enc;
            friend class ubiq::platform::builder;
 
          };
        } // structured
    } // platform
} // ubiq

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */

