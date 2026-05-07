#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include <ubiq/platform/credentials.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS

/*
 * Decrypt a single buffer, outputting the entire plain text at once
 *
 * Given a (valid) set of credentials and a cipher text buffer and size,
 * this function obtains data key associated with the cipher text from the
 * Ubiq service and uses it and the assigned algorithm to decrypt the cipher
 * text buffer.
 *
 * A pointer to the decrypted cipher text is returned in *ptbuf and the
 * number of bytes of plain text is returned in *ptlen.
 *
 * The function returns 0 on success or a negative error number on failure.
 * In the case of success, *ptbuf will point to memory allocated with
 * malloc(3), and the caller is responsible for releasing the memory with
 * free(3).
 */
UBIQ_PLATFORM_API
int
ubiq_platform_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const void * const ctbuf, const size_t ctlen,
    void ** ptbuf, size_t * ptlen);



/* Opaque decryption object */
struct ubiq_platform_decryption;

struct ubiq_platform_decryption_session;

/*
 * Create a decryption object that can be used to decrypt any number
 * of separate cipher texts.
 *
 * This function returns 0 on success or a negative error number on failure.
 * In the case of success, the decryption object is returned in *dec, and
 * must be destroyed by ubiq_platform_decryption_destroy() to avoid leaking
 * resources.
 */
UBIQ_PLATFORM_API
int
ubiq_platform_decryption_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_decryption ** const dec);

/*
 * Create a decryption object that can be used to decrypt any number
 * of separate cipher texts.  The configuration object adjusts the 
 * frequency of the billing processing.
 *
 * This function returns 0 on success or a negative error number on failure.
 * In the case of success, the decryption object is returned in *dec, and
 * must be destroyed by ubiq_platform_decryption_destroy() to avoid leaking
 * resources.
 */

UBIQ_PLATFORM_API
int
ubiq_platform_decryption_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_decryption ** const dec);

/*
 * Destroy a decryption object.
 *
 * This function releases resources associated with a previously created
 * decryption object. The most recent call on the object must either be
 * ubiq_platform_decryption_create() or ubiq_platform_decryption_end().
 */
UBIQ_PLATFORM_API
void
ubiq_platform_decryption_destroy(
    struct ubiq_platform_decryption * const dec);

/*
 * Begin decryption of a cipher text using the specified decryption object.
 *
 * The function returns 0 on success or a negative error number on failure.
 * The caller should treat the ptbuf and ptlen pointers as if data were
 * returned in them and *ptbuf needed to be released with free(3); however,
 * in practice, the function returns NULL and 0 in these parameters.
 */
UBIQ_PLATFORM_API
int
ubiq_platform_decryption_begin(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen);

UBIQ_PLATFORM_API
int
ubiq_platform_decryption_beginTS(
    struct ubiq_platform_decryption * const dec,
    struct ubiq_platform_decryption_session * const session,
    void ** const ptbuf, size_t * const ptlen);

/*
 * Decrypt a portion of cipher text.
 *
 * This function should be called repeatedly to process the cipher text. Each
 * call may generate some amount of plain text.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the plain text
 * in *ptbuf and the number of bytes pointed to by that pointer in *ptlen.
 * The caller is responsible for freeing that pointer using free(3).
 */
UBIQ_PLATFORM_API
int
ubiq_platform_decryption_update(
    struct ubiq_platform_decryption * const dec,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen);

UBIQ_PLATFORM_API
int
ubiq_platform_decryption_updateTS(
    struct ubiq_platform_decryption * const dec,
    struct ubiq_platform_decryption_session * const session,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen);

/*
 * Complete an decryption of a plain text.
 *
 * Once all of the cipher text has been processed by the calls to update(),
 * this function must be called to finalize the encryption. Note that for
 * some algorithms, this function may indicate that the decryption can't be
 * trusted as authentic. In that case the function has completed successfully,
 * but the caller should discard the plain text.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the plain text
 * in *ptbuf and the number of bytes pointed to by that pointer in *ptlen.
 * The caller is responsible for freeing that pointer using free(3).
 *
 * After this function is called, the caller can call begin() again to start
 * an decryption a different cihper text or destroy() to release the decryption
 * object.
 */
UBIQ_PLATFORM_API
int
ubiq_platform_decryption_end(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen);

UBIQ_PLATFORM_API
int
ubiq_platform_decryption_endTS(
    struct ubiq_platform_decryption * const dec,
    struct ubiq_platform_decryption_session * const session,
    void ** const ptbuf, size_t * const ptlen);


UBIQ_PLATFORM_API
int
ubiq_platform_decryption_add_user_defined_metadata(
    struct ubiq_platform_decryption * const dec,
    const char * const jsonString);

UBIQ_PLATFORM_API
int
ubiq_platform_decryption_get_copy_of_usage(
    struct ubiq_platform_decryption * const dec,
    char ** const buffer, size_t * const buffer_len);

UBIQ_PLATFORM_API
int
ubiq_platform_decryption_init_session(
struct ubiq_platform_decryption * const dec,
struct ubiq_platform_decryption_session ** const session);

UBIQ_PLATFORM_API
void ubiq_platform_decryption_destroy_session(
  struct ubiq_platform_decryption_session * const session);

/*
 * *******************************************
 *                  Structured
 * *******************************************
 */

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_u32data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char32_t * const ptbuf, const size_t ptlen,
  char32_t ** const ctbuf, size_t * const ctlen
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_int_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int32_t ct,
  int32_t * const pt
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_long_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int64_t ct,
  int64_t * const pt
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_date_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const ct,
  struct tm * const pt
);

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_datetime_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const ct,
  struct tm * const pt
);

// __attribute__ ((deprecated))   UBIQ_PLATFORM_API
// int
// ubiq_platform_structured_old_decrypt_data_prealloc(
//   struct ubiq_platform_structured_old_enc_dec_obj * const enc,
//   const char * const ffs_name,
//   const uint8_t * const tweak, const size_t tweaklen,
//   const char * const ctbuf, const size_t ctlen,
//   char * const ptbuf, size_t * const ptlen
// );

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char * const ptbuf, size_t * const ptlen
);

// The NEW should be the char32_t
UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
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

      class builder;
      class decryption_session;
      class decryption;

        class decryption_session {
          public:

          UBIQ_PLATFORM_API
          decryption_session();

          UBIQ_PLATFORM_API
          decryption_session(decryption &decryption);

          UBIQ_PLATFORM_API
          virtual ~decryption_session(void) = default;


          UBIQ_PLATFORM_API
          decryption_session(const decryption_session &) = default;
          UBIQ_PLATFORM_API
          decryption_session(decryption_session &&) =  default;

          UBIQ_PLATFORM_API
          decryption_session & operator =(const decryption_session &) = default;
          UBIQ_PLATFORM_API
          decryption_session & operator =(decryption_session &&) = default;

        /*
          * Gives access to the underlying C object
          */
        UBIQ_PLATFORM_API
        ::ubiq_platform_decryption_session & operator *(void) const;

          private:
          std::shared_ptr<::ubiq_platform_decryption_session> _session;

          friend class decryption;

        };

        UBIQ_PLATFORM_API
        std::vector<std::uint8_t>
        decrypt(const credentials & creds,
                const void * ctbuf, std::size_t ctlen);

        class decryption : public transform
        {
        public:
            UBIQ_PLATFORM_API
            virtual ~decryption(void) = default;

            /*
             * The default constructor creates an empty decryption object.
             * This object cannot be used to perform a decryption, and
             * the constructor is provided for convenience.
             */
            UBIQ_PLATFORM_API
            decryption(void) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_decryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
            UBIQ_PLATFORM_API
            decryption(const credentials & creds);

            UBIQ_PLATFORM_API
            decryption(const credentials & creds, const configuration & cfg);

            decryption(const decryption &) = delete;
            UBIQ_PLATFORM_API
            decryption(decryption &&) = default;

            decryption & operator =(const decryption &) = delete;
            UBIQ_PLATFORM_API
            decryption & operator =(decryption &&) = default;

            /*
             * This function is equivalent to ubiq_platform_decryption_begin();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            begin(void)
                override;

            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            begin(decryption_session &session);

             /*
             * This function is equivalent to ubiq_platform_decryption_update();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            update(const void * ctbuf, std::size_t ctlen)
                override;

            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            update(decryption_session &session, const void * ctbuf, std::size_t ctlen);

            /*
             * This function is equivalent to ubiq_platform_decryption_end();
             * however, it returns the generated cipher text in a vector and
             * throws an exception on failure.
             */
            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            end(void)
                override;

            UBIQ_PLATFORM_API
            virtual
            std::vector<std::uint8_t>
            end(decryption_session &session);

            UBIQ_PLATFORM_API
            std::string
            get_copy_of_usage(void);

            UBIQ_PLATFORM_API
            virtual
            void
            add_user_defined_metadata(const std::string & jsonString);

        private:
            UBIQ_PLATFORM_API
            decryption(::ubiq_platform_decryption * d);

            std::shared_ptr<::ubiq_platform_decryption> _dec;
            decryption_session _session;

            friend class builder;
            friend class decryption_session;
        };


        namespace structured {
          class decryption
          {

          public:
            UBIQ_PLATFORM_API
            virtual ~decryption(void) = default;

            /*
             * The default constructor creates an empty decryption object.
             * This object cannot be used to perform an decryption, and
             * the constructor is provided for convenience.
             */
            UBIQ_PLATFORM_API
            decryption(void) = default;

            decryption(const decryption &) = delete;

            UBIQ_PLATFORM_API
            decryption(decryption &&) = default;

            decryption & operator =(const decryption &) = delete;

            UBIQ_PLATFORM_API
            decryption & operator =(decryption &&) = default;

            /*
             * This constructor is equivalent to
             * ubiq_platform_encryption_create(), and the constructor throws
             * an exception if it fails to properly construct the object.
             */
            UBIQ_PLATFORM_API
            decryption(const credentials & creds);

            UBIQ_PLATFORM_API
            decryption(const credentials & creds, const configuration & cfg);

            UBIQ_PLATFORM_API
            virtual
            std::string
            decrypt(
              const std::string & ffs_name,
              const std::string & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::u32string
            decrypt(
              const std::string & ffs_name,
              const std::u32string & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            int32_t
            decryptInt(
              const std::string & ffs_name,
              const int32_t & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            int64_t
            decryptLong(
              const std::string & ffs_name,
              const int64_t & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            struct tm
            decryptDate(
              const std::string & ffs_name,
              const struct tm & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            struct tm
            decryptDateTime(
              const std::string & ffs_name,
              const struct tm & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::string
            decrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::u32string
            decrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::u32string & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            int32_t
            decryptInt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const int32_t & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            int64_t
            decryptLong(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const int64_t & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            struct tm
            decryptDate(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const struct tm & ct
            ) ;

            UBIQ_PLATFORM_API
            virtual
            struct tm
            decryptDateTime(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const struct tm & ct
            );

            UBIQ_PLATFORM_API
            virtual
            std::string
            get_copy_of_usage(void);

            UBIQ_PLATFORM_API
            virtual
            void
            add_user_defined_metadata(const std::string & jsonString);

          private:
            UBIQ_PLATFORM_API
            decryption(ubiq_platform_structured_enc_dec_obj * d);

            std::shared_ptr<::ubiq_platform_structured_enc_dec_obj> _dec;

            friend class ubiq::platform::builder;

          }; // class decryption

        } // structured
    } // platform
} // ubiq

#endif /* __cplusplus */

/*
 * local variables:
 * mode: c++
 * end:
 */


