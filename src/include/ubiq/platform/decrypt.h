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

UBIQ_PLATFORM_API
int
ubiq_platform_fpe_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const void * const ctbuf, const size_t ctlen,
    char ** const ptbuf, size_t * const ptlen);


/* Opaque decryption object */
struct ubiq_platform_decryption;

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

/*
 * *******************************************
 *                  FPE
 * *******************************************
 */

UBIQ_PLATFORM_API
int
ubiq_platform_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen
);

__END_DECLS

#if defined(__cplusplus)

#include <memory>
#include <string>
#include <vector>

#include <ubiq/platform/transform.h>

namespace ubiq {
    namespace platform {
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

        private:
            std::shared_ptr<::ubiq_platform_decryption> _dec;
        };


        namespace fpe {

          UBIQ_PLATFORM_API
          std::string
          decrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::string & ct);

          UBIQ_PLATFORM_API
          std::string
          decrypt(const credentials & creds,
                  const std::string & ffs_name,
                  const std::vector<std::uint8_t> & tweak,
                  const std::string & ct);

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
            virtual
            std::string
            decrypt(
              const std::string & ffs_name,
              const std::string & pt
            ) ;

            UBIQ_PLATFORM_API
            virtual
            std::string
            decrypt(
              const std::string & ffs_name,
              const std::vector<std::uint8_t> & tweak,
              const std::string & pt
            ) ;

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
