#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include <ubiq/platform/internal/algorithm.h>
#include <ubiq/platform/internal/http.h>

#include <time.h>

#if defined(_WIN32)
#  include <winsock2.h>
#else
#  include <arpa/inet.h>
#endif

__BEGIN_DECLS

/* returned string must be freed via free() */
int ubiq_support_get_home_dir(char ** const);
int ubiq_support_gmtime_r(const time_t * const, struct tm * const);

/* returned string/data must be freed via free() */
int ubiq_support_base64_encode(char ** const, const void * const, const size_t);
int ubiq_support_base64_decode(void ** const, const char * const, const size_t);




struct ubiq_support_hash_context;

int ubiq_support_digest_init(
    const char * const,
    struct ubiq_support_hash_context ** const);
void ubiq_support_digest_update(
    struct ubiq_support_hash_context * const,
    const void * const, const size_t);
/* returned pointer must be freed via free() */
int ubiq_support_digest_finalize(
    struct ubiq_support_hash_context * const,
    void ** const, size_t * const);

int ubiq_support_hmac_init(
    const char * const,
    const void * const, const size_t,
    struct ubiq_support_hash_context ** const);
void ubiq_support_hmac_update(
    struct ubiq_support_hash_context * const,
    const void * const, const size_t);
/* returned pointer must be freed via free() */
int ubiq_support_hmac_finalize(
    struct ubiq_support_hash_context * const,
    void ** const, size_t * const);

int ubiq_support_getrandom(void * const, const size_t);

struct ubiq_support_cipher_context;

void ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context * const);

int ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm * const,
    const void * const, const size_t, /* key */
    const void * const, const size_t, /* iv */
    const void * const, const size_t, /* aad */
    struct ubiq_support_cipher_context ** const);
/* returned pointer must be freed via free() */
int ubiq_support_encryption_update(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* pt */
    void ** const, size_t * const /* ct */);
/* returned pointers must be freed via free() */
int ubiq_support_encryption_finalize(
    struct ubiq_support_cipher_context * const,
    void ** const, size_t * const, /* ct */
    void ** const, size_t * const /* tag */);

int ubiq_support_decryption_init(
    const struct ubiq_platform_algorithm * const,
    const void * const, const size_t, /* key */
    const void * const, const size_t, /* iv */
    const void * const, const size_t, /* aad */
    struct ubiq_support_cipher_context ** const);
/* returned pointer must be freed via free() */
int ubiq_support_decryption_update(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* ct */
    void ** const, size_t * const /* pt */);
/* returned pointer must be freed via free() */
int ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* tag */
    void ** const, size_t * const /* pt */);

/*
 * this function takes a pem encoding of a private key encrypted
 * with a password and uses it to decrypt the input. the plain text
 * is returned via a pointer that must be freed via free()
 */
int ubiq_support_asymmetric_decrypt(
    const char * const, const char * const, /* private key pem, password */
    const void * const, const size_t, /* input */
    void ** const, size_t * const /* output */);

extern const char * ubiq_support_user_agent;
int ubiq_support_http_init(void);
void ubiq_support_http_exit();

struct ubiq_support_http_handle;
struct ubiq_support_http_handle * ubiq_support_http_handle_create(void);
/* reset a handle for reuse with another request */
void ubiq_support_http_handle_reset(struct ubiq_support_http_handle * const);
void ubiq_support_http_handle_destroy(struct ubiq_support_http_handle * const);

/* response code sent by the server */
http_response_code_t
ubiq_support_http_response_code(
    const struct ubiq_support_http_handle * const);
/*
 * content type sent by the server
 * contains only the value, not the header name
 */
const char *
ubiq_support_http_response_content_type(
    const struct ubiq_support_http_handle * const);

/*
 * supplied header must be fully formed, i.e:
 * Header-Name: value
 */
int
ubiq_support_http_add_header(
    struct ubiq_support_http_handle * const, const char * const);
/* returned pointer must be freed via free() */
int
ubiq_support_http_request(
    struct ubiq_support_http_handle * const,
    const http_request_method_t, const char * const /* url */,
    const void * const /* request content */,
    const size_t /* request content length */,
    void ** const /* response content */,
    size_t * const /* response content length */);


    /* encoded_uri must be freed via free() */
    int ubiq_support_uri_escape(struct ubiq_support_http_handle * const hnd,
      char * const uri, char ** const encoded_uri);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
