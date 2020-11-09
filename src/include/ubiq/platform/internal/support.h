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

int ubiq_support_get_home_dir(char ** const);
int ubiq_support_gmtime_r(const time_t * const, struct tm * const);

int ubiq_support_base64_encode(char ** const, const void * const, const size_t);
int ubiq_support_base64_decode(void ** const, const char * const, const size_t);

struct ubiq_support_digest_context;
int ubiq_support_digest_init(
    const char * const,
    struct ubiq_support_digest_context ** const);
void ubiq_support_digest_update(
    struct ubiq_support_digest_context * const,
    const void * const, const size_t);
int ubiq_support_digest_finalize(
    struct ubiq_support_digest_context * const,
    void ** const, size_t * const);

struct ubiq_support_hmac_context;
int ubiq_support_hmac_init(
    const char * const,
    const void * const, const size_t,
    struct ubiq_support_hmac_context ** const);
void ubiq_support_hmac_update(
    struct ubiq_support_hmac_context * const,
    const void * const, const size_t);
int ubiq_support_hmac_finalize(
    struct ubiq_support_hmac_context * const,
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
int ubiq_support_encryption_update(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* pt */
    void ** const, size_t * const /* ct */);
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
int ubiq_support_decryption_update(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* ct */
    void ** const, size_t * const /* pt */);
int ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* tag */
    void ** const, size_t * const /* pt */);

int ubiq_support_asymmetric_decrypt(
    const char * const, const char * const, /* private key pem, password */
    const void * const, const size_t, /* input */
    void ** const, size_t * const /* output */);

extern const char * ubiq_support_user_agent;
int ubiq_support_http_init(void);
void ubiq_support_http_exit();

struct ubiq_support_http_handle;
struct ubiq_support_http_handle * ubiq_support_http_handle_create(void);
void ubiq_support_http_handle_reset(struct ubiq_support_http_handle * const);
void ubiq_support_http_handle_destroy(struct ubiq_support_http_handle * const);

http_response_code_t
ubiq_support_http_response_code(
    const struct ubiq_support_http_handle * const);
const char *
ubiq_support_http_response_content_type(
    const struct ubiq_support_http_handle * const);

int
ubiq_support_http_add_header(
    struct ubiq_support_http_handle * const, const char * const);
int
ubiq_support_http_request(
    struct ubiq_support_http_handle * const,
    const http_request_method_t, const char * const,
    const char * const, const void * const, const size_t,
    void ** const, size_t * const);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
