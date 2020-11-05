#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include <ubiq/platform/internal/algorithm.h>
#include <ubiq/platform/internal/http.h>

__BEGIN_DECLS

int ubiq_support_get_home_dir(char ** const);

int ubiq_support_base64_encode(char **, const void *, size_t);
int ubiq_support_base64_decode(void **, const char *, size_t);

struct ubiq_support_digest_context;
int ubiq_support_digest_init(
    const char *, struct ubiq_support_digest_context **);
void ubiq_support_digest_update(
    struct ubiq_support_digest_context *, const void *, size_t);
int ubiq_support_digest_finalize(
    struct ubiq_support_digest_context *, void **, size_t *);

struct ubiq_support_hmac_context;
int ubiq_support_hmac_init(
    const char *, const void *, size_t,
    struct ubiq_support_hmac_context **);
void ubiq_support_hmac_update(
    struct ubiq_support_hmac_context *, const void *, size_t);
int ubiq_support_hmac_finalize(
    struct ubiq_support_hmac_context *, void **, size_t *);

int ubiq_support_getrandom(void *, size_t);

struct ubiq_support_cipher_context;

void ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context *);

int ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm *,
    const void *, size_t, /* key */
    const void *, size_t, /* iv */
    const void *, size_t, /* aad */
    struct ubiq_support_cipher_context **);
int ubiq_support_encryption_update(
    struct ubiq_support_cipher_context *,
    const void *, size_t, /* pt */
    void **, size_t * /* ct */);
int ubiq_support_encryption_finalize(
    struct ubiq_support_cipher_context *,
    void **, size_t *, /* ct */
    void **, size_t * /* tag */);

int ubiq_support_decryption_init(
    const struct ubiq_platform_algorithm *,
    const void *, size_t, /* key */
    const void *, size_t, /* iv */
    const void *, size_t, /* aad */
    struct ubiq_support_cipher_context **);
int ubiq_support_decryption_update(
    struct ubiq_support_cipher_context *,
    const void *, size_t, /* ct */
    void **, size_t * /* pt */);
int ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context *,
    const void *, size_t, /* tag */
    void **, size_t * /* pt */);

int ubiq_support_asymmetric_decrypt(
    const char *, const char *, /* private key pem, password */
    const void *, size_t, /* input */
    void **, size_t * /* output */);

extern const char * ubiq_support_user_agent;
int ubiq_support_http_init(void);
void ubiq_support_http_exit();

struct ubiq_support_http_handle;
struct ubiq_support_http_handle * ubiq_support_http_handle_create(void);
void ubiq_support_http_handle_reset(struct ubiq_support_http_handle *);
void ubiq_support_http_handle_destroy(struct ubiq_support_http_handle *);

http_response_code_t
ubiq_support_http_response_code(
    const struct ubiq_support_http_handle *);
const char *
ubiq_support_http_response_content_type(
    const struct ubiq_support_http_handle *);

int
ubiq_support_http_add_header(
    struct ubiq_support_http_handle *, const char *);
int
ubiq_support_http_request(
    struct ubiq_support_http_handle *,
    http_request_method_t, const char *,
    const char *, const void *, size_t,
    void **, size_t *);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
