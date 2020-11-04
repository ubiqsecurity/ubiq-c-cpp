#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include <ubiq/platform/internal/http.h>

__BEGIN_DECLS

int ubiq_platform_algorithm_init(void);
void ubiq_platform_algorithm_exit(void);

struct ubiq_platform_cipher;
struct ubiq_platform_algorithm
{
    unsigned int id;
    const char * name;

    const struct ubiq_platform_cipher * cipher;
    struct {
        unsigned int key, iv, tag;
    } len;
};

int
ubiq_platform_algorithm_get_byid(
    unsigned int,
    const struct ubiq_platform_algorithm **);
int
ubiq_platform_algorithm_get_byname(
    const char *,
    const struct ubiq_platform_algorithm **);

struct ubiq_platform_digest_context;
int ubiq_platform_digest_init(
    const char *, struct ubiq_platform_digest_context **);
void ubiq_platform_digest_update(
    struct ubiq_platform_digest_context *, const void *, size_t);
int ubiq_platform_digest_finalize(
    struct ubiq_platform_digest_context *, void **, size_t *);

struct ubiq_platform_hmac_context;
int ubiq_platform_hmac_init(
    const char *, const void *, size_t,
    struct ubiq_platform_hmac_context **);
void ubiq_platform_hmac_update(
    struct ubiq_platform_hmac_context *, const void *, size_t);
int ubiq_platform_hmac_finalize(
    struct ubiq_platform_hmac_context *, void **, size_t *);

int ubiq_platform_base64_encode(char **, const void *, size_t);
int ubiq_platform_base64_decode(void **, const char *, size_t);

int ubiq_platform_http_init(const char * agent);
void ubiq_platform_http_exit();

struct ubiq_platform_http_handle;
struct ubiq_platform_http_handle * ubiq_platform_http_handle_create(void);
void ubiq_platform_http_handle_reset(struct ubiq_platform_http_handle *);
void ubiq_platform_http_handle_destroy(struct ubiq_platform_http_handle *);

http_response_code_t
ubiq_platform_http_response_code(
    const struct ubiq_platform_http_handle *);
const char *
ubiq_platform_http_response_content_type(
    const struct ubiq_platform_http_handle *);

int
ubiq_platform_http_add_header(
    struct ubiq_platform_http_handle *, const char *);
int
ubiq_platform_http_request(
    struct ubiq_platform_http_handle *,
    http_request_method_t, const char *,
    const char *, const void *, size_t,
    void **, size_t *);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
