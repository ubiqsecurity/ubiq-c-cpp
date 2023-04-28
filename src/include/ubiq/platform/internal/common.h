#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include "cJSON/cJSON.h"

#include "ubiq/platform/internal/http.h"

__BEGIN_DECLS

struct ubiq_url
{
    /*
     * A full URL looks like:
     * scheme://[user:pass@]host[:port]/path[?query][#frag]
     *
     * This structure supports:
     * scheme://host[:port]/[path][?query]
     *
     * see ubiq_url_parse()
     */
    char * scheme;
    char * hostname;
    char * port;
    char * path;
    char * query;
};

void ubiq_url_init(struct ubiq_url * const);
void ubiq_url_reset(struct ubiq_url * const);
int ubiq_url_parse(struct ubiq_url * const, const char * const);

int
ubiq_platform_common_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    // char ** const session, char ** const fingerprint,
    void ** const keybuf, size_t * const keylen);

int
ubiq_platform_common_fpe_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    void ** const keybuf, size_t * const keylen);

int
ubiq_platform_http_error(
    const http_response_code_t rc);

__END_DECLS
