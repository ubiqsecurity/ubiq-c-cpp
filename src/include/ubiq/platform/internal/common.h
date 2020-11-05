#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include "cJSON/cJSON.h"

#include "ubiq/platform/internal/http.h"

__BEGIN_DECLS

int
ubiq_platform_common_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    char ** const session, char ** const fingerprint,
    void ** const keybuf, size_t * const keylen);

int
ubiq_platform_http_error(
    const http_response_code_t rc);

__END_DECLS
