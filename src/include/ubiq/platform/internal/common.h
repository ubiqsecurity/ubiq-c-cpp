#pragma once

#include <sys/cdefs.h>
#include <stddef.h>

#include "ubiq/platform/internal/request.h"

__BEGIN_DECLS

int
ubiq_platform_parse_new_key(
    const struct ubiq_platform_rest_handle * rest,
    const char * srsa,
    char ** session, char ** fingerprint,
    void ** keybuf, size_t * keylen);

__END_DECLS
