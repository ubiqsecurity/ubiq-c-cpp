#pragma once

#include <sys/cdefs.h>
#include <stddef.h>

#include "cJSON/cJSON.h"

__BEGIN_DECLS

int
ubiq_platform_common_parse_new_key(
    const cJSON * const json,
    const char * srsa,
    char ** session, char ** fingerprint,
    void ** keybuf, size_t * keylen);

__END_DECLS
