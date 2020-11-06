#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/credentials.h>

__BEGIN_DECLS

const char *
ubiq_platform_credentials_get_host(
    const struct ubiq_platform_credentials * creds);
const char *
ubiq_platform_credentials_get_papi(
    const struct ubiq_platform_credentials * creds);
const char *
ubiq_platform_credentials_get_sapi(
    const struct ubiq_platform_credentials * creds);
const char *
ubiq_platform_credentials_get_srsa(
    const struct ubiq_platform_credentials * creds);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
