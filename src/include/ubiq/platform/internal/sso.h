#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/credentials.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS

int ubiq_platform_sso_renewIdpCert(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config);

int
ubiq_platform_sso_login(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
