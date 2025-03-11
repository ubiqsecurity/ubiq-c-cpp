#pragma once

#include <time.h>

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/credentials.h>

__BEGIN_DECLS

const char *
ubiq_platform_credentials_get_host(
    const struct ubiq_platform_credentials * const creds);
const char *
ubiq_platform_credentials_get_papi(
    const struct ubiq_platform_credentials * const creds);
const char *
ubiq_platform_credentials_get_sapi(
    const struct ubiq_platform_credentials * const creds);
const char *
ubiq_platform_credentials_get_srsa(
    const struct ubiq_platform_credentials * const creds);

const char *
ubiq_platform_credentials_get_idp_password(
    const struct ubiq_platform_credentials * const creds);
const char *
ubiq_platform_credentials_get_idp_username(
    const struct ubiq_platform_credentials * const creds);

const char *
ubiq_platform_credentials_get_access_token(
      const struct ubiq_platform_credentials * const creds);

size_t
ubiq_platform_credentials_get_access_token_duration_seconds(
      const struct ubiq_platform_credentials * const creds);

const char *
ubiq_platform_credentials_get_csr(
      const struct ubiq_platform_credentials * const creds);

const char *
ubiq_platform_credentials_get_cert_b64(
      const struct ubiq_platform_credentials * const creds);

const char *
ubiq_platform_credentials_get_encrypted_private_key(
      const struct ubiq_platform_credentials * const creds);

const time_t
ubiq_platform_credentials_get_cert_expiration(
      const struct ubiq_platform_credentials * const creds);

void
ubiq_platform_credentials_set_host(
    struct ubiq_platform_credentials * const creds,
    const char * host);

void
ubiq_platform_credentials_set_papi(
     struct ubiq_platform_credentials * const creds,
     const char * papi);

void
ubiq_platform_credentials_set_sapi(
     struct ubiq_platform_credentials * const creds,
     const char * sapi);

void
ubiq_platform_credentials_set_srsa(
     struct ubiq_platform_credentials * const creds,
     const char * srsa);
     
void
ubiq_platform_credentials_set_idp_username(
    struct ubiq_platform_credentials * const creds,
    const char * idp_username);

void
ubiq_platform_credentials_set_idp_password(
    struct ubiq_platform_credentials * const creds,
    const char * idp_password);

/**
 * @brief Returns true if this credentials has IDP values set
 * 
 * @param creds 
 * @return int - true (1) if idp_username is set
 */
 int ubiq_platform_credentials_is_idp(
   const struct ubiq_platform_credentials * const creds);

int ubiq_platform_credentials_set_access_token(
    struct ubiq_platform_credentials * const creds,
    const char * access_token,
    const size_t duration_seconds);

int ubiq_platform_credentials_set_rsa_keys(
    struct ubiq_platform_credentials * const creds,
    const char * srsa_b64,
    const char * encrypted_private_pem,
    const char * csr_pem);

int ubiq_platform_credentials_set_rsa_cert(
    struct ubiq_platform_credentials * const creds,
    const char * cert_pem);

// Deep copy
int ubiq_platform_credentials_clone(
  const struct ubiq_platform_credentials * const src,
  struct ubiq_platform_credentials ** const creds);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
