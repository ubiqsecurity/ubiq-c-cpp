#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS

int
ubiq_platform_rsa_generate_key_pair(
  char ** const private_pem,
  char ** const public_pem);


int
ubiq_platform_rsa_create_csr(
  const char * const private_pem,
  char ** const csr_pem);


int
ubiq_platform_rsa_encrypt_private_pem(
  const char * const private_pem,
  const char * const passphrase,
  char ** const encrypted_pem);


__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
