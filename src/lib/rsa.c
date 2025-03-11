#include "ubiq/platform/internal/support.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;

int
ubiq_platform_rsa_generate_key_pair(
  char ** const private_pem,
  char ** const public_pem)
{
  static const char * csu = "ubiq_platform_rsa_generate_key_pair";
  int res = 0;
  int bits = 4096;
  RSA *rsa = NULL;
  BIGNUM *bne = NULL;
  BIO *priv_bio = NULL;
  BIO *pub_bio = NULL;
  long priv_len = 0;
  long pub_len = 0;

  *private_pem = NULL;
  *public_pem = NULL;
  char * prv = NULL;
  char * pub = NULL;

  // Initialize Big Number for the public exponent (e = 65537)
  if ((bne = BN_new()) != NULL) {
    if (BN_set_word(bne, RSA_F4) != 1) {
      UBIQ_DEBUG(debug_flag, printf("%s: %s\n", csu, "Error setting exponent"));
      res = ERR_get_error();
    } 
  } else {
    res = ERR_get_error();
  }

  if (!res) {
    if ((rsa = RSA_new()) != NULL) {
      if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1) {
        UBIQ_DEBUG(debug_flag, printf("%s: %s\n", csu, "Error generating RSA key pair"));
        res = ERR_get_error();
      }
    } else {
      res = ERR_get_error();
    }
  }

  if (!res) {
  // Create BIOs to hold the keys in memory
    priv_bio = BIO_new(BIO_s_mem());
    pub_bio = BIO_new(BIO_s_mem());
    if (priv_bio == NULL || pub_bio == NULL) {
      UBIQ_DEBUG(debug_flag, printf("%s: %s\n", csu, "Error creating BIOs"));
      res = -ENOMEM;
    }
  }
  if (!res && PEM_write_bio_RSAPrivateKey(priv_bio, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
    UBIQ_DEBUG(debug_flag, printf("%s: %s\n", csu, "Error writing private key to BIO"));
    res = -EINVAL;
  }

  // Write the public key to the BIO
  if (!res && PEM_write_bio_RSA_PUBKEY(pub_bio, rsa) != 1) {
    res = -EINVAL;
    UBIQ_DEBUG(debug_flag, printf("%s: %s\n", csu, "Error writing public key to BIO"));
  }

  if (!res) {
    // Get the private key in PEM format from the BIO
    priv_len = BIO_get_mem_data(priv_bio, &prv);
    pub_len = BIO_get_mem_data(pub_bio, &pub);

    UBIQ_DEBUG(debug_flag, printf("%s: %s %d\n", csu, "priv_len", priv_len));
    UBIQ_DEBUG(debug_flag, printf("%s: %s %d\n", csu, "pub_len", pub_len));

    // Ensure memory was allocated for both keys
    if (priv_len <= 0 || pub_len <= 0) {
      res = -EINVAL;
      UBIQ_DEBUG(debug_flag, printf("%s: %s\n", csu, "Error reading keys from BIO"));
    }
  }

  if (!res && prv != NULL) {
      char * c = calloc(1, priv_len + 1);
      if (!c) {
        res = -ENOMEM;
      } else {
        memcpy(c, prv, priv_len);
        // *private_key_pem = strdup(prv);
        *private_pem = c;
        UBIQ_DEBUG(debug_flag, printf("%s: %s %s\n", csu, "Private Key (PEM)", *private_pem));
      }
  }
  if (!res && pub != NULL) {
      char * c = calloc(1, pub_len + 1);
      if (!c) {
        res = -ENOMEM;
      } else {
        memcpy(c, pub, pub_len);
        *public_pem = c;
        UBIQ_DEBUG(debug_flag, printf("%s: %s %s\n", csu, "Public Key (PEM)", *public_pem));
      }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));

  // cleanup
  if (rsa != NULL) RSA_free(rsa);
  if (bne != NULL) BN_free(bne);
  if (priv_bio != NULL) BIO_free(priv_bio);
  if (pub_bio != NULL) BIO_free(pub_bio);

  return res;
}


int
ubiq_platform_rsa_create_csr(
  const char * const private_pem,
  char ** const csr_pem)
{
  static const char * csu = "ubiq_platform_rsa_create_csr";
  int res = 0;

  RSA *rsa = NULL;
  EVP_PKEY *pkey = EVP_PKEY_new();
  X509_REQ *req = X509_REQ_new();
  char * cn_b64 = NULL;
  BIO *mem_bio = BIO_new(BIO_s_mem());
  BIO *bio = NULL;
  char *csr_pem_buffer = NULL;
  X509_NAME *name = X509_NAME_new();

  // 1. Create a BIO object from the PEM buffer.  BIOs are an abstraction
  //    for I/O operations in OpenSSL.  We use a memory BIO here.
  bio = BIO_new_mem_buf(private_pem, -1); // -1 means read until null terminator

  if (!bio) {
      fprintf(stderr, "Error creating BIO\n");
      ERR_print_errors_fp(stderr); // Print OpenSSL error messages
      res = -EINVAL;
  }

  if (!res) {
  // 2. Read the PEM-encoded private key from the BIO.
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL); // No password callback

    if (!rsa) {
        fprintf(stderr, "Error reading RSA private key\n");
        ERR_print_errors_fp(stderr);
        res = -EINVAL;
    }
  }

  if (bio) BIO_free_all(bio); // Free the BIO.  Important to prevent memory leaks!

  if (!res) {
    if (!pkey || !EVP_PKEY_set1_RSA(pkey, rsa)) {
      fprintf(stderr, "Error converting RSA to EVP_PKEY.\n");
      ERR_print_errors_fp(stderr);
      res = -EINVAL;
    }
  }


  if (!res && req) {
    X509_REQ_set_version(req, 1);

    if (!name) {
      res = -EINVAL;
    }
  }
    if (!res) {

      u_int8_t cn[18];
      res = ubiq_support_getrandom(cn, sizeof(cn));
      ubiq_support_base64_encode(&cn_b64, cn, sizeof(cn));

      X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,(unsigned char *)cn_b64, -1, -1, 0); // Customize
      X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,(unsigned char *)"US", -1, -1, 0); // Customize
      X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,(unsigned char *)"California", -1, -1, 0); // Customize
      X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,(unsigned char *)"San Diego", -1, -1, 0); // Customize
      X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,(unsigned char *)"Ubiq Security, Inc.", -1, -1, 0); // Customize
      X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,(unsigned char *)"Ubiq Platform", -1, -1, 0); // Customize

      X509_REQ_set_subject_name(req, name);
      if (!X509_REQ_set_pubkey(req, pkey)) {
        res = -EINVAL;
      }
    }

    if (!res && !X509_REQ_sign(req, pkey, EVP_sha256())) {
      res = -EINVAL;
    }

    if (!res && !mem_bio) {
        fprintf(stderr, "Error creating memory BIO.\n");
        ERR_print_errors_fp(stderr);
        res = -EINVAL;
    }

    if (!res && !PEM_write_bio_X509_REQ(mem_bio, req)) {
        fprintf(stderr, "Error writing CSR to memory BIO.\n");
        ERR_print_errors_fp(stderr);
        res = -EINVAL;
    }

    if (!res) {
    // Get the CSR string from the memory BIO
      long csr_len = BIO_get_mem_data(mem_bio, &csr_pem_buffer);
      if (csr_len > 0) {
        *csr_pem = calloc(csr_len + 1, 1);
        memcpy(*csr_pem, csr_pem_buffer, csr_len);
      }
    }
  if (cn_b64) free(cn_b64);
  if (mem_bio) BIO_free_all(mem_bio); // Free the memory BIO
  if (req) X509_REQ_free(req);
  if (name) X509_NAME_free(name);
  if (pkey) EVP_PKEY_free(pkey);
  if (rsa) RSA_free(rsa);

  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));

  return res;
}

int
ubiq_platform_rsa_encrypt_private_pem(
  const char * const private_pem,
  const char * const passphrase,
  char ** const encrypted_pem)
{
  static const char * csu = "ubiq_platform_rsa_encrypt_private_pem";
  int res = 0;

  RSA *rsa = NULL;
  EVP_PKEY *pkey = EVP_PKEY_new();
  BIO *encrypted_priv_bio = BIO_new(BIO_s_mem());
  BIO *bio = NULL;
  BIO *pkcs8_bio = BIO_new(BIO_s_mem());
  char *encrypted_priv_key_pem = NULL;

    // 1. Create a BIO object from the PEM buffer.  BIOs are an abstraction
    //    for I/O operations in OpenSSL.  We use a memory BIO here.
    bio = BIO_new_mem_buf(private_pem, -1); // -1 means read until null terminator

    if (!bio) {
        fprintf(stderr, "Error creating BIO\n");
        ERR_print_errors_fp(stderr); // Print OpenSSL error messages
        res = -EINVAL;
    }

    if (!res) {
      // 2. Read the PEM-encoded private key from the BIO.
      rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL); // No password callback
    }

    if (rsa && !res) {
      if (!PEM_write_bio_RSAPrivateKey(encrypted_priv_bio, rsa, EVP_aes_256_cbc(), (unsigned char *)passphrase, strlen(passphrase), NULL, NULL)) {
          fprintf(stderr, "Error PEM_write_bio_RSAPrivateKey\n");
          ERR_print_errors_fp(stderr); // Print OpenSSL error messages
          res = -EINVAL;
      }
    }

    if (!res) {
            // Extract the encrypted private key into a variable
      long encrypted_priv_len = BIO_get_mem_data(encrypted_priv_bio, &encrypted_priv_key_pem);

      if (!pkey || !EVP_PKEY_set1_RSA(pkey, rsa)) {
          fprintf(stderr, "Error EVP_PKEY_set1_RSA\n");
          ERR_print_errors_fp(stderr); // Print OpenSSL error messages
          res = -EINVAL;
      }
    }

    if (!res && !PEM_write_bio_PKCS8PrivateKey(pkcs8_bio, pkey, EVP_aes_256_cbc(), (unsigned char *)passphrase, strlen(passphrase), NULL, NULL)) {
          fprintf(stderr, "Error PEM_write_bio_PKCS8PrivateKey\n");
          ERR_print_errors_fp(stderr); // Print OpenSSL error messages
          res = -EINVAL;
    }

    if (!res) {
      char *pkcs8_pem = NULL;
      long pkcs8_len = BIO_get_mem_data(pkcs8_bio, &pkcs8_pem);
      if (pkcs8_len <= 0) {
          fprintf(stderr, "Error BIO_get_mem_data(pkcs8_bio)\n");
          ERR_print_errors_fp(stderr); // Print OpenSSL error messages
          res = -EINVAL;
      } else {
        UBIQ_DEBUG(debug_flag, printf("Encrypted PKCS#8 Private Key:\n%.*s\n", (int)pkcs8_len, pkcs8_pem));
        *encrypted_pem = calloc(pkcs8_len + 1, sizeof(char));
        memcpy(*encrypted_pem,pkcs8_pem,pkcs8_len);
      }
    }

  if (pkcs8_bio) BIO_free_all(pkcs8_bio);
  if (bio) BIO_free_all(bio);
  if (encrypted_priv_bio) BIO_free_all(encrypted_priv_bio);
  if (rsa) RSA_free(rsa);
  if (pkey) EVP_PKEY_free(pkey);

  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));

  return res;
}