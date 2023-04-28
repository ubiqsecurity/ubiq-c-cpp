#include "common.h"
#include <ubiq/platform.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static
int
ubiq_fpe_simple_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const char * const pt)
{
  char * ctbuf = NULL;
  size_t ctlen = 0;
  int res;
  res = ubiq_platform_fpe_encrypt(creds,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);

  if (!res) {
    printf("eFPE Encrypted Data Results => '%.*s'\n", ctlen, ctbuf);
  } else {
    fprintf(stderr, "Encryption Error Code: %d\n\n", res);
  }
  free(ctbuf);
  return res;
}

static
int
ubiq_fpe_simple_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const char * const ct)
{
  char * ptbuf = NULL;
  size_t ptlen = 0;
  int res;
  res = ubiq_platform_fpe_decrypt(creds,
    ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);

  if (!res) {
    printf("eFPE Decrypt Data Results => '%.*s'\n", ptlen, ptbuf);
  } else {
    fprintf(stderr, "Decryption Error Code: %d\n\n", res);
  }
  free(ptbuf);
  return res;
}

static
int
ubiq_fpe_bulk_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const char * const pt)
{
  struct ubiq_platform_fpe_enc_dec_obj *enc = NULL;
  char * ctbuf = NULL;
  size_t ctlen = 0;
  int res;

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);

  if (!res) {
    for (int i = 0; i < 5;i++) {
      res = ubiq_platform_fpe_encrypt_data(enc,
        ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      if (!res) {
        printf("eFPE Encrypted Data Results => '%.*s'\n", ctlen, ctbuf);
      } else {
        int err_num;
        char * err_msg = NULL;
        res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
        fprintf(stderr, "Encryption Error Code: %d  %s\n\n", err_num, err_msg);
        free(err_msg);
      }
      free(ctbuf);
      sleep(1);
    }
  }
  ubiq_platform_fpe_enc_dec_destroy(enc);
  return res;
}

static
int
ubiq_fpe_bulk_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const char * const ct)
{
  struct ubiq_platform_fpe_enc_dec_obj *enc = NULL;
  char * ptbuf = NULL;
  size_t ptlen = 0;
  int res;

  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);
  if (!res) {

    res = ubiq_platform_fpe_decrypt_data(enc,
      ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);

    if (!res) {
      printf("eFPE Decrypt Data Results => '%.*s'\n", ptlen, ptbuf);
    } else {
      int err_num;
      char * err_msg = NULL;
      res = ubiq_platform_fpe_get_last_error(enc, &err_num, &err_msg);
      fprintf(stderr, "Decryption Error Code: %d  %s\n\n", err_num, err_msg);
      free(err_msg);
    }
  }
  free(ptbuf);
  ubiq_platform_fpe_enc_dec_destroy(enc);
  return res;
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_method_t method;
    ubiq_sample_mode_t mode;
    const char * inputstring, * ffsname, * credfile, * profile;

    struct ubiq_platform_credentials * creds;
    size_t size;
    int res;

    /* library must be initialized */
    ubiq_platform_init();

    /*
     * the getopt function will parse the command line for arguments
     * specific to the sample application and return the found options
     * in the variables below.
     *
     * `mode`, `method`, `ffnsname`, and `inputstring`
     * are required and will be set to the options found on the command
     * line.
     *
     * `credfile` and `profile` are not required arguments and may be
     * NULL upon return from the call.
     */
    ubiq_fpe_getopt(argc, argv,
                      &mode, &method,
                      &ffsname, &inputstring,
                      &credfile, &profile);

    /*
     * If neither `credfile` nor `profile are specified, then the
     * credentials found in the environment or specified in
     * ~/.ubiq/credentials are loaded. Otherwise, the credentials
     * will be loaded as specified by the credentials file and named
     * profile.
     */
    if (!credfile && !profile) {
        res = ubiq_platform_credentials_create(&creds);
    } else {
        res = ubiq_platform_credentials_create_specific(
            credfile, profile, &creds);
    }

    if (res != 0) {
        fprintf(stderr, "unable to load credentials\n");
        exit(EXIT_FAILURE);
    }

    if ( method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            res = ubiq_fpe_simple_encrypt(creds, ffsname, inputstring);
        } else /* decrypt */ {
            res = ubiq_fpe_simple_decrypt(creds, ffsname, inputstring);
        }
    } else /* bulk */{
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            res = ubiq_fpe_bulk_encrypt(creds, ffsname, inputstring);
        } else {
            res = ubiq_fpe_bulk_decrypt(creds, ffsname, inputstring);
        }
    }

    ubiq_platform_credentials_destroy(creds);

    ubiq_platform_exit();

    if (res) {
      exit(EXIT_FAILURE);
    }
    return res;
}
