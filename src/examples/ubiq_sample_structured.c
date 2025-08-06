#include "common.h"
#include <ubiq/platform.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static
int
ubiq_structured_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    const char * const dataset_name,
    const char * const pt,
    const int encryptForSearch)
{
  struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
  char * ctbuf = NULL;
  size_t ctlen = 0;
  int res;

  res = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, &enc);

  if (!res) {
    if (encryptForSearch) {
      char ** ctbuf;
      size_t count;
      res = ubiq_platform_structured_encrypt_data_for_search(enc,
        dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &count);
      if (!res) {
        printf("EncryptForSearch results:\n");
        for (int i = 0; i < count; i++) {
            printf("\t%s\n", ctbuf[i]);
        }
      }
      free(ctbuf);
    } else {
      res = ubiq_platform_structured_encrypt_data(enc,
        dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      if (!res) {
        printf("Structured Encryption Data Results => '%.*s'\n", ctlen, ctbuf);
      }
    }
    if (res) {
      int err_num;
      char * err_msg = NULL;
      res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
      fprintf(stderr, "Encryption Error Code: %d  %s\n\n", err_num, err_msg);
      free(err_msg);
    }
  }
  free(ctbuf);
  ubiq_platform_structured_enc_dec_destroy(enc);
  return res;
}

static
int
ubiq_structured_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    const char * const dataset_name,
    const char * const ct)
{
  struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
  char * ptbuf = NULL;
  size_t ptlen = 0;
  int res;

  res = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, &enc);
  if (!res) {

    res = ubiq_platform_structured_decrypt_data(enc,
      dataset_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);

    if (!res) {
      printf("Structured Decryption Data Results => '%.*s'\n", ptlen, ptbuf);
    } else {
      int err_num;
      char * err_msg = NULL;
      res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
      fprintf(stderr, "Decryption Error Code: %d  %s\n\n", err_num, err_msg);
      free(err_msg);
    }
  }
  free(ptbuf);
  ubiq_platform_structured_enc_dec_destroy(enc);
  return res;
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    const char * inputstring, * dataset_name, * credfile, * profile, *cfgfile;
    int encryptForSearch;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * cfg;

    size_t size;
    int res;

    /* library must be initialized */
    ubiq_platform_init();

    /*
     * the getopt function will parse the command line for arguments
     * specific to the sample application and return the found options
     * in the variables below.
     *
     * `mode`, `method`, `dataset_name`, and `inputstring`
     * are required and will be set to the options found on the command
     * line.
     *
     * `credfile` and `profile` are not required arguments and may be
     * NULL upon return from the call.
     */
    ubiq_structured_getopt(argc, argv,
                      &mode, 
                      &dataset_name, &inputstring,
                      &credfile, &profile, &cfgfile, &encryptForSearch);

    if (encryptForSearch && mode != UBIQ_SAMPLE_MODE_ENCRYPT) {
      fprintf(stderr, "EncryptForSearch is only compatible when encrypting data\n");
      exit(EXIT_FAILURE);
    }
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

    if (!res) {
      res = ubiq_platform_configuration_load_configuration(cfgfile, &cfg);
    } 

    if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
        res = ubiq_structured_encrypt(creds, cfg, dataset_name, inputstring, encryptForSearch);
    } else {
        res = ubiq_structured_decrypt(creds, cfg, dataset_name, inputstring);
    }

    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_configuration_destroy(cfg);

    ubiq_platform_exit();

    if (res) {
      exit(EXIT_FAILURE);
    }
    return res;
}
