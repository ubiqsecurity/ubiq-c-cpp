#include "common.h"
#include <ubiq/platform.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>


static
int
encrypt(
    struct ubiq_platform_structured_enc_dec_obj * const enc,
    const char * const dataset_name,
    const char * const pt,
    const ubiq_dataset_type_t dataset_type)
{
  int res = 0;

  switch (dataset_type) {
    case UBIQ_DATASET_TYPE_INTEGER32:
    {
        int32_t ct = 0;
        int32_t p = 0;
        p = atoi(pt);

        res = ubiq_platform_structured_encrypt_int_data(enc,dataset_name, NULL, 0, p, &ct);
        if (!res) {
          printf("Structured Encryption Data Results => '%d'\n", ct);
        }
      }
    break;
    case UBIQ_DATASET_TYPE_INTEGER64:
    {
        int64_t ct = 0;
        int64_t p = 0;
        p = atoll(pt);

        res = ubiq_platform_structured_encrypt_long_data(enc,dataset_name, NULL, 0, p, &ct);
        if (!res) {
          printf("Structured Encryption Data Results => '%ld'\n", ct);
        }
      }
    break;
    case UBIQ_DATASET_TYPE_DATE:
    {
        struct tm ct;
        struct tm p;
        res = parse_iso8601(pt, &p);

        res = ubiq_platform_structured_encrypt_date_data(enc,dataset_name, NULL, 0, &p, &ct);
        if (!res) {
          char buffer[30];
          size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct);
          printf("Structured Encryption Data Results => '%s'\n", buffer);
        }
      }
    break;
    case UBIQ_DATASET_TYPE_DATETIME:
    {
        struct tm ct;
        struct tm p;
        res = parse_iso8601(pt, &p);

        res = ubiq_platform_structured_encrypt_datetime_data(enc,dataset_name, NULL, 0, &p, &ct);
        if (!res) {
          char buffer[30];
          size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct);
          printf("Structured Encryption Data Results => '%s'\n", buffer);
        }
      }
    break;
    default:
    {
      char * ctbuf = NULL;
      size_t ctlen = 0;
      res = ubiq_platform_structured_encrypt_data(enc,
        dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      if (!res) {
        printf("Structured Encryption Data Results => '%.*s'\n", ctlen, ctbuf);
      }
      free(ctbuf);
    }
    break;
  }
  return res;
}

static
int
encryptForSearch(
    struct ubiq_platform_structured_enc_dec_obj * const enc,
    const char * const dataset_name,
    const char * const pt,
    const ubiq_dataset_type_t dataset_type)
{
  int res = 0;

  switch (dataset_type) {
    case UBIQ_DATASET_TYPE_INTEGER32:
    {
        int32_t * ct = NULL;
        size_t count = 0;
        int32_t p = 0;
        p = atoi(pt);

        res = ubiq_platform_structured_encrypt_int_data_for_search(enc,dataset_name, NULL, 0, p, &ct, &count);
        if (!res) {
          printf("EncryptForSearch results:\n");
          for (int i = 0; i < count; i++) {
            printf("\t'%d'\n", ct[i]);
          }
        }
        free(ct);
      }
    break;
    case UBIQ_DATASET_TYPE_INTEGER64:
    {
        int64_t * ct = NULL;
        size_t count = 0;
        int64_t p = 0;
        p = atoll(pt);

        res = ubiq_platform_structured_encrypt_long_data_for_search(enc,dataset_name, NULL, 0, p, &ct, &count);
        if (!res) {
          printf("EncryptForSearch results:\n");
          for (int i = 0; i < count; i++) {
            printf("\t'%ld'\n", ct[i]);
          }
        }
        free(ct);
      }
    break;
    case UBIQ_DATASET_TYPE_DATE:
    {
        struct tm * ct = NULL;
        size_t count = 0;
        struct tm p;
        res = parse_iso8601(pt, &p);

        res = ubiq_platform_structured_encrypt_date_data_for_search(enc,dataset_name, NULL, 0, &p, &ct, &count);
        if (!res) {
          printf("EncryptForSearch results:\n");
          for (int i = 0; i < count; i++) {
            char buffer[30];
            size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct[i]);
            printf("\t%s\n", buffer);
          }
        }
        free(ct);
      }
    break;
    case UBIQ_DATASET_TYPE_DATETIME:
    {
        struct tm * ct = NULL;
        size_t count = 0;

        struct tm p;
        res = parse_iso8601(pt, &p);

        res = ubiq_platform_structured_encrypt_datetime_data_for_search(enc,dataset_name, NULL, 0, &p, &ct, &count);
        if (!res) {
          printf("EncryptForSearch results:\n");
          for (int i = 0; i < count; i++) {
            char buffer[30];
            size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct[i]);
            printf("\t%s\n", buffer);
          }
        }
        free(ct);
      }
    break;
    default:
    {
      char ** ctbuf = NULL;
      size_t count = 0;
      res = ubiq_platform_structured_encrypt_data_for_search(enc,
        dataset_name, NULL, 0, pt, strlen(pt), &ctbuf, &count);
      if (!res) {
        printf("EncryptForSearch results:\n");
        for (int i = 0; i < count; i++) {
            printf("\t%s\n", ctbuf[i]);
            free(ctbuf[i]);
        }
      }
      free(ctbuf);
    }
    break;
  }
  return res;
}

static
int
decrypt(
    struct ubiq_platform_structured_enc_dec_obj * const enc,
    const char * const dataset_name,
    const char * const ct,
    const ubiq_dataset_type_t dataset_type)
{
  int res = 0;

  switch (dataset_type) {
    case UBIQ_DATASET_TYPE_INTEGER32:
    {
        int32_t pt = 0;
        int32_t c = 0;
        c = atoi(ct);

        res = ubiq_platform_structured_decrypt_int_data(enc,dataset_name, NULL, 0, c, &pt);
        if (!res) {
          printf("Structured Decryption Data Results => '%d'\n", pt);
        }
      }
    break;
    case UBIQ_DATASET_TYPE_INTEGER64:
    {
        int64_t pt = 0;
        int64_t c = 0;
        c = atoll(ct);

        res = ubiq_platform_structured_decrypt_long_data(enc,dataset_name, NULL, 0, c, &pt);
        if (!res) {
          printf("Structured Decryption Data Results => '%ld'\n", pt);
        }
      }
    break;
    case UBIQ_DATASET_TYPE_DATE:
    {
        struct tm pt;
        struct tm c;
        res = parse_iso8601(ct, &c);

        res = ubiq_platform_structured_decrypt_date_data(enc,dataset_name, NULL, 0, &c, &pt);
        if (!res) {
          char buffer[30];
          size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &pt);
          printf("Structured Encryption Data Results => '%s'\n", buffer);
        }
      }
    break;
    case UBIQ_DATASET_TYPE_DATETIME:
    {
        struct tm pt;
        struct tm c;
        res = parse_iso8601(ct, &c);

        res = ubiq_platform_structured_decrypt_datetime_data(enc,dataset_name, NULL, 0, &c, &pt);
        if (!res) {
          char buffer[30];
          size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &pt);
          printf("Structured Encryption Data Results => '%s'\n", buffer);
        }
      }
    break;
    default:
    {
      char * ptbuf = NULL;
      size_t ptlen = 0;
      res = ubiq_platform_structured_decrypt_data(enc,
        dataset_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);
      if (!res) {
        printf("Structured Decryption Data Results => '%.*s'\n", ptlen, ptbuf);
      }
      free(ptbuf);
    }
    break;
  }
  return res;
}

static
int
ubiq_structured_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    const char * const dataset_name,
    const char * const pt,
    const int encryptForSearchFlag,
    const ubiq_dataset_type_t dataset_type)
{
  struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
  char * ctbuf = NULL;
  size_t ctlen = 0;
  int res;

  res = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, &enc);

  if (!res) {
    if (encryptForSearchFlag) {
      res = encryptForSearch(enc,
        dataset_name, pt, dataset_type);
    } else {
      res = encrypt(enc,
            dataset_name, pt, dataset_type);
    }
    if (res) {
      int err_num;
      char * err_msg = NULL;
      res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
      fprintf(stderr, "Encryption Error Code: %d  %s\n\n", err_num, err_msg);
      free(err_msg);
    }
  }
  // free(ctbuf);
  ubiq_platform_structured_enc_dec_destroy(enc);
  return res;
}

static
int
ubiq_structured_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    const char * const dataset_name,
    const char * const ct,
    const ubiq_dataset_type_t dataset_type)
{
  struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
  // char * ptbuf = NULL;
  // size_t ptlen = 0;
  int res;

  res = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, &enc);
  if (!res) {

    res = decrypt(enc,
      dataset_name, ct, dataset_type);

    // res = ubiq_platform_structured_decrypt_data(enc,
    //   dataset_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);

    // if (!res) {
    //   printf("Structured Decryption Data Results => '%.*s'\n", ptlen, ptbuf);
    if (res) {
      int err_num;
      char * err_msg = NULL;
      res = ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
      fprintf(stderr, "Decryption Error Code: %d  %s\n\n", err_num, err_msg);
      free(err_msg);
    }
  }
  // free(ptbuf);
  ubiq_platform_structured_enc_dec_destroy(enc);
  return res;
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    const char * inputstring, * dataset_name, * credfile, * profile, *cfgfile;
    int encryptForSearch;
    ubiq_dataset_type_t dataset_type;

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
                      &credfile, &profile, &cfgfile, &encryptForSearch,
                      &dataset_type);

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
        res = ubiq_structured_encrypt(creds, cfg, dataset_name, inputstring, encryptForSearch, dataset_type);
    } else {
        res = ubiq_structured_decrypt(creds, cfg, dataset_name, inputstring, dataset_type);
    }

    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_configuration_destroy(cfg);

    ubiq_platform_exit();

    if (res) {
      exit(EXIT_FAILURE);
    }
    return res;
}
