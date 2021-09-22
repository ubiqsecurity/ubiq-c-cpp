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
  char * ctbuf;
  size_t ctlen;
  int res;
  res = ubiq_platform_fpe_encrypt(creds,
    ffs_name, NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);

  if (!res) {
    printf("FPE Encrypted Data Results => '%.*s'\n", ctlen, ctbuf);
  } else {
    fprintf(stderr, "Encryption Error Code: %d\n\n", res);
  }
  return res;
}

static
int
ubiq_fpe_simple_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const char * const ct)
{
  char * ptbuf;
  size_t ptlen;
  int res;
  res = ubiq_platform_fpe_decrypt(creds,
    ffs_name, NULL, 0, ct, strlen(ct), &ptbuf, &ptlen);

  if (!res) {
    printf("FPE Decrypt Data Results => '%.*s'\n", ptlen, ptbuf);
  } else {
    fprintf(stderr, "Decryption Error Code: %d\n\n", res);
  }
  return res;
}

static
int
ubiq_sample_simple_decrypt(
    const struct ubiq_platform_credentials * const creds,
    FILE * const ifp, FILE * const ofp,
    const size_t ilen)
{
    void * ibuf, * obuf;
    size_t olen;
    int res;

    ibuf = malloc(ilen);
    fread(ibuf, 1, ilen, ifp);

    res = ubiq_platform_decrypt(creds, ibuf, ilen, &obuf, &olen);
    if (res == 0) {
        fwrite(obuf, 1, olen, ofp);
        free(obuf);
    }

    free(ibuf);

    return 0;
}


int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    const char * inputstring, * ffsname, * credfile, * profile;

    struct ubiq_platform_credentials * creds;
    size_t size;
    int res;

    /*
     * the getopt function will parse the command line for arguments
     * specific to the sample application and return the found options
     * in the variables below.
     *
     * `mode`, `method`, `infile`, and `outfile`
     * are required and will be set to the options found on the command
     * line.
     *
     * `credfile` and `profile` are not required arguments and may be
     * NULL upon return from the call.
     */
    ubiq_fpe_getopt(argc, argv,
                      &mode,
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

    if (1) { //method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
          printf("DEBUG ffname (%s) input (%s)\n", ffsname, inputstring);
            res = ubiq_fpe_simple_encrypt(creds, ffsname, inputstring);
        } else /* decrypt */ {
            res = ubiq_fpe_simple_decrypt(creds, ffsname, inputstring);
        }
    } else /* piecewise */{
        // if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
        //     res = ubiq_sample_piecewise_encrypt(creds, ifp, ofp);
        // } else {
        //     res = ubiq_sample_piecewise_decrypt(creds, ifp, ofp);
        // }
    }

    ubiq_platform_credentials_destroy(creds);

    if (res) {
      exit(EXIT_FAILURE);
    }
    return res;
}
