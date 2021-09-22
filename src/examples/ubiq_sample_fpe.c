#include "common.h"
#include <ubiq/platform.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static
int
ubiq_sample_simple_encrypt(
    const struct ubiq_platform_credentials * const creds,
    FILE * const ifp, FILE * const ofp,
    const size_t ilen)
{
    void * ibuf, * obuf;
    size_t olen;
    int res;

    ibuf = malloc(ilen);
    fread(ibuf, 1, ilen, ifp);

    res = ubiq_platform_encrypt(creds, ibuf, ilen, &obuf, &olen);
    if (res == 0) {
        fwrite(obuf, 1, olen, ofp);
        free(obuf);
    }

    free(ibuf);

    return 0;
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

static
int
ubiq_sample_piecewise_encrypt(
    const struct ubiq_platform_credentials * const creds,
    FILE * const ifp, FILE * const ofp)
{
    struct ubiq_platform_encryption * ctx;
    void * obuf;
    size_t olen;
    int res;

    res = ubiq_platform_encryption_create(
        creds, 1 /* want to use the key once */, &ctx);
    if (res == 0) {

        /*
         * Start by calling the begin() function. It may produce
         * some data which needs to be written to the output.
         */

        res = ubiq_platform_encryption_begin(ctx, &obuf, &olen);
        if (res == 0) {
            fwrite(obuf, 1, olen, ofp);
            free(obuf);

            /*
             * Now read the contents of the input file in pieces,
             * encrypting each piece via the update function and
             * writing the output produced to the output stream.
             */
            while (!feof(ifp) && res == 0) {
                uint8_t ibuf[128 * 1024];
                size_t ilen;

                ilen = fread(ibuf, 1, sizeof(ibuf), ifp);

                res = ubiq_platform_encryption_update(
                    ctx, ibuf, ilen, &obuf, &olen);
                if (res == 0) {
                    fwrite(obuf, 1, olen, ofp);
                    free(obuf);
                }
            }

            /*
             * Finally, call end() to complete the operation and
             * write any data produced by the call to the output file
             */
            if (res == 0) {
                res = ubiq_platform_encryption_end(ctx, &obuf, &olen);
                if (res == 0) {
                    fwrite(obuf, 1, olen, ofp);
                    free(obuf);
                }
            }
        }

        ubiq_platform_encryption_destroy(ctx);
    }

    return res;
}

static
int
ubiq_sample_piecewise_decrypt(
    const struct ubiq_platform_credentials * const creds,
    FILE * const ifp, FILE * const ofp)
{
    struct ubiq_platform_decryption * ctx;
    void * obuf;
    size_t olen;
    int res;

    res = ubiq_platform_decryption_create(creds, &ctx);
    if (res == 0) {

        /*
         * Start by calling the begin() function. It may produce
         * some data which needs to be written to the output.
         */

        res = ubiq_platform_decryption_begin(ctx, &obuf, &olen);
        if (res == 0) {
            fwrite(obuf, 1, olen, ofp);
            free(obuf);

            /*
             * Now read the contents of the input file in pieces,
             * decrypting each piece via the update function and
             * writing the output produced to the output stream.
             */
            while (!feof(ifp) && res == 0) {
                uint8_t ibuf[128 * 1024];
                size_t ilen;

                ilen = fread(ibuf, 1, sizeof(ibuf), ifp);

                res = ubiq_platform_decryption_update(
                    ctx, ibuf, ilen, &obuf, &olen);
                if (res == 0) {
                    fwrite(obuf, 1, olen, ofp);
                    free(obuf);
                }
            }

            /*
             * Finally, call end() to complete the operation and
             * write any data produced by the call to the output file
             */
            if (res == 0) {
                res = ubiq_platform_decryption_end(ctx, &obuf, &olen);
                if (res == 0) {
                    fwrite(obuf, 1, olen, ofp);
                    free(obuf);
                }
            }
        }

        ubiq_platform_decryption_destroy(ctx);
    }

    return res;
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    ubiq_sample_method_t method;
    const char * infile, * outfile, * credfile, * profile;

    struct ubiq_platform_credentials * creds;
    FILE * ifp, * ofp;
    size_t size;
    int res;

    /* library must be initialized */
    ubiq_platform_init();

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
    ubiq_sample_getopt(argc, argv,
                      &mode, &method,
                      &infile, &outfile,
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

    /* Open the input file */
    ifp = fopen(infile, "rb");
    if (!ifp) {
        fprintf(stderr, "unable to open input file: %s\n", infile);
        ubiq_platform_credentials_destroy(creds);
        exit(EXIT_FAILURE);
    }

    /*
     * The simple method reads the entire input file into memory,
     * and therefore, the application places a limit on the size
     * of the file that can be encrypted/decrypted using the simple
     * method. If the file exceeds that size, force the piecewise
     * method.
     */
    fseek(ifp, 0, SEEK_END);
    size = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);

    if (method == UBIQ_SAMPLE_METHOD_SIMPLE &&
        size > UBIQ_SAMPLE_MAX_SIMPLE_SIZE) {
        fprintf(stderr, "NOTE: This is only for demonstration purposes and is designed to work on memory\n");
        fprintf(stderr, "      constrained devices.  Therefore, this sample application will switch to\n");
        fprintf(stderr, "      the piecewise APIs for files larger than %u bytes in order to reduce\n", UBIQ_SAMPLE_MAX_SIMPLE_SIZE);
        fprintf(stderr, "      excessive resource usages on resource constrained IoT devices\n");
        method = UBIQ_SAMPLE_METHOD_PIECEWISE;
    }

    /* Open the output file */
    ofp = fopen(outfile, "wb+");
    if (!ofp) {
        fprintf(stderr, "unable to open output file: %s\n", outfile);
        fclose(ifp);
        ubiq_platform_credentials_destroy(creds);
        exit(EXIT_FAILURE);
    }

    if (method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            res = ubiq_sample_simple_encrypt(creds, ifp, ofp, size);
        } else /* decrypt */ {
            res = ubiq_sample_simple_decrypt(creds, ifp, ofp, size);
        }
    } else /* piecewise */{
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            res = ubiq_sample_piecewise_encrypt(creds, ifp, ofp);
        } else {
            res = ubiq_sample_piecewise_decrypt(creds, ifp, ofp);
        }
    }

    /*
     * Clean up file pointers, credentials, and the library itself
     */

    fclose(ofp);
    fclose(ifp);

    ubiq_platform_credentials_destroy(creds);

    ubiq_platform_exit();

    return res;
}
