/*
 * Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Ubiq Security, Inc. The intellectual and technical concepts contained
 * herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
 * covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Ubiq Security, Inc.
 *
 * Your use of the software is expressly conditioned upon the terms
 * and conditions available at:
 *
 *     https://ubiqsecurity.com/legal
 *
 */

#include "common.h"
#include <ubiq/platform.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/*
 * Function to perform encryption/decryption of a single buffer in memory
 *
 * `transform` is a function pointer pointing to either
 * `ubiq_platform_encrypt` or `ubiq_platform_decrypt`, depending on
 * the operation desired.
 *
 * `creds` is a pointer to an object containing the credentials for the
 * Ubiq platform.
 *
 * `ifp` is a stream referring to an open file and positioned at the point
 * at which this function should start reading. The file will be read to the
 * end.
 *
 * `ofp` is a stream referring to an open file and positioned at the point
 * at which this function should start writing.
 *
 * Given the above, the function will read the entire contents of the file
 * referred to by `ifp`, pass that data through the operation specified by
 * `transform`, and write the entire output to `ofs`.
 */
static
int
ubiq_sample_transform_simple(
    int (* const transform)(
        const struct ubiq_platform_credentials *,
        const void *, size_t, void **, size_t *),
    const struct ubiq_platform_credentials * const creds,
    FILE * const ifp, FILE * const ofp)
{
    void * ibuf, * obuf;
    size_t ilen, olen;
    int res;

    /*
     * determine the size of the input buffer by seeking to the
     * end of the file and using the resulting offset as the size.
     */
    fseek(ifp, 0, SEEK_END);
    ilen = ftell(ifp);
    ibuf = malloc(ilen);
    fseek(ifp, 0, SEEK_SET);

    fread(ibuf, 1, ilen, ifp);

    res = (*transform)(creds, ibuf, ilen, &obuf, &olen);
    if (res == 0) {
        fwrite(obuf, 1, olen, ofp);
        free(obuf);
    }

    free(ibuf);

    return res;
}

/*
 * Function to perform encryption/decryption of a file stream in pieces
 *
 * `begin`, `update`, and `end` point to `ubiq_platform_encryption_begin`,
 * `ubiq_platform_encryption_update`, and `ubiq_platform_encryption_end` or
 * their decryption counterparts, respectively, depending on whether the
 * transformation is an encryption or decryption.
 *
 * `ctx` points to a `ubiq_platform_encryption` or `ubiq_platform_decryption`
 * object.
 *
 * `ifp` is a stream referring to an open file and positioned at the point
 * at which this function should start reading. The file will be read to the
 * end.
 *
 * `ofp` is a stream referring to an open file and positioned at the point
 * at which this function should start writing.
 *
 * Given the above, the function will read the contents of the file referred
 * to by `ifp` in pieces, passing each piece through the operation
 * specified by the `begin`, `update`, and `end` function pointers and writing
 * any output to `ofs`. The transform operation is accomplished by first
 * calling `begin()`, followed by repeated calls to `update()` for each piece.
 * When all data has been processed, the function calls `end()` to complete
 * the operation.
 */
static
int
ubiq_sample_transform_piecewise(
    int (* const begin)(void *, void **, size_t *),
    int (* const update)(void *, const void *, size_t, void **, size_t *),
    int (* const end)(void *, void **, size_t *),
    void * const ctx, FILE * const ifp, FILE * const ofp)
{
    void * obuf;
    size_t olen;
    int res;

    /*
     * Start by calling the begin() function. It may produce
     * some data which needs to be written to the output.
     */

    res = (*begin)(ctx, &obuf, &olen);
    if (res == 0) {
        fwrite(obuf, 1, olen, ofp);
        free(obuf);

        /*
         * Now read the contents of the input file in pieces,
         * passing each piece through the transform's update
         * function and writing the output produced to the
         * output stream.
         */
        while (!feof(ifp) && res == 0) {
            uint8_t ibuf[128 * 1024];
            size_t ilen;

            ilen = fread(ibuf, 1, sizeof(ibuf), ifp);

            res = (*update)(ctx, ibuf, ilen, &obuf, &olen);
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
            res = (*end)(ctx, &obuf, &olen);
            if (res == 0) {
                fwrite(obuf, 1, olen, ofp);
                free(obuf);
            }
        }
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
    if (method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        size_t size;

        fseek(ifp, 0, SEEK_END);
        size = ftell(ifp);
        fseek(ifp, 0, SEEK_SET);

        if (size > UBIQ_SAMPLE_MAX_SIMPLE_SIZE) {
            fprintf(stderr, "NOTE: This is only for demonstration purposes and is designed to work on memory\n");
            fprintf(stderr, "      constrained devices.  Therefore, this sample application will switch to\n");
            fprintf(stderr, "      the piecewise APIs for files larger than %u bytes in order to reduce\n", UBIQ_SAMPLE_MAX_SIMPLE_SIZE);
            fprintf(stderr, "      excesive resource usages on resource constrained IoT devices\n");
            method = UBIQ_SAMPLE_METHOD_PIECEWISE;
        }
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
        res = ubiq_sample_transform_simple(
            (mode == UBIQ_SAMPLE_MODE_ENCRYPT) ?
            &ubiq_platform_encrypt : &ubiq_platform_decrypt,
            creds, ifp, ofp);
    } else {
        int (* begin)(void *, void **, size_t *);
        int (* update)(void *, const void *, size_t, void **, size_t *);
        int (* end)(void *, void **, size_t *);
        int (* destroy)(void *);
        void * ctx;

        /*
         * Set the function and context/object pointers to specify
         * whether the file should be encrypted or decrypted. The
         * code uses `void` pointers to avoid warnings/errors about
         * the difference in types between the encryption and
         * decryption objects.
         */

        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            begin = (void *)&ubiq_platform_encryption_begin;
            update = (void *)&ubiq_platform_encryption_update;
            end = (void *)&ubiq_platform_encryption_end;
            destroy = (void *)&ubiq_platform_encryption_destroy;

            res = ubiq_platform_encryption_create(
                creds, 1, (struct ubiq_platform_encryption **)&ctx);
        } else {
            begin = (void *)&ubiq_platform_decryption_begin;
            update = (void *)&ubiq_platform_decryption_update;
            end = (void *)&ubiq_platform_decryption_end;
            destroy = (void *)&ubiq_platform_decryption_destroy;

            res = ubiq_platform_decryption_create(
                creds, (struct ubiq_platform_decryption **)&ctx);
        }

        /*
         * Finally, perform the transform, and destroy the context
         * object open return from the transform.
         */

        if (res == 0) {
            res = ubiq_sample_transform_piecewise(
                begin, update, end, ctx, ifp, ofp);

            (*destroy)(ctx);
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
