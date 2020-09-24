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

#include <iostream>
#include <fstream>
#include <functional>

static
void
ubiq_sample_simple_encrypt(
    const ubiq::platform::credentials & creds,
    std::ifstream & ifs, std::ofstream & ofs,
    const std::size_t size)
{
    std::vector<char> ibuf;
    std::vector<std::uint8_t> obuf;

    ibuf.resize(size);
    ifs.read(ibuf.data(), ibuf.size());

    obuf = ubiq::platform::encrypt(creds, ibuf.data(), ibuf.size());

    ofs.write((const char *)obuf.data(), obuf.size());
}

static
void
ubiq_sample_simple_decrypt(
    const ubiq::platform::credentials & creds,
    std::ifstream & ifs, std::ofstream & ofs,
    const std::size_t size)
{
    std::vector<char> ibuf;
    std::vector<std::uint8_t> obuf;

    ibuf.resize(size);
    ifs.read(ibuf.data(), ibuf.size());

    obuf = ubiq::platform::decrypt(creds, ibuf.data(), ibuf.size());

    ofs.write((const char *)obuf.data(), obuf.size());
}

static
void
ubiq_sample_piecewise_encrypt(
    const ubiq::platform::credentials & creds,
    std::ifstream & ifs, std::ofstream & ofs)
{
    ubiq::platform::encryption enc(
        creds, 1 /* want to use the key once */);
    std::vector<std::uint8_t> obuf;

    /*
     * Start by calling the begin() function. It may produce
     * some data which needs to be written to the output.
     */
    obuf = enc.begin();
    ofs.write((const char *)obuf.data(), obuf.size());

    /*
     * Now read the contents of the input file in pieces,
     * encrypting each piece via the update function and
     * writing the output produced to the output stream.
     */
    while (!ifs.eof()) {
        std::vector<char> ibuf(128 * 1024);

        ifs.read(ibuf.data(), ibuf.size());
        ibuf.resize(ifs.gcount());
        obuf = enc.update(ibuf.data(), ibuf.size());
        ofs.write((const char *)obuf.data(), obuf.size());
    }

    /*
     * Finally, call end() to complete the operation and
     * write any data produced by the call to the output file
     */
    obuf = enc.end();
    ofs.write((const char *)obuf.data(), obuf.size());
}

static
void
ubiq_sample_piecewise_decrypt(
    const ubiq::platform::credentials & creds,
    std::ifstream & ifs, std::ofstream & ofs)
{
    ubiq::platform::decryption dec(creds);
    std::vector<std::uint8_t> obuf;

    /*
     * Start by calling the begin() function. It may produce
     * some data which needs to be written to the output.
     */
    obuf = dec.begin();
    ofs.write((const char *)obuf.data(), obuf.size());

    /*
     * Now read the contents of the input file in pieces,
     * decrypting each piece via the update function and
     * writing the output produced to the output stream.
     */
    while (!ifs.eof()) {
        std::vector<char> ibuf(128 * 1024);

        ifs.read(ibuf.data(), ibuf.size());
        ibuf.resize(ifs.gcount());
        obuf = dec.update(ibuf.data(), ibuf.size());
        ofs.write((const char *)obuf.data(), obuf.size());
    }

    /*
     * Finally, call end() to complete the operation and
     * write any data produced by the call to the output file
     */
    obuf = dec.end();
    ofs.write((const char *)obuf.data(), obuf.size());
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    ubiq_sample_method_t method;
    const char * infile, * outfile, * credfile, * profile;

    ubiq::platform::credentials creds;
    std::ifstream ifs;
    std::ofstream ofs;
    std::size_t size;

    /* library must be initialized */
    ubiq::platform::init();

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
     * When `creds` was declared above, it loaded the default
     * credentials found in ~/.ubiq/credentials or it failed to load
     * those credentials and the object is in an invalid state.
     *
     * If `credfile` or `profile` was specified, reload the credentials
     * using those parameters. Note that the constructor takes
     * std::string's as arguments, which cannot be initialized from
     * NULL pointers.
     */
    if (credfile || profile) {
        creds = ubiq::platform::credentials(
            std::string(credfile ? credfile : ""),
            std::string(profile ? profile : ""));
    }

    if (!creds) {
        std::cerr << "unable to load credentials" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    /* Open the input file */
    ifs = std::ifstream(infile, std::ios::in | std::ios::binary);
    if (!ifs) {
        std::cerr << "unable to open input file: " << infile << std::endl;
        std::exit(EXIT_FAILURE);
    }

    /*
     * The simple method reads the entire input file into memory,
     * and therefore, the application places a limit on the size
     * of the file that can be encrypted/decrypted using the simple
     * method. If the file exceeds that size, force the piecewise
     * method.
     */
    ifs.seekg(0, std::ios::end);
    size = ifs.tellg();
    ifs.seekg(0);

    if (method == UBIQ_SAMPLE_METHOD_SIMPLE &&
        size > UBIQ_SAMPLE_MAX_SIMPLE_SIZE) {
        std::cerr << "NOTE: This is only for demonstration purposes and is designed to work on memory" << std::endl;
        std::cerr << "      constrained devices.  Therefore, this sample application will switch to" << std::endl;
        std::cerr << "      the piecewise APIs for files larger than " << UBIQ_SAMPLE_MAX_SIMPLE_SIZE << " bytes in order to reduce" << std::endl;
        std::cerr << "      excesive resource usages on resource constrained IoT devices" << std::endl;
        method = UBIQ_SAMPLE_METHOD_PIECEWISE;
    }

    /* Open the output file */
    ofs = std::ofstream(outfile,
                        std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs) {
        std::cerr << "unable to open output file: " << outfile << std::endl;
        std::exit(EXIT_FAILURE);
    }

    if (method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            ubiq_sample_simple_encrypt(creds, ifs, ofs, size);
        } else /* decrypt */ {
            ubiq_sample_simple_decrypt(creds, ifs, ofs, size);
        }
    } else {
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            ubiq_sample_piecewise_encrypt(creds, ifs, ofs);
        } else /* decrypt */{
            ubiq_sample_piecewise_decrypt(creds, ifs, ofs);
        }
    }

    /* The library needs to clean up after itself */
    ubiq::platform::exit();

    return 0;
}
