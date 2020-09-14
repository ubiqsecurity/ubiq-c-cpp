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

/*
 * Function to perform encryption/decryption of a single buffer in memory
 *
 * `transform` is a function object pointing to either
 * `ubiq::platform::encrypt` or `ubiq::platform::decrypt`, depending on
 * the operation desired.
 *
 * `creds` is an object containing the credentials for the Ubiq platform.
 *
 * `ifs` is a stream referring to an open file and positioned at the point
 * at which this function should start reading. The file will be read to the
 * end.
 *
 * `ofs` is a stream referring to an open file and positioned at the point
 * at which this function should start writing.
 *
 * Given the above, the function will read the entire contents of the file
 * referred to by `ifs`, pass that data through the operation specified by
 * `transform`, and write the entire output to `ofs`.
 */
static
void
ubiq_sample_transform_simple(
    const std::function<std::vector<std::uint8_t>(
        const ubiq::platform::credentials &,
        const void *, std::size_t)> & transform,
    const ubiq::platform::credentials & creds,
    std::ifstream & ifs, std::ofstream & ofs)
{
    std::vector<char> ibuf;
    std::vector<std::uint8_t> obuf;

    /*
     * determine the size of the input buffer by seeking to the
     * end of the file and using the resulting offset as the size.
     */
    ifs.seekg(0, std::ios::end);
    ibuf.resize(ifs.tellg());
    ifs.seekg(0);

    ifs.read(ibuf.data(), ibuf.size());
    obuf = transform(creds, ibuf.data(), ibuf.size());
    ofs.write((const char *)obuf.data(), obuf.size());
}

/*
 * Function to perform encryption/decryption of a file stream in pieces
 *
 * `xfrm` is a `ubiq::platform::encryption` or `ubiq::platform::decryption`
 * object, depending on the desired operation. The object already contains
 * the credentials necessary to perform the operation.
 *
 * `ifs` is a stream referring to an open file and positioned at the point
 * at which this function should start reading. The file will be read to the
 * end.
 *
 * `ofs` is a stream referring to an open file and positioned at the point
 * at which this function should start writing.
 *
 * Given the above, the function will read the contents of the file referred
 * to by `ifs` in pieces, passing each piece through the operation
 * specified by `xfrm` and writing any output to `ofs`. The transform
 * operation is accomplished by first calling `xfrm.begin()`, followed by
 * repeated calls to `xfrm.update()` for each piece. When all data has been
 * processed, the function calls `xfrm.end()` to complete the operation.
 */
static
void
ubiq_sample_transform_piecewise(
    ubiq::platform::transform & xfrm,
    std::ifstream & ifs, std::ofstream & ofs)
{
    std::vector<std::uint8_t> obuf;

    obuf = xfrm.begin();
    ofs.write((const char *)obuf.data(), obuf.size());

    while (!ifs.eof()) {
        std::vector<char> ibuf(128 * 1024);

        ifs.read(ibuf.data(), ibuf.size());
        ibuf.resize(ifs.gcount());
        obuf = xfrm.update(ibuf.data(), ibuf.size());
        ofs.write((const char *)obuf.data(), obuf.size());
    }

    obuf = xfrm.end();
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
    if (method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        ifs.seekg(0, std::ios::end);
        if (ifs.tellg() > UBIQ_SAMPLE_MAX_SIMPLE_SIZE) {
            std::cerr << "NOTE: This is only for demonstration purposes and is designed to work on memory" << std::endl;
            std::cerr << "      constrained devices.  Therefore, this sample application will switch to" << std::endl;
            std::cerr << "      the piecewise APIs for files larger than " << UBIQ_SAMPLE_MAX_SIMPLE_SIZE << " bytes in order to reduce" << std::endl;
            std::cerr << "      excesive resource usages on resource constrained IoT devices" << std::endl;
            method = UBIQ_SAMPLE_METHOD_PIECEWISE;
        }

        ifs.seekg(0);
    }

    /* Open the output file */
    ofs = std::ofstream(outfile,
                        std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs) {
        std::cerr << "unable to open output file: " << outfile << std::endl;
        std::exit(EXIT_FAILURE);
    }

    if (method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        ubiq_sample_transform_simple(
            (mode == UBIQ_SAMPLE_MODE_ENCRYPT) ?
            &ubiq::platform::encrypt : &ubiq::platform::decrypt,
            creds, ifs, ofs);
    } else {
        std::unique_ptr<ubiq::platform::transform> xfrm;

        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            xfrm.reset(new ubiq::platform::encryption(creds, 1));
        } else {
            xfrm.reset(new ubiq::platform::decryption(creds));
        }

        ubiq_sample_transform_piecewise(*xfrm, ifs, ofs);
    }

    /* The library needs to clean up after itself */
    ubiq::platform::exit();

    return 0;
}
