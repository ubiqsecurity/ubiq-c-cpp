#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <getopt.h>

#include "common.h"

static
void
ubiq_sample_usage(
    const char * const cmd, const char * const err)
{
    if (err) {
        fprintf(stderr, "%s\n\n", err);
    }

    fprintf(stderr, "Usage: %s -e|-d -s|-p -i INFILE -o OUTFILE\n", cmd);
    fprintf(stderr, "Encrypt or decrypt files using the Ubiq service\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h, --help               Show this help message and exit\n");
    fprintf(stderr, "  -V, --version            Show program's version number and exit\n");
    fprintf(stderr, "  -e, --encrypt            Encrypt the contents of the input file and write\n");
    fprintf(stderr, "                             the results to the output file\n");
    fprintf(stderr, "  -d, --decrypt            Decrypt the contents of the input file and write\n");
    fprintf(stderr, "                             the results to the output file\n");
    fprintf(stderr, "  -s, --simple             Use the simple encryption / decryption interfaces\n");
    fprintf(stderr, "  -p, --pieceswise         Use the piecewise encryption / decryption interfaces\n");
    fprintf(stderr, "  -i INFILE, --in INFILE   Set input file name\n");
    fprintf(stderr, "  -o OUTFILE, --out OUTFILE\n");
    fprintf(stderr, "                           Set output file name\n");
    fprintf(stderr, "  -c CREDENTIALS, --creds CREDENTIALS\n");
    fprintf(stderr, "                           Set the file name with the API credentials\n");
    fprintf(stderr, "                             (default: ~/.ubiq/credentials)\n");
    fprintf(stderr, "  -P PROFILE, --profile PROFILE\n");
    fprintf(stderr, "                           Identify the profile within the credentials file\n");
}

int
ubiq_sample_getopt(
    const int argc, char * const argv[],
    ubiq_sample_mode_t * const mode,
    ubiq_sample_method_t * const method,
    const char ** const infile, const char ** const outfile,
    const char ** const credfile, const char ** const profile)
{
#define OPTION(LONGOPT, HASARG, SHORTOPT)                               \
    { .name = LONGOPT, .has_arg = HASARG, .flag = NULL, .val = SHORTOPT }

    static const struct option longopt[] = {
        OPTION("help",        0, 'h'),
        OPTION("version",     0, 'V'),
        OPTION("encrypt",     0, 'e'),
        OPTION("decrypt",     0, 'd'),
        OPTION("simple",      0, 's'),
        OPTION("piecewise",   0, 'p'),
        OPTION("in",          1, 'i'),
        OPTION("out",         1, 'o'),
        OPTION("creds",       1, 'c'),
        OPTION("profile",     1, 'P'),
        { NULL, 0, NULL, 0 },
    };

#undef OPTION

    optind = 1;
    opterr = 0;

    int opt;

    *mode = UBIQ_SAMPLE_MODE_UNSPEC;
    *method = UBIQ_SAMPLE_METHOD_UNSPEC;
    *infile = *outfile = *credfile = *profile = NULL;

    while ((opt = getopt_long(argc, argv,
                              "+:hVedspi:o:c:P:",
                              longopt, NULL)) != -1) {
        switch (opt) {
        case 'h':
            ubiq_sample_usage(argv[0], NULL);
            exit(EXIT_SUCCESS);
            break;
        case 'V':
            fprintf(stderr, "version %s\n", UBIQ_SAMPLE_VERSION);
            exit(EXIT_SUCCESS);
        case 'e':
        case 'd':
            if (*mode != UBIQ_SAMPLE_MODE_UNSPEC) {
                ubiq_sample_usage(
                    argv[0], "please specify one of encrypt or decrypt once");
                exit(EXIT_FAILURE);
            }

            *mode = (opt == 'e') ?
                UBIQ_SAMPLE_MODE_ENCRYPT : UBIQ_SAMPLE_MODE_DECRYPT;

            break;
        case 's':
        case 'p':
            if (*method != UBIQ_SAMPLE_METHOD_UNSPEC) {
                ubiq_sample_usage(
                    argv[0], "please specify one of simple or piecewise once");
                exit(EXIT_FAILURE);
            }

            *method = (opt == 's') ?
                UBIQ_SAMPLE_METHOD_SIMPLE : UBIQ_SAMPLE_METHOD_PIECEWISE;

            break;
        case 'i':
            if (*infile) {
                ubiq_sample_usage(
                    argv[0], "please specify only one input file");
                exit(EXIT_FAILURE);
            }

            *infile = optarg;

            break;
        case 'o':
            if (*outfile) {
                ubiq_sample_usage(
                    argv[0], "please specify only one output file");
                exit(EXIT_FAILURE);
            }

            *outfile = optarg;

            break;
        case 'c':
            if (*credfile) {
                ubiq_sample_usage(
                    argv[0], "please specify only one credentials file");
                exit(EXIT_FAILURE);
            }

            *credfile = optarg;

            break;
        case 'P':
            if (*profile) {
                ubiq_sample_usage(
                    argv[0], "please specify only one profile name");
                exit(EXIT_FAILURE);
            }

            *profile = optarg;

            break;
        case '?':
            fprintf(stderr, "unrecognized option: %s\n\n", argv[optind - 1]);
            ubiq_sample_usage(argv[0], NULL);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr,
                    "missing argument for option: %s\n\n",
                    argv[optind - 1]);
            ubiq_sample_usage(argv[0], NULL);
            exit(EXIT_FAILURE);
        }
    }

    if (*mode == UBIQ_SAMPLE_MODE_UNSPEC) {
        ubiq_sample_usage(argv[0], "encrypt / decrypt operation not specified");
        exit(EXIT_FAILURE);
    }

    if (*method == UBIQ_SAMPLE_METHOD_UNSPEC) {
        ubiq_sample_usage(argv[0], "simple / piecewise method not specified");
        exit(EXIT_FAILURE);
    }

    if (!*infile) {
        ubiq_sample_usage(argv[0], "input file not specified");
        exit(EXIT_FAILURE);
    }

    if (!*outfile) {
        ubiq_sample_usage(argv[0], "output file not specified");
        exit(EXIT_FAILURE);
    }

    return 0;
}
