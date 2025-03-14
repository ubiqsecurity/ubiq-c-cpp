#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

static int   opterr   = 1;    /* if error message should be printed */
static int   optind   = 1;    /* index into parent argv vector */
static int   optopt   = 0;    /* character checked for validity */
static int   optreset = 0;    /* reset getopt */
static char *optarg   = NULL; /* argument associated with option */

#define BADCH   (int)'?'
#define BADARG  (int)':'
#define EMSG    ""

/*
 * getopt --
 *  Parse argc/argv argument vector.
 *
 * This code originally came from:
 * https://github.com/freebsd/freebsd/blob/master/lib/libc/stdlib/getopt.c
 */
static
int
getopt(int nargc, char * const nargv[], const char *ostr)
{
    char empty[] = EMSG;
    static char *place = NULL;      /* option letter processing */
    char *oli;              /* option letter list index */

    if (!place) {
        place = empty;
    }

    if (optreset || *place == 0) {      /* update scanning pointer */
        optreset = 0;
        place = nargv[optind];
        if (optind >= nargc || *place++ != '-') {
            /* Argument is absent or is not an option */
            place = empty;
            return (-1);
        }
        optopt = *place++;
        if (optopt == '-' && *place == 0) {
            /* "--" => end of options */
            ++optind;
            place = empty;
            return (-1);
        }
        if (optopt == 0) {
            /* Solitary '-', treat as a '-' option
               if the program (eg su) is looking for it. */
            place = empty;
            if (strchr(ostr, '-') == NULL)
                return (-1);
            optopt = '-';
        }
    } else
        optopt = *place++;

    /* See if option letter is one the caller wanted... */
    if (optopt == ':' || (oli = strchr((char *)ostr, optopt)) == NULL) {
        if (*place == 0)
            ++optind;
        if (opterr && *ostr != ':')
            (void)fprintf(stderr,
                          ": illegal option -- %c\n",
                          optopt);
        return (BADCH);
    }

    /* Does this option need an argument? */
    if (oli[1] != ':') {
        /* don't need argument */
        optarg = NULL;
        if (*place == 0)
            ++optind;
    } else {
        /* Option-argument is either the rest of this argument or the
           entire next argument. */
        if (*place)
            optarg = place;
        else if (oli[2] == ':')
            /*
             * GNU Extension, for optional arguments if the rest of
             * the argument is empty, we return NULL
             */
            optarg = NULL;
        else if (nargc > ++optind)
            optarg = nargv[optind];
        else {
            /* option-argument absent */
            place = empty;
            if (*ostr == ':' ||
                ((*ostr == '+' || *ostr == '-') &&
                 *(ostr + 1) == ':'))
                return (BADARG);
            if (opterr)
                (void)fprintf(stderr,
                              ": option requires an argument -- %c\n",
                              optopt);
            return (BADCH);
        }
        place = empty;
        ++optind;
    }
    return (optopt);            /* return option letter */
}

static
void
ubiq_sample_usage(
    const char * const cmd, const char * const err)
{
    if (err) {
        fprintf(stderr, "%s\n\n", err);
    }

    fprintf(stderr, "Usage: %s -e|-d -s|-p -i INFILE -o OUTFILE [-g CONFIGURATION]\n", cmd);
    fprintf(stderr, "Encrypt or decrypt files using the Ubiq service\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h                       Show this help message and exit\n");
    fprintf(stderr, "  -V                       Show program's version number and exit\n");
    fprintf(stderr, "  -e                       Encrypt the contents of the input file and write\n");
    fprintf(stderr, "                             the results to the output file\n");
    fprintf(stderr, "  -d                       Decrypt the contents of the input file and write\n");
    fprintf(stderr, "                             the results to the output file\n");
    fprintf(stderr, "  -s                       Use the simple encryption / decryption interfaces\n");
    fprintf(stderr, "  -p                       Use the encryption / decryption interfaces to handle large data elements where data is loaded in chunks\n");
    fprintf(stderr, "  -i INFILE                Set input file name\n");
    fprintf(stderr, "  -o OUTFILE               Set output file name\n");
    fprintf(stderr, "  -c CREDENTIALS           Set the file name with the API credentials\n");
    fprintf(stderr, "                             (default: ~/.ubiq/credentials)\n");
    fprintf(stderr, "  -P PROFILE               Identify the profile within the credentials file\n");
    fprintf(stderr, "  -g CONFIGURATION         Set the file name with the configuration\n");
    fprintf(stderr, "                             (default: ~/.ubiq/configuration)\n");
}

int
ubiq_sample_getopt(
    const int argc, char * const argv[],
    ubiq_sample_mode_t * const mode,
    ubiq_sample_method_t * const method,
    const char ** const infile, const char ** const outfile,
    const char ** const credfile, const char ** const profile,
    const char ** const cfgfile)
{
    int opt;

    optind = 1;
    opterr = 0;

    *mode = UBIQ_SAMPLE_MODE_UNSPEC;
    *method = UBIQ_SAMPLE_METHOD_UNSPEC;
    *infile = *outfile = *credfile = *profile = NULL;

    while ((opt = getopt(argc, argv, "+:hVedspi:o:c:P:g:")) != -1) {
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
                    argv[0], "please specify one of simple or chunking interfaces");
                exit(EXIT_FAILURE);
            }

            *method = (opt == 's') ?
                UBIQ_SAMPLE_METHOD_SIMPLE : UBIQ_SAMPLE_METHOD_CHUNKING;

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
        case 'g':
            if (*cfgfile) {
                ubiq_sample_usage(
                    argv[0], "please specify only one configuration file");
                exit(EXIT_FAILURE);
            }

            *cfgfile = optarg;

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
        ubiq_sample_usage(argv[0], "simple / chunking method not specified");
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

static
void
ubiq_structured_usage(
    const char * const cmd, const char * const err)
{
    if (err) {
        fprintf(stderr, "%s\n\n", err);
    }

    fprintf(stderr, "Usage: %s -e|-d INPUT -s|-p -n Dataset [-c CREDENTIALS] [-P PROFILE]\n", cmd);
    fprintf(stderr, "Encrypt or decrypt data using the Ubiq Structured Encryption service\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h                       Show this help message and exit\n");
    fprintf(stderr, "  -V                       Show program's version number and exit\n");
    fprintf(stderr, "  -e INPUT                 Encrypt the supplied input string\n");
    fprintf(stderr, "                             escape or use quotes if input string\n");
    fprintf(stderr, "                             contains special characters\n");
    fprintf(stderr, "  -d INPUT                 Decrypt the supplied input string\n");
    fprintf(stderr, "                             escape or use quotes if input string\n");
    fprintf(stderr, "                             contains special characters\n");
    fprintf(stderr, "  -n Dataset               Use the supplied Dataset name\n");
    fprintf(stderr, "  -c CREDENTIALS           Set the file name with the API credentials\n");
    fprintf(stderr, "                             (default: ~/.ubiq/credentials)\n");
    fprintf(stderr, "  -P PROFILE               Identify the profile within the credentials file\n");
    fprintf(stderr, "  -g CONFIGURATION         Set the file name with the configuration\n");
    fprintf(stderr, "                             (default: ~/.ubiq/configuration)\n");
}

int
ubiq_structured_getopt(
    const int argc, char * const argv[],
    ubiq_sample_mode_t * const mode,
    const char ** const ffsname, const char ** const inputstring,
    const char ** const credfile, const char ** const profile,
    const char ** const cfgfile)
{
    int opt;

    optind = 1;
    opterr = 0;

    *mode = UBIQ_SAMPLE_MODE_UNSPEC;
    *inputstring = *ffsname = *credfile = *profile = NULL;

    while ((opt = getopt(argc, argv, "+:hVe:d:c:P:n:g:")) != -1) {
        switch (opt) {
        case 'h':
            ubiq_structured_usage(argv[0], NULL);
            exit(EXIT_SUCCESS);
            break;
        case 'V':
            fprintf(stderr, "version %s\n", UBIQ_SAMPLE_VERSION);
            exit(EXIT_SUCCESS);
        case 'e':
        case 'd':
            if (*mode != UBIQ_SAMPLE_MODE_UNSPEC) {
                ubiq_structured_usage(
                    argv[0], "please specify either encrypt or decrypt once");
                exit(EXIT_FAILURE);
            }

            *mode = (opt == 'e') ?
                UBIQ_SAMPLE_MODE_ENCRYPT : UBIQ_SAMPLE_MODE_DECRYPT;

            *inputstring = optarg;

            break;
        case 'n':
            if (*ffsname) {
                ubiq_structured_usage(
                    argv[0], "please specify only one Dataset name");
                exit(EXIT_FAILURE);
            }

            *ffsname = optarg;

            break;
        case 'c':
            if (*credfile) {
                ubiq_structured_usage(
                    argv[0], "please specify only one credentials file");
                exit(EXIT_FAILURE);
            }

            *credfile = optarg;

            break;
        case 'P':
            if (*profile) {
                ubiq_structured_usage(
                    argv[0], "please specify only one profile name");
                exit(EXIT_FAILURE);
            }

            *profile = optarg;

            break;
        case 'g':
            if (*cfgfile) {
                ubiq_sample_usage(
                    argv[0], "please specify only one configuration file");
                exit(EXIT_FAILURE);
            }

            *cfgfile = optarg;

            break;
        case '?':
            fprintf(stderr, "unrecognized option: %s\n\n", argv[optind - 1]);
            ubiq_structured_usage(argv[0], NULL);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr,
                    "missing argument for option: %s\n\n",
                    argv[optind - 1]);
            ubiq_structured_usage(argv[0], NULL);
            exit(EXIT_FAILURE);
        }
    }

    if (*mode == UBIQ_SAMPLE_MODE_UNSPEC) {
        ubiq_structured_usage(argv[0], "encrypt / decrypt operation not specified");
        exit(EXIT_FAILURE);
    }

    if (!*inputstring) {
        ubiq_structured_usage(argv[0], "input string not specified");
        exit(EXIT_FAILURE);
    }

    if (!*ffsname) {
      ubiq_structured_usage(argv[0], "Dataset name not specified");
      exit(EXIT_FAILURE);
    }


    return 0;
}
