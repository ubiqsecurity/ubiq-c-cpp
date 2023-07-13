#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <strings.h>
#include <sstream>
#include <fstream>
#include <iostream>


#include "test_harness_helper.h"
#include "cJSON/cJSON.h"


static int   opterr   = 1;    /* if error message should be printed */
static int   optind   = 1;    /* index into parent argv vector */
static int   optopt   = 0;    /* character checked for validity */
static int   optreset = 0;    /* reset getopt */
static char *optarg   = NULL; /* argument associated with option */

#define BADCH   (int)'?'
#define BADARG  (int)':'
#define EMSG    ""

#define GETENV(VAR, NAME)                       \
    do {                                        \
        VAR = getenv(NAME);                     \
        if (VAR) {                              \
            VAR = strdup(VAR);                  \
        }                                       \
    } while (0)

#define UBIQ_TEST_DATA_FILE "UBIQ_TEST_DATA_FILE"
#define UBIQ_MAX_AVG_ENCRYPT "UBIQ_MAX_AVG_ENCRYPT"
#define UBIQ_MAX_AVG_DECRYPT "UBIQ_MAX_AVG_DECRYPT"
#define UBIQ_MAX_TOTAL_ENCRYPT "UBIQ_MAX_TOTAL_ENCRYPT"
#define UBIQ_MAX_TOTAL_DECRYPT "UBIQ_MAX_TOTAL_DECRYPT"
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
get_int_env_option(long & var, const char * const env_name) {

  if (var == 0) {
      char * data = NULL;
      GETENV(data,env_name);
      if (data) {
        std::stringstream ss;
        ss << data;
        ss >> var;
        free(data);
      }
  }
}


static
void
test_harness_usage(
    const char * const cmd, const char * const err)
{
    if (err) {
        fprintf(stderr, "%s\n\n", err);
    }

    fprintf(stderr, "Usage: %s -e AVG_ENCRYPT -d AVG_DECRYPT -E TOTAL_ENCRYPT -D TOTAL_DECRYPT -i INFILE -c CREDENTIALS -P PROFILE [-p]\n", cmd);
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h                       Show this help message and exit\n");
    fprintf(stderr, "  -p                       Print information regarding the failing records.\n");
    fprintf(stderr, "  -e                       Maximum allowed average encrypt time in microseconds.\n");
    fprintf(stderr, "                             Not including first call to server\n");
    fprintf(stderr, "                             Can be set using environment variable '%s'\n", UBIQ_MAX_AVG_ENCRYPT);
    fprintf(stderr, "  -d                       Maximum allowed average decrypt time in microseconds.\n");
    fprintf(stderr, "                             Not including first call to server\n");
    fprintf(stderr, "                             Can be set using environment variable '%s'\n", UBIQ_MAX_AVG_DECRYPT);
    fprintf(stderr, "  -E                       Maximum allowed total encrypt time in microseconds.\n");
    fprintf(stderr, "                             Not including first call to server\n");
    fprintf(stderr, "                             Can be set using environment variable '%s'\n", UBIQ_MAX_TOTAL_ENCRYPT);
    fprintf(stderr, "  -D                       Maximum allowed total decrypt time in microseconds.\n");
    fprintf(stderr, "                             Not including first call to server\n");
    fprintf(stderr, "                             Can be set using environment variable '%s'\n", UBIQ_MAX_TOTAL_DECRYPT);
    fprintf(stderr, "  -i INFILE                Set input file name\n");
    fprintf(stderr, "                             Can be set using environment variable '%s'\n", UBIQ_TEST_DATA_FILE);
    fprintf(stderr, "  -c CREDENTIALS           Set the file name with the API credentials\n");
    fprintf(stderr, "                             (default: ~/.ubiq/credentials)\n");
    fprintf(stderr, "  -P PROFILE               Identify the profile within the credentials file\n");
}

int
ubiq_getopt(
    const int argc, char * const argv[],
    Options & options)
{
    int opt;

  options.max_avg_decrypt = 0;
    optind = 1;
    opterr = 0;
    
    while ((opt = getopt(argc, argv, "+:phe:d:E:D:i:c:P:")) != -1) {
        switch (opt) {
        case 'h':
            test_harness_usage(argv[0], NULL);
            exit(EXIT_SUCCESS);
            break;

        case 'p':
            options.print_errors = true;
            break;
            
        case 'e':
            if (options.max_avg_encrypt != 0) {
                test_harness_usage(
                    argv[0], "please specify encrypt average only once");
                exit(EXIT_FAILURE);
            }
            {
              std::stringstream ss;
              ss << optarg;
              ss >> options.max_avg_encrypt;
            }
            break;

        case 'E':
            if (options.max_total_encrypt != 0) {
                test_harness_usage(
                    argv[0], "please specify encrypt total only once");
                exit(EXIT_FAILURE);
            }
            {
              std::stringstream ss;
              ss << optarg;
              ss >> options.max_total_encrypt;
            }
            break;

        case 'd':
            if (options.max_avg_decrypt != 0) {
                test_harness_usage(
                    argv[0], "please specify decrypt average only once");
                exit(EXIT_FAILURE);
            }
            {
              std::stringstream ss;
              ss << optarg;
              ss >> options.max_avg_decrypt;
            }
            break;

        case 'D':
            if (options.max_total_decrypt != 0) {
                test_harness_usage(
                    argv[0], "please specify decrypt total only once");
                exit(EXIT_FAILURE);
            }
            {
              std::stringstream ss;
              ss << optarg;
              ss >> options.max_total_decrypt;
            }
            break;

        case 'i':
            if (options.infile.length() != 0) {
                test_harness_usage(
                    argv[0], "please specify only one input file");
                exit(EXIT_FAILURE);
            }

            options.infile = optarg;

            break;
        case 'c':
            if (options.credentials.length() != 0) {
                test_harness_usage(
                    argv[0], "please specify only one credentials file");
                exit(EXIT_FAILURE);
            }

            options.credentials = optarg;

            break;
        case 'P':
            if (options.profile.length() != 0) {
                test_harness_usage(
                    argv[0], "please specify only one profile name");
                exit(EXIT_FAILURE);
            }

            options.profile = optarg;

            break;
        case '?':
            fprintf(stderr, "unrecognized option: %s\n\n", argv[optind - 1]);
            test_harness_usage(argv[0], NULL);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr,
                    "missing argument for option: %s\n\n",
                    argv[optind - 1]);
            test_harness_usage(argv[0], NULL);
            exit(EXIT_FAILURE);
        }
    }

    if (options.infile.length() == 0) {
      char * data = NULL;
      GETENV(data, UBIQ_TEST_DATA_FILE);
      if (data) {
        options.infile = data;
        free(data);
      }
      if (options.infile.length() == 0) {
          test_harness_usage(argv[0], "input file not specified");
          exit(EXIT_FAILURE);
      }
    }

    get_int_env_option(options.max_avg_encrypt, UBIQ_MAX_AVG_ENCRYPT);
    get_int_env_option(options.max_avg_decrypt, UBIQ_MAX_AVG_DECRYPT);
    get_int_env_option(options.max_total_encrypt, UBIQ_MAX_TOTAL_ENCRYPT);
    get_int_env_option(options.max_total_decrypt, UBIQ_MAX_TOTAL_DECRYPT);

    return 0;
}


int ubiq_load_datafile(
  std::string & infile,
  std::list<Data_rec> & data
) 
{
  std::cout << "Loading file: " << infile << std::endl;
  std::ifstream t(infile);
  std::stringstream buffer;
  buffer << t.rdbuf();

    // parse the JSON data
  cJSON *json = cJSON_Parse(buffer.str().c_str());
  if (json == NULL) {
      const char *error_ptr = cJSON_GetErrorPtr();
      if (error_ptr != NULL) {
          printf("Error: %s\n", error_ptr);
      }
      cJSON_Delete(json);
      return 1;
  }

  // cJSON is very inefficient parsing arrays - which are stored as a linked list
  // Get first element, parse out what is needed, delete first element
  // and loop
  long array_count = cJSON_GetArraySize(json);

  for (long i = 0; i < array_count; i++) {
    cJSON * elem = cJSON_GetArrayItem(json, 0);

    Data_rec d(
      cJSON_GetObjectItem(elem,"dataset")->valuestring,
      cJSON_GetObjectItem(elem,"plaintext")->valuestring,
      cJSON_GetObjectItem(elem,"ciphertext")->valuestring);
    data.push_back(d);

    cJSON_DeleteItemFromArray(json,0);
  }

  cJSON_Delete(json);
  return 0;
}
