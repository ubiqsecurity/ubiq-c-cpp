#include "getopt.h"

int local_opterr(1);     /* if error message should be printed */
int local_optind(1);     /* index into parent argv vector */
int local_optopt(0);         /* character checked for validity */
int local_optreset(0);       /* reset getopt */
char *local_optarg(nullptr);        /* argument associated with option */

#define BADCH   (int)'?'
#define BADARG  (int)':'
#define EMSG    ""

/*
 * getopt --
 *  Parse argc/argv argument vector.
 */
int
local_getopt(int nargc, char * const nargv[], const char *ostr)
{
    char empty[] = EMSG;
    static char *place = empty;      /* option letter processing */
    char *oli;              /* option letter list index */

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
