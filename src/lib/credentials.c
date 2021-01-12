#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "inih/ini.h"

#define GETENV(VAR, NAME)                       \
    do {                                        \
        VAR = getenv(NAME);                     \
        if (VAR) {                              \
            VAR = strdup(VAR);                  \
        }                                       \
    } while (0)

struct ubiq_platform_credentials
{
    char * papi, * sapi, *srsa, * host;
};

static
void
ubiq_platform_credentials_init(
    struct ubiq_platform_credentials * const c)
{
    c->host = c->srsa = c->sapi = c->papi = NULL;
}

static
void
ubiq_platform_credentials_clear(
    struct ubiq_platform_credentials * const c)
{
    free(c->host);
    free(c->srsa);
    free(c->sapi);
    free(c->papi);
    ubiq_platform_credentials_init(c);
}


const char *
ubiq_platform_credentials_get_host(
    const struct ubiq_platform_credentials * const creds)
{
    return creds->host;
}

const char *
ubiq_platform_credentials_get_papi(
    const struct ubiq_platform_credentials * const creds)
{
    return creds->papi;
}

const char *
ubiq_platform_credentials_get_sapi(
    const struct ubiq_platform_credentials * const creds)
{
    return creds->sapi;
}

const char *
ubiq_platform_credentials_get_srsa(
    const struct ubiq_platform_credentials * const creds)
{
    return creds->srsa;
}

void
ubiq_platform_credentials_destroy(
    struct ubiq_platform_credentials * const creds)
{
    ubiq_platform_credentials_clear(creds);
    free(creds);
}

static
void
ubiq_platform_credentials_from_env(
    struct ubiq_platform_credentials * const c)
{
    GETENV(c->papi, "UBIQ_ACCESS_KEY_ID");
    GETENV(c->sapi, "UBIQ_SECRET_SIGNING_KEY");
    GETENV(c->srsa, "UBIQ_SECRET_CRYPTO_ACCESS_KEY");
    GETENV(c->host, "UBIQ_SERVER");
}

struct ubiq_platform_credentials_list
{
    struct ubiq_platform_credentials_list_entry {
        char * profile;
        struct ubiq_platform_credentials creds;
    } * entries;
    size_t count;
};

static
void
ubiq_platform_credentials_list_init(
    struct ubiq_platform_credentials_list * const cl)
{
    cl->entries = NULL;
    cl->count = 0;
}

static
void
ubiq_platform_credentials_list_clear(
    struct ubiq_platform_credentials_list * const cl)
{
    for (unsigned int i = 0; i < cl->count; i++) {
        ubiq_platform_credentials_clear(&cl->entries[i].creds);
        free(cl->entries[i].profile);
    }

    free(cl->entries);
    ubiq_platform_credentials_list_init(cl);
}

static
struct ubiq_platform_credentials_list_entry *
ubiq_platform_credentials_list_find(
    const struct ubiq_platform_credentials_list * const cl,
    const char * const name)
{
    for (unsigned int i = 0; i < cl->count; i++) {
        if (strcmp(name, cl->entries[i].profile) == 0) {
            return &cl->entries[i];
        }
    }

    return NULL;
}

/*
 * is the credentials file is parsed, this function is
 * called by the parser for each name/value encountered
 * in the file. this function constructs the list of
 * credentials from the entries given to it.
 */
static
int
ubiq_platform_credentials_param_handler(
    void * const udata,
    const char * const section,
    const char * const name, const char * const value)
{
    int res;

    res = 1;
    if (section && strlen(section) > 0) {
        struct ubiq_platform_credentials_list * const cl = udata;

        struct ubiq_platform_credentials_list_entry * e;

        e = ubiq_platform_credentials_list_find(cl, section);
        if (!e) {
            struct ubiq_platform_credentials_list_entry * const entries =
                realloc(cl->entries, sizeof(*cl->entries) * (cl->count + 1));

            res = -ENOMEM;
            if (entries) {
                cl->entries = entries;

                e = &cl->entries[cl->count];
                e->profile = strdup(section);
                ubiq_platform_credentials_init(&e->creds);

                cl->count++;
            }
        }

        if (e) {
            if (strcmp(name, "ACCESS_KEY_ID") == 0) {
                free(e->creds.papi);
                e->creds.papi = strdup(value);
            } else if (strcmp(name, "SECRET_SIGNING_KEY") == 0) {
                free(e->creds.sapi);
                e->creds.sapi = strdup(value);
            } else if (strcmp(name, "SECRET_CRYPTO_ACCESS_KEY") == 0) {
                free(e->creds.srsa);
                e->creds.srsa = strdup(value);
            } else if (strcmp(name, "SERVER") == 0) {
                free(e->creds.host);
                e->creds.host = strdup(value);
            }
        }
    }

    return res;
}

/*
 * obtain a set of credentials associated with the named profile
 * from the given list. the profile may be NULL, in which case,
 * the "default" profile will be used.
 */
static
void
ubiq_platform_credentials_from_list(
    const struct ubiq_platform_credentials_list * const cl,
    const char * const prof,
    struct ubiq_platform_credentials * const c)
{
    const struct ubiq_platform_credentials_list_entry * def, * fnd;

    fnd = def = ubiq_platform_credentials_list_find(cl, "default");
    if (prof) {
        unsigned int i;

        /* look for a profile matching the given name */

        for (i = 0;
             i < cl->count &&
                 strcmp(prof, cl->entries[i].profile) != 0;
             i++)
            ;

        if (i < cl->count) {
            fnd = &cl->entries[i];
        }
    }

    /*
     * there are 3 possible combinations of `def` and `fnd`
     * - both are NULL
     * - both are non-NULL (may or may not be equal)
     * - `fnd` is non-NULL and `def` is NULL
     *
     * if `fnd` is NULL, it's because no matching profile was
     * found and `def` is also NULL. in this case, there are
     * no credentials to be loaded.
     *
     * the other cases are handled by the code below.
     */

    if (fnd) {
        if ((fnd->creds.papi || (def && def->creds.papi)) &&
            (fnd->creds.sapi || (def && def->creds.sapi)) &&
            (fnd->creds.srsa || (def && def->creds.srsa))) {
            c->papi = strdup(
                fnd->creds.papi ? fnd->creds.papi : def->creds.papi);
            c->sapi = strdup(
                fnd->creds.sapi ? fnd->creds.sapi : def->creds.sapi);
            c->srsa = strdup(
                fnd->creds.srsa ? fnd->creds.srsa : def->creds.srsa);
            if (fnd->creds.host || (def && def->creds.host)) {
                c->host = strdup(
                    fnd->creds.host ? fnd->creds.host : def->creds.host);
            }
        }
    }
}

/*
 * loads a credentials file into memory
 */
static
void
ubiq_platform_credentials_load_file(
    const char * const path,
    struct ubiq_platform_credentials_list * const cl)
{
    const char * _path;

    _path = path;
    if (!_path) {
        static const char * const cred_path = ".ubiq/credentials";
        char * homedir;
        int err;

        err = ubiq_support_get_home_dir(&homedir);
        if (!err) {
            int len;

            len = snprintf(NULL, 0, "%s/%s", homedir, cred_path) + 1;
            _path = malloc(len);
            if (_path) {
                snprintf((char *)_path, len, "%s/%s", homedir, cred_path);
            }

            free(homedir);
        }
    }

    if (_path) {
        FILE * fp;

        fp = fopen(_path, "rb");
        if (fp) {
            if (ini_parse_file(
                    fp, &ubiq_platform_credentials_param_handler, cl) != 0) {
                ubiq_platform_credentials_list_clear(cl);
            }

            fclose(fp);
        }

        if (path != _path) {
            free((void *)_path);
        }
    }
}

/*
 * if `into` is missing any components of a complete set
 * of credentials, move those missing components from the
 * `from` object.
 */
static
void
ubiq_platform_credentials_merge(
    struct ubiq_platform_credentials * const into,
    struct ubiq_platform_credentials * const from)
{
    if (!into->papi) {
        into->papi = from->papi;
        from->papi = NULL;
    }
    if (!into->sapi) {
        into->sapi = from->sapi;
        from->sapi = NULL;
    }
    if (!into->srsa) {
        into->srsa = from->srsa;
        from->srsa = NULL;
    }
    if (!into->host) {
        into->host = from->host;
        from->host = NULL;
    }
}

/*
 * try to create a set of credentials from the environment
 * and then from the default file, using the default profile.
 */
int
ubiq_platform_credentials_create(
    struct ubiq_platform_credentials ** const creds)
{
    struct ubiq_platform_credentials_list list;
    struct ubiq_platform_credentials into, from;

    int res;

    ubiq_platform_credentials_list_init(&list);
    ubiq_platform_credentials_init(&into);
    ubiq_platform_credentials_init(&from);

    ubiq_platform_credentials_from_env(&into);

    ubiq_platform_credentials_load_file(NULL, &list);
    ubiq_platform_credentials_from_list(&list, "default", &from);

    ubiq_platform_credentials_merge(&into, &from);

    res = -ENOENT;
    if (into.papi && into.sapi && into.srsa) {
        res = ubiq_platform_credentials_create_explicit(
            into.papi, into.sapi, into.srsa, into.host, creds);
    }

    ubiq_platform_credentials_clear(&from);
    ubiq_platform_credentials_clear(&into);
    ubiq_platform_credentials_list_clear(&list);

    return res;
}

/*
 * create a set of credentials from a specific file
 * using a specific profile. the environment can supply
 * the server (if it is otherwise missing) but cannot
 * supply or override any of the other components.
 */
int
ubiq_platform_credentials_create_specific(
    const char * const path, const char * const profile,
    struct ubiq_platform_credentials ** const creds)
{
    struct ubiq_platform_credentials_list l;
    struct ubiq_platform_credentials c;
    int res;

    ubiq_platform_credentials_list_init(&l);
    ubiq_platform_credentials_init(&c);

    ubiq_platform_credentials_load_file(path, &l);
    ubiq_platform_credentials_from_list(&l, profile, &c);
    if (!c.host) {
        GETENV(c.host, "UBIQ_SERVER");
    }

    res = -ENOENT;
    if (c.papi && c.sapi && c.srsa) {
        res = ubiq_platform_credentials_create_explicit(
            c.papi, c.sapi, c.srsa, c.host, creds);
    }

    ubiq_platform_credentials_clear(&c);
    ubiq_platform_credentials_list_clear(&l);

    return res;
}

/*
 * create a set of credentials using the
 * explicitly specified components.
 */
int
ubiq_platform_credentials_create_explicit(
    const char * const papi, const char * const sapi,
    const char * const srsa,
    const char * const host,
    struct ubiq_platform_credentials ** const creds)
{
    int res;

    res = -EINVAL;
    if (papi && sapi && srsa) {
        struct ubiq_platform_credentials * c;

        res = -ENOMEM;
        c = calloc(1, sizeof(*c));
        if (c) {
            c->papi = strdup(papi);
            c->sapi = strdup(sapi);
            c->srsa = strdup(srsa);
            c->host = strdup(host ? host : "api.ubiqsecurity.com");

            if (c->papi && c->sapi && c->srsa && c->host) {
                *creds = c;
                res = 0;
            } else {
                free(c->host);
                free(c->srsa);
                free(c->sapi);
                free(c->papi);
                free(c);
            }
        }
    }

    return res;
}
