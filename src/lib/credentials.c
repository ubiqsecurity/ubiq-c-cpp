#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform.h"

#include <openssl/pem.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "inih/ini.h"


// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;

#define GETENV(VAR, NAME)                       \
    do {                                        \
        VAR = getenv(NAME);                     \
        if (VAR) {                              \
            VAR = strdup(VAR);                  \
        }                                       \
    } while (0)

struct ubiq_platform_credentials
{
    char * papi, * sapi, *srsa, * host; // User
    char * idp_username, * idp_password; // User
    char * access_token;
    char * cert_pem;
    char * cert_b64;
    char * encrypted_private_pem;
    char * csr_pem;
    size_t token_duration_seconds;
    time_t cert_expiration;
};

static int ubiq_platform_credentials_create_struct(
  struct ubiq_platform_credentials ** const creds);


static
void
ubiq_platform_credentials_init(
    struct ubiq_platform_credentials * const c)
{
    c->host = c->srsa = c->sapi = c->papi = NULL;
    c->idp_username = c->idp_password = NULL;
    c->access_token = NULL;
    c->cert_pem = c->cert_b64 = c->encrypted_private_pem = c->csr_pem = NULL;
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
    free(c->idp_username);
    free(c->idp_password);
    free(c->access_token);
    free(c->cert_pem);
    free(c->cert_b64);
    free(c->encrypted_private_pem);
    free(c->csr_pem);
    ubiq_platform_credentials_init(c);
}

// Deep copy
int ubiq_platform_credentials_clone(
  const struct ubiq_platform_credentials * const src,
  struct ubiq_platform_credentials ** const creds)
{
  static const char * csu = "ubiq_platform_credentials_clone";

  UBIQ_DEBUG(debug_flag, printf("%s: %s' \n", csu, "started"));

  int res = 0;

  res = ubiq_platform_credentials_create_struct(creds);
  if (!res) {
    if (src->papi) (*creds)->papi = strdup(src->papi);
    if (src->sapi) (*creds)->sapi = strdup(src->sapi);
    if (src->srsa) (*creds)->srsa = strdup(src->srsa);
    if (src->host) (*creds)->host = strdup(src->host);
    if (src->idp_username) (*creds)->idp_username = strdup(src->idp_username);
    if (src->idp_password) (*creds)->idp_password = strdup(src->idp_password);
    if (src->access_token) (*creds)->access_token = strdup(src->access_token);
    if (src->cert_pem) (*creds)->cert_pem = strdup(src->cert_pem);
    if (src->cert_b64) (*creds)->cert_b64 = strdup(src->cert_b64);
    if (src->encrypted_private_pem) (*creds)->encrypted_private_pem = strdup(src->encrypted_private_pem);
    if (src->csr_pem) (*creds)->csr_pem = strdup(src->csr_pem);
    if (src->token_duration_seconds) (*creds)->token_duration_seconds = src->token_duration_seconds;
    (*creds)->cert_expiration = src->cert_expiration;
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d' \n", csu, res));

  return res;
}

const char *
ubiq_platform_credentials_get_host(
    const struct ubiq_platform_credentials * const creds)
{
    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_credentials_get_host: %s\n", creds->host));
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

const char *
ubiq_platform_credentials_get_idp_username(
    const struct ubiq_platform_credentials * const creds)
{
    return creds->idp_username;
}

const char *
ubiq_platform_credentials_get_idp_password(
    const struct ubiq_platform_credentials * const creds)
{
    return creds->idp_password;
}

const char *
ubiq_platform_credentials_get_access_token(
      const struct ubiq_platform_credentials * const creds)
{
  return creds->access_token;
}

size_t
ubiq_platform_credentials_get_access_token_duration_seconds(
      const struct ubiq_platform_credentials * const creds)
{
  return creds->token_duration_seconds;
}

const char *
ubiq_platform_credentials_get_csr(
      const struct ubiq_platform_credentials * const creds)
{
  return creds->csr_pem;
}

const char *
ubiq_platform_credentials_get_cert_b64(
      const struct ubiq_platform_credentials * const creds)
{
  return creds->cert_b64;
}

const char *
ubiq_platform_credentials_get_encrypted_private_key(
      const struct ubiq_platform_credentials * const creds)
{
  UBIQ_DEBUG(debug_flag, printf("in ubiq_platform_credentials_get_encrypted_private_key\n"));
  UBIQ_DEBUG(debug_flag, printf("in encrypted_private_pem %s\n", creds->encrypted_private_pem));
  return creds->encrypted_private_pem;
}

const time_t
ubiq_platform_credentials_get_cert_expiration(
      const struct ubiq_platform_credentials * const creds)
{
  return creds->cert_expiration;
}
void
ubiq_platform_credentials_set_host(
    struct ubiq_platform_credentials * const creds,
    const char * host)
{
    static const struct {
        const char * http;
        const char * https;
    } scheme = {
        .http = "http://",
        .https = "https://",
    };

    free(creds->host);

    // Does it begin with http or https ?
    if (strncmp(host, scheme.http, strlen(scheme.http)) == 0 ||
        strncmp(host, scheme.https, strlen(scheme.https)) == 0) {
        creds->host = strdup(host);
      // 
    } else { // Else, add the https prefix
        size_t len = strlen(scheme.https) + strlen(host) + 1;
        creds->host = calloc(len, sizeof(char));
        snprintf(creds->host, len, "%s%s", scheme.https, host);
    } 
}

void
ubiq_platform_credentials_set_papi(
     struct ubiq_platform_credentials * const creds,
     const char * papi)
{
    free(creds->papi);
    creds->papi = strdup(papi);
}

void
ubiq_platform_credentials_set_sapi(
     struct ubiq_platform_credentials * const creds,
     const char * sapi)
{
    free(creds->sapi);
    creds->sapi = strdup(sapi);
}

void
ubiq_platform_credentials_set_srsa(
     struct ubiq_platform_credentials * const creds,
     const char * srsa)
{
    free(creds->srsa);
    creds->srsa = strdup(srsa);
}

void
ubiq_platform_credentials_set_idp_username(
     struct ubiq_platform_credentials * const creds,
     const char * idp_username)
{
    free(creds->idp_username);
    creds->idp_username = strdup(idp_username);
}

void
ubiq_platform_credentials_set_idp_password(
    struct ubiq_platform_credentials * const creds,
    const char * idp_password)
{
    free(creds->idp_password);
    creds->idp_password = strdup(idp_password);
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
    static const char * csu = "ubiq_platform_credentials_from_env";

    GETENV(c->papi, "UBIQ_ACCESS_KEY_ID");
    GETENV(c->sapi, "UBIQ_SECRET_SIGNING_KEY");
    GETENV(c->srsa, "UBIQ_SECRET_CRYPTO_ACCESS_KEY");
    GETENV(c->host, "UBIQ_SERVER");
    GETENV(c->idp_username, "UBIQ_IDP_USERNAME");
    GETENV(c->idp_password, "UBIQ_IDP_PASSWORD");
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s\n", csu, "UBIQ_IDP_USERNAME", c->idp_username));
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s\n", csu, "UBIQ_IDP_PASSWORD", c->idp_password));
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s\n", csu, "UBIQ_SERVER", c->host));
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
    int res = 1;

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
            } else if (strcmp(name, "IDP_USERNAME") == 0) {
                free(e->creds.idp_username);
                e->creds.idp_username = strdup(value);
            } else if (strcmp(name, "IDP_PASSWORD") == 0) {
                free(e->creds.idp_password);
                e->creds.idp_password = strdup(value);
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
        for (unsigned int i = 0; i < cl->count; i++) {
            if (strcmp(prof, cl->entries[i].profile) == 0) {
                fnd = &cl->entries[i];
                break;
            }
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
        } else if ((fnd->creds.idp_password || (def && def->creds.idp_password)) &&
            (fnd->creds.idp_username || (def && def->creds.idp_username))) {
              c->idp_password = strdup(fnd->creds.idp_password ? fnd->creds.idp_password : def->creds.idp_password);
              c->idp_username = strdup(fnd->creds.idp_username ? fnd->creds.idp_username : def->creds.idp_username);
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
    if (!into->idp_username) {
        into->idp_username = from->idp_username;
        from->idp_username = NULL;
    }
    if (!into->idp_password) {
        into->idp_password = from->idp_password;
        from->idp_password = NULL;
    }
}

static int ubiq_platform_credentials_create_struct(
  struct ubiq_platform_credentials ** const creds)
{
  int res;

  res = -ENOMEM;
  struct ubiq_platform_credentials * c;

  c = calloc(1, sizeof(*c));
  if (c) {
    *creds = c;
    res = 0;
  }
  return res;
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
    } else if (into.idp_password && into.idp_username) {
      if ((res = ubiq_platform_credentials_create_struct(creds)) == 0) {
        if ((res = ubiq_platform_credentials_set_idp(*creds,
          into.idp_username, into.idp_password, into.host)) != 0) {
            ubiq_platform_credentials_destroy(*creds);
            *creds = NULL;
          }
      }
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
    } else if (c.idp_password && c.idp_password) {
        if ((res = ubiq_platform_credentials_create_struct(creds)) == 0) {
           res = ubiq_platform_credentials_set_idp(*creds,
                    c.idp_username, c.idp_password, c.host);
        }
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
  static const char * csu = "ubiq_platform_credentials_create_explicit";
  int res;

  res = -EINVAL;
  if (papi && sapi && srsa) {
      struct ubiq_platform_credentials * c;

      res = -ENOMEM;
      c = calloc(1, sizeof(*c));
      if (c) {
        ubiq_platform_credentials_set_papi(c, papi);
        ubiq_platform_credentials_set_sapi(c, sapi);
        ubiq_platform_credentials_set_srsa(c, srsa);
        ubiq_platform_credentials_set_host(c, host ? host : "api.ubiqsecurity.com");

        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "papi", c->papi));
        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "sapi", c->sapi));
        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "srsa", c->srsa));
        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "host", c->host));


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
  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));

  return res;
}

int
ubiq_platform_credentials_set_idp(
struct ubiq_platform_credentials * const creds,
    const char * const username, 
    const char * const password,
    const char * const host)
{
  static const char * csu = "ubiq_platform_credentials_set_idp";

  int res;

  res = -EINVAL;
  if (username && password && creds) {
        ubiq_platform_credentials_set_idp_username(creds, username);
        ubiq_platform_credentials_set_idp_password(creds, password);
        ubiq_platform_credentials_set_host(creds, host ? host : "api.ubiqsecurity.com");

        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "username", creds->idp_username));
        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "password", creds->idp_password));
        UBIQ_DEBUG(debug_flag, printf("%s: %s '%s' \n", csu, "host", creds->host));

        if (creds->idp_username && creds->idp_password && creds->host) {
            res = 0;
        } else {
            free(creds->idp_username);
            free(creds->idp_password);
            free(creds->host);
        }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d)\n", csu, res));

  return res;

}

int ubiq_platform_credentials_is_idp(
  const struct ubiq_platform_credentials * const creds
)
{
  static const char * csu = "ubiq_platform_credentials_is_idp";
  int res = 0;
  UBIQ_DEBUG(debug_flag, printf("%s: NULL ? %d\n", csu, (creds->idp_username == NULL)));
  UBIQ_DEBUG(debug_flag, printf("%s: idp_username ? %s\n", csu, creds->idp_username));
  if (creds->idp_username && *(creds->idp_username) != '\0') {
    res = 1;
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));
  return res;
}

int ubiq_platform_credentials_set_access_token(
    struct ubiq_platform_credentials * const creds,
    const char * access_token,
    const size_t duration_seconds)
{
  static const char * csu = "ubiq_platform_credentials_set_access_token";
  int res = -ENOMEM;

  free(creds->access_token);
  creds->access_token = strdup(access_token);
  creds->token_duration_seconds = duration_seconds;
  
  if (creds->access_token) {
    res = 0;
  }

  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));
  return res;
}

int ubiq_platform_credentials_set_rsa_keys(
    struct ubiq_platform_credentials * const creds,
    const char * srsa_b64,
    const char * encrypted_private_pem,
    const char * csr_pem)
 {
  static const char * csu = "ubiq_platform_credentials_set_rsa_keys";
  int res = -ENOMEM;
  
  free(creds->encrypted_private_pem);
  free(creds->csr_pem);
  free(creds->srsa);

  creds->encrypted_private_pem = strdup(encrypted_private_pem);
  creds->csr_pem = strdup(csr_pem);
  creds->srsa = strdup(srsa_b64);

  if (creds->encrypted_private_pem && creds->csr_pem && creds->srsa) {
    res = 0;
  }

  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));
  return res;
}

int ubiq_platform_credentials_set_rsa_cert(
    struct ubiq_platform_credentials * const creds,
    const char * cert_pem)
 {
  static const char * csu = "ubiq_platform_credentials_set_rsa_keys";
  int res = -ENOMEM;
  time_t expires_at = 0;

  free(creds->cert_pem);
  creds->cert_pem = strdup(cert_pem);
  free(creds->cert_b64);
  
  ubiq_support_base64_encode(&(creds->cert_b64), cert_pem, strlen(cert_pem));

  {
      BIO *cert_bio = BIO_new_mem_buf((void *)cert_pem, -1); // -1 means read all

      if (!cert_bio) {
          res = -EINVAL;
      } else {
        res = 0;
      }
      if (!res) {
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        BIO_free(cert_bio);
        if (!cert) {
          res = -EINVAL;
        }
        if (!res) {

          ASN1_TIME *not_after = X509_get_notAfter(cert);
          struct tm tm;
        
          ASN1_TIME_to_tm(not_after, &tm);
          creds->cert_expiration = mktime(&tm) - 60; // Subtract 60 seconds to avoid edge cases
          // Need to free AFTER not_after is no longer needed
          X509_free(cert);
        }
      }
  }
  if (creds->cert_pem && creds->cert_b64 && creds->cert_expiration) {
    res = 0;
  }

  UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));
  return res;
}