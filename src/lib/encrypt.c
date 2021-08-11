#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"

#include "ubiq/fpe/internal/bn.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cJSON/cJSON.h"

struct ubiq_platform_encryption
{
    /* http[s]://host/api/v0 */
    const char * restapi;
    struct ubiq_platform_rest_handle * rest;

    char * session;
    int fragment;

    struct {
        struct {
            void * buf;
            size_t len;
        } raw, enc;

        char * fingerprint;

        struct {
            unsigned int max, cur;
        } uses;
    } key;

    const struct ubiq_platform_algorithm * algo;
    struct ubiq_support_cipher_context * ctx;
};

void
ubiq_platform_encryption_destroy(
    struct ubiq_platform_encryption * const e)
{
    /*
     * if there is a session and a fingerprint
     * and the key was used less times than requested,
     * then update the server with the actual number
     * of uses
     */
    if (e->session && e->key.fingerprint &&
        e->key.uses.cur < e->key.uses.max) {
        const char * const fmt = "%s/encryption/key/%s/%s";

        cJSON * json;
        char * url, * str;
        int len, res;

        /* create the request url using the fingerprint and session */

        len = snprintf(
            NULL, 0, fmt, e->restapi, e->key.fingerprint, e->session);
        url = malloc(len + 1);
        snprintf(
            url, len + 1, fmt, e->restapi, e->key.fingerprint, e->session);

        /* the json object to send */

        json = cJSON_CreateObject();
        cJSON_AddItemToObject(
            json, "requested", cJSON_CreateNumber(e->key.uses.max));
        cJSON_AddItemToObject(
            json, "actual", cJSON_CreateNumber(e->key.uses.cur));
        str = cJSON_Print(json);
        cJSON_Delete(json);

        /* and send the request */

        res = ubiq_platform_rest_request(
            e->rest,
            HTTP_RM_PATCH, url, "application/json", str, strlen(str));

        free(str);
        free(url);

        if (res != 0 ||
            ubiq_platform_rest_response_code(e->rest) != HTTP_RC_NO_CONTENT) {
            /*
             * TODO: there's not much to do if the http request fails
             * since the encryption object itself is being destroyed,
             * and the function doesn't return a value. this failure
             * should probably be logged somewhere.
             */
        }
    }

    ubiq_platform_rest_handle_destroy(e->rest);

    free(e->key.fingerprint);
    free(e->key.enc.buf);
    free(e->key.raw.buf);

    free(e->session);

    if (e->ctx) {
        ubiq_support_cipher_destroy(e->ctx);
    }

    free(e);
}

static
int
ubiq_platform_encryption_new(
    const char * const host,
    const char * const papi, const char * const sapi,
    struct ubiq_platform_encryption ** const enc)
{
    static const char * const api_path = "api/v0";

    struct ubiq_platform_encryption * e;
    size_t len;
    int res;

    res = -ENOMEM;
    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path) + 1;
    e = calloc(1, sizeof(*e) + len);
    if (e) {
        ubiq_platform_snprintf_api_url((char *)(e + 1), len, host, api_path);
        e->restapi = (char *)(e + 1);

        res = ubiq_platform_rest_handle_create(papi, sapi, &e->rest);
        if (res != 0) {
            free(e);
            e = NULL;
        }
    }

    *enc = e;
    return res;
}

static
int
ubiq_platform_encryption_parse_new_key(
    struct ubiq_platform_encryption * const e,
    const char * const srsa, const cJSON * const json)
{
    const cJSON * j;
    int res;

    res = ubiq_platform_common_parse_new_key(
        json, srsa,
        &e->session, &e->key.fingerprint,
        &e->key.raw.buf, &e->key.raw.len);

    if (res == 0) {
        /*
         * the encrypted data key is stored at the front end of
         * any encrypted data. base64 decode it and just store
         * the result
         */
        j = cJSON_GetObjectItemCaseSensitive(json, "encrypted_data_key");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            e->key.enc.len = ubiq_support_base64_decode(
                &e->key.enc.buf, j->valuestring, strlen(j->valuestring));
        } else {
            res = -EBADMSG;
        }
    }

    if (res == 0) {
        /*
         * save the maximum number of uses of the key
         */
        j = cJSON_GetObjectItemCaseSensitive(json, "max_uses");
        if (cJSON_IsNumber(j)) {
            e->key.uses.max = j->valueint;
        } else {
            res = -EBADMSG;
        }
    }

    if (res == 0) {
        j = cJSON_GetObjectItemCaseSensitive(json, "security_model");
        if (cJSON_IsObject(j)) {
            const cJSON * k;

            if (res == 0) {
                k = cJSON_GetObjectItemCaseSensitive(j, "algorithm");
                if (cJSON_IsString(k) && k->valuestring != NULL) {
                    res = ubiq_platform_algorithm_get_byname(
                        k->valuestring, &e->algo);
                } else {
                    res = -EBADMSG;
                }
            }

            if (res == 0) {
                /*
                 * keep track of whether fragmentation is enabled
                 */
                k = cJSON_GetObjectItemCaseSensitive(
                    j, "enable_data_fragmentation");
                if (cJSON_IsBool(k)) {
                    e->fragment = cJSON_IsTrue(k);
                } else {
                    res = -EBADMSG;
                }
            }
        } else {
            res = -EBADMSG;
        }
    }

    return res;
}

int ubiq_platform_encryption_create(
    const struct ubiq_platform_credentials * const creds,
    const unsigned int uses,
    struct ubiq_platform_encryption ** const enc)
{
    struct ubiq_platform_encryption * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    res = ubiq_platform_encryption_new(host, papi, sapi, &e);
    if (res == 0) {
        const char * const fmt = "%s/encryption/key";

        cJSON * json;
        char * url, * str;
        int len;

        /*
         * create the url for the request
         */
        len = snprintf(NULL, 0, fmt, e->restapi);
        url = malloc(len + 1);
        snprintf(url, len + 1, fmt, e->restapi);

        /*
         * request body just contains the number of
         * desired uses of the key
         */
        json = cJSON_CreateObject();
        cJSON_AddItemToObject(json, "uses", cJSON_CreateNumber(uses));
        str = cJSON_Print(json);
        cJSON_Delete(json);

        res = ubiq_platform_rest_request(
            e->rest,
            HTTP_RM_POST, url, "application/json", str, strlen(str));

        free(str);
        free(url);

        /*
         * if the request was successful, parse the response
         */

        if (res == 0) {
            const http_response_code_t rc =
                ubiq_platform_rest_response_code(e->rest);

            if (rc == HTTP_RC_CREATED) {
                const void * rsp;
                size_t len;
                cJSON * json;

                rsp = ubiq_platform_rest_response_content(e->rest, &len);
                res = (json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

                if (res == 0) {
                    res = ubiq_platform_encryption_parse_new_key(e, srsa, json);
                    cJSON_Delete(json);
                }
            } else {
                res = ubiq_platform_http_error(rc);
            }
        }
    }

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_encryption_destroy(e);
    }

    return res;
}

int
ubiq_platform_encryption_begin(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    if (enc->ctx) {
        /* encryption already in progress */
        res = -EINPROGRESS;
    } else if (enc->key.uses.cur >= enc->key.uses.max) {
        /* key is all used up */
        res = -ENOSPC;
    } else {
        /*
         * good to go, build a header; create the context
         */
        const size_t ivlen = enc->algo->len.iv;
        union ubiq_platform_header * hdr;
        size_t len;

        len = sizeof(*hdr) + ivlen + enc->key.enc.len;
        hdr = malloc(len);

        /* the fixed-size portion of the header */

        hdr->pre.version = 0;
        hdr->v0.flags = enc->algo->len.tag ? UBIQ_HEADER_V0_FLAG_AAD : 0;
        hdr->v0.algorithm = enc->algo->id;
        hdr->v0.ivlen = (uint8_t)ivlen;
        hdr->v0.keylen = htons((uint16_t)enc->key.enc.len);

        /* add on the initialization vector */
        res = ubiq_support_getrandom(hdr + 1, ivlen);
        if (res == 0) {
            const void * aadbuf;
            size_t aadlen;

            /* add the encrypted key */
            memcpy((char *)(hdr + 1) + ivlen, enc->key.enc.buf,
                   enc->key.enc.len);

            *ctbuf = (void *)hdr;
            *ctlen = len;

            aadbuf = (hdr->v0.flags & UBIQ_HEADER_V0_FLAG_AAD) ? hdr : NULL;
            aadlen = aadbuf ? (sizeof(*hdr) + ivlen + enc->key.enc.len) : 0;

            res = ubiq_support_encryption_init(
                enc->algo,
                enc->key.raw.buf, enc->key.raw.len,
                hdr + 1, ivlen,
                aadbuf, aadlen,
                &enc->ctx);
            if (res == 0) {
                enc->key.uses.cur++;
            }
        } else {
            free(hdr);
        }
    }

    return res;
}

int
ubiq_platform_encryption_update(
    struct ubiq_platform_encryption * const enc,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    res = -ESRCH;
    if (enc->ctx) {
        res = ubiq_support_encryption_update(
            enc->ctx, ptbuf, ptlen, ctbuf, ctlen);
    }

    return res;
}

int
ubiq_platform_encryption_end(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    res = -ESRCH;
    if (enc->ctx) {
        void * tagbuf;
        size_t taglen;

        tagbuf = NULL;
        taglen = 0;
        res = ubiq_support_encryption_finalize(
            enc->ctx, ctbuf, ctlen, &tagbuf, &taglen);
        if (res == 0) {
            enc->ctx = NULL;
        }

        if (res == 0 && tagbuf && taglen) {
            void * buf;

            res = -ENOMEM;
            buf = realloc(*ctbuf, *ctlen + taglen);
            if (buf) {
                memcpy((char *)buf + *ctlen, tagbuf, taglen);
                *ctbuf = buf;
                *ctlen += taglen;
                res = 0;
            } else {
                free(*ctbuf);
            }

            free(tagbuf);
        }
    }

    return res;
}

int
ubiq_platform_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const void * ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    struct ubiq_platform_encryption * enc;
    int res;

    struct {
        void * buf;
        size_t len;
    } pre, upd, end;

    pre.buf = upd.buf = end.buf = NULL;

    enc = NULL;
    res = ubiq_platform_encryption_create(creds, 1, &enc);

    if (res == 0) {
        res = ubiq_platform_encryption_begin(
            enc, &pre.buf, &pre.len);
    }

    if (res == 0) {
        res = ubiq_platform_encryption_update(
            enc, ptbuf, ptlen, &upd.buf, &upd.len);
    }

    if (res == 0) {
        res = ubiq_platform_encryption_end(
            enc, &end.buf, &end.len);
    }

    if (enc) {
        ubiq_platform_encryption_destroy(enc);
    }

    if (res == 0) {
        *ctlen = pre.len + upd.len + end.len;
        *ctbuf = malloc(*ctlen);

        memcpy(*ctbuf, pre.buf, pre.len);
        memcpy((char *)*ctbuf + pre.len, upd.buf, upd.len);
        memcpy((char *)*ctbuf + pre.len + upd.len, end.buf, end.len);
    }

    free(end.buf);
    free(upd.buf);
    free(pre.buf);

    return res;
}

struct ubiq_platform_fpe_encryption
{
    /* http[s]://host/api/v0 */
    const char * restapi;
    struct ubiq_platform_rest_handle * rest;

    struct {
        struct {
            void * buf;
            size_t len;
        } raw, enc;

    } key;

};

static
int
ubiq_platform_fpe_encryption_new(
    const char * const host,
    const char * const papi, const char * const sapi,
    struct ubiq_platform_fpe_encryption ** const enc)
{
    static const char * const api_path = "api/v0";

    struct ubiq_platform_fpe_encryption * e;
    size_t len;
    int res;

    res = -ENOMEM;
    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path) + 1;
    e = calloc(1, sizeof(*e) + len);
    if (e) {
        ubiq_platform_snprintf_api_url((char *)(e + 1), len, host, api_path);
        e->restapi = (char *)(e + 1);

        res = ubiq_platform_rest_handle_create(papi, sapi, &e->rest);
        if (res != 0) {
            free(e);
            e = NULL;
        }
    }

    *enc = e;
    return res;
}

void
ubiq_platform_fpe_encryption_destroy(
    struct ubiq_platform_fpe_encryption * const e)
{
    /*
     * if there is a session and a fingerprint
     * and the key was used less times than requested,
     * then update the server with the actual number
     * of uses
     */

    ubiq_platform_rest_handle_destroy(e->rest);

    free(e);
}

int ubiq_platform_fpe_encryption_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_fpe_encryption ** const enc)
{
    struct ubiq_platform_fpe_encryption * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    res = ubiq_platform_fpe_encryption_new(host, papi, sapi, &e);

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_fpe_encryption_destroy(e);
    }

    return res;
}

struct ubiq_platform_ffs {
  char * name;
  char * tweak;
  int min_input_length;
  int max_input_length;
  char * regex;
  char * input_character_set;
  char * output_character_set;
  char * passthrough_character_set;
  int max_key_rotations;
  int efpe_flag;
};

struct ubiq_platform_app {
  char * papi;
};

struct ubiq_platform_ffs_app {
  struct ubiq_platform_app * app;
  struct ubiq_platform_ffs * ffs;
  unsigned int current_key;
};


static int set_ffs_string(
  cJSON * ffs_data,
  char * field_name,
  char **  destination)
{
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(ffs_data, field_name);
  if (cJSON_IsString(j) && j->valuestring != NULL) {
    *destination = strdup(j->valuestring);
    if (!*destination) {
      res = -errno;
    }
  }
  return res;
}

static int set_ffs_int(
  cJSON * ffs_data,
  char * field_name,
  int *  destination)
{
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(ffs_data, field_name);
  if (cJSON_IsNumber(j)) {
    *destination = j->valueint;
  }
  return res;
}

static
int
ubiq_platform_ffs_app_create(
    cJSON * ffs_data,
    struct ubiq_platform_ffs_app ** const ffs_app)
{
  int res = 0;

  // Going to allocate memory as a single block
  // First with the structure.  Then with the
  // length of strings.  This will allow simple copy and
  // avoid fragmented memory

  struct ubiq_platform_ffs_app * e;
  e = calloc(1, sizeof(*e));
  if (!e) {
    res = -ENOMEM;
  } else {
    e->app = calloc(1, sizeof(struct ubiq_platform_app));
    e->ffs = calloc(1, sizeof(struct ubiq_platform_ffs));
  }

  if (!res) {res = set_ffs_string(ffs_data, "ffs_name", &e->ffs->name);}
  if (!res) {res = set_ffs_string(ffs_data, "tweak_source", &e->ffs->tweak);}
  if (!res) {res = set_ffs_string(ffs_data, "regex", &e->ffs->regex);}
  if (!res) {res = set_ffs_string(ffs_data, "input_character_set", &e->ffs->input_character_set);}
  if (!res) {res = set_ffs_string(ffs_data, "output_character_set", &e->ffs->output_character_set);}
  if (!res) {res = set_ffs_string(ffs_data, "passthrough_character_set", &e->ffs->passthrough_character_set);}

  if (!res) {res = set_ffs_int(ffs_data, "min_input_length", &e->ffs->min_input_length);}
  if (!res) {res = set_ffs_int(ffs_data, "max_input_length", &e->ffs->max_input_length);}
  if (!res) {res = set_ffs_int(ffs_data, "max_key_rotations", &e->ffs->max_key_rotations);}


  if (!res) {
    e->ffs->efpe_flag = 1; // DEBUG just to indicate this is an eFPE field
    *ffs_app = e;
  }
  return res;
}

int
ubiq_platform_fpe_encryption_get_ffs(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name,
  const char * const papi,
  struct ubiq_platform_ffs_app ** ffs_app)
{
  const char * const fmt = "%s/ffs/%s";

  cJSON * json;
  char * url, * str;
  int len;
  int res = 0;

  char * encoded_papi = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, papi, &encoded_papi);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_papi);

  free(encoded_papi);
  json = cJSON_CreateObject();

  cJSON_AddItemToObject(json, "ffs_name", cJSON_CreateString(ffs_name));
  cJSON_AddItemToObject(json, "ldap", cJSON_CreateString("ldap info"));
  str = cJSON_Print(json);
  printf("DEBUG Request Payload '%s'\n", str);
  cJSON_Delete(json);

  res = ubiq_platform_rest_request(
      e->rest,
      HTTP_RM_GET, url, "application/json", str, strlen(str));

    char * content = ubiq_platform_rest_response_content(e->rest, &len);

    if (content) {
      printf("DEBUG Result payload '%s'\n", content);
      cJSON * ffs_json = cJSON_Parse(content);
      if (ffs_json) {
        res = ubiq_platform_ffs_app_create(ffs_json,  ffs_app);
      }
    }

    return res;
}

int
ubiq_platform_fpe_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const void * const ldap, const size_t ldaplen,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{

  struct ubiq_platform_fpe_encryption * enc;
  char * empty_formatted_output = NULL;
  char * trimmed = NULL;

  struct {
      void * buf;
      size_t len;
  } ffs;

  int res = 0;
  ffs.buf = NULL;

  // cJSON * ffs_json;
  // ffs_json = cJSON_CreateObject();
  struct ubiq_platform_ffs_app * ffs_app;

  // Create Structure that will handle REST calls.
  // Std voltron gets additional information, this will
  // simply allocate structure.  Mapping creds to individual strings
  enc = NULL;
  res = ubiq_platform_fpe_encryption_create(creds, &enc);

  // Get the FFS data from server
  if (res == 0) {
      res = ubiq_platform_fpe_encryption_get_ffs(
          enc, ffs_name, ubiq_platform_credentials_get_papi(creds), &ffs_app);
  }

  // Allocate the space for Trimmer or Empty Format String based on the length of the plain text.
  // Using calloc to set all bytes to null but then set based on the appropriate character set.
  // leaving the last byte as null terminator('\0')
  printf("pt '%s'  :    '%d'\n", ptbuf, ptlen);
  printf("trimmed '%s'  empty_formatted_output '%s'\n", trimmed, empty_formatted_output);

  if ((ffs_app)) {
    if (ffs_app->ffs) {
      if (ffs_app->ffs->input_character_set) {
     }
   }
  }

  if (!res) {
    trimmed = calloc(1, ptlen + 1);
    if (!trimmed) {res = -ENOMEM;}
    if (!res) {
      memset(trimmed, ffs_app->ffs->input_character_set[0], ptlen);
    }
  }

  if (!res) {
    empty_formatted_output = calloc(1, ptlen + 1);
    if (!empty_formatted_output)  {res = -ENOMEM;}
    if (!res) {
      memset(empty_formatted_output, ffs_app->ffs->output_character_set[0], ptlen);
    }
  }

  // Parse the pt to get the trimmed and formatted
  res = ubiq_platform_efpe_parsing_parse_input(
    ptbuf, ffs_app->ffs->input_character_set, ffs_app->ffs->passthrough_character_set,
    trimmed, empty_formatted_output);

  printf("trimmed '%s'  empty_formatted_output '%s'\n", trimmed, empty_formatted_output);

  // FPE Encrypt the trimmed

  // Convert encrypted to output radix

  bigint_t n;

  /* @n will be the numerical value of @inp */
  bigint_init(&n);

  if (!res) {res = __bigint_set_str(&n, trimmed, ffs_app->ffs->input_character_set);}
  if (!res) {
    size_t len = __bigint_get_str(NULL, 0, ffs_app->ffs->output_character_set, &n);

    char * outstr = calloc(1, len + 1);
    res = __bigint_get_str(outstr, len, ffs_app->ffs->output_character_set, &n);

    printf("__bigint_get_str outstr %s\n", outstr);

    if (res <= len) {
      res = 0;
      int d = strlen(empty_formatted_output) - 1;
      int s = len - 1;
      while (s >= 0 && d >= 0)
      {
        // Find the first available destination character
        while (d >=0 && empty_formatted_output[d] != ffs_app->ffs->output_character_set[0])
        {
          d--;
        }
        if (d >= 0) {
          empty_formatted_output[d] = outstr[s];
        }
        s--;
        d--;
      }
      printf("outstr '%s'   formatted_output '%s'   res(%d)\n", outstr, empty_formatted_output,res);
    }

    free(outstr);
  }

  // ASSERT_GT(r1, 0);
  // output.resize(r1);
  //
  // r2 = __bigint_get_str((char *)output.data(), r1, oalpha, &n);
  // EXPECT_EQ(r1, r2);
  // EXPECT_EQ(std::string(output), expect);

  bigint_deinit(&n);



  // Copy output into formatted output

  //cJSON_Delete(ffs_json);

  return res;
}
