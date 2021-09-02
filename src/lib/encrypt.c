#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
#include <ubiq/fpe/ff1.h>
#include <ubiq/fpe/internal/ffx.h>

#include "ubiq/fpe/internal/bn.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "cJSON/cJSON.h"

static const char * base2_charset = "01";
static const int FF1_base2_min_length = 20; // NIST requirement ceil(log2(1000000))

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


struct ubiq_platform_ffs {
  char * name;
  int min_input_length;
  int max_input_length;
  char * tweak_source;
  char * regex;
  char * input_character_set;
  char * output_character_set;
  char * passthrough_character_set;
  int msb_encoding_bits;
  int efpe_flag;
  struct {
          void * buf;
          size_t len;
  } tweak;
  int tweak_min_len;
  int tweak_max_len;
};

struct ubiq_platform_app {
  char * papi;
};

struct ubiq_platform_ffs_app {
  struct ubiq_platform_app * app;
  struct ubiq_platform_ffs * ffs;
};

struct ubiq_platform_fpe_encryption
{
    /* http[s]://host/api/v0 */
    char * restapi;
    char * encoded_papi;
    char * srsa;
    struct ubiq_platform_rest_handle * rest;

    struct ubiq_platform_ffs_app * ffs_app;

    struct {
            void * buf;
            size_t len;
            unsigned int key_number;
    } key;

};


struct fpe_ffs_parsed
{
  char * trimmed_buf;
  size_t trimmed_len;
  char * formatted_dest_buf;
  size_t formatted_dest_len;
};

static
void
fpe_ffs_parsed_destroy(
  struct fpe_ffs_parsed * const parsed
)
{
  free(parsed->trimmed_buf);
  free(parsed->formatted_dest_buf);
  free(parsed);

}

static
int fpe_ffs_parsed_create(
  struct fpe_ffs_parsed ** parsed,
  const size_t buf_len
)
{
  struct fpe_ffs_parsed *p;

  int res = -ENOMEM;

  p = calloc(1, sizeof(*p));
  if (p) {

    // Use calloc to set all to 0 and
    // use buflen + 1 to make sure room for '\0'
    // Either buffer can only be as long as the original input
    p->trimmed_buf = calloc(1, buf_len + 1);
    p->formatted_dest_buf = calloc(1, buf_len + 1);
    if (p->trimmed_buf && p->formatted_dest_buf) {
      p->trimmed_len = buf_len;
      p->formatted_dest_len = buf_len;
      res = 0;
    } else {
      fpe_ffs_parsed_destroy(p);
      p = NULL;
    }
  }
  *parsed = p;
  return res;
}

static int encode_keynum(
  struct ubiq_platform_fpe_encryption * const enc,
  char * const buf
)
{
  int res = 0;

  char * pos = strchr(enc->ffs_app->ffs->output_character_set, (int)*buf);
  unsigned int ct_value = pos - enc->ffs_app->ffs->output_character_set;

  ct_value += enc->key.key_number << enc->ffs_app->ffs->msb_encoding_bits;
  *buf = enc->ffs_app->ffs->output_character_set[ct_value];

  return res;
}

static unsigned int decode_keynum(
  struct ubiq_platform_fpe_encryption * const enc,
  char * const encoded_char
)
{

  char * pos = strchr(enc->ffs_app->ffs->output_character_set, (int)*encoded_char);
  unsigned int encoded_value = pos - enc->ffs_app->ffs->output_character_set;

  unsigned int key_num = encoded_value >> enc->ffs_app->ffs->msb_encoding_bits;


  *encoded_char = enc->ffs_app->ffs->output_character_set[encoded_value - (key_num << enc->ffs_app->ffs->msb_encoding_bits)];
  printf("Key number is %d\n", key_num);
  return key_num;
}

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
ubiq_platform_ffs_destroy(
    struct ubiq_platform_ffs * const ffs)
{
  if (ffs) {
    free (ffs->name);
    free (ffs->tweak_source);
    free (ffs->regex);
    free (ffs->input_character_set);
    free (ffs->output_character_set);
    free (ffs->passthrough_character_set);
    free (ffs->tweak.buf);
  }
  free(ffs);
}


static
int
ubiq_platform_ffs_app_destroy(
    struct ubiq_platform_ffs_app * const ffs_app)
{
  if (ffs_app) {
    free(ffs_app->app);
    ubiq_platform_ffs_destroy(ffs_app->ffs);
  }
  free(ffs_app);
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
    ubiq_platform_ffs_app_destroy(e->ffs_app);
    free(e->key.buf);
    free(e->restapi);
    free(e->encoded_papi);
    free(e->srsa);
    free(e);
}

static
int
ubiq_platform_fpe_encryption_new(
    const char * const host,
    const char * const papi, const char * const sapi,
    const char * const srsa,
    struct ubiq_platform_fpe_encryption ** const enc)
{
    static const char * const csu = "ubiq_platform_fpe_encryption_new";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_fpe_encryption * e;
    size_t len;
    int res;

    res = -ENOMEM;
    e = calloc(1, sizeof(*e));
    if (e) {
        len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path) + 1;
        e->restapi = calloc(len, 1);
        ubiq_platform_snprintf_api_url(e->restapi, len, host, api_path);
        res = ubiq_platform_rest_handle_create(papi, sapi, &e->rest);
        if (!res) {
          res = ubiq_platform_rest_uri_escape(e->rest, papi, &e->encoded_papi);
        }
        if (!res) {
          e->srsa = strdup(srsa);
          if (e->srsa == NULL) {
            res = -ENOMEM;
          }
        }
    }

    if (res) {
      ubiq_platform_fpe_encryption_destroy(e);
      e = NULL;
    }

    *enc = e;
//    printf("DEBUG %s END %d \n", csu, res);
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

  struct ubiq_platform_ffs_app * e = NULL;
  e = calloc(1, sizeof(*e));
  if (!e) {
    res = -ENOMEM;
  } else {
    e->app = calloc(1, sizeof(struct ubiq_platform_app));
    e->ffs = calloc(1, sizeof(struct ubiq_platform_ffs));
  }

  if (!res) {res = set_ffs_string(ffs_data, "name", &e->ffs->name);}
  if (!res) {res = set_ffs_string(ffs_data, "tweak_source", &e->ffs->tweak_source);}
  if (!res) {res = set_ffs_string(ffs_data, "regex", &e->ffs->regex);}
  if (!res) {res = set_ffs_string(ffs_data, "input_character_set", &e->ffs->input_character_set);}
  if (!res) {res = set_ffs_string(ffs_data, "output_character_set", &e->ffs->output_character_set);}
  if (!res) {res = set_ffs_string(ffs_data, "passthrough", &e->ffs->passthrough_character_set);}
  if (!res) {res = set_ffs_int(ffs_data, "min_input_length", &e->ffs->min_input_length);}
  if (!res) {res = set_ffs_int(ffs_data, "max_input_length", &e->ffs->max_input_length);}
//  if (!res) {res = set_ffs_int(ffs_data, "max_key_rotations", &e->ffs->max_key_rotations);}
  if (!res) {res = set_ffs_int(ffs_data, "msb_encoding_bits", &e->ffs->msb_encoding_bits);}

  if (!res) {res = set_ffs_int(ffs_data, "tweak_min_len", &e->ffs->tweak_min_len);}
  if (!res) {res = set_ffs_int(ffs_data, "tweak_max_len", &e->ffs->tweak_max_len);}

  if (!res && strcmp(e->ffs->tweak_source, "constant") == 0) {
    char * s = NULL;
    res = set_ffs_string(ffs_data, "tweak", &s);
    // printf("DEBUG %s\n", s);
    e->ffs->tweak.len = ubiq_support_base64_decode(
        &e->ffs->tweak.buf, s, strlen(s));
    free(s);

    // printf("tweak value: ");
    // char * b;
    // b = e->ffs->tweak.buf;
    // for (int i = 0; i < e->ffs->tweak.len; i++) {
    //   printf("%x ", b[i] & 0xff);
    // }
    // printf("\n");

  }

  if (!res) {
    e->ffs->efpe_flag = 1; // DEBUG just to indicate this is an eFPE field
    *ffs_app = e;
  } else {
    ubiq_platform_ffs_app_destroy(e);
  }

  return res;
}

static
int
ubiq_platform_fpe_encryption_get_ffs(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name)
{
  const char * const csu = "ubiq_platform_fpe_encryption_get_ffs";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";

  cJSON * json;
  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  free(encoded_name);

  res = ubiq_platform_rest_request(
      e->rest,
      HTTP_RM_GET, url, "application/json", NULL, 0);

  const char * content = ubiq_platform_rest_response_content(e->rest, &len);

  if (content) {
//    printf("FFS => '%s'\n", content);
    cJSON * ffs_json;
    res = (ffs_json = cJSON_ParseWithLength(content, len)) ? 0 : INT_MIN;
    if (!res) {
      char * str = cJSON_Print(ffs_json);
      printf("FFS => %s\n", str);
      free(str);
    }

//    cJSON * ffs_json = cJSON_Parse(content);
    if (ffs_json) {
//      printf("before ubiq_platform_ffs_app_create\n");
      res = ubiq_platform_ffs_app_create(ffs_json,  &e->ffs_app);
    }
    cJSON_Delete(ffs_json);
  }
  free(url);
//  printf("DEBUG %s END %d \n", csu, res);
  return res;
}

static
int
ubiq_platform_fpe_encryption_get_key_helper(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const url)
{
  cJSON * json;
  size_t len;
  int res = 0;

  res = ubiq_platform_rest_request(
    e->rest,
    HTTP_RM_GET, url, "application/json", NULL , 0);

  const char * content = ubiq_platform_rest_response_content(e->rest, &len);


//  printf("contents %.*s\n", len, content);
  if (content) {
    cJSON * rsp_json;
    res = (rsp_json = cJSON_ParseWithLength(content, len)) ? 0 : INT_MIN;
    {
      char * str = cJSON_Print(rsp_json);
      printf("contents %s\n", str);
      free(str);
    }

    res = ubiq_platform_common_fpe_parse_new_key(
        rsp_json, e->srsa,
        &e->key.buf, &e->key.len);

    if (!res) {
      const cJSON * k = cJSON_GetObjectItemCaseSensitive(
                        rsp_json, "key_number");
      if (cJSON_IsString(k) && k->valuestring != NULL) {
        const char * errstr = NULL;
        uintmax_t n = strtoumax(k->valuestring, NULL, 10);
        if (n == UINTMAX_MAX && errno == ERANGE) {
          res = -ERANGE;
        } else {
          e->key.key_number = (unsigned int)n;
//          printf("get key %d\n", e->key.key_number );
        }
      } else {
        res = -EBADMSG;
      }
    }

    cJSON_Delete(rsp_json);
  }
  return res;
}

static
int
ubiq_platform_fpe_encryption_get_key(
  struct ubiq_platform_fpe_encryption * const e)
{
  const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s";

  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, e->ffs_app->ffs->name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  free(encoded_name);
  res = ubiq_platform_fpe_encryption_get_key_helper(e, url);
  free(url);

}

static
int
ubiq_platform_fpe_decryption_get_key(
  struct ubiq_platform_fpe_encryption * const e,
  const unsigned int key_number)
{
  const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";

  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, e->ffs_app->ffs->name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi, key_number);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi, key_number);

  free(encoded_name);
  res = ubiq_platform_fpe_encryption_get_key_helper(e, url);
  free(url);
}

// static
// int
// ubiq_platform_fpe_decryption_get_key(
//   struct ubiq_platform_fpe_encryption * const e,
//   const char * const papi,
//   const char * const srsa)
// {
//   const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";
//
//   cJSON * json;
//   char * url;
//   size_t len;
//   int res = 0;
//
//   char * encoded_papi = NULL;
//   char * encoded_name = NULL;
//   res = ubiq_platform_rest_uri_escape(e->rest, papi, &encoded_papi);
//   res = ubiq_platform_rest_uri_escape(e->rest, e->ffs_app->ffs->name, &encoded_name);
//
//   len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, encoded_papi, e->key.key_number);
//   url = malloc(len + 1);
//   snprintf(url, len + 1, fmt, e->restapi, encoded_name, encoded_papi, e->key.key_number);
//
//   free(encoded_papi);
//   free(encoded_name);
//   // json = cJSON_CreateObject();
//   //
//   // cJSON_AddItemToObject(json, "ffs_name", cJSON_CreateString(e->ffs_app->ffs->name));
//   // cJSON_AddItemToObject(json, "ldap", cJSON_CreateString("ldap info"));
//   // str = cJSON_Print(json);
//   // cJSON_Delete(json);
//
//   res = ubiq_platform_rest_request(
//     e->rest,
//     HTTP_RM_GET, url, "application/json", NULL , 0);
//
//   const char * content = ubiq_platform_rest_response_content(e->rest, &len);
//
//   printf("contents %s\n", content);
//
//   if (content) {
//     cJSON * rsp_json;
//     res = (rsp_json = cJSON_ParseWithLength(content, len)) ? 0 : INT_MIN;
//
//     res = ubiq_platform_common_fpe_parse_new_key(
//         rsp_json, srsa,
//         &e->key.buf, &e->key.len);
//
//     cJSON_Delete(rsp_json);
//   }
//
//   free(url);
//   return res;
// }

int ubiq_platform_fpe_encryption_create(
    const struct ubiq_platform_credentials * const creds,
//    const char * const ffs_name,
    struct ubiq_platform_fpe_encryption ** const enc)
{
    struct ubiq_platform_fpe_encryption * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    res = ubiq_platform_fpe_encryption_new(host, papi, sapi, srsa, &e);

    // printf("BEFORE ubiq_platform_fpe_encryption_get_ffs (%d)\n", res);
    // if (0 == res) {
    //     res = ubiq_platform_fpe_encryption_get_ffs(
    //         e, ffs_name, papi);
    // }
    //
    // // TODO - Need to have way to pass KEY_NUMBER into rest to
    // // get key for specific key in the cycle
    // if (!res) {
    //   res = ubiq_platform_fpe_encryption_get_key(
    //     e, papi, srsa
    //   );
    // }

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_fpe_encryption_destroy(e);
    }


    return res;
}


static
int
ubiq_platform_encryption_fpe_parse_new_key(
    struct ubiq_platform_fpe_encryption * const e,
    const char * const srsa, const cJSON * const json)
{
    const cJSON * j;
    int res;

    res = ubiq_platform_common_fpe_parse_new_key(
        json, srsa,
        &e->key.buf, &e->key.len);

    return res;
}


int ubiq_platform_fpe_string_parse(
  struct ubiq_platform_fpe_encryption * enc,
  const int conversion_direction, // Positive means input to output, negative means output to input
  const void * const source_string,
  const size_t source_len,
  struct fpe_ffs_parsed * const parsed
)
{
  int res = 0;
  const char * src_char_set = NULL;
  char dest_zeroth_char = '\0';
  // struct fpe_ffs_parsed * p;

  if (conversion_direction > 0) {// input to output
    src_char_set = enc->ffs_app->ffs->input_character_set;
    dest_zeroth_char = enc->ffs_app->ffs->output_character_set[0];
  } else {
    dest_zeroth_char = enc->ffs_app->ffs->input_character_set[0];
    src_char_set = enc->ffs_app->ffs->output_character_set;
  }
  // res = fpe_ffs_parsed_create(&p, source_len);

  if (!res) {
    memset(parsed->trimmed_buf, src_char_set[0], source_len);
    memset(parsed->formatted_dest_buf, dest_zeroth_char, source_len);

    res = ubiq_platform_efpe_parsing_parse_input(
      source_string, src_char_set, enc->ffs_app->ffs->passthrough_character_set,
      parsed->trimmed_buf, parsed->formatted_dest_buf);

//    printf("trimmed '%s'  empty_formatted_output '%s'\n", parsed->trimmed_buf, parsed->formatted_dest_buf);
  }

  // if (res) {
  //   res = -ENOMEM;
  //   // *parsed = p;
  // }
  return res;
}

static
int
str_convert_radix(
  const char * const src_str,
  const char * const input_radix,
  const char * const output_radix,
  char ** out_str
)
{
  static const char * csu = "str_convert_radix";

  int res = 0;
  bigint_t n;

  bigint_init(&n);
  if (!res) {res = __bigint_set_str(&n, src_str, input_radix);}

  if (!res) {
    size_t len = __bigint_get_str(NULL, 0, output_radix, &n);

    char * out = calloc(len + 1, 1);
    if (out == NULL) {
      res = -ENOMEM;
    }
    if (!res) {
      res = __bigint_get_str(out, len, output_radix, &n);
      if (res <= len && res > 0) {
        *out_str = out;
        res = 0;
      }
    }
  }
  bigint_deinit(&n);

   // printf("\n\tDEBUG %s res(%d) src '%s'  => '%s' \n", csu, res, src_str, *out_str);
   // printf("\n\t\t Radix input '%s'  output '%s' \n", input_radix, output_radix);

  return res;
}

static
int
pad_text(char ** str, const size_t minlen, const char c)
{
  int res = 0;
  char * p = NULL;
  int len = strlen(*str);
  if (len < minlen) {
    if ((p = calloc(minlen + 1, 1)) == NULL) {
      res = -ENOMEM;
    } else {
      // Moving memory to end so can't use realloc (original ptr is invalid)
      memset(p, c, (minlen-len));
      memcpy(p + (minlen-len), *str, len);  // copy the characters
      free(*str);
      *str = p;
    }
  }
//  printf("debug: trimmed %s\n", *str);
  return res;
}

static
int
fpe_decrypt(
  struct ubiq_platform_fpe_encryption * const enc,
  const char * const ctbuf, const size_t ctlen,
  const uint8_t * const tweak, const size_t tweaklen,
  char ** const ptbuf, size_t * const ptlen
)
{
  const char * csu = "fpe_decrypt";

  int res = 0;
  struct fpe_ffs_parsed * parsed = NULL;
  char * ct_base2 = NULL;
  char * pt_base2 = NULL;
  char * pt_trimmed = NULL;
  // Trim pt

  /*
  * Need to parse the CT to get the encryption algorithm and key number
  */

  const char * alg = "FF1"; // DEBUG Hard coded for now

  const int key_number = 1; // DEBUG hardcoded for now

  res = fpe_ffs_parsed_create(&parsed, ctlen);
  if (!res) {res = ubiq_platform_fpe_string_parse(enc, -1, ctbuf, ctlen, parsed);}

  // TODO - Need to manipulate the trimmed_buf[0] - removing the
  // embedded information
  unsigned int keynum = decode_keynum(enc, &parsed->trimmed_buf[0]);

  if (!res) {
    res = ubiq_platform_fpe_decryption_get_key(enc, keynum);
  }

  // Convert trimmed into base 10 to prepare for decrypt
  if (!res) {
    res = str_convert_radix(
      parsed->trimmed_buf,
      enc->ffs_app->ffs->output_character_set,
      base2_charset,
      &ct_base2);

      int padlen = ceil(fmax(FF1_base2_min_length,log2(strlen(enc->ffs_app->ffs->input_character_set)) * strlen(parsed->trimmed_buf)));

      pad_text(&ct_base2,padlen, base2_charset[0]);

    if (!res) {pt_base2 = calloc(strlen(ct_base2) + 1, 1);}
    if (pt_base2 == NULL) {
      res = -ENOMEM;
    }

//    printf("DEBUG '%s' trimmed '%s' to '%s' base2\n", csu, parsed->trimmed_buf, ct_base2);

  }

  // TODO - Need logic to check tweak source and error out depending on supplied tweak
  printf("\nTWEAK: ");
  char * b;
  b = enc->ffs_app->ffs->tweak.buf;
  for (int i = 0; i < enc->ffs_app->ffs->tweak.len; i++) {
    printf("%x ", b[i] & 0xff);
  }
  printf("\n");


  if (!res) {
    struct ff1_ctx * ctx;
    res = ff1_ctx_create(&ctx, enc->key.buf, enc->key.len, enc->ffs_app->ffs->tweak.buf, enc->ffs_app->ffs->tweak.len, enc->ffs_app->ffs->tweak_min_len, enc->ffs_app->ffs->tweak_max_len, strlen(base2_charset));

    if (!res) {

      res = ff1_decrypt(ctx, pt_base2, ct_base2, NULL, 0);

      printf("DEBUG '%s' %d \n",csu, res);
      printf("\t     ct '%.*s'\n", ctlen, ctbuf);
      printf("\ttrimmed '%s'\n",parsed->trimmed_buf);
      printf("\tpadded base2 '%s'\n", ct_base2);
      printf("\t    pt base2 '%s'\n", pt_base2);
      printf("\tformatted_dest_buf '%s'\n", parsed->formatted_dest_buf);
    }
    ff1_ctx_destroy(ctx);

  }

  // Convert PT to output radix
  if (!res) {
    res = str_convert_radix(
      pt_base2,
      base2_charset,
      enc->ffs_app->ffs->input_character_set,
      &pt_trimmed);

    if (pt_trimmed == NULL) {
      res = -ENOMEM;
    }
    printf("\ttrimmed   PT '%s' \n", pt_trimmed);
  }

  // Merge PT to formatted output
  if (!res) {
    int d = strlen(parsed->formatted_dest_buf) - 1;
    int s = strlen(pt_trimmed) - 1;
    while (s >= 0 && d >= 0)
    {
      // Find the first available destination character
      while (d >=0 && parsed->formatted_dest_buf[d] != enc->ffs_app->ffs->input_character_set[0])
      {
        d--;
      }
      // Copy the encrypted text into the formatted output string
      if (d >= 0) {
        parsed->formatted_dest_buf[d] = pt_trimmed[s];
      }
      s--;
      d--;
    }

    printf("\t          PT '%s' \n", parsed->formatted_dest_buf);
  }

  if (!res) {
    *ptbuf = strdup(parsed->formatted_dest_buf);
    if (*ptbuf != NULL) {
      *ptlen = strlen(*ptbuf);
    } else {
      res = -ENOMEM;
    }
  }
  fpe_ffs_parsed_destroy(parsed);
  free(ct_base2);
  free(pt_base2);
  free(pt_trimmed);
  return res;
}

static
int
fpe_encrypt(
  struct ubiq_platform_fpe_encryption * const enc,
  const char * const ptbuf, const size_t ptlen,
  const uint8_t * const tweak, const size_t tweaklen,
  char ** const ctbuf, size_t * const ctlen
)
{
  static const char * csu = "fpe_encrypt";
  int res = 0;
  struct fpe_ffs_parsed * parsed = NULL;
  char * ct_base2 = NULL;
  char * pt_base2 = NULL;
  char * ct_trimmed = NULL;


  // Trim pt
  res = fpe_ffs_parsed_create(&parsed, ptlen);

  if (!res) {res = ubiq_platform_fpe_string_parse(enc, 1, ptbuf, ptlen, parsed);}

  if (!res) {
    res = ubiq_platform_fpe_encryption_get_key(enc);
  }

  // Convert trimmed into base 10 to prepare for decrypt
  if (!res) {
    res = str_convert_radix(
      parsed->trimmed_buf,
      enc->ffs_app->ffs->input_character_set,
      base2_charset,
      &pt_base2);

    if (!res) {
      // Figure out how long to pad the binary string.  Formula is input_radix^len = 2^Y which is log2(input_radix) * len
      // Due to FF1 constraints, the there is a minimum length for a base2 string, so make sure to be at least that long too
      // or fpe will fail
      int padlen = ceil(fmax(FF1_base2_min_length,log2(strlen(enc->ffs_app->ffs->input_character_set)) * strlen(parsed->trimmed_buf)));

      // The padding may re-allocate so make sure to allow for pt_base2 to change pointer
      res = pad_text(&pt_base2, padlen, base2_charset[0]);
    }
    // Allocate buffer of same size for ct_base2
    if (!res) {
      if ((ct_base2 = calloc(strlen(pt_base2) + 1, 1)) == NULL) {
        res = -ENOMEM;
      }
    }

  }

  // TODO - Need logic to check tweak source and error out depending on supplied tweak

  printf("\nTWEAK: ");
  char * b;
  b = enc->ffs_app->ffs->tweak.buf;
  for (int i = 0; i < enc->ffs_app->ffs->tweak.len; i++) {
    printf("%x ", b[i] & 0xff);
  }
  printf("\n");


  // Encrypt
  if (!res) {
    struct ff1_ctx * ctx;

    res = ff1_ctx_create(&ctx, enc->key.buf, enc->key.len, enc->ffs_app->ffs->tweak.buf, enc->ffs_app->ffs->tweak.len, enc->ffs_app->ffs->tweak_min_len, enc->ffs_app->ffs->tweak_max_len, strlen(base2_charset));
    if (!res) {

      res = ff1_encrypt(ctx, ct_base2, pt_base2, NULL, 0);

      printf("DEBUG '%s' %d \n",csu, res);
      printf("\t     pt '%.*s'\n", ptlen, ptbuf);
      printf("\ttrimmed '%s'\n",parsed->trimmed_buf);
      printf("\tpadded base2 '%s'\n", pt_base2);
      printf("\t    ct base2 '%s'\n", ct_base2);
      printf("\tformatted_dest_buf '%s'\n", parsed->formatted_dest_buf);
    }
    ff1_ctx_destroy(ctx);
  }

  // Convert PT to output radix
  if (!res) {
    res = str_convert_radix(
      ct_base2,
      base2_charset,
      enc->ffs_app->ffs->output_character_set,
      &ct_trimmed);

    if (ct_trimmed == NULL) {
      res = -ENOMEM;
    }
    printf("\ttrimmed   CT '%s' \n", ct_trimmed);
  }

  // Merge PT to formatted output
  if (!res) {
    res = 0;
    int d = strlen(parsed->formatted_dest_buf) - 1;
    int s = strlen(ct_trimmed) - 1;
    while (s >= 0 && d >= 0)
    {
      // Find the first available destination character
      while (d >=0 && parsed->formatted_dest_buf[d] != enc->ffs_app->ffs->output_character_set[0])
      {
        d--;
      }
      // Copy the encrypted text into the formatted output string
      if (d >= 0) {
        parsed->formatted_dest_buf[d] = ct_trimmed[s];
      }
      s--;
      d--;
    }
    printf("\tUnencoded CT '%s' \n", parsed->formatted_dest_buf);

  }

  /*
  * Since ct_trimmed may not include empty leading characters, Need to walk through the formated_dest_buf and find
  * first non-pass through character.  Could be char 0 or MSB with some actual CT
  */
  if (!res) {
    /*
    * eFPE
    */
    char * pos = parsed->formatted_dest_buf;
    while ((*pos != '\0') && (NULL != strchr(enc->ffs_app->ffs->passthrough_character_set, *pos))) {pos++;};
//    printf("first non-passthrough %s\n", pos);
    res = encode_keynum(enc, pos);
//    printf("ct %s\n", ct_trimmed);

  }



  if (!res) {
    *ctbuf = strdup(parsed->formatted_dest_buf);

    if (*ctbuf != NULL) {
      *ctlen = strlen(*ctbuf);
    } else {
      res = -ENOMEM;
    }
  }
  printf("\t  Encoded CT '%s' \n", *ctbuf);

  fpe_ffs_parsed_destroy(parsed);
  free(ct_base2);
  free(pt_base2);
  free(ct_trimmed);
  return res;
}


int
ubiq_platform_fpe_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char ** const ctbuf, size_t * const ctlen)
{

  struct ubiq_platform_fpe_encryption * enc;
  int res = 0;

  // Create Structure that will handle REST calls.
  // Std voltron gets additional information, this will
  // simply allocate structure.  Mapping creds to individual strings
  enc = NULL;
  res = ubiq_platform_fpe_encryption_create(creds,  &enc);

  if (!res) {
    res = ubiq_platform_fpe_encryption_get_ffs(enc, ffs_name);
  }

  /*
  * Key is retrieved in the encrypt call
  */

  if (!res) {
     res  = fpe_encrypt(enc, ptbuf, ptlen, tweak, tweaklen, ctbuf, ctlen);
  }
  ubiq_platform_fpe_encryption_destroy(enc);


  return res;
}

int
ubiq_platform_fpe_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const void * const ctbuf, const size_t ctlen,
    char ** const ptbuf, size_t * const ptlen)
{
  struct ubiq_platform_fpe_encryption * enc;
  int res = 0;

  // Create Structure that will handle REST calls.
  // Std voltron gets additional information, this will
  // simply allocate structure.  Mapping creds to individual strings
  enc = NULL;
  res = ubiq_platform_fpe_encryption_create(creds, &enc);

  if (!res) {
    res = ubiq_platform_fpe_encryption_get_ffs(enc, ffs_name);
  }

  if (!res) {
    res  = fpe_decrypt(enc, ctbuf, ctlen, tweak, tweaklen, ptbuf, ptlen);
  }
    ubiq_platform_fpe_encryption_destroy(enc);
  return res;
}
