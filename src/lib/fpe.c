#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
#include "ubiq/platform/internal/cache.h"
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

typedef enum {encrypt=0, decrypt=1}  action_type ;



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

// struct ubiq_platform_app {
//   char * papi;
// };

// struct ubiq_platform_ffs_app {
//   // struct ubiq_platform_app * app;
//   struct ubiq_platform_ffs * ffs;
// };

struct ubiq_platform_fpe_encryption
{
    /* http[s]://host/api/v0 */
    char * restapi;
    char * encoded_papi;
    char * srsa;
    struct ubiq_platform_rest_handle * rest;

//    struct ubiq_platform_ffs_app * ffs_app;

    // struct {
    //         void * buf;
    //         size_t len;
    //         unsigned int key_number;
    // } key;

    struct ubiq_platform_cache * ffs_cache; // URL / ubiq_platform_ffs
    struct ubiq_platform_cache * key_cache; // URL / JSON response from server
};

struct ubiq_platform_fpe_key {
        void * buf;
        size_t len;
        unsigned int key_number;
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
int
fpe_key_create(struct ubiq_platform_fpe_key ** key){
  struct ubiq_platform_fpe_key * k;

  int res = -ENOMEM;

  k = calloc(1, sizeof(*k));
  if (k) {
    *key = k;
    res = 0;
  }
  return res;
}

static
void
fpe_key_destroy(struct ubiq_platform_fpe_key * const key){
  if (key && key->buf) {
    if (key->len > 0) {
      memset(key->buf, 0, key->len);
    }
    free(key->buf);
  }
  free(key);
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
  const struct ubiq_platform_ffs * ffs,
  const unsigned int key_number,
  char * const buf
)
{
  int res = 0;

  char * pos = strchr(ffs->output_character_set, (int)*buf);
  unsigned int ct_value = pos - ffs->output_character_set;

  ct_value += key_number << ffs->msb_encoding_bits;
  *buf = ffs->output_character_set[ct_value];

  return res;
}

static unsigned int decode_keynum(
  const struct ubiq_platform_ffs * ffs,
  char * const encoded_char
)
{

  char * pos = strchr(ffs->output_character_set, (int)*encoded_char);
  unsigned int encoded_value = pos - ffs->output_character_set;

  unsigned int key_num = encoded_value >> ffs->msb_encoding_bits;


  *encoded_char = ffs->output_character_set[encoded_value - (key_num << ffs->msb_encoding_bits)];
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
void
ubiq_platform_ffs_destroy(
    void * f)
{
  struct ubiq_platform_ffs * const ffs = (struct ubiq_platform_ffs * const) f;
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

#ifdef NODEF
static
int
ubiq_platform_ffs_app_destroy(
    struct ubiq_platform_ffs_app * const ffs_app)
{
  if (ffs_app) {
//    free(ffs_app->app);
    ubiq_platform_ffs_destroy(ffs_app->ffs);
  }
  free(ffs_app);
}
#endif

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
//    ubiq_platform_ffs_app_destroy(e->ffs_app);
//    free(e->key.buf);
    free(e->restapi);
    free(e->encoded_papi);
    free(e->srsa);
    ubiq_platform_cache_destroy(e->ffs_cache);
    ubiq_platform_cache_destroy(e->key_cache);
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
        if (!res) {
          res = ubiq_platform_cache_create(&e->ffs_cache);
        }
        if (!res) {
          res = ubiq_platform_cache_create(&e->key_cache);
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

#ifdef NODEF
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
//    e->app = calloc(1, sizeof(struct ubiq_platform_app));
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
#endif

static
int
ubiq_platform_ffs_create(
    cJSON * ffs_data,
    struct ubiq_platform_ffs ** const ffs)
{
  int res = 0;

  // Going to allocate memory as a single block
  // First with the structure.  Then with the
  // length of strings.  This will allow simple copy and
  // avoid fragmented memory

  struct ubiq_platform_ffs * e = NULL;
  e = calloc(1, sizeof(*e));
  if (!e) {
    res = -ENOMEM;
  }

  if (!res) {res = set_ffs_string(ffs_data, "name", &e->name);}
  if (!res) {res = set_ffs_string(ffs_data, "tweak_source", &e->tweak_source);}
  if (!res) {res = set_ffs_string(ffs_data, "regex", &e->regex);}
  if (!res) {res = set_ffs_string(ffs_data, "input_character_set", &e->input_character_set);}
  if (!res) {res = set_ffs_string(ffs_data, "output_character_set", &e->output_character_set);}
  if (!res) {res = set_ffs_string(ffs_data, "passthrough", &e->passthrough_character_set);}
  if (!res) {res = set_ffs_int(ffs_data, "min_input_length", &e->min_input_length);}
  if (!res) {res = set_ffs_int(ffs_data, "max_input_length", &e->max_input_length);}
//  if (!res) {res = set_ffs_int(ffs_data, "max_key_rotations", &e->ffs->max_key_rotations);}
  if (!res) {res = set_ffs_int(ffs_data, "msb_encoding_bits", &e->msb_encoding_bits);}

  if (!res) {res = set_ffs_int(ffs_data, "tweak_min_len", &e->tweak_min_len);}
  if (!res) {res = set_ffs_int(ffs_data, "tweak_max_len", &e->tweak_max_len);}

  if (!res && strcmp(e->tweak_source, "constant") == 0) {
    char * s = NULL;
    res = set_ffs_string(ffs_data, "tweak", &s);
    // printf("DEBUG %s\n", s);
    e->tweak.len = ubiq_support_base64_decode(
        &e->tweak.buf, s, strlen(s));
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
    e->efpe_flag = 1; // DEBUG just to indicate this is an eFPE field
    *ffs = e;
  } else {
    ubiq_platform_ffs_destroy(e);
  }

  return res;
}

#ifdef NODEF
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

  const char * content = ubiq_platform_cache_find_element(e->ffs_cache, url);
  printf("Checked cache %s\n", content);
  if (content != NULL) {
    len = strlen(content);
  } else {

    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL, 0);

    content = ubiq_platform_rest_response_content(e->rest, &len);

    ubiq_platform_cache_add_element(e->ffs_cache, url, 24*60*60*3,strndup(content, len), &free);
    printf("Cache added %s\n", ubiq_platform_cache_find_element(e->ffs_cache, url));

  }

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
#endif

static
int
ubiq_platform_fpe_encryption_get_ffs_def(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name,
  struct ubiq_platform_ffs ** ffs_definition)
{
  const char * const csu = "ubiq_platform_fpe_encryption_get_ffs_def";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";

  cJSON * json;
  char * url;
  size_t len;
  int res = 0;

  struct ubiq_platform_ffs * ffs;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  free(encoded_name);

  ffs = (const struct ubiq_platform_ffs *)ubiq_platform_cache_find_element(e->ffs_cache, url);
  if (ffs == NULL) {
    const char * content = NULL;
    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL, 0);

    content = ubiq_platform_rest_response_content(e->rest, &len);

//    ubiq_platform_cache_add_element(e->ffs_cache, url, 24*60*60*3,strndup(content, len), &free);
//    printf("Cache added %s\n", ubiq_platform_cache_find_element(e->ffs_cache, url));

    if (content) {
  //    printf("FFS => '%s'\n", content);
      cJSON * ffs_json;
      res = (ffs_json = cJSON_ParseWithLength(content, len)) ? 0 : INT_MIN;
      if (!res) {
        char * str = cJSON_Print(ffs_json);
        printf("FFS => %s\n", str);
        free(str);
      }
      printf("DEBUG 1\n");

  //    cJSON * ffs_json = cJSON_Parse(content);
      if (ffs_json) {
  //      printf("before ubiq_platform_ffs_app_create\n");
        struct ubiq_platform_ffs * f = NULL;
        printf("DEBUG 2\n");

        res = ubiq_platform_ffs_create(ffs_json,  &f);
        printf("DEBUG 3 res(%d)\n", res);
        if (!res) {
          printf("DEBUG f(%p)\n", (void *)f);
          printf("DEBUG name(%s)\n", f->name);
          ubiq_platform_cache_add_element(e->ffs_cache, url, 24*60*60*3, f, &ubiq_platform_ffs_destroy);
          *ffs_definition = f;
          printf("DEBUG name(%s)\n", (*ffs_definition)->name);
        }
      }
      cJSON_Delete(ffs_json);
    }
  }
  free(url);
//  printf("DEBUG %s END %d \n", csu, res);
  return res;
}

#ifdef NODEF
static
int
ubiq_platform_fpe_encryption_get_key_helper_old(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const url)
{
  cJSON * json;
  size_t len;
  int res = 0;

  const char * content = ubiq_platform_cache_find_element(e->key_cache, url);
  printf("Checked key cache %s\n", content);
  if (content != NULL) {
    len = strlen(content);
  }
  else {

    res = ubiq_platform_rest_request(
      e->rest,
      HTTP_RM_GET, url, "application/json", NULL , 0);

    content = ubiq_platform_rest_response_content(e->rest, &len);

    ubiq_platform_cache_add_element(e->key_cache, url, 24*60*60*3,strndup(content, len), &free);
    printf("Key Cache added %s\n", ubiq_platform_cache_find_element(e->key_cache, url));
  }

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

        printf("\nKEY: ");
        char * b;
        b = e->key.buf;
        for (int i = 0; i < e->key.len; i++) {
          printf("%x ", b[i] & 0xff);
        }
        printf("\n");

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
ubiq_platform_fpe_encryption_get_key_old(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name)
{
  const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s";

  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  free(encoded_name);
  res = ubiq_platform_fpe_encryption_get_key_helper_old(e, url);
  free(url);
  return res;
}

static
int
ubiq_platform_fpe_decryption_get_key_old(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name,
  const unsigned int key_number)
{
  const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";

  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi, key_number);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi, key_number);

  free(encoded_name);
  res = ubiq_platform_fpe_encryption_get_key_helper_old(e, url);
  free(url);
  return res;
}
#endif

static
int
ubiq_platform_fpe_encryption_get_key_helper(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const url,
  struct ubiq_platform_fpe_key ** const key)
{
  cJSON * json;
  size_t len;
  int res = 0;
  struct ubiq_platform_fpe_key * k = NULL;

  res = fpe_key_create(&k);
  if (!res) {
    const char * content = ubiq_platform_cache_find_element(e->key_cache, url);
    printf("Checked key cache %s\n", content);
    if (content != NULL) {
      len = strlen(content);
    }
    else {

      res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL , 0);

      content = ubiq_platform_rest_response_content(e->rest, &len);

      ubiq_platform_cache_add_element(e->key_cache, url, 24*60*60*3,strndup(content, len), &free);
      printf("Key Cache added %s\n", ubiq_platform_cache_find_element(e->key_cache, url));
    }

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
          &k->buf, &k->len);

      printf("\nKEY: ");
      char * b;
      b = k->buf;
      for (int i = 0; i < k->len; i++) {
        printf("%x ", b[i] & 0xff);
      }
      printf("\n");

      if (!res) {
        const cJSON * kn = cJSON_GetObjectItemCaseSensitive(
                          rsp_json, "key_number");
        if (cJSON_IsString(kn) && kn->valuestring != NULL) {
          const char * errstr = NULL;
          uintmax_t n = strtoumax(kn->valuestring, NULL, 10);
          if (n == UINTMAX_MAX && errno == ERANGE) {
            res = -ERANGE;
          } else {
            k->key_number = (unsigned int)n;
  //          printf("get key %d\n", e->key.key_number );
          }
        } else {
          res = -EBADMSG;
        }
      }
      cJSON_Delete(rsp_json);
    }
    if (!res) {
      *key = k;
    }
  }
  return res;
}

static
int
ubiq_platform_fpe_encryption_get_key(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name,
  struct ubiq_platform_fpe_key ** const key)
{
  const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s";

  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  free(encoded_name);
  res = ubiq_platform_fpe_encryption_get_key_helper(e, url, key);
  free(url);
  return res;
}

static
int
ubiq_platform_fpe_decryption_get_key(
  struct ubiq_platform_fpe_encryption * const e,
  const char * const ffs_name,
  const unsigned int key_number,
  struct ubiq_platform_fpe_key ** const key)
{
  const char * const fmt = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";

  char * url;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi, key_number);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi, key_number);

  free(encoded_name);
  res = ubiq_platform_fpe_encryption_get_key_helper(e, url, key);
  free(url);
  return res;
}


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

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_fpe_encryption_destroy(e);
    }

    return res;
}

#ifdef NODEF
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
#endif

int ubiq_platform_fpe_string_parse(
  const struct ubiq_platform_ffs * ffs,
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
    src_char_set = ffs->input_character_set;
    dest_zeroth_char = ffs->output_character_set[0];
  } else {
    dest_zeroth_char = ffs->input_character_set[0];
    src_char_set = ffs->output_character_set;
  }
  // res = fpe_ffs_parsed_create(&p, source_len);

  if (!res) {
    memset(parsed->trimmed_buf, src_char_set[0], source_len);
    memset(parsed->formatted_dest_buf, dest_zeroth_char, source_len);

    res = ubiq_platform_efpe_parsing_parse_input(
      source_string, src_char_set, ffs->passthrough_character_set,
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
  const char * ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen
)
{
  const char * csu = "fpe_decrypt";

  int res = 0;
  struct fpe_ffs_parsed * parsed = NULL;
  char * ct_base2 = NULL;
  char * pt_base2 = NULL;
  char * pt_trimmed = NULL;

  const struct ubiq_platform_ffs * ffs_definition = NULL;
  const struct ubiq_platform_fpe_key * key = NULL;
  // Trim pt

  /*
  * Need to parse the CT to get the encryption algorithm and key number
  */

  const char * alg = "FF1"; // DEBUG Hard coded for now

  res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);

  if (!res) {res = fpe_ffs_parsed_create(&parsed, ctlen);}
  if (!res) {res = ubiq_platform_fpe_string_parse(ffs_definition, -1, ctbuf, ctlen, parsed);}

  // TODO - Need to manipulate the trimmed_buf[0] - removing the
  // embedded information
  unsigned int keynum = decode_keynum(ffs_definition, &parsed->trimmed_buf[0]);

  if (!res) {
    res = ubiq_platform_fpe_decryption_get_key(enc, ffs_name, keynum, &key);
//    res = ubiq_platform_fpe_decryption_get_key_old(enc, ffs_name, keynum);


  }

  // Convert trimmed into base 10 to prepare for decrypt
  if (!res) {
    res = str_convert_radix(
      parsed->trimmed_buf,
      ffs_definition->output_character_set,
      base2_charset,
      &ct_base2);

      int padlen = ceil(fmax(FF1_base2_min_length,log2(strlen(ffs_definition->input_character_set)) * strlen(parsed->trimmed_buf)));

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
  b = ffs_definition->tweak.buf;
  for (int i = 0; i < ffs_definition->tweak.len; i++) {
    printf("%x ", b[i] & 0xff);
  }
  printf("\n");


  if (!res) {
    struct ff1_ctx * ctx;
    res = ff1_ctx_create(&ctx, key->buf, key->len, ffs_definition->tweak.buf, ffs_definition->tweak.len, ffs_definition->tweak_min_len, ffs_definition->tweak_max_len, strlen(base2_charset));

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
      ffs_definition->input_character_set,
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
      while (d >=0 && parsed->formatted_dest_buf[d] != ffs_definition->input_character_set[0])
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
  fpe_key_destroy(key);
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
  const char * ffs_name,
//  const uint8_t * const key, const size_t keylen, const size_t keynum,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen
)
{
  static const char * csu = "fpe_encrypt";
  int res = 0;
  struct fpe_ffs_parsed * parsed = NULL;
  char * ct_base2 = NULL;
  char * pt_base2 = NULL;
  char * ct_trimmed = NULL;
  const struct ubiq_platform_ffs * ffs_definition = NULL;
  const struct ubiq_platform_fpe_key * key = NULL;

  // ffs_definition is cached so do not delete
  res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);

  // Trim pt
  if (!res) {  res = fpe_ffs_parsed_create(&parsed, ptlen); }

  if (!res) {res = ubiq_platform_fpe_string_parse(ffs_definition, 1, ptbuf, ptlen, parsed);}

  if (!res) {
    res = ubiq_platform_fpe_encryption_get_key(enc, ffs_name, &key);
//    res = ubiq_platform_fpe_encryption_get_key_old(enc, ffs_definition->name);
  }

  // Convert trimmed into base 10 to prepare for decrypt
  if (!res) {
    res = str_convert_radix(
      parsed->trimmed_buf,
      ffs_definition->input_character_set,
      base2_charset,
      &pt_base2);

    if (!res) {
      // Figure out how long to pad the binary string.  Formula is input_radix^len = 2^Y which is log2(input_radix) * len
      // Due to FF1 constraints, the there is a minimum length for a base2 string, so make sure to be at least that long too
      // or fpe will fail
      int padlen = ceil(fmax(FF1_base2_min_length,log2(strlen(ffs_definition->input_character_set)) * strlen(parsed->trimmed_buf)));

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

  printf("\nKey: ");
  char * b;
  b = key->buf;
  for (int i = 0; i < key->len; i++) {
    printf("%x ", b[i] & 0xff);
  }
  printf("\n");

  printf("\nTWEAK: ");
  b = ffs_definition->tweak.buf;
  for (int i = 0; i < ffs_definition->tweak.len; i++) {
    printf("%x ", b[i] & 0xff);
  }
  printf("\n");


  // Encrypt
  if (!res) {
    struct ff1_ctx * ctx;

    printf("Before ff1_ctx_create\n");
    res = ff1_ctx_create(&ctx, key->buf, key->len, ffs_definition->tweak.buf, ffs_definition->tweak.len, ffs_definition->tweak_min_len, ffs_definition->tweak_max_len, strlen(base2_charset));
    printf("After ff1_ctx_create res(%d)\n", res);
    if (!res) {

      printf("Before ff1_encrypt\n");
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
      ffs_definition->output_character_set,
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
      while (d >=0 && parsed->formatted_dest_buf[d] != ffs_definition->output_character_set[0])
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
    while ((*pos != '\0') && (NULL != strchr(ffs_definition->passthrough_character_set, *pos))) {pos++;};
//    printf("first non-passthrough %s\n", pos);
    res = encode_keynum(ffs_definition, key->key_number, pos);
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

  fpe_key_destroy(key);
  fpe_ffs_parsed_destroy(parsed);
  free(ct_base2);
  free(pt_base2);
  free(ct_trimmed);
  return res;
}

static
int
ubiq_platform_fpe_billing(
  struct ubiq_platform_fpe_encryption * const e,
  const char * ffs_name,
  const action_type action,
  unsigned int count) {

    static const char * const fmt = "%s/fpe/billing/%s";
    time_t now;

    cJSON * json;
    char * url;
    size_t len;
    int res = 0;


    len = snprintf(NULL, 0, fmt, e->restapi, e->encoded_papi);
    url = malloc(len + 1);
    snprintf(url, len + 1, fmt, e->restapi, e->encoded_papi);

    char guid_hex[37]; // 8 - 4 - 4 - 4 - 12
    uint16_t guid[8];

    ubiq_support_getrandom(&guid, sizeof(guid));
    snprintf(guid_hex, sizeof(guid_hex), "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
			guid[0], guid[1], guid[2], guid[3],
			guid[4], guid[5], guid[6], guid[7]);

    json = cJSON_CreateObject();
    cJSON * array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "count", cJSON_CreateNumber(count));

    time(&now);
    char buf[sizeof("2011-10-08T07:07:09Z   ")];
    strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&now));

    cJSON_AddItemToObject(json, "id", cJSON_CreateString(guid_hex));
    cJSON_AddItemToObject(json, "timestamp", cJSON_CreateString(buf));
    cJSON_AddItemToObject(json, "ffs_name", cJSON_CreateString(ffs_name));
    if (action == encrypt) {
      cJSON_AddItemToObject(json, "action", cJSON_CreateString("encrypt"));
    } else {
      cJSON_AddItemToObject(json, "action", cJSON_CreateString("decrypt"));
    }

    cJSON_AddItemToArray(array, cJSON_Duplicate(json, cJSON_True));

    // Intentionally create an invalid item to test error payload
    cJSON_DeleteItemFromObject(json, "id");
    cJSON_AddItemToObject(json, "id", cJSON_CreateString("1"));
    cJSON_DeleteItemFromObject(json, "count");
    cJSON_AddItemToObject(json, "count", cJSON_CreateNumber(-1 * (int)count));
    cJSON_AddItemToArray(array, json);

    char * str = cJSON_Print(array);
    cJSON_Delete(array);

    printf("BILLING Payload: %s\n", str);

    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_POST, url, "application/json", str, strlen(str));

    // If Success, simply proceed
    if (res == 0) {
      const http_response_code_t rc =
          ubiq_platform_rest_response_code(e->rest);

      if (rc == HTTP_RC_BAD_REQUEST) {
          const void * rsp;
          size_t len;
          cJSON * json;

          rsp = ubiq_platform_rest_response_content(e->rest, &len);
          res = (json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

          if (res == 0) {
            char * str = cJSON_Print(json);
            printf("RESULTS => %s\n", str);
            // TODO - Loops through json array and remove items UNTIL we find
            // record with the provided ID.
            // NOTE - It is possible that there were NOT any records successfully
            // processed which means everything would need to be resent.
            free(str);
          }
          cJSON_Delete(json);
      } else if (rc == HTTP_RC_CREATED) {
          res = 0;
      } else {
        res = ubiq_platform_http_error(rc);
      }
    }


    const char * content = ubiq_platform_rest_response_content(e->rest, &len);

//  free(guid_hex);
  free(str);
  free(url);
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

  // if (!res) {
  //   res = ubiq_platform_fpe_encryption_get_ffs(enc, ffs_name);
  // }

  /*
  * Key is retrieved in the encrypt call
  */

  if (!res) {
     res  = fpe_encrypt(enc, ffs_name,
//       enc->key.buf, enc->key.len, enc->key.key_number,
       tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
     ubiq_platform_fpe_billing(enc, ffs_name, encrypt, 1);
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

  enc = NULL;
  res = ubiq_platform_fpe_encryption_create(creds, &enc);

  // if (!res) {
  //   res = ubiq_platform_fpe_encryption_get_ffs(enc, ffs_name);
  // }

  if (!res) {
    res  = fpe_decrypt(enc, ffs_name, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen);
    res = ubiq_platform_fpe_billing(enc, ffs_name, decrypt, 1);
  }
    ubiq_platform_fpe_encryption_destroy(enc);
  return res;
}

int
ubiq_platform_fpe_encrypt_data(
  struct ubiq_platform_fpe_encryption * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen
)
{
  int res = 0;
  // const struct ubiq_platform_ffs * ffs_definition;
//  const struct ubiq_platform_fpe_key * fpe_key;
   /*
    * Fetch the FFS information, use CACHE if available
    * Consider case where Cache could expire during middle of this
    * so retrive it all now.
    */
   // res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);
   //
   // printf("After ubiq_platform_fpe_encryption_get_ffs_def res(%d) name(%s)\n", res, ffs_definition->name);
   //
   // res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);
   //
   // printf("After ubiq_platform_fpe_encryption_get_ffs_def res(%d) name(%s)\n", res, ffs_definition->name);

   // res = ubiq_platform_fpe_encryption_get_key(enc, ffs_name, &fpe_key);
   // fpe_key_destroy(fpe_key);
   //
   // res = ubiq_platform_fpe_encryption_get_key(enc, ffs_name, &fpe_key);

   if (!res) {
      res  = fpe_encrypt(enc, ffs_name,
//        fpe_key->buf, fpe_key->len, fpe_key->key_number,
        tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
      printf("After fpe_encrypt res(%d) ct(%.*s)\n", res, *ctlen, *ctbuf);
      ubiq_platform_fpe_billing(enc, ffs_name, encrypt, 1);
   }

//   fpe_key_destroy(fpe_key);

   return res;
}

int
ubiq_platform_fpe_decrypt_data(
  struct ubiq_platform_fpe_encryption * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen
)
{
  int res = 0;
  // const struct ubiq_platform_ffs * ffs_definition;
  // const struct ubiq_platform_fpe_key * fpe_key;
   /*
    * Fetch the FFS information, use CACHE if available
    * Consider case where Cache could expire during middle of this
    * so retrive it all now.
    */
   // res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);
   //
   // printf("After ubiq_platform_fpe_encryption_get_ffs_def res(%d) name(%s)\n", res, ffs_definition->name);
   //
   //
   // printf("After ubiq_platform_fpe_encryption_get_ffs_def res(%d) name(%s)\n", res, ffs_definition->name);

   if (!res) {
      res  = fpe_decrypt(enc, ffs_name,
//        fpe_key->buf, fpe_key->len, fpe_key->key_number,
        tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen);
      printf("After fpe_encrypt res(%d) ct(%.*s)\n", res, *ptlen, *ptbuf);
      ubiq_platform_fpe_billing(enc, ffs_name, encrypt, 1);
   }

   // fpe_key_destroy(fpe_key);

   return res;
}
