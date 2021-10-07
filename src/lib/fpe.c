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
#include <pthread.h>
#include <unistd.h>

#include "cJSON/cJSON.h"

#define MSG_SIZE 128

// Need to capture value of res, not test value
// since it may be a function and don't want it to get executed
// more than once
#define CAPTURE_ERROR(e,res,msg) ({ \
  int result = res; \
  if (result) { \
    e->error.err_num = result; \
    if (e->error.err_msg) { \
      free (e->error.err_msg); \
    } \
    if (!msg) { \
      e->error.err_msg = malloc(MSG_SIZE); \
      strerror_r(abs(e->error.err_num), e->error.err_msg, MSG_SIZE); \
    } else { \
      e->error.err_msg = strdup(msg); \
    } \
  } \
  result; \
})

static const char * BASE2_CHARSET = "01";
static const int FF1_BASE2_MIN_LENGTH = 20; // NIST requirement ceil(log2(1000000))
static const time_t CACHE_DURATION = 3 * 24 * 60 * 60;
typedef enum {ENCRYPT=0, DECRYPT=1}  action_type ;
static const char * EFPE_TYPE = "EfpeDefinition";
static const char * FPE_TYPE = "FpeDefinition";
typedef enum {PARSE_INPUT_TO_OUTPUT = 0, PARSE_OUTPUT_TO_INPUT = 1} conversion_direction_type;

static
int
ubiq_platform_process_billing(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  cJSON ** json_array);

static
void *
process_billing(void * data);

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

struct ubiq_platform_fpe_enc_dec_obj
{
    /* http[s]://host/api/v0 */
    char * restapi;
    char * encoded_papi;
    char * srsa;
    struct ubiq_platform_rest_handle * rest;

    cJSON * billing_elements;
    pthread_mutex_t billing_lock;
    pthread_t process_billing_thread;
    pthread_cond_t process_billing_cond;

    struct ubiq_platform_cache * ffs_cache; // URL / ubiq_platform_ffs
    struct ubiq_platform_cache * key_cache; // URL / JSON response from server

    struct {
            char * err_msg;
            size_t err_num;
    } error;

};

struct ubiq_platform_fpe_key {
        void * buf;
        size_t len;
        unsigned int key_number;
};

struct fpe_ffs_parsed
{
  char * trimmed_buf;
  char * formatted_dest_buf;
};

static
void
fpe_ffs_parsed_destroy(
  void * parsed
)
{
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

  // Single alloc and just point to locations in the object
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1));
  if (p) {

    p->trimmed_buf = (char *) (p + 1);
    p->formatted_dest_buf = (char *)  p->trimmed_buf + buf_len + 1;

    if (p->trimmed_buf && p->formatted_dest_buf) {
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
  int res = -EINVAL;

  // If *buf is null terminator or if the character cannot be found,
  // it would be an error.
  char * pos = strchr(ffs->output_character_set, (int)*buf);
  if (pos != NULL && *pos != '\0') {
    unsigned int ct_value = pos - ffs->output_character_set;

    ct_value += key_number << ffs->msb_encoding_bits;
    *buf = ffs->output_character_set[ct_value];
    res = 0;
  }
  return res;
}

static int decode_keynum(
  const struct ubiq_platform_ffs * ffs,
  char * const encoded_char,
   unsigned int * const key_number
)
{
  int res = -EINVAL;
  char * pos = strchr(ffs->output_character_set, (int)*encoded_char);
  if (pos != NULL && *pos != '\0') {
    unsigned int encoded_value = pos - ffs->output_character_set;

    unsigned int key_num = encoded_value >> ffs->msb_encoding_bits;

    *encoded_char = ffs->output_character_set[encoded_value - (key_num << ffs->msb_encoding_bits)];
    *key_number = key_num;
    res = 0;
    }
  return res;
}

static int get_json_string(
  cJSON * ffs_data,
  char * field_name,
  char **  destination)
{
  *destination = NULL;
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

static int get_json_int(
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

void
ubiq_platform_fpe_enc_dec_destroy(
    struct ubiq_platform_fpe_enc_dec_obj * const e)
{
  const char * csu = "ubiq_platform_fpe_enc_dec_destroy";

  if (e) {
    pthread_mutex_lock(&e->billing_lock);
    cJSON * json_array = e->billing_elements;
    e->billing_elements = NULL;
    pthread_mutex_unlock(&e->billing_lock);
    pthread_cond_signal(&e->process_billing_cond);
    pthread_join(e->process_billing_thread, NULL);
    ubiq_platform_process_billing(e, &json_array);
    pthread_cond_destroy(&e->process_billing_cond);
    pthread_mutex_destroy(&e->billing_lock);
    cJSON_Delete(json_array);
    ubiq_platform_rest_handle_destroy(e->rest);
    free(e->restapi);
    free(e->encoded_papi);
    free(e->srsa);
    ubiq_platform_cache_destroy(e->ffs_cache);
    ubiq_platform_cache_destroy(e->key_cache);
    free(e->error.err_msg);
  }
  free(e);
}

static
int
ubiq_platform_fpe_encryption_new(
    const char * const host,
    const char * const papi, const char * const sapi,
    const char * const srsa,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc)
{
    static const char * const csu = "ubiq_platform_fpe_encryption_new";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_fpe_enc_dec_obj * e;
    size_t len;
    int res;
    res = -ENOMEM;
    e = calloc(1, sizeof(*e));
    if (e) {
      len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);
      if (((int)len) <= 0) { // error of some sort
        res = len;
      } else {
        len++; // null terminator
        e->restapi = calloc(len, 1);
        ubiq_platform_snprintf_api_url(e->restapi, len, host, api_path);
        res = ubiq_platform_rest_handle_create(papi, sapi, &e->rest);
      }
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
      if (!res) {
        e->billing_elements = cJSON_CreateArray();
      }
      if (!res) {
        if ((res = pthread_mutex_init(&e->billing_lock, NULL)) != 0) {
          res = -errno;
        }
      }
      if (!res) {
        if ((res = pthread_cond_init(&e->process_billing_cond, NULL)) != 0) {
          res = -res;
        }
      }
      if (!res) {
        if ((res = pthread_create(&e->process_billing_thread, NULL, &process_billing, e)) != 0) {
          res = -res;
        }
      }
    }

    if (res) {
      ubiq_platform_fpe_enc_dec_destroy(e);
      e = NULL;
    }

    *enc = e;
    return res;
}


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

  if (!res) {res = get_json_string(ffs_data, "name", &e->name);}
  if (!res) {res = get_json_string(ffs_data, "tweak_source", &e->tweak_source);}
  if (!res) {res = get_json_string(ffs_data, "regex", &e->regex);}
  if (!res) {res = get_json_string(ffs_data, "input_character_set", &e->input_character_set);}
  if (!res) {res = get_json_string(ffs_data, "output_character_set", &e->output_character_set);}
  if (!res) {res = get_json_string(ffs_data, "passthrough", &e->passthrough_character_set);}
  if (!res) {res = get_json_int(ffs_data, "min_input_length", &e->min_input_length);}
  if (!res) {res = get_json_int(ffs_data, "max_input_length", &e->max_input_length);}
  if (!res) {res = get_json_int(ffs_data, "msb_encoding_bits", &e->msb_encoding_bits);}

  if (!res) {res = get_json_int(ffs_data, "tweak_min_len", &e->tweak_min_len);}
  if (!res) {res = get_json_int(ffs_data, "tweak_max_len", &e->tweak_max_len);}

  if (!res && strcmp(e->tweak_source, "constant") == 0) {
    char * s = NULL;
    if ((res = get_json_string(ffs_data, "tweak", &s)) == 0) {
      e->tweak.len = ubiq_support_base64_decode(
          &e->tweak.buf, s, strlen(s));
    }
    free(s);
  }

  if (!res) {
    char * s = NULL;

    if ((res = get_json_string(ffs_data, "fpe_definable_type", &s)) == 0) {
      e->efpe_flag = (strcmp(s, EFPE_TYPE) == 0);
    }
    free(s);
  }
  if (!res) {
    *ffs = e;
  } else {
    ubiq_platform_ffs_destroy(e);
  }

  return res;
}

static
int
save_rest_error(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  struct ubiq_platform_rest_handle * const rest,
  const http_response_code_t rc)
{
  char * msg = NULL;
  size_t len = 0;
  const void * rsp;

  rsp = ubiq_platform_rest_response_content(rest, &len);
  if (rsp != NULL && len > 0) {
    msg = strndup(rsp, len);
    CAPTURE_ERROR(e, -rc, msg);
    free(msg);
  }
  return -rc;
}


static
int
ubiq_platform_fpe_encryption_get_ffs_def(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const char * const ffs_name,
  const struct ubiq_platform_ffs ** ffs_definition)
{
  const char * const csu = "ubiq_platform_fpe_encryption_get_ffs_def";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";

  cJSON * json;
  char * url;
  size_t len;
  int res = 0;
  const void * rsp;
  const struct ubiq_platform_ffs * ffs = NULL;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  free(encoded_name);

  ffs = (const struct ubiq_platform_ffs *)ubiq_platform_cache_find_element(e->ffs_cache, url);
  if (ffs != NULL) {
    *ffs_definition = ffs;
  } else {
    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL, 0);

    if (!CAPTURE_ERROR(e, res, "Unable to process request to get FFS"))
    {
      // Get HTTP response code.  If not OK, return error value
      http_response_code_t rc = ubiq_platform_rest_response_code(e->rest);

      if (rc != HTTP_RC_OK) {
        // Capture Error
        res = save_rest_error(e, e->rest, rc);
      } else {
        // Get the response payload, parse, and continue.
        cJSON * ffs_json;
        rsp = ubiq_platform_rest_response_content(e->rest, &len);
        res = (ffs_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

        if (res == 0 && ffs_json) {
          struct ubiq_platform_ffs * f = NULL;
          res = ubiq_platform_ffs_create(ffs_json,  &f);
          if (!res) {
            ubiq_platform_cache_add_element(e->ffs_cache, url, CACHE_DURATION, f, &ubiq_platform_ffs_destroy);
            *ffs_definition = f;
          }
        }
        cJSON_Delete(ffs_json);
      }
    }
  }
  free(url);
  return res;
}

static
int
ubiq_platform_fpe_encryption_get_key_helper(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const char * const url,
  struct ubiq_platform_fpe_key ** const key)
{
  cJSON * json;
  size_t len;
  int res = 0;
  struct ubiq_platform_fpe_key * k = NULL;
  cJSON * rsp_json = NULL;

  res = fpe_key_create(&k);
  if (!res) {
    const char * content = ubiq_platform_cache_find_element(e->key_cache, url);
    if (content != NULL) {
      len = strlen(content);
      res = (rsp_json = cJSON_ParseWithLength(content, len)) ? 0 : INT_MIN;
    }
    else {
      res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL , 0);

      // If Success, simply proceed
      if (res == 0) {
        const http_response_code_t rc =
            ubiq_platform_rest_response_code(e->rest);

        if (rc != HTTP_RC_OK) {
          res = save_rest_error(e, e->rest, rc);
        } else {
          const void * rsp = ubiq_platform_rest_response_content(e->rest, &len);
          res = (rsp_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;
          if (!res) { res = ubiq_platform_cache_add_element(e->key_cache, url, CACHE_DURATION,strndup(rsp, len), &free);}
        }
      }
    }

    if (!res && rsp_json != NULL) {

      res = ubiq_platform_common_fpe_parse_new_key(
          rsp_json, e->srsa,
          &k->buf, &k->len);

      if (!CAPTURE_ERROR(e, res, "Unable to parse key from server")) {
        const cJSON * kn = cJSON_GetObjectItemCaseSensitive(
                          rsp_json, "key_number");
        if (cJSON_IsString(kn) && kn->valuestring != NULL) {
          const char * errstr = NULL;
          uintmax_t n = strtoumax(kn->valuestring, NULL, 10);
          if (n == UINTMAX_MAX && errno == ERANGE) {
            res = CAPTURE_ERROR(e, -ERANGE, "Invalid key range");
          } else {
            k->key_number = (unsigned int)n;
          }
        } else {
          res = CAPTURE_ERROR(e, -EBADMSG, "Invalid server response");
        }
      }
    }
    cJSON_Delete(rsp_json);
    if (!res) {
      *key = k;
    } else {
      fpe_key_destroy(k);
    }
  }
  return res;
}

static
int
ubiq_platform_fpe_encryption_get_key(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
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
  struct ubiq_platform_fpe_enc_dec_obj * const e,
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


int ubiq_platform_fpe_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
//    const char * const ffs_name,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc)
{
    struct ubiq_platform_fpe_enc_dec_obj * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    res = ubiq_platform_fpe_encryption_new(host, papi, sapi, srsa, &e);

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_fpe_enc_dec_destroy(e);
    }

    return res;
}

static
int ubiq_platform_fpe_string_parse(
  const struct ubiq_platform_ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const void * const source_string,
  const size_t source_len,
  struct fpe_ffs_parsed * const parsed
)
{
  int res = 0;
  const char * src_char_set = NULL;
  char dest_zeroth_char = '\0';
  // struct fpe_ffs_parsed * p;

  if (conversion_direction == PARSE_INPUT_TO_OUTPUT) {// input to output
    src_char_set = ffs->input_character_set;
    dest_zeroth_char = ffs->output_character_set[0];
  } else if (conversion_direction == PARSE_OUTPUT_TO_INPUT) {
    dest_zeroth_char = ffs->input_character_set[0];
    src_char_set = ffs->output_character_set;
  } else {
    res = -EINVAL;
  }

  if (!res) {
    memset(parsed->trimmed_buf, src_char_set[0], source_len);
    memset(parsed->formatted_dest_buf, dest_zeroth_char, source_len);

    res = ubiq_platform_efpe_parsing_parse_input(
      source_string, src_char_set, ffs->passthrough_character_set,
      parsed->trimmed_buf, parsed->formatted_dest_buf);

  }

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
    if ((p = realloc(*str, minlen + 1)) == NULL) {
      res = -ENOMEM;
    } else {
      // Moving memory to end first before setting new locations
      memmove(p + (minlen - len), p, len + 1); // Include null terminator
      memset(p, c, (minlen-len));
      *str = p;
    }
  }
  return res;
}

static
int
fpe_decrypt(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
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
  struct ubiq_platform_fpe_key * key = NULL;

  /*
  * Need to parse the CT to get the encryption algorithm and key number
  */

  res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);

  if (!res) {res = CAPTURE_ERROR(enc, fpe_ffs_parsed_create(&parsed, ctlen), NULL);}
  if (!res) {res = CAPTURE_ERROR(enc, ubiq_platform_fpe_string_parse(ffs_definition, PARSE_OUTPUT_TO_INPUT, ctbuf, ctlen, parsed),"Invalid input string");}

  if (!res) {
    size_t len = strlen(parsed->trimmed_buf);
     if (len <ffs_definition->min_input_length || len > ffs_definition->max_input_length) {
       res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
     }
   }

  if (!res) {
    unsigned int keynum = 0;
    res = CAPTURE_ERROR(enc, decode_keynum(ffs_definition, &parsed->trimmed_buf[0], &keynum), "Unable to find key number in cipher text");
    if (!res) {res = ubiq_platform_fpe_decryption_get_key(enc, ffs_name, keynum, &key);}
  }

  // Convert trimmed into base 10 to prepare for decrypt
  if (!res) {
    res = str_convert_radix(
      parsed->trimmed_buf,
      ffs_definition->output_character_set,
      BASE2_CHARSET,
      &ct_base2);

      // Length of the string based on algorithm and actual number of characters need to represent
      // largest value when converted to binary string
      int padded_string_length = ceil(fmax(FF1_BASE2_MIN_LENGTH,log2(strlen(ffs_definition->input_character_set)) * strlen(parsed->trimmed_buf)));

      res = CAPTURE_ERROR(enc, pad_text(&ct_base2,padded_string_length, BASE2_CHARSET[0]), NULL);

    if (!res) {pt_base2 = calloc(strlen(ct_base2) + 1, 1);}
    if (pt_base2 == NULL) {
      res = CAPTURE_ERROR(enc, -ENOMEM, NULL);
    }
  }

  // TODO - Need logic to check tweak source and error out depending on supplied tweak
  if (!res) {
    struct ff1_ctx * ctx;
    res = ff1_ctx_create(&ctx, key->buf, key->len, ffs_definition->tweak.buf, ffs_definition->tweak.len, ffs_definition->tweak_min_len, ffs_definition->tweak_max_len, strlen(BASE2_CHARSET));

    if (!CAPTURE_ERROR(enc, res, "Failure with ff1_ctx_create")) {
      res = CAPTURE_ERROR(enc, ff1_decrypt(ctx, pt_base2, ct_base2, NULL, 0), "Failure with ff1_decrypt");
    }
    ff1_ctx_destroy(ctx);

  }

  // Convert PT to output radix
  if (!res) {
    res = str_convert_radix(
      pt_base2,
      BASE2_CHARSET,
      ffs_definition->input_character_set,
      &pt_trimmed);

    CAPTURE_ERROR(enc, res, "Unable to format results into input character set");

    if (pt_trimmed == NULL) {
      res = CAPTURE_ERROR(enc, -ENOMEM, NULL);
    }
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
  }

  if (!res) {
    *ptbuf = strdup(parsed->formatted_dest_buf);
    if (*ptbuf != NULL) {
      *ptlen = strlen(*ptbuf);
    } else {
      res = CAPTURE_ERROR(enc, -ENOMEM, NULL);
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
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
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
  struct ubiq_platform_fpe_key * key = NULL;

  // ffs_definition is cached so do not delete
  res = ubiq_platform_fpe_encryption_get_ffs_def(enc, ffs_name, &ffs_definition);

  // Trim pt
  if (!res) {res = CAPTURE_ERROR(enc, fpe_ffs_parsed_create(&parsed, ptlen), NULL); }
  if (!res) {res = CAPTURE_ERROR(enc, ubiq_platform_fpe_string_parse(ffs_definition, PARSE_INPUT_TO_OUTPUT, ptbuf, ptlen, parsed), "Invalid input string");}

  if (!res) {
    size_t len = strlen(parsed->trimmed_buf);
     if (len <ffs_definition->min_input_length || len > ffs_definition->max_input_length) {
       res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
     }
   }

  if (!res) {
    res = ubiq_platform_fpe_encryption_get_key(enc, ffs_name, &key);
  }

  // Convert trimmed into base 10 to prepare for decrypt
  if (!res) {
    res = str_convert_radix(
      parsed->trimmed_buf,
      ffs_definition->input_character_set,
      BASE2_CHARSET,
      &pt_base2);

    if (!res) {
      // Figure out how long to pad the binary string.  Formula is input_radix^len = 2^Y which is log2(input_radix) * len
      // Due to FF1 constraints, the there is a minimum length for a base2 string, so make sure to be at least that long too
      // or fpe will fail
      int padded_string_length = ceil(fmax(FF1_BASE2_MIN_LENGTH,log2(strlen(ffs_definition->input_character_set)) * strlen(parsed->trimmed_buf)));

      // The padding may re-allocate so make sure to allow for pt_base2 to change pointer
      res = CAPTURE_ERROR(enc, pad_text(&pt_base2, padded_string_length, BASE2_CHARSET[0]), NULL);
    }
    // Allocate buffer of same size for ct_base2
    if (!res) {
      if ((ct_base2 = calloc(strlen(pt_base2) + 1, 1)) == NULL) {
        res = CAPTURE_ERROR(enc, -ENOMEM, NULL);
      }
    }
  }

  // TODO - Need logic to check tweak source and error out depending on supplied tweak

  // Encrypt
  if (!res) {
    struct ff1_ctx * ctx;

    res = ff1_ctx_create(&ctx, key->buf, key->len, ffs_definition->tweak.buf, ffs_definition->tweak.len, ffs_definition->tweak_min_len, ffs_definition->tweak_max_len, strlen(BASE2_CHARSET));
    if (!CAPTURE_ERROR(enc, res, "Failure with ff1_ctx_create")) {
      res = CAPTURE_ERROR(enc, ff1_encrypt(ctx, ct_base2, pt_base2, NULL, 0), "Failure with ff1_encrypt");
    }
    ff1_ctx_destroy(ctx);
  }

  // Convert PT to output radix
  if (!res) {
    res = str_convert_radix(
      ct_base2,
      BASE2_CHARSET,
      ffs_definition->output_character_set,
      &ct_trimmed);

    CAPTURE_ERROR(enc, res, "Unable to format results in output character set");

    if (ct_trimmed == NULL) {
      res = CAPTURE_ERROR(enc, -ENOMEM, NULL);
    }
  }

  // Merge PT to formatted output
  if (!res) {
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
    while (ffs_definition->passthrough_character_set != NULL && (*pos != '\0') && (NULL != strchr(ffs_definition->passthrough_character_set, *pos))) {pos++;};
    res = encode_keynum(ffs_definition, key->key_number, pos);
    CAPTURE_ERROR(enc, res, "Unable to encode key material into results");
  }

  if (!res) {
    *ctbuf = strdup(parsed->formatted_dest_buf);

    if (*ctbuf != NULL) {
      *ctlen = strlen(*ctbuf);
    } else {
      res = CAPTURE_ERROR(enc, -ENOMEM, NULL);
    }

  }
  fpe_key_destroy(key);
  fpe_ffs_parsed_destroy(parsed);
  free(ct_base2);
  free(pt_base2);
  free(ct_trimmed);
  return res;
}

static
int
ubiq_platform_add_billing(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const char * ffs_name,
  const action_type action,
  unsigned int count)
{
  const char * csu = "ubiq_platform_add_billing";
  static const int MAX_BILLING_ARRAY_SIZE = 50;
  int res = 0;
  cJSON * json;
  time_t now;
  char guid_hex[37]; // 8 - 4 - 4 - 4 - 12
  uint16_t guid[8];

  ubiq_support_getrandom(&guid, sizeof(guid));
  snprintf(guid_hex, sizeof(guid_hex), "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
    guid[0], guid[1], guid[2], guid[3],
    guid[4], guid[5], guid[6], guid[7]);

  json = cJSON_CreateObject();
  cJSON_AddItemToObject(json, "count", cJSON_CreateNumber(count));

  time(&now);
  char buf[sizeof("2011-10-08T07:07:09Z   ")];
  strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&now));

  cJSON_AddItemToObject(json, "id", cJSON_CreateString(guid_hex));
  cJSON_AddItemToObject(json, "timestamp", cJSON_CreateString(buf));
  cJSON_AddItemToObject(json, "ffs_name", cJSON_CreateString(ffs_name));
  if (action == ENCRYPT) {
    cJSON_AddItemToObject(json, "action", cJSON_CreateString("encrypt"));
  } else {
    cJSON_AddItemToObject(json, "action", cJSON_CreateString("decrypt"));
  }

  pthread_mutex_lock(&e->billing_lock);
  cJSON_AddItemToArray(e->billing_elements, json);
  unsigned int array_size = cJSON_GetArraySize(e->billing_elements);
  pthread_mutex_unlock(&e->billing_lock); // Make sure locked before trying to unlock

  if (array_size > MAX_BILLING_ARRAY_SIZE) {
    pthread_cond_signal(&e->process_billing_cond);
  }

  return res;
}

static
int
ubiq_platform_process_billing(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  cJSON ** json_array)
{
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

  char * str = cJSON_Print(*json_array);


  unsigned int array_size = cJSON_GetArraySize(*json_array);

  if (array_size > 0) {

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
            cJSON * last_valid = cJSON_GetObjectItemCaseSensitive(json, "last_valid");
            if (cJSON_IsObject(last_valid)) {
              cJSON * id = cJSON_GetObjectItemCaseSensitive(last_valid, "id");
              if (cJSON_IsString(id) && id->valuestring != NULL) {

                int match = 0;
                while (array_size > 0 && !match){
                  cJSON * item = cJSON_DetachItemFromArray(*json_array, 0);
                  if (cJSON_IsObject(item)) {
                    cJSON * element_id = cJSON_GetObjectItemCaseSensitive(item, "id");
                    if (cJSON_IsString(element_id) && element_id->valuestring != NULL) {
                      match = (strcmp(id->valuestring, element_id->valuestring) == 0);
                    }
                  }
                  cJSON_Delete(item);
                  array_size--;
                }
              }
            }
          }
          cJSON_Delete(json);
      } else if (rc == HTTP_RC_CREATED) {
          cJSON_Delete(*json_array);
          *json_array = cJSON_CreateArray();
          res = 0;
      } else {
        res = ubiq_platform_http_error(rc);
      }
    }

//    const char * content = ubiq_platform_rest_response_content(e->rest, &len);
  }
  free(str);
  free(url);
  return res;

}


static
void *
process_billing(void * data) {
  const char * csu = "process_billing";
  struct ubiq_platform_fpe_enc_dec_obj * e = (struct ubiq_platform_fpe_enc_dec_obj *)data;

  while (1) {
    // Test to see if done using simple mutex rather than the conditional
    pthread_mutex_lock(&e->billing_lock);

    // Should we exit?
    if (e->billing_elements == NULL || cJSON_IsNull(e->billing_elements) || !cJSON_IsArray(e->billing_elements)) {
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    // Locked above.
    pthread_cond_wait(&e->process_billing_cond, &e->billing_lock);

    // Should we exit?  Need here to since was getting deadlock for simple create and destroy object
    if (e->billing_elements == NULL || cJSON_IsNull(e->billing_elements) || !cJSON_IsArray(e->billing_elements)) {
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    unsigned int array_size = cJSON_GetArraySize(e->billing_elements);

    cJSON * json_array = NULL;

    // If there are any elements.  Will only be woken when time to process
    if (array_size > 0) {
      json_array = e->billing_elements;
      e->billing_elements = cJSON_CreateArray();
    }

    pthread_mutex_unlock(&e->billing_lock);
    if (json_array != NULL) {
      ubiq_platform_process_billing(e, &json_array);

      // For anything not processed, add to the end of the billing elements.
      array_size = cJSON_GetArraySize(json_array);
      if (array_size > 0) {
        pthread_mutex_lock(&e->billing_lock);
        do {
          cJSON * element = cJSON_DetachItemFromArray(json_array, 0);
          cJSON_AddItemToArray(e->billing_elements, element);
        } while (cJSON_GetArraySize(json_array) > 0);
        pthread_mutex_unlock(&e->billing_lock);
      }

      cJSON_Delete(json_array);
    }
  }
}


int
ubiq_platform_fpe_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char ** const ctbuf, size_t * const ctlen)
{

  struct ubiq_platform_fpe_enc_dec_obj * enc;
  int res = 0;

  // Create Structure that will handle REST calls.
  // Std voltron gets additional information, this will
  // simply allocate structure.  Mapping creds to individual strings
  enc = NULL;
  res = ubiq_platform_fpe_enc_dec_create(creds,  &enc);

  if (!res) {
     res = fpe_encrypt(enc, ffs_name,
       tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
     if (!res) {res = ubiq_platform_add_billing(enc, ffs_name, ENCRYPT, 1);}
  }
  ubiq_platform_fpe_enc_dec_destroy(enc);

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
  struct ubiq_platform_fpe_enc_dec_obj * enc;
  int res = 0;

  enc = NULL;
  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);

  if (!res) {
    res  = fpe_decrypt(enc, ffs_name, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen);
    res = ubiq_platform_add_billing(enc, ffs_name, DECRYPT, 1);
  }
    ubiq_platform_fpe_enc_dec_destroy(enc);
  return res;
}

int
ubiq_platform_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen
)
{
  int res = 0;

  res = fpe_encrypt(enc, ffs_name,
    tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
  if (!res) {res = ubiq_platform_add_billing(enc, ffs_name, ENCRYPT, 1);}

  return res;
}

int
ubiq_platform_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen
)
{
  int res = 0;

  res  = fpe_decrypt(enc, ffs_name,
    tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen);
  if (!res) {res = ubiq_platform_add_billing(enc, ffs_name, DECRYPT, 1);}

  return res;
}

int
ubiq_platform_fpe_get_last_error(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  int * const err_num,
  char ** const err_msg
)
{
  int res = -EINVAL;

  if (enc != NULL) {
    res = 0;
    *err_num = enc->error.err_num;
    if (enc->error.err_msg != NULL) {
      *err_msg = strdup(enc->error.err_msg);
      if (*err_msg == NULL) {
        res = -errno;
      }
    }
  }

  return res;
}
