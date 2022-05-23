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
#include <stdio.h>
#include <unistr.h>
#include <string.h>
#include <stdlib.h>
#include <uniwidth.h>

#include "cJSON/cJSON.h"

/**************************************************************************************
 *
 * Defines
 *
**************************************************************************************/

// Need to capture value of res, not test value
// since it may be a function and don't want it to get executed
// more than once
#define MSG_SIZE 128
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

/**************************************************************************************
 *
 * Constants
 *
**************************************************************************************/

static const time_t CACHE_DURATION = 3 * 24 * 60 * 60;

typedef enum {MULTIBYTE=0, SIMPLE_CHAR=1}  ffs_character_types ;
typedef enum {PARSE_INPUT_TO_OUTPUT = 0, PARSE_OUTPUT_TO_INPUT = 1} conversion_direction_type;

/**************************************************************************************
 *
 * Structures
 *
**************************************************************************************/

struct fpe_key {
        void * buf;
        size_t len;
        unsigned int key_number;
};


/* Used if the FFS supports UTF8 characters */
struct u32_fpe_ffs_parsed
{
  uint32_t * u32_trimmed_buf;
  uint32_t * u32_formatted_dest_buf;
};

struct fpe_ffs_parsed
{
  char * trimmed_buf;
  char * formatted_dest_buf;
};

struct parsed_data
{
  void * trimmed_buf;
  void * formatted_dest_buf;
  int element_size;
  ffs_character_types char_types;
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

    struct ubiq_platform_cache * ffs_cache; // URL / ffs
    struct ubiq_platform_cache * key_cache; // ffs_name:key_number => void * (either ff1_ctx or ff3_ctx)

    struct {
            char * err_msg;
            size_t err_num;
    } error;

};

struct ffs {
  char * name;
  int min_input_length;
  int max_input_length;
  char * tweak_source;
  char * regex;
  char * input_character_set;
  char * output_character_set;
  char * passthrough_character_set;
  uint32_t * u32_input_character_set;
  uint32_t * u32_output_character_set;
  uint32_t * u32_passthrough_character_set;
  int msb_encoding_bits;
//   int efpe_flag;
  struct {
          void * buf;
          size_t len;
  } tweak;
  int tweak_min_len;
  int tweak_max_len;
  ffs_character_types character_types;
};

// struct u32_ffs {
//   char * name;
//   int min_input_length;
//   int max_input_length;
//   char * tweak_source;
//   char * regex;
//   uint32_t * input_character_set;
//   uint32_t * output_character_set;
//   uint32_t * passthrough_character_set;
//   int msb_encoding_bits;
//   int efpe_flag;
//   struct {
//           void * buf;
//           size_t len;
//   } tweak;
//   int tweak_min_len;
//   int tweak_max_len;
// };


struct ctx_cache_element {
  void * fpe_ctx;
  unsigned int key_number;
};

/*
*
*
*/ 


/**************************************************************************************
 *
 * Static functions
 *
**************************************************************************************/

static void debug(const char * const csu, const char * const msg) {
  return; //printf("DEBUG %s: %s\n", csu, msg);
}

static int encode_keynum(
  const struct ffs * ffs,
  const unsigned int key_number,
  char * const buf
)
{
  int res = -EINVAL;

  char * pos = strchr(ffs->output_character_set, (int)*buf);

  // If *buf is null terminator or if the character cannot be found,
  // it would be an error.
  if (pos != NULL && *pos != 0){
    size_t ct_value = pos - ffs->output_character_set;
    ct_value += (key_number << ffs->msb_encoding_bits);
    *buf = ffs->output_character_set[ct_value];
    res = 0;
  }
  return res;
}

static int decode_keynum(
  const struct ffs * ffs,
  char * const encoded_char,
  unsigned int * const key_number
)
{
  int res = -EINVAL;
  char * pos = strchr(ffs->output_character_set, *encoded_char);
  if (pos != NULL && *pos != 0) {
    unsigned int encoded_value = pos - ffs->output_character_set;

    unsigned int key_num = encoded_value >> ffs->msb_encoding_bits;

    *encoded_char = ffs->output_character_set[encoded_value - (key_num << ffs->msb_encoding_bits)];
    *key_number = key_num;
    res = 0;
    }
  return res;
}

static
int
str_convert_radix(
  const char * const src_str,
  const char * const input_radix,
  const char * const output_radix,
  char * out_str
)
{
  int debug = 0;
  static const char * csu = "str_convert_radix";
  int res = 0;
  bigint_t n;
  size_t len = strlen(src_str);
  // Malloc causes valgrind to consider out uninitialized and spits out warnings
  char * out = calloc(len + 50,sizeof(char));
  // char * out = malloc(len + 1);
  // memset(out,0,len + 1);

  bigint_init(&n);

  if (out == NULL) {
    res = -ENOMEM;
  }

  (debug) && printf("src_str %s\n", src_str);
  if (!res) {res = __bigint_set_str(&n, src_str, input_radix);}

  (debug) && gmp_printf("INPUT num = %Zd\n", n);

  (debug) && printf("input ----%s----\n", input_radix);
  (debug) && printf("output_radix ----%s----\n", output_radix);

  if (!res) {
    res = __bigint_get_str(out, len+50, output_radix, &n);
    (debug) && printf("__bigint_get_str res (%d), out %s\n", res, out);

    size_t out_len = strlen(out);

    // // pad the leading characters of the output radix with zeroth character
    char * c = out_str;
    for (int i = 0; i < len - out_len; i++) {
      *c = output_radix[0];
      c++;
    }
    strcpy(c, out);
  }
  bigint_deinit(&n);
  free(out);
  return res;
}

static
int
fpe_key_create(struct fpe_key ** key){
  struct fpe_key * k;

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
fpe_key_destroy(struct fpe_key * const key){
  if (key && key->buf) {
    if (key->len > 0) {
      memset(key->buf, 0, key->len);
    }
    free(key->buf);
  }
  free(key);
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

static void
ctx_cache_element_destroy(void * const e) {
  struct ctx_cache_element * ctx = (struct ctx_cache_element *) e;
   ff1_ctx_destroy((struct ff1_ctx *const)ctx->fpe_ctx);
   free(e);
}

static int
ctx_cache_element_create(struct ctx_cache_element ** e,
  struct ff1_ctx *const ff1_ctx,
  unsigned int key_number
) {
  int res = -ENOMEM;
  struct ctx_cache_element * ctx = NULL;
  ctx = calloc(1, sizeof(*ctx));
  if (ctx != NULL) {
    ctx->fpe_ctx = ff1_ctx;
    ctx->key_number = key_number;
    *e = ctx;
    res = 0;
  }
  return res;
}

static
void
ffs_destroy(
    void * const f)
{
  struct ffs * const ffs = (struct ffs * const) f;
  if (ffs) {
    free (ffs->name);
    free (ffs->tweak_source);
    free (ffs->regex);
    free (ffs->input_character_set);
    free (ffs->output_character_set);
    free (ffs->passthrough_character_set);
    free (ffs->u32_input_character_set);
    free (ffs->u32_output_character_set);
    free (ffs->u32_passthrough_character_set);
    free (ffs->tweak.buf);
  }
  free(ffs);
}

static
int
ffs_create(
    cJSON * ffs_data,
    struct ffs ** const ffs)
{
  static const char * const csu = "ffs_create";
  int res = 0;

  // Going to allocate memory as a single block
  // First with the structure.  Then with the
  // length of strings.  This will allow simple copy and
  // avoid fragmented memory

  struct ffs * e = NULL;
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

  // Test the input_character_set, output_character_set, passthrough characterset
  // to see if they are UTF8 multibyte strings or simply contain single byte characters.
  // if at least one is multibyte, move the strings to the u32 version for the associated elements

  if (!res && ((strlen(e->input_character_set) != u8_mbsnlen(e->input_character_set, strlen(e->input_character_set))) ||
      (strlen(e->output_character_set) != u8_mbsnlen(e->output_character_set, strlen(e->output_character_set))) ||
      (strlen(e->passthrough_character_set) != u8_mbsnlen(e->passthrough_character_set, strlen(e->passthrough_character_set))))) {
      debug(csu, "Multibyte UTF8 found");
        res = convert_utf8_to_utf32(e->input_character_set, &e->u32_input_character_set);
        if (!res) {res = convert_utf8_to_utf32(e->output_character_set, &e->u32_output_character_set);}
        if (!res) {res = convert_utf8_to_utf32(e->passthrough_character_set, &e->u32_passthrough_character_set);}

        free(e->input_character_set);
        free(e->output_character_set);
        free(e->passthrough_character_set);
        e->input_character_set = NULL;
        e->output_character_set = NULL;
        e->passthrough_character_set = NULL;
        e->character_types = MULTIBYTE;
  } else {
          debug(csu, "No Multibyte UTF8 found");
        e->character_types = SIMPLE_CHAR;
  }


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
    *ffs = e;
  } else {
    ffs_destroy(e);
  }

  return res;
}


static
void
parsed_destroy(
  void * const parsed
)
{
  free((void *)parsed);
}

static
int parse_data(
  const struct ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const char * const source_string,
  const size_t source_len,
  struct parsed_data * const parsed
)
{
  static const char * csu = "parse_data";
  int res = 0;
  const void * src_char_set = NULL;
  uint32_t dest_zeroth_char = 0;
  // struct fpe_ffs_parsed * p;

  if (ffs->character_types == MULTIBYTE) {
    debug(csu, "(uint32_t *)parsed->trimmed_buf");

  } else {
    char dest_zeroth_char;
    char * src_char_set = NULL;
    if (conversion_direction == PARSE_INPUT_TO_OUTPUT) {// input to output
      src_char_set = ffs->input_character_set;
      dest_zeroth_char = ffs->output_character_set[0];
    } else if (conversion_direction == PARSE_OUTPUT_TO_INPUT) {
      src_char_set = ffs->output_character_set;
      dest_zeroth_char = ffs->input_character_set[0];
    } else {
      res = -EINVAL;
    }

    if (!res) {
      res = parsing_decompose_string(
        source_string, src_char_set, ffs->passthrough_character_set,
        dest_zeroth_char,
        parsed->trimmed_buf, parsed->formatted_dest_buf);
    }
    debug(csu, (char *)parsed->trimmed_buf);
    debug(csu, (char *)parsed->formatted_dest_buf);
    // Standard acsii
  }

  return res;
} // parse_data

#ifdef NODEF
static
int fpe_u32_ffs_parsed_create(
  struct u32_fpe_ffs_parsed ** parsed,
  const size_t buf_len
)
{
  struct u32_fpe_ffs_parsed *p;

  int res = -ENOMEM;

  // Single alloc and just point to locations in the object
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1) * sizeof(uint32_t));
  if (p) {

    p->u32_trimmed_buf = (uint32_t *) (p + 1);
    p->u32_formatted_dest_buf = (uint32_t *)  p->u32_trimmed_buf + buf_len + 1;

    if (p->u32_trimmed_buf && p->u32_formatted_dest_buf) {
      res = 0;
    } else {
      fpe_ffs_parsed_destroy(p);
      p = NULL;
    }
  }
  *parsed = p;
  return res;
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
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1) * sizeof(char));
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
#endif

static
int parsed_create(
  struct parsed_data ** const parsed,
  const ffs_character_types char_types,
  const size_t buf_len
)
{
  struct parsed_data *p;

  int res = -ENOMEM;
  size_t element_size = sizeof(char);

  if (char_types == MULTIBYTE) {
    element_size = sizeof(uint32_t);
  }

  // Single alloc and just point to locations in the object.  The element size will
  // automatically help align to right boundaries
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1) * element_size);
  if (p) {

    p->trimmed_buf = (p + 1);
    p->formatted_dest_buf = p->trimmed_buf + (buf_len + 1) * element_size;
    p->element_size = element_size;
    p->char_types = char_types;
    if (p->trimmed_buf && p->formatted_dest_buf) {
      res = 0;
    } else {
      parsed_destroy(p);
      p = NULL;
    }
  }
  *parsed = p;
  return res;
}


static
void *
process_billing(void * data) {
    // TODO
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
int
ubiq_platform_fpe_encryption(
    const char * const host,
    const char * const papi, const char * const sapi,
    const char * const srsa,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc)
{
    static const char * const csu = "ubiq_platform_fpe_encryption";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_fpe_enc_dec_obj * e;
    size_t len;
    int res;
    res = -ENOMEM;
    e = calloc(1, sizeof(*e));
    if (e) {
      // Just a way to determine if it has been created correctly later
      e->process_billing_thread = pthread_self();

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

// static
// void free_ff1_ctx(void * ctx) {
//   ff1_ctx_destroy((struct ff1_ctx *const)ctx);
// }

static
int
get_ctx(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const struct ffs * const ffs,
  int * key_number,
  struct ff1_ctx ** ff1_ctx 
) 
{
  const char * const csu = "get_ctx";
  // static const char radix36[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  // static const char radix62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  int res = 0;
  struct ctx_cache_element * ctx_element = NULL;
  // struct ff1_ctx * ctx = NULL;
  int key_len = strlen(ffs->name) + 25; // magic number to accomodate a max int plus null terminator and colon
  char * key_str = calloc(1, key_len);

  snprintf(key_str, key_len, "%s:%d", ffs->name, *key_number);
  
  ctx_element = (struct ctx_cache_element *)ubiq_platform_cache_find_element(e->key_cache, key_str);
 
  if (ctx_element != NULL) {
    debug(csu, "key found in Cache");
  } else {
    if (!res) {
        debug(csu, "key NOT found in Cache");
        debug(csu, key_str);
        static const char * const fmt_encrypt_key = "%s/fpe/key?ffs_name=%s&papi=%s";
        static const char * const fmt_decrypt_key = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";

        cJSON * rsp_json = NULL;
        char * url = NULL;
        size_t len;

        char * encoded_name = NULL;
        res = ubiq_platform_rest_uri_escape(e->rest, ffs->name, &encoded_name);

        if (!res) {
          if (*key_number >= 0) {
            len = snprintf(NULL, 0, fmt_decrypt_key, e->restapi, encoded_name, e->encoded_papi, *key_number);
          } else {
            len = snprintf(NULL, 0, fmt_encrypt_key, e->restapi, encoded_name, e->encoded_papi);
          }
          if ((url = malloc(len + 1)) == NULL) {
            res = -ENOMEM;
          } else {
            if (*key_number >= 0) {
              snprintf(url, len + 1, fmt_decrypt_key, e->restapi, encoded_name, e->encoded_papi, *key_number);
            } else {
              snprintf(url, len + 1, fmt_encrypt_key, e->restapi, encoded_name, e->encoded_papi);
            }
          }
        }
        free(encoded_name);

        if (!res) {
          debug ("url", url);
          res = ubiq_platform_rest_request(
            e->rest,
            HTTP_RM_GET, url, "application/json", NULL , 0);
        }
        free(url);
        // If Success, simply proceed
        if (!res) {
          const http_response_code_t rc =
              ubiq_platform_rest_response_code(e->rest);

          if (rc != HTTP_RC_OK) {
            res = save_rest_error(e, e->rest, rc);
          } else {
            const void * rsp = ubiq_platform_rest_response_content(e->rest, &len);
            res = (rsp_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

          }
        }

      struct fpe_key * k = NULL;
      if (!res && rsp_json != NULL) {

        res = fpe_key_create(&k);

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
        size_t radix_len;
        struct ff1_ctx * ctx = NULL;
        if (ffs->character_types == MULTIBYTE) {
          radix_len = u32_strlen(ffs->u32_input_character_set);
          res = ff1_ctx_create(&ctx, k->buf, k->len, ffs->tweak.buf, ffs->tweak.len, ffs->tweak_min_len, ffs->tweak_max_len, radix_len);
        } else {
          res = ff1_ctx_create_custom_radix(&ctx, k->buf, k->len, ffs->tweak.buf, ffs->tweak.len, ffs->tweak_min_len, ffs->tweak_max_len, ffs->input_character_set);
        }
        if (!res) { res = ctx_cache_element_create(&ctx_element, ctx, k->key_number);}
        if (!res) {res = ubiq_platform_cache_add_element(e->key_cache, key_str, CACHE_DURATION, ctx_element, &ctx_cache_element_destroy);}
        // printf("DEBUG - after create cache element %d  %p\n", res, ctx_element->fpe_ctx);
      }
      fpe_key_destroy(k);
    }
  }

  if (!res) {
      *ff1_ctx = ctx_element->fpe_ctx;
      *key_number = ctx_element->key_number;

  }

  free(key_str);

  return res;
}

static
int
ffs_get_def(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const char * const ffs_name,
  const struct ffs ** ffs_definition)
{
  const char * const csu = "ffs_get_def";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";

  cJSON * json;
  char * url;
  size_t len;
  int res = 0;
  const void * rsp;
  const struct ffs * ffs = NULL;

  // The ubiq_platform_fpe_enc_dec_obj was created using specific credentials,
  // so can simply use the ffs_name to look for a key, not the full URL.  This will save
  // having to encode the URL each time

  ffs = (const struct ffs *)ubiq_platform_cache_find_element(e->ffs_cache, ffs_name);
  if (ffs != NULL) {
    debug(csu, "Found in Cache");
    *ffs_definition = ffs;
  } else {
    debug(csu, "Fetching from server");
    char * encoded_name = NULL;
    res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

    len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
    url = malloc(len + 1);
    snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

    free(encoded_name);

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
          struct ffs * f = NULL;
          res = ffs_create(ffs_json,  &f);
          if (!res) {
            ubiq_platform_cache_add_element(e->ffs_cache, ffs_name, CACHE_DURATION, f, &ffs_destroy);
            *ffs_definition = f;
          }
        }
        cJSON_Delete(ffs_json);
      }
    }
    free(url);
  }

  return res;
} // ffs_get_def


/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/

int
ubiq_platform_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen)
{
  static const char * csu = "ubiq_platform_fpe_encrypt_data";
  int res = 0;
  const struct ffs * ffs_definition = NULL;
  struct parsed_data * parsed = NULL;
  struct ff1_ctx * ctx = NULL;
  char * ct = NULL;
  int key_number = -1;
  // Get FFS (cache or otherwise)
  res = ffs_get_def(enc, ffs_name, &ffs_definition);

  // Create an object to hold the parsed data, 
  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, ffs_definition->character_types, ptlen),  NULL); }

  if (!res) { res = CAPTURE_ERROR(enc, parse_data(ffs_definition, PARSE_INPUT_TO_OUTPUT, ptbuf, ptlen, parsed ), "Invalid input string characters");}
    // Get Encryption object (cache or otherwise - returns ff1_ctx object (ffs_name and current key_number)

  // Passing ffs_definition since it includes algorithm
  if (!res) {res = get_ctx(enc, ffs_definition, &key_number , &ctx);}
    // For encrypt - get FFS and get encryption object could be same call
    // For decrypt - need to get FFS first so know how to decode key num
    //               Then get Decryption Object (ff1_ctx) (ffs_name and key number)

    // ff1_encrypt
    if (!res ) {
      debug(csu, "before ct = malloc");
      // TODO Need check for input character set in ascii8
      ct = malloc(ptlen + 1);
      debug(csu, "before ff1_encrypt");
      res = ff1_encrypt(ctx, ct, parsed->trimmed_buf, tweak, tweaklen);
      debug(csu, "after ff1_encrypt");
      debug(csu, ct);
    }
    // change radix
      debug(csu, "before radix");
    if (!res) { res = str_convert_radix(ct, ffs_definition->input_character_set, ffs_definition->output_character_set, ct);}

    debug(csu, "after radix");
    debug(csu, ct);

    // Encode ct
    if (!res) {
      res = encode_keynum(ffs_definition, key_number, ct);
    }

    if (!res) {
    // Merge encoded key with cipher text
      char * tmp = strdup(parsed->formatted_dest_buf);
      if (tmp == NULL) {
        res = -ENOMEM;
      }

      if (!res) {
        size_t src_idx=0;
        for (size_t i = 0; i < ptlen; i++) {
          // Anything that isn't a zeroth character is a passthrough and can be skipped
          if (tmp[i] == ffs_definition->output_character_set[0]) {
            tmp[i] = ct[src_idx++];
          } 
        }
      }
    // if (!res) {
    //     *ffs = ffs_definition;
    //     *parsed_data = parsed;
    // }

      if (!res) {
        *ctbuf = tmp;      
        *ctlen = ptlen;
      }
    }

    parsed_destroy(parsed);
    free(ct);


    return res;
}

int
ubiq_platform_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen)
{
  static const char * csu = "ubiq_platform_fpe_decrypt_data";
  int res = 0;
  const struct ffs * ffs_definition = NULL;
  struct parsed_data * parsed = NULL;
  struct ff1_ctx * ctx = NULL;
  char * pt = NULL;
  unsigned int key_number = 0;

  // Get FFS (cache or otherwise)
  res = ffs_get_def(enc, ffs_name, &ffs_definition);

  // Create an object to hold the parsed data and parse
  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, ffs_definition->character_types, ctlen),  "Unable to allocate memory"); }

  if (!res) { res = CAPTURE_ERROR(enc, parse_data(ffs_definition, PARSE_OUTPUT_TO_INPUT, ctbuf, ctlen, parsed ), "Invalid input string characters");}

  // decode key number
  if (!res) { res = CAPTURE_ERROR(enc, decode_keynum(ffs_definition, parsed->trimmed_buf, &key_number ), "Unable to determine key number in cipher text");}

  // printf("key number %d\n", key_number );
  // Get Encryption object (cache or otherwise - returns ff1_ctx object (ffs_name and current key_number)
  if (!res) {
    res = get_ctx(enc, ffs_definition, &key_number , &ctx);}

  // printf("key number %d\n", key_number );

  // Convert radix back to input character set
  debug("parsed->trimmed_buf BEFORE str_convert_radix", parsed->trimmed_buf);
  if (!res) {res = str_convert_radix( parsed->trimmed_buf, ffs_definition->output_character_set, ffs_definition->input_character_set, parsed->trimmed_buf);}
  // {
  //   char buf[500];
  // if (!res) {res = str_convert_radix( "!!=J*K42c(", ffs_definition->output_character_set, ffs_definition->input_character_set, buf);}
  // debug("buf str_convert_radix", buf);


  // }
  debug("parsed->trimmed_buf after str_convert_radix ", parsed->trimmed_buf);

  //  ff1_decrypt
        // printf("BEFORE decrypt %d  %p\n", res, ctx);
        pt = malloc(ctlen + 1);
  if (!res) {res = CAPTURE_ERROR(enc, ff1_decrypt(ctx, pt,  parsed->trimmed_buf, tweak, tweaklen), "Failure with ff1_decrypt");}

  debug("parsed->trimmed_buf after ff1_decrypt", pt);

  // Merge plain text with formatted text
 if (!res) {
    // Merge encoded key with cipher text
    char * tmp = strdup(parsed->formatted_dest_buf);
    if (tmp == NULL) {
      res = -ENOMEM;
    }

    if (!res) {
      size_t src_idx=0;
      for (size_t i = 0; i < ctlen; i++) {
        // Anything that isn't a zeroth character is a passthrough and can be skipped
        if (tmp[i] == ffs_definition->input_character_set[0]) {
          tmp[i] = pt[src_idx++];
        } 
      }
    }

    // setup return buffer
    if (!res) {
      *ptbuf = tmp;      
      *ptlen = ctlen;
    }
  }

  parsed_destroy(parsed);
  free(pt);

  return res;
}

// Piecewise functions
int
ubiq_platform_fpe_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc) {
      
    struct ubiq_platform_fpe_enc_dec_obj * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    // This function will actually create and initialize the object
    res = ubiq_platform_fpe_encryption(host, papi, sapi, srsa, &e);

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_fpe_enc_dec_destroy(e);
    }

    return res;

}



void
ubiq_platform_fpe_enc_dec_destroy(
    struct ubiq_platform_fpe_enc_dec_obj * const e)
{
  const char * csu = "ubiq_platform_fpe_enc_dec_destroy";

  if (e) {
    int i= 0;
    pthread_mutex_lock(&e->billing_lock);
    cJSON * json_array = e->billing_elements;
    e->billing_elements = NULL;
    pthread_mutex_unlock(&e->billing_lock);
    pthread_cond_signal(&e->process_billing_cond);
    // If the billing thread is this, thread than we know there
    // was a problem during setup so no need to join.
    if (!pthread_equal(e->process_billing_thread,pthread_self())) {
      pthread_join(e->process_billing_thread, NULL);
    }
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
     res = ubiq_platform_fpe_encrypt_data(enc, ffs_name,
       tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
    // TODO BILLING
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
    res  = ubiq_platform_fpe_decrypt_data(enc, ffs_name, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen);
    // TODO BILLING
  }
    ubiq_platform_fpe_enc_dec_destroy(enc);
  return res;
}

//************ TODO

int
ubiq_platform_fpe_encrypt_for_search(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char *** const ctbuf, size_t * const count)
{
  return -1;

}

int
ubiq_platform_fpe_encrypt_data_for_search(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char *** const ctbuf, size_t * const count
)
{
  return -1;

}