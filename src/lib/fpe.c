#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
#include "ubiq/platform/internal/billing.h"
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

#include <locale.h>

#include "cJSON/cJSON.h"

/**************************************************************************************
 *
 * Defines
 *
**************************************************************************************/
// #define UBIQ_DEBUG_ON // UNCOMMENT to Enable UBIQ_DEBUG macro

#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

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

typedef enum {UINT32=0, UINT8=1}  ffs_character_types ;
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

// Buf could be char, uint8_t or int, uint32, etc.
// len is the number of units, not including null terminator.
// buf will always point to at least one longer than len in order to handle the
// null terminator
struct data {
        void * buf;
        size_t len;
};



struct parsed_data
{
  struct data trimmed_buf;
  struct data formatted_dest_buf;
};


struct ubiq_platform_fpe_enc_dec_obj
{
    /* http[s]://host/api/v0 */
    char * restapi;
    char * papi;
    char * encoded_papi;
    char * srsa;
    struct ubiq_platform_rest_handle * rest;

    struct ubiq_billing_ctx * billing_ctx;

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
  char * input_character_set; // WILL be set regardless of whether data is ascii or utf8
  char * output_character_set; // Will be NULL if any of the char sets are
  char * passthrough_character_set;// Will be NULL if any of the char sets are
  uint32_t * u32_input_character_set; // Needed for convenience.  Can be null.
  uint32_t * u32_output_character_set;  // Will be set if any of char sets are utf8
  uint32_t * u32_passthrough_character_set;// Will be set if any of char sets are utf8
  int msb_encoding_bits;
  struct {
          void * buf;
          size_t len;
  } tweak;
  int tweak_min_len;
  int tweak_max_len;
  ffs_character_types character_types; // Set if any of the character sets contain utf8
};



struct ctx_cache_element {
  void * fpe_ctx;
  unsigned int key_number;
};

/**************************************************************************************
 *
 * Static functions
 *
**************************************************************************************/


static int encode_keynum(
  const struct ffs * ffs,
  const unsigned int key_number,
  char * const buf
)
{
  static const char * const csu = "encode_keynum";
  int debug_flag = 0;
  int res = -EINVAL;

  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "start", res));

  char * pos = strchr(ffs->output_character_set, (int)*buf);

  // If *buf is null terminator or if the character cannot be found,
  // it would be an error.
  if (pos != NULL && *pos != 0){
    size_t ct_value = pos - ffs->output_character_set;
  UBIQ_DEBUG(debug_flag, printf("%s \n \tct_value(%d) res(%i)\n",csu, ct_value, res));
  UBIQ_DEBUG(debug_flag, printf("%s \n \tkey_number%d) res(%i)\n",csu, key_number, res));
    ct_value += (key_number << ffs->msb_encoding_bits);
    *buf = ffs->output_character_set[ct_value];
    res = 0;
  }
  return res;
}

static int u32_encode_keynum(
  const struct ffs * ffs,
  const unsigned int key_number,
  uint32_t * const buf
)
{
  int res = -EINVAL;

  uint32_t * pos = u32_strchr(ffs->u32_output_character_set, (int)*buf);

  // If *buf is null terminator or if the character cannot be found,
  // it would be an error.
  if (pos != NULL && *pos != 0){
    size_t ct_value = pos - ffs->u32_output_character_set;
    ct_value += (key_number << ffs->msb_encoding_bits);
    *buf = ffs->u32_output_character_set[ct_value];
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

static int u32_decode_keynum(
  const struct ffs * ffs,
  uint32_t * const encoded_char,
  unsigned int * const key_number
)
{
  int res = -EINVAL;
  uint32_t * pos = u32_strchr(ffs->u32_output_character_set, *encoded_char);
  if (pos != NULL && *pos != 0) {
    unsigned int encoded_value = pos - ffs->u32_output_character_set;

    unsigned int key_num = encoded_value >> ffs->msb_encoding_bits;

    *encoded_char = ffs->u32_output_character_set[encoded_value - (key_num << ffs->msb_encoding_bits)];
    *key_number = key_num;
    res = 0;
    }
  return res;
}


static
int
u32_str_convert_u32_radix(
  const uint32_t * const src_str,
  const uint32_t * const input_radix,
  const uint32_t * output_radix,
  uint32_t * out_str)
{
  static const char * const csu = "u32_str_convert_u32_radix";
  int debug_flag = 0;
  static size_t magic_number = 50; // Allow for null and extra space in get_string function
  int res = 0;
  bigint_t n;

  size_t len = u32_strlen(src_str);
  // Malloc causes valgrind to consider out uninitialized and spits out warnings
  uint32_t * out = calloc(len + magic_number,sizeof(uint32_t));

  bigint_init(&n);

  if (out == NULL) {
    res = -ENOMEM;
  }

  if (!res) {res = __u32_bigint_set_str(&n, src_str, input_radix);}

  if (!res) {
    res = __u32_bigint_get_str(out, len+magic_number, output_radix, &n);
    UBIQ_DEBUG(debug_flag,printf("__bigint_get_str res (%d), out %s\n", res, out));

    size_t out_len = u32_strlen(out);

    // Make sure the get_string succeeded
    if ((!res) && (out_len > len)) {
      res = -EINVAL;
    } 
    
    if (!res) {
      // // pad the leading characters of the output radix with zeroth character
      uint32_t * c = out_str;
      for (int i = 0; i < len - out_len; i++) {
        *c = output_radix[0];
        c++;
      }
      u32_strcpy(c, out);
    }
  }
  bigint_deinit(&n);
  free(out);
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
  int debug_flag = 0;
  static const char * const csu = "str_convert_radix";
  static size_t magic_number = 50; // Allow for null and extra space in get_string function
  int res = 0;
  bigint_t n;
  size_t len = strlen(src_str);
  // Malloc causes valgrind to consider out uninitialized and spits out warnings
  char * out = calloc(len + magic_number,sizeof(char));

  bigint_init(&n);

  if (out == NULL) {
    res = -ENOMEM;
  }

  UBIQ_DEBUG(debug_flag,printf("src_str %s\n", src_str));
  if (!res) {res = __bigint_set_str(&n, src_str, input_radix);}

  UBIQ_DEBUG(debug_flag,gmp_printf("INPUT num = %Zd\n", n));

  UBIQ_DEBUG(debug_flag,printf("input ----%s----\n", input_radix));
  UBIQ_DEBUG(debug_flag,printf("output_radix ----%s----\n", output_radix));

  if (!res) {
    res = __bigint_get_str(out, len+magic_number, output_radix, &n);
    UBIQ_DEBUG(debug_flag,printf("__bigint_get_str res (%d), out %s\n", res, out));

    size_t out_len = strlen(out);

    // Make sure the get_string succeeded
    if ((!res) && (out_len > len)) {
      res = -EINVAL;
    } 
    
    if (!res) {
      // // pad the leading characters of the output radix with zeroth character
      char * c = out_str;
      for (int i = 0; i < len - out_len; i++) {
        *c = output_radix[0];
        c++;
      }
      strcpy(c, out);
    }
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
ctx_cache_element_create(
  struct ctx_cache_element ** e,
  struct ff1_ctx *const ff1_ctx,
  unsigned int key_number)
{
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
  int debug_flag = 0;

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

  if (!res && (strlen(e->input_character_set) != u8_mbsnlen(e->input_character_set, strlen(e->input_character_set))) ||
      (strlen(e->output_character_set) != u8_mbsnlen(e->output_character_set, strlen(e->output_character_set))) ||
      (strlen(e->passthrough_character_set) != u8_mbsnlen(e->passthrough_character_set, strlen(e->passthrough_character_set)))) {
      UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "Multibyte UTF8 found"));
        res = convert_utf8_to_utf32(e->input_character_set, &e->u32_input_character_set);
        if (!res) {res = convert_utf8_to_utf32(e->output_character_set, &e->u32_output_character_set);}
        if (!res) {res = convert_utf8_to_utf32(e->passthrough_character_set, &e->u32_passthrough_character_set);}

        //free(e->input_character_set);
        free(e->output_character_set);
        free(e->passthrough_character_set);
        //e->input_character_set = NULL;
        e->output_character_set = NULL;
        e->passthrough_character_set = NULL;
        e->character_types = UINT32;
  } else {
        UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "No Multibyte UTF8 found"));
        e->character_types = UINT8;
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

  UBIQ_DEBUG(debug_flag, printf("%s ffs->input_character_set(%s)\n", csu, e->input_character_set));
  UBIQ_DEBUG(debug_flag, printf("%s ffs->u32_input_character_set(%S)\n", csu, e->u32_input_character_set));


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
  struct parsed_data * const parsed
)
{
  static const char * const csu = "parsed_destroy";
 
  if (parsed) {free(parsed->trimmed_buf.buf);}
  if (parsed) {free(parsed->formatted_dest_buf.buf);}
  free((void *)parsed);
}


static
int parsed_create(
  struct parsed_data ** const parsed,
  const ffs_character_types char_types,
  const size_t buf_len
)
{
  static const char * const csu = "parsed_create";
  struct parsed_data *p;

  size_t element_size = sizeof(char);
  if (char_types == UINT32) {
    element_size = sizeof(uint32_t);
  }

  int res = -ENOMEM;
  p = calloc(1, sizeof(*p));
  if (p) {
    p->trimmed_buf.buf = calloc(buf_len + 1, element_size);
    p->trimmed_buf.len = buf_len;

    p->formatted_dest_buf.buf = calloc(buf_len + 1, element_size);
    p->formatted_dest_buf.len = buf_len;
  
    if (p->trimmed_buf.buf && p->formatted_dest_buf.buf) {
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
int char_parse_data(
  const struct ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const char * const source_string,
  const size_t source_len,
  struct parsed_data * const parsed
)
{
  static const char * const csu = "char_parse_data";
  int res = 0;

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
    res = char_parsing_decompose_string(
      source_string, src_char_set, ffs->passthrough_character_set,
      dest_zeroth_char,
      (char *)parsed->trimmed_buf.buf, &parsed->trimmed_buf.len,
      (char *) parsed->formatted_dest_buf.buf,  &parsed->formatted_dest_buf.len);
  }

  return res;
} // char_parse_data

static
int u32_parse_data(
  const struct ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const uint32_t * const source_string,
  const size_t source_len,
  struct parsed_data * const parsed
)
{
  static const char * const csu = "u32_parse_data";
  int res = 0;

  uint32_t dest_zeroth_char;
  uint32_t * src_char_set = NULL;
  if (conversion_direction == PARSE_INPUT_TO_OUTPUT) {// input to output
    src_char_set = ffs->u32_input_character_set;
    dest_zeroth_char = ffs->u32_output_character_set[0];
  } else if (conversion_direction == PARSE_OUTPUT_TO_INPUT) {
    src_char_set = ffs->u32_output_character_set;
    dest_zeroth_char = ffs->u32_input_character_set[0];
  } else {
    res = -EINVAL;
  }

  if (!res) {
    res = u32_parsing_decompose_string(
      source_string, src_char_set, ffs->u32_passthrough_character_set,
      dest_zeroth_char,
      parsed->trimmed_buf.buf, &parsed->trimmed_buf.len,
      parsed->formatted_dest_buf.buf,  &parsed->formatted_dest_buf.len);
  }

  return res;
} // u32_parse_data


static
int
get_key_cache_string(const char * const ffs_name,
  const int key_number,
  char ** str) 
{
  size_t key_len = strlen(ffs_name) + 25; // magic number to accomodate a max int plus null terminator and colon
  char * key_str = calloc(1, key_len);

  snprintf(key_str, key_len, "%s:%d", ffs_name, key_number);

  *str = key_str;
  return 0;
}

static
int
create_and_add_ctx_cache(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const struct ffs * const ffs,
  int key_number,
  struct fpe_key * key,
  struct ctx_cache_element ** element)
{
  static const char * const csu = "create_and_add_ctx_cache";
  int debug_flag = 0;
  int res = 0;

  struct ctx_cache_element * ctx_element = NULL;

  char * key_str = NULL;

  get_key_cache_string(ffs->name, key_number, &key_str);

  struct ff1_ctx * ctx = NULL;
  UBIQ_DEBUG(debug_flag, printf("%s ffs->input_character_set(%s)\n", csu, ffs->input_character_set ));

  // ff1_ctx will recognize utf8 and handle accordingly.  That is why we need to keep 
  // input_character_set, even when utf8
  res = ff1_ctx_create_custom_radix(&ctx, key->buf, key->len, ffs->tweak.buf, ffs->tweak.len, ffs->tweak_min_len, ffs->tweak_max_len, ffs->input_character_set);

  if (!res) { res = ctx_cache_element_create(&ctx_element, ctx, key->key_number);}
  if (!res) {res = ubiq_platform_cache_add_element(e->key_cache, key_str, CACHE_DURATION, ctx_element, &ctx_cache_element_destroy);}

  if (!res) {
    *element = ctx_element;
  } else {
    ctx_cache_element_destroy(ctx_element);
  }
  free(key_str);
  return res;

}


static
int
ubiq_platform_fpe_encryption(
    const char * const host,
    const char * const papi, const char * const sapi,
    const char * const srsa,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc)
{
    static const char * const csu = "ubiq_platform_fpe_encryption";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_fpe_enc_dec_obj * e = NULL;
    size_t len;
    int res;
    res = -ENOMEM;
    e = calloc(1, sizeof(*e));
    if (e) {
      // Just a way to determine if it has been created correctly later
      // e->process_billing_thread = pthread_self();

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
        e->papi = strdup(papi);
        if (e->papi == NULL) {
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
        res = ubiq_billing_ctx_create(&e->billing_ctx, host, e->rest, cfg);
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
get_ctx(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const struct ffs * const ffs,
  int * key_number,
  struct ff1_ctx ** ff1_ctx 
) 
{
  const char * const csu = "get_ctx";
  int debug_flag = 0;
  int res = 0;
  struct ctx_cache_element * ctx_element = NULL;
  char * key_str = NULL;

  get_key_cache_string(ffs->name, *key_number, &key_str);
  
  ctx_element = (struct ctx_cache_element *)ubiq_platform_cache_find_element(e->key_cache, key_str);
 
  if (ctx_element != NULL) {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "key found in Cache"));
  } else {
    if (!res) {
        UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "key NOT found in Cache"));
        UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, key_str));
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
          UBIQ_DEBUG(debug_flag, printf("url %s\n", url));
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

        res = create_and_add_ctx_cache(e,ffs, k->key_number, k, &ctx_element);

        if (!res && (*key_number == -1)) {
          res = create_and_add_ctx_cache(e,ffs, *key_number, k, &ctx_element);
        }

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

  int debug_flag = 0;
  cJSON * json = NULL;
  char * url = NULL;
  size_t len;
  int res = 0;
  const void * rsp = NULL;
  const struct ffs * ffs = NULL;

  // The ubiq_platform_fpe_enc_dec_obj was created using specific credentials,
  // so can simply use the ffs_name to look for a key, not the full URL.  This will save
  // having to encode the URL each time

  ffs = (const struct ffs *)ubiq_platform_cache_find_element(e->ffs_cache, ffs_name);
  if (ffs != NULL) {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "Found in Cache"));
    *ffs_definition = ffs;
  } else {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "Fetching from server"));
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


static 
int alloc(
  const size_t nmemb,
  const size_t size,
  void ** data
) 
{
  int res = -ENOMEM;

  void * d = calloc(nmemb, size);
  if (d) {
    *data = d;
    res = 0;
  } 
  return res;
}

static
int u32_finalize_output_string(
  struct parsed_data * parsed,
  const size_t original_data_len,
  const uint32_t * const data,
  const size_t data_len,
  const uint32_t zero_char,
  uint32_t ** finalized_data,
  size_t * finalized_data_len
)
{
  static const char * const csu = "u32_finalize_output_string";
  int debug_flag = 0;
  // To save a couple cycles - Use the parsed formatted destination buffer

  UBIQ_DEBUG(debug_flag, printf("%s data(%s) data_len(%d) zero_char(%c)\n", csu, data, data_len, zero_char));
  int res = 0;

  size_t src_idx=0;
  for (size_t i = 0; i < parsed->formatted_dest_buf.len; i++) {
    if (((uint32_t *)parsed->formatted_dest_buf.buf)[i] == zero_char) {
      ((uint32_t *)parsed->formatted_dest_buf.buf)[i] = data[src_idx++];
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s parsed->formatted_dest_buf.buf(%s)\n", csu, parsed->formatted_dest_buf.buf));

  if (!res) {
    // Like a C++ move
    *finalized_data = (uint32_t *)parsed->formatted_dest_buf.buf;
    *finalized_data_len = parsed->formatted_dest_buf.len;
    parsed->formatted_dest_buf.buf = NULL;
    parsed->formatted_dest_buf.len = 0;
  }

  return res;
}

static
int char_finalize_output_string(
  struct parsed_data * parsed,
  const size_t original_data_len,
  const char * const data,
  const size_t data_len,
  const char zero_char,
  char ** finalized_data,
  size_t * finalized_data_len
)
{
  static const char * const csu = "char_finalize_output_string";
  int debug_flag = 0;
  // To save a couple cycles - Use the parsed formatted destination buffer

  UBIQ_DEBUG(debug_flag, printf("%s data(%s) data_len(%d) zero_char(%c)\n", csu, data, data_len, zero_char));
  int res = 0;

  size_t src_idx=0;
  for (size_t i = 0; i < parsed->formatted_dest_buf.len; i++) {
    if (((char *)parsed->formatted_dest_buf.buf)[i] == zero_char) {
      ((char *)parsed->formatted_dest_buf.buf)[i] = data[src_idx++];
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s parsed->formatted_dest_buf.buf(%s)\n", csu, parsed->formatted_dest_buf.buf));

  if (!res) {
    // Like a C++ move
    *finalized_data = (char *)parsed->formatted_dest_buf.buf;
    *finalized_data_len = parsed->formatted_dest_buf.len;
    parsed->formatted_dest_buf.buf = NULL;
    parsed->formatted_dest_buf.len = 0;
  }

  return res;
}

static
int char_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  struct ff1_ctx * const ctx,
  const int key_number,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen)
{
  static const char * const csu = "char_fpe_encrypt_data";
  int debug_flag = 0;
  int res = 0;
  struct parsed_data * parsed = NULL;
  char * ct = NULL;

  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, UINT8, ptlen),  "Memory Allocation Error"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "parsed_create", res));

  if (!res) { res = CAPTURE_ERROR(enc, char_parse_data(ffs_definition, PARSE_INPUT_TO_OUTPUT, ptbuf, ptlen, parsed ), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "char_parse_data", res));

  if (!res && (parsed->trimmed_buf.len < ffs_definition->min_input_length || parsed->trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  if (!res ) { res = CAPTURE_ERROR(enc, alloc(ptlen + 1, sizeof(char), (void **)&ct), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) buf(%s)\n",csu, "alloc", res, parsed->trimmed_buf.buf));

  if (!res) { res = CAPTURE_ERROR(enc, ff1_encrypt(ctx, ct, parsed->trimmed_buf.buf, tweak, tweaklen), "Unable to encrypt data");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ct(%s)\n",csu, "ff1_encrypt", res, ct));

  if (!res) { res = CAPTURE_ERROR(enc, str_convert_radix(ct, ffs_definition->input_character_set, ffs_definition->output_character_set, ct), "Unable to convert to output character set");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ct(%s)\n",csu, "str_convert_radix", res, ct));

  if (!res) {res = CAPTURE_ERROR(enc, encode_keynum(ffs_definition, key_number, ct), "Unable to encode key number to cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "encode_keynum", res));

  if (!res) {res = CAPTURE_ERROR(enc, char_finalize_output_string(parsed, ptlen, ct, strlen(ct), ffs_definition->output_character_set[0], ctbuf, ctlen), "Unable to produce cipher text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "char_finalize_output_string", res));

  parsed_destroy(parsed);
  free(ct);

  return res;
}

static
int u32_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  struct ff1_ctx * const ctx,
  const int key_number,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen)
{
  static const char * const csu = "u32_fpe_encrypt_data";
  int debug_flag = 0;
  int res = 0;
  struct parsed_data * parsed = NULL;
  char * u8_ct = NULL;
  uint32_t * u32_ct = NULL;
  uint32_t * u32_ptbuf = NULL;
  uint8_t * u8_trimmed = NULL;
  size_t len = 0;

  uint32_t * u32_finalized = NULL;

  setlocale(LC_ALL, "C.UTF-8");

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf8_to_utf32(ptbuf, &u32_ptbuf),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s ptbuf(%s) u32_pt(%S) res(%i)\n",csu, "convert_utf8_to_utf32", ptbuf, u32_ptbuf, res));

  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, UINT32, ptlen),  "Memory Allocation Error"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "parsed_create", res));

  len = u32_strlen(u32_ptbuf);

  if (!res) { res = CAPTURE_ERROR(enc, u32_parse_data(ffs_definition, PARSE_INPUT_TO_OUTPUT, u32_ptbuf, len, parsed ), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "char_parse_data", res));

  if (!res && (parsed->trimmed_buf.len < ffs_definition->min_input_length || parsed->trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( parsed->trimmed_buf.buf, &u8_trimmed),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s u32_trimmed(%S) u8_trimmed(%s) res(%i)\n",csu, "convert_utf8_to_utf32", parsed->trimmed_buf.buf, u8_trimmed, res));
  
  if (!res ) { res = CAPTURE_ERROR(enc, alloc(4 * (len + 1), sizeof(char), (void **)&u8_ct), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) \n",csu, "alloc", res));

  if (!res) { res = CAPTURE_ERROR(enc, ff1_encrypt(ctx, u8_ct, u8_trimmed, tweak, tweaklen), "Unable to encrypt data");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ct(%s)\n",csu, "ff1_encrypt", res, u8_ct));

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf8_to_utf32(u8_ct, &u32_ct),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s u8_ct(%s) u32_ct(%S) res(%i)\n",csu, "convert_utf8_to_utf32", u8_ct, u32_ct, res));

  if (!res) { res = CAPTURE_ERROR(enc, u32_str_convert_u32_radix(u32_ct, ffs_definition->u32_input_character_set, ffs_definition->u32_output_character_set, u32_ct), "Unable to convert to output character set");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s res(%i) u32_ct(%S)\n",csu, "u32_str_convert_u32_radix", res, u32_ct));

  if (!res) {res = CAPTURE_ERROR(enc, u32_encode_keynum(ffs_definition, key_number, u32_ct), "Unable to encode key number to cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s res(%i) u32_ct(%S)\n",csu, "u32_encode_keynum", res, u32_ct));

  if (!res) {res = CAPTURE_ERROR(enc, u32_finalize_output_string(parsed, ptlen, u32_ct, u32_strlen(u32_ct), ffs_definition->u32_output_character_set[0], & u32_finalized, ctlen), "Unable to produce cipher text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "char_finalize_output_string", res));

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( u32_finalized, (uint8_t **)ctbuf),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s res(%i) ctbuf(%s)\n",csu, "convert_utf32_to_utf8", res, *ctbuf));

  if (!res) {
    *ctlen = u8_strlen(*ctbuf);
  }
  parsed_destroy(parsed);
  free(u8_ct);
  free(u32_ct);
  free(u32_ptbuf);
  free(u8_trimmed);
  free(u32_finalized);
  return res;
}


static
int char_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen,
  int * key_number)
{
  static const char * const csu = "char_fpe_decrypt_data";
  int debug_flag = 0;
  int res = 0;
  struct parsed_data * parsed = NULL;
  struct ff1_ctx * ctx = NULL;
  char * pt = NULL;

  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, UINT8, ctlen),  "Memory Allocation Error"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "parsed_create", res));

  if (!res) { res = CAPTURE_ERROR(enc, char_parse_data(ffs_definition, PARSE_OUTPUT_TO_INPUT, ctbuf, ctlen, parsed ), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed(%s) formatted(%s)\n",csu, "char_parse_data", res, parsed->trimmed_buf.buf, parsed->formatted_dest_buf.buf));

  if (!res && (parsed->trimmed_buf.len < ffs_definition->min_input_length || parsed->trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  if (!res ) { res = CAPTURE_ERROR(enc, alloc(ctlen + 1, sizeof(char), (void **)&pt), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) buf(%s)\n",csu, "alloc", res, parsed->trimmed_buf.buf));

  // decode keynum
  if (!res) { res = CAPTURE_ERROR(enc, decode_keynum(ffs_definition, parsed->trimmed_buf.buf, key_number ), "Unable to determine key number in cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) key(%d) buf(%s)\n",csu, "decode_keynum", res, *key_number, parsed->trimmed_buf.buf));

  // convert radix
  if (!res) {res = CAPTURE_ERROR(enc, str_convert_radix( parsed->trimmed_buf.buf, ffs_definition->output_character_set, ffs_definition->input_character_set, parsed->trimmed_buf.buf), "Invalid input string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed_buf.buf(%s)\n",csu, "str_convert_radix", res, parsed->trimmed_buf.buf));

  // get ctx
  if (!res) {res = get_ctx(enc, ffs_definition, key_number , &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "get_ctx", res));
  
  // decrypt
  if (!res) { res = CAPTURE_ERROR(enc, ff1_decrypt(ctx, pt, parsed->trimmed_buf.buf, tweak, tweaklen), "Unable to decrypt data");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) (%s)\n",csu, "ff1_decrypt", res, pt));

  // char_finalize_output_string
  if (!res) {res = CAPTURE_ERROR(enc, char_finalize_output_string(parsed, ctlen, pt, strlen(pt), ffs_definition->input_character_set[0], ptbuf, ptlen), "Unable to produce plain text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ptbuf(%s)\n",csu, "char_finalize_output_string", res, ptbuf));

  parsed_destroy(parsed);
  free(pt);

  return res;
}


static
int u32_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen,
  int * key_number)
{
  static const char * const csu = "u32_fpe_decrypt_data";
  int debug_flag = 0;
  int res = 0;
  struct parsed_data * parsed = NULL;
  struct ff1_ctx * ctx = NULL;
  char * pt = NULL;

  uint32_t * u32_ctbuf = NULL;
  uint32_t * u32_pt = NULL;
  uint8_t * u8_trimmed = NULL;
  char * u8_pt = NULL;
  uint32_t * u32_finalized = NULL;
  size_t len = 0;

  setlocale(LC_ALL, "C.UTF-8");

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf8_to_utf32(ctbuf, &u32_ctbuf),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s ctbuf(%s) u32_ctbuf(%S) res(%i)\n",csu, "convert_utf8_to_utf32", ctbuf, u32_ctbuf, res));

  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, UINT32, ctlen),  "Memory Allocation Error"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "parsed_create", res));

  len = u32_strlen(u32_ctbuf);

  if (!res) { res = CAPTURE_ERROR(enc, u32_parse_data(ffs_definition, PARSE_OUTPUT_TO_INPUT, u32_ctbuf, len, parsed ), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed(%S) formatted(%S)\n",csu, "u32_parse_data", res, parsed->trimmed_buf.buf, parsed->formatted_dest_buf.buf));

  if (!res && (parsed->trimmed_buf.len < ffs_definition->min_input_length || parsed->trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  // decode keynum
  if (!res) { res = CAPTURE_ERROR(enc, u32_decode_keynum(ffs_definition, parsed->trimmed_buf.buf, key_number ), "Unable to determine key number in cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) key(%d) buf(%S)\n",csu, "u32_decode_keynum", res, *key_number, parsed->trimmed_buf.buf));

  // convert radix
  if (!res) {res = CAPTURE_ERROR(enc, u32_str_convert_u32_radix( parsed->trimmed_buf.buf, ffs_definition->u32_output_character_set, ffs_definition->u32_input_character_set, parsed->trimmed_buf.buf), "Invalid input string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed_buf.buf(%S)\n",csu, "u32_str_convert_u32_radix", res, parsed->trimmed_buf.buf));

  // Convert trimmed to UTF8
  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( parsed->trimmed_buf.buf, &u8_trimmed),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s u32_trimmed(%S) u8_trimmed(%s) res(%i)\n",csu, "convert_utf8_to_utf32", parsed->trimmed_buf.buf, u8_trimmed, res));

  // get ctx
  if (!res) {res = get_ctx(enc, ffs_definition, key_number , &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "get_ctx", res));
  
  // allocate u8_pt
  if (!res ) { res = CAPTURE_ERROR(enc, alloc(4 * (len + 1), sizeof(char), (void **)&u8_pt), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) \n",csu, "alloc", res));

  // decrypt
  if (!res) { res = CAPTURE_ERROR(enc, ff1_decrypt(ctx, u8_pt, u8_trimmed, tweak, tweaklen), "Unable to decrypt data");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) (%s)\n",csu, "ff1_decrypt", res, u8_pt));

  // Convert PT u8 to u32  in order to finalize PT
  if (!res) { res = CAPTURE_ERROR(enc, convert_utf8_to_utf32(u8_pt, &u32_pt),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s u8_pt(%s) u32_pt(%S) res(%i)\n",csu, "convert_utf8_to_utf32", u8_pt, u32_pt, res));

  // u32_finalize_output_string
  if (!res) {res = CAPTURE_ERROR(enc, u32_finalize_output_string(parsed, ctlen, u32_pt, u32_strlen(u32_pt), ffs_definition->u32_input_character_set[0], &u32_finalized, ptlen), "Unable to produce plain text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ptbuf(%S)\n",csu, "u32_finalize_output_string", res, u32_finalized));

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( u32_finalized, (uint8_t **)ptbuf),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s res(%i) ptbuf(%s)\n",csu, "convert_utf32_to_utf8", res, *ptbuf));
  if (!res) {
    *ptlen = u8_strlen(*ptbuf);
  }

  parsed_destroy(parsed);
  free(u32_ctbuf);
  free(u32_pt);
  free(u8_trimmed);
  free(u8_pt);
  free(u32_finalized);

  return res;
}

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
  static const char * const csu = "ubiq_platform_fpe_encrypt_data";
  int debug_flag = 0;
  int res = 0;
  const struct ffs * ffs_definition = NULL;
  struct ff1_ctx * ctx = NULL;
  int key_number = -1;

  char * dataset_groups_name = NULL; // TODO - change to parameter in the future for FQN

  // Get FFS (cache or otherwise)
  res = ffs_get_def(enc, ffs_name, &ffs_definition);
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "ffs_get_def", res));

  if (!res) {res = get_ctx(enc, ffs_definition, &key_number , &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "get_ctx", res));

  // If any of ICS, PCS, OCS are uint32

  if (!res) {
    if (ffs_definition->character_types == UINT8) {
      res = char_fpe_encrypt_data(enc, ffs_definition, ctx, key_number, tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
    } else {
      res = u32_fpe_encrypt_data(enc, ffs_definition, ctx, key_number, tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
    }
  }

  if (!res) {

    res = ubiq_billing_add_billing_event(
      enc->billing_ctx,
      enc->papi,
      ffs_name, dataset_groups_name,
      ENCRYPTION,
      1, key_number );
  }


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
  static const char * const csu = "ubiq_platform_fpe_decrypt_data";
  int debug_flag = 0;
  int res = 0;
  const struct ffs * ffs_definition = NULL;

  char * dataset_groups_name = NULL; // TODO - change to parameter in the future for FQN
  int key_number = -1;
  // Get FFS (cache or otherwise)
  res = ffs_get_def(enc, ffs_name, &ffs_definition);
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "ffs_get_def", res));

  // If any of ICS, PCS, OCS are uint32

  if (!res) {
    if (ffs_definition->character_types == UINT8) {
      res = char_fpe_decrypt_data(enc, ffs_definition, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen, &key_number);
    } else {
      res = u32_fpe_decrypt_data(enc, ffs_definition, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen, &key_number);
    }
  }

  if (!res) {

    res = ubiq_billing_add_billing_event(
      enc->billing_ctx,
      enc->papi,
      ffs_name, dataset_groups_name,
      DECRYPTION,
      1, key_number );
  }


  return res;

}

int
ubiq_platform_fpe_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc) {

  struct ubiq_platform_configuration * cfg = NULL;

  ubiq_platform_configuration_load_configuration(NULL, &cfg);

  int ret = ubiq_platform_fpe_enc_dec_create_with_config(creds, cfg, enc);
  ubiq_platform_configuration_destroy(cfg);
  return ret;

}

// Piecewise functions
int
ubiq_platform_fpe_enc_dec_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc) {
      
    struct ubiq_platform_fpe_enc_dec_obj * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    // This function will actually create and initialize the object
    res = ubiq_platform_fpe_encryption(host, papi, sapi, srsa, cfg, &e);

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
  const char * const csu = "ubiq_platform_fpe_enc_dec_destroy";

  if (e) {
    int i= 0;
    // Need to make sure billing ctx is destroyed before other objects
    ubiq_billing_ctx_destroy(e->billing_ctx);

    ubiq_platform_rest_handle_destroy(e->rest);
    free(e->restapi);
    free(e->papi);
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
  }
    ubiq_platform_fpe_enc_dec_destroy(enc);
  return res;
}

int
ubiq_platform_fpe_encrypt_for_search(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char *** const ctbuf, size_t * const count)
{
  struct ubiq_platform_fpe_enc_dec_obj * enc;
  int res = 0;

  enc = NULL;
  res = ubiq_platform_fpe_enc_dec_create(creds, &enc);

   if (!res) {
    res  = ubiq_platform_fpe_encrypt_data_for_search(enc, ffs_name, tweak, tweaklen, ptbuf, ptlen, ctbuf, count);
  }

  ubiq_platform_fpe_enc_dec_destroy(enc);
  return res;

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
  static const char * const csu = "ubiq_platform_fpe_encrypt_data_for_search";
  int debug_flag = 0;
  const struct ffs * ffs_definition = NULL;
  struct ff1_ctx * ctx = NULL;
  int key_number = -1;
  int res = 0;
  char ** ret_ct = NULL;
  char * dataset_groups_name = NULL; // TODO - change to parameter in the future for FQN

  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "start", res));

  // Get the FFS Definition
  if (!res) {res = ffs_get_def(enc, ffs_name, &ffs_definition);}
  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "ffs_get_def", res));

  // Get the ctx and the key number for the current key
  if (!res) {res = get_ctx(enc, ffs_definition, &key_number , &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) key_number(%d)\n", csu, "get_ctx", res, key_number));

  // Loop over all keys up to the current key, and encrypt the data using each key
  if (!res) {
    *count = key_number + 1;
    ret_ct = (char **)calloc(*count, sizeof(char *));
    if (!ret_ct) {
      res = -ENOMEM;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) key_number(%d)\n", csu, "alloc", res, key_number));

  for (int i = 0; !res && i <= key_number; i++) {
    size_t len = 0;
    int x = i;
    if (!res) {res = get_ctx(enc, ffs_definition, &x , &ctx);}
    UBIQ_DEBUG(debug_flag, printf("i(%d) x(%d) res(%d)\n", i, x, res));

    if (!res) {
      if (ffs_definition->character_types == UINT8) {
        res = char_fpe_encrypt_data(enc, ffs_definition, ctx, i, tweak, tweaklen, ptbuf, ptlen,  &ret_ct[i], &len);
        UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) ret_ct[i](%s)\n", csu, "char_fpe_encrypt_data", res, ret_ct[i]));
      } else {
        res = u32_fpe_encrypt_data(enc, ffs_definition, ctx, i, tweak, tweaklen, ptbuf, ptlen, &ret_ct[i], &len);
        UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) ret_ct[i](%s)\n", csu, "u32_fpe_encrypt_data", res, ret_ct[i]));
      }
    }

    // if (!res) { res = char_fpe_encrypt_data(enc, ffs_definition, ctx, i, tweak, tweaklen, ptbuf, ptlen, &ret_ct[i], &len);}

    // char_fpe_encrypt_data does not add billing event - ubiq_platform_fpe_enc_dec_obj adds billing but does not accept key number.
    // Therefore, need to add billing records here

    if (!res) {
      res = ubiq_billing_add_billing_event(
        enc->billing_ctx,
        enc->papi,
        ffs_name, dataset_groups_name,
        ENCRYPTION,
        1, i );
    }
  }

  if (res) {
    for (int i = 0; i <= key_number; i++) {
      free(ret_ct[i]);
      ret_ct = NULL;
    }
    *count = 0;
  }
  *ctbuf = ret_ct;


  return res;

}