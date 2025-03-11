#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
#include "ubiq/platform/internal/billing.h"
#include "ubiq/platform/internal/cache.h"
#include "ubiq/platform/internal/ff1.h"
#include "ubiq/platform/internal/ffx.h"
#include "ubiq/platform/internal/sso.h"

#include "ubiq/platform/internal/bn.h"

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
#include <wchar.h>
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

static int debug_flag = 1;

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

typedef enum {UINT32=0, UINT8=1}  ffs_character_types ;
typedef enum {PARSE_INPUT_TO_OUTPUT = 0, PARSE_OUTPUT_TO_INPUT = 1} conversion_direction_type;
typedef enum {NONE = 0, PASSTHROUGH = 1, PREFIX = 2, SUFFIX = 3} passthrough_rules_priority_type;

/**************************************************************************************
 *
 * Structures
 *
**************************************************************************************/

typedef struct {
     void * buf;
     size_t len;
} ubiq_key_t;

// wrapped_data_key is in base64
// decrypted_data_key is byte array
// decrypted_data_key will have length 0 if key_caching is stored encrypted and it needs to be decrypted
// each time.
typedef struct cached_key {
  ubiq_key_t wrapped_data_key, decrypted_data_key;
  unsigned int key_number;
} cached_key_t;


struct structured_key {
        void * buf;
        size_t len;
        unsigned int key_number;
};

// Buf could be char, uint8_t or int, uint32, etc.
// len is the number of units, not including null terminator.
// buf will always point to at least one longer than len in order to handle the
// null terminator

typedef struct formatted_data {
        void * buf;
        size_t len;
        size_t first_empty_idx; // When trimming - passthrough or prefix, suffix - where to start trimming.  When merging, location of first empty element
} formatted_data_type;

typedef struct trimmed_data {
        void * buf; // Points to the usable data.  May not point to beginning of data due to prefix characters
        void * data; // What is actually allocated / freed
        size_t len; // Length of the trimmed buffer which may be less than actual allocation due to prefix / suffix characters removed
} trimmed_data_type;


struct parsed_data
{
  trimmed_data_type trimmed_buf;
  formatted_data_type formatted_dest_buf;
};


struct ubiq_platform_structured_enc_dec_obj
{
    /* http[s]://host/api/v0 */
    char * restapi;
    // char * papi;
    char * encoded_papi;
    // char * srsa;

    struct {
      void * buf;
      size_t len;
    } encrypted_private_key;

    // Curl library is not thread safe.  Need separate one for Billing and non-billing.
    // Billing rest handle is created / managed in billing_ctx
    struct ubiq_platform_rest_handle * rest;

    struct ubiq_billing_ctx * billing_ctx;

    struct ubiq_platform_cache * ffs_cache; // URL / ffs
    // If key is stored encrypted, need separate cache of rest

    // Will only have contents IF we are caching AND not encrypted.
    struct ubiq_platform_cache * ff1_ctx_cache; // ffs_name:key_number => void * (ff1_ctx)

    struct ubiq_platform_cache * stuctured_key_cache; // ffs_name:key_number => void * (ff1_ctx)

    struct {
            char * err_msg;
            size_t err_num;
    } error;

    int key_cache_encrypt;
    int key_cache_ttl_seconds;
    int key_cache_structured;

    // Creds are needed for IDP since cert can be updated and needs to be renewed
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * cfg;
};

struct ffs {
  char * name;
  int min_input_length;
  int max_input_length;
  char * tweak_source;
  char * regex;
  char * input_character_set; // WILL be set regardless of whether data is ascii or multi-byte utf8
  char * output_character_set; // Will be NULL if any of the char sets are multi-byte utf8
  char * passthrough_character_set;// Will be NULL if any of the char sets are multi-byte utf8
  uint32_t * u32_input_character_set; // Will be set if any of char sets are multi-byte utf8
  uint32_t * u32_output_character_set;  // Will be set if any of char sets are multi-byte utf8
  uint32_t * u32_passthrough_character_set;// Will be set if any of char sets are multi-byte utf8
  uint32_t prefix_passthrough_length;
  uint32_t suffix_passthrough_length;
  int msb_encoding_bits;
  passthrough_rules_priority_type passthrough_rules_priority[3]; // Three known rules.  Ordered list of 
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
structured_key_create(struct structured_key ** key){
  struct structured_key * k;

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
structured_key_destroy(struct structured_key * const key){
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
  struct ubiq_platform_structured_enc_dec_obj * const e,
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

static int get_json_array(
  cJSON * ffs_data,
  char * field_name,
  cJSON **  destination)
{
  *destination = NULL;
  int res = 0;
  cJSON * j = cJSON_GetObjectItemCaseSensitive(ffs_data, field_name);
  if (cJSON_IsArray(j)) {
    *destination = j;
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

static int set_rule_priority(
  struct ffs * e,
  int idx,
  cJSON* rule,
  const passthrough_rules_priority_type rule_type)
{
  int res = 0;
  if (!res && idx >= 0 && idx < sizeof(e->passthrough_rules_priority)) {
    e->passthrough_rules_priority[idx] = rule_type;
  } else {
    res = -EINVAL;
  }
  return res;
}

// [{ priority: 1, type: 'passthrough', value: ' abc' }, { priority: 2, type: 'prefix', value: 1 }, { priority: 3, type: 'suffix', value: 3 }]

static int comparator(const void* p1, const void* p2) {
  static const char * const csu = "comparator";

  cJSON ** e1 = (cJSON ** )p1;
  cJSON ** e2 = (cJSON ** )p2;

  int priority1;
  int priority2;
  
  get_json_int(*e1, "priority", &priority1);
  get_json_int(*e2, "priority", &priority2);

  // Negative if p1 < p2, positive if p2 > p1
  return (priority1 - priority2);
}

static int parse_passthrough_rules(
  cJSON * ffs_data,
  struct ffs * e) 
{
  static const char * const csu = "parse_passthrough_rules";

  int res = 0;
  int rules_idx = 0;
  UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "started"));

  const cJSON * passthrough_rules = cJSON_GetObjectItemCaseSensitive(ffs_data, "passthrough_rules");

  if (cJSON_IsArray(passthrough_rules)) {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "passthrough_rules is array"));

    int arraySize = cJSON_GetArraySize(passthrough_rules);
    UBIQ_DEBUG(debug_flag, printf("%s %s %d\n",csu, "arraySize", arraySize));
    cJSON * array[arraySize];
    cJSON * rule;
    int idx = 0;
    cJSON_ArrayForEach(rule, passthrough_rules) {
      array[idx] = rule;
      idx++;
    }

    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "before qsort"));
    qsort((void *)array, arraySize, sizeof(cJSON *), comparator);
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "after qsort"));

    char * value = NULL;

    for (int idx = 0; res == 0 && idx < arraySize; idx++ ) {
      cJSON * rule = array[idx];

      res = get_json_string(rule, "type", &value);
      UBIQ_DEBUG(debug_flag, printf("%s type(%s)\t idx(%d) ret(%d) %s\n",csu, value, idx, res, cJSON_Print(rule)));
      if (!res && value) {
        if (strcmp(value, "passthrough") == 0) {
          res = get_json_string(rule, "value", &e->passthrough_character_set);
          if (!res) {
            res = set_rule_priority(e, idx, rule, PASSTHROUGH);
          }
          UBIQ_DEBUG(debug_flag, printf("%s e->passthrough_character_set(%s) \t res(%d)\n",csu, e->passthrough_character_set, res));
        } else if (strcmp(value, "prefix") == 0) {
          res = get_json_int(rule, "value", &e->prefix_passthrough_length);
          if (!res) {
            res = set_rule_priority(e, idx, rule, PREFIX);
          }
          UBIQ_DEBUG(debug_flag, printf("%s e->prefix_passthrough_length(%d) \t ret(%d)\n",csu, e->prefix_passthrough_length, res));
        } else if (strcmp(value, "suffix") == 0) {
          res = get_json_int(rule, "value", &e->suffix_passthrough_length);
          if (!res) {
            res = set_rule_priority(e, idx, rule, SUFFIX);
          }
          UBIQ_DEBUG(debug_flag, printf("%s e->suffix_passthrough_length(%d) \t ret(%d)\n",csu, e->suffix_passthrough_length, res));
        } else {
          UBIQ_DEBUG(debug_flag, printf("%s ignored\n",csu));
          res = -EINVAL;
        }
        // Ignoring 
        if (res != 0) {
          break;
        }
      }
      free (value);
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s %s %d\n",csu, "end", res));
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

  if (!res) {
      UBIQ_DEBUG(debug_flag, printf("%s prepare to parse passthrough_rules\n",csu));

    res = parse_passthrough_rules(ffs_data, e);

    // If e->passthrough_characterset is NULL, then assume no passthrough rules
    // so get passthrough characterset directly
    if (e->passthrough_character_set == NULL && !res) {
      res = get_json_string(ffs_data, "passthrough", &e->passthrough_character_set);
    }
  }

  // Test the input_character_set, output_character_set, passthrough characterset
  // to see if they are UTF8 multibyte strings or simply contain single byte characters.
  // if at least one is multibyte, move the strings to the u32 version for the associated elements

  if (!res && (strlen(e->input_character_set) != u8_mbsnlen(e->input_character_set, strlen(e->input_character_set))) ||
      (strlen(e->output_character_set) != u8_mbsnlen(e->output_character_set, strlen(e->output_character_set))) ||
      (strlen(e->passthrough_character_set) != u8_mbsnlen(e->passthrough_character_set, strlen(e->passthrough_character_set)))) {
        UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "Multibyte UTF8 found"));
        // At this point, we know we are dealing with WCHAR, so can set the local
        setlocale(LC_ALL, "C.UTF-8");

        res = convert_utf8_to_utf32(e->input_character_set, &e->u32_input_character_set);
        UBIQ_DEBUG(debug_flag, printf("%s \t res(%d) \t ffs->u32_input_character_set(%S) \n", csu, res, e->u32_input_character_set));
        if (!res) {res = convert_utf8_to_utf32(e->output_character_set, &e->u32_output_character_set);}
        UBIQ_DEBUG(debug_flag, printf("%s \t res(%d) \t ffs->u32_output_character_set(%S) \n", csu, res, e->u32_output_character_set));
        if (!res) {res = convert_utf8_to_utf32(e->passthrough_character_set, &e->u32_passthrough_character_set);}
        UBIQ_DEBUG(debug_flag, printf("%s \t res(%d) \t ffs->u32_passthrough_character_set(%S) \n", csu, res, e->u32_passthrough_character_set));

        // ???? TODO - FIXME Why aren't we freeing this?
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
 
  if (parsed) {free(parsed->trimmed_buf.data);}
  if (parsed) {free(parsed->formatted_dest_buf.buf);}
  free((void *)parsed);
}

static 
int char_process_prefix(
  trimmed_data_type * const trimmed_data,
  const char * const passthrough_char_set,
  const char zeroth_char,
  const size_t prefix_len,
  formatted_data_type * const formatted_data,
  const int passthrough_processed_already)
{
  static const char * const csu = "char_process_prefix";
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s \t start empty_idx(%d)\n",csu, formatted_data->first_empty_idx));

  // Need to step over prefix_len characters.  
  // If passthrough_processed_already, then we need to step over trimmed characters
  // If !passthrough_processed_already, then we need to step over total characters
  // Need to adjust trimmed_data

  char * src = (char *) trimmed_data->buf;
  char * dest = (char *) formatted_data->buf;

  size_t idx = 0;
  while (idx < prefix_len) {
    UBIQ_DEBUG(debug_flag, printf("%s \t loop empty_idx(%d)\n",csu, formatted_data->first_empty_idx));
    if (passthrough_processed_already) {
    // If passthrough has already been processed, don't count passthrough characters
      while (*dest != '\0' && strchr(passthrough_char_set, *dest)) {
        dest++;
      }
      if (*dest == '\0') {
        res = -EINVAL;
      } else {
        *dest++ = *src++;
        trimmed_data->len--;
      }
    } else {
      // Passthrough has not been processed but only copy over a source string
      // if the dest is not a passthrough.  Otherwise count the move and go to next dest.
      if (!strchr(passthrough_char_set, *dest)) {
        *dest = *src++;
        trimmed_data->len--;
      }
      dest++;
    }
    idx++;
  }
  if (!res) {
    trimmed_data->buf = src;
    formatted_data->first_empty_idx = dest -((char *)formatted_data->buf);
  }
  UBIQ_DEBUG(debug_flag, printf("%s \t formatted_data(%s) formatted_data.len(%d) res(%d) empty_idx(%d)\n",csu, formatted_data->buf, formatted_data->len, res, formatted_data->first_empty_idx));
  UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_data(%s) trimmed_data.len(%d) res(%d)\n",csu, trimmed_data->buf, trimmed_data->len, res));
  return res;
}

static 
int char_process_suffix(
  trimmed_data_type * const trimmed_data,
  const char * const passthrough_char_set,
  const char zeroth_char,
  const size_t suffix_len,
  formatted_data_type * const formatted_data,
  const int passthrough_processed_already)
{
  static const char * const csu = "char_process_suffix";
  int res = 0;

  // Start at end of string and move forward

  char * dest = ((char *)formatted_data->buf) + formatted_data->len - 1; // go before null terminator
  char * src = ((char *)trimmed_data->buf) + trimmed_data->len - 1; // go before null terminator

  UBIQ_DEBUG(debug_flag, printf("%s start \t formatted_data(%s) formatted_data.len(%d) res(%d)\n",csu, formatted_data->buf, formatted_data->len, res));
  UBIQ_DEBUG(debug_flag, printf("%s start \t trimmed_data(%s) trimmed_data.len(%d) res(%d)\n",csu, trimmed_data->buf, trimmed_data->len, res));

  size_t idx = 0;
  while (idx < suffix_len) {
    if (passthrough_processed_already) {
      // If passthrough has already been processed, don't count passthrough characters
      while (dest > (char *)formatted_data->buf && strchr(passthrough_char_set, *dest)) {
        dest--;
      }
      if (dest == (char *)formatted_data->buf) {
        res = -EINVAL;
      } else {
        *dest-- = *src--;
        trimmed_data->len--;
      }
    } else {
      // Passthrough has not been processed but only copy over a source string
      // if the dest is not a passthrough.  Otherwise count the move and go to next dest.
      if (!strchr(passthrough_char_set, *dest)) {
        *dest = *src--;
        trimmed_data->len--;
      }
      dest--;
    }
    idx++;
  }
  if (!res) {
    ((char*)trimmed_data->buf)[trimmed_data->len] = '\0';
  }

  UBIQ_DEBUG(debug_flag, printf("%s \t formatted_data(%s) formatted_data.len(%d) res(%d)\n",csu, formatted_data->buf, formatted_data->len, res));
  UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_data(%s) trimmed_data.len(%d) res(%d)\n",csu, trimmed_data->buf, trimmed_data->len, res));

  return res;
}


static 
int u32_process_prefix(
  trimmed_data_type * const trimmed_data,
  const uint32_t * const passthrough_char_set,
  const uint32_t zeroth_char,
  const size_t prefix_len,
  formatted_data_type * const formatted_data,
  const int passthrough_processed_already)
{
  static const char * const csu = "u32_process_prefix";
  int res = 0;

  uint32_t * src = (uint32_t *) trimmed_data->buf;
  uint32_t * dest = (uint32_t *) formatted_data->buf;

  size_t idx = 0;
  while (idx < prefix_len) {
    if (passthrough_processed_already) {
    // If passthrough has already been processed, don't count passthrough characters
      while (*dest != '\0' && u32_strchr(passthrough_char_set, *dest)) {
        dest++;
        // formatted_data->first_empty_idx++;
      }
      if (*dest == '\0') {
        res = -EINVAL;
      } else {
        *dest++ = *src++;
        trimmed_data->len--;
        // formatted_data->first_empty_idx++;
      }
    } else {
      // Passthrough has not been processed but only copy over a source string
      // if the dest is not a passthrough.  Otherwise count the move and go to next dest.
      if (!u32_strchr(passthrough_char_set, *dest)) {
        *dest = *src++;
        trimmed_data->len--;
      }
      dest++;
    }
    idx++;
  }
  if (!res) {
    trimmed_data->buf = src;
   formatted_data->first_empty_idx = dest - ((uint32_t *)formatted_data->buf);
   }
  UBIQ_DEBUG(debug_flag, printf("%s \t formatted_data(%s) formatted_data.len(%d) res(%d)\n",csu, formatted_data->buf, formatted_data->len, res));
  UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_data(%s) trimmed_data.len(%d) res(%d)\n",csu, trimmed_data->buf, trimmed_data->len, res));
  return res;
}

static 
int u32_process_suffix(
  trimmed_data_type * const trimmed_data,
  const uint32_t * const passthrough_char_set,
  const uint32_t zeroth_char,
  const size_t prefix_len,
  formatted_data_type * const formatted_data,
  const int passthrough_processed_already)
{
  static const char * const csu = "u32_process_suffix";
  int res = 0;

  // Start at end of string and move forward

  uint32_t * dest = ((uint32_t *)formatted_data->buf) + formatted_data->len - 1; // go before null terminator
  uint32_t * src = ((uint32_t *)trimmed_data->buf) + trimmed_data->len - 1; // go before null terminator

  size_t idx = 0;
  while (idx < prefix_len) {
    if (passthrough_processed_already) {
      // If passthrough has already been processed, don't count passthrough characters
      while (dest > (uint32_t *)formatted_data->buf && u32_strchr(passthrough_char_set, *dest)) {
        dest--;
      }
      if (dest == (uint32_t *)formatted_data->buf) {
        res = -EINVAL;
      } else {
        *dest-- = *src--;
        trimmed_data->len--;
      }
    } else {
      // Passthrough has not been processed but only copy over a source string
      // if the dest is not a passthrough.  Otherwise count the move and go to next dest.
      if (!u32_strchr(passthrough_char_set, *dest)) {
        *dest = *src--;
        trimmed_data->len--;
      }
      dest--;      
    }
    idx++;
    if (!res) {
      ((uint32_t*)trimmed_data->buf)[trimmed_data->len] = '\0';
    }
  }

  UBIQ_DEBUG(debug_flag, printf("%s \t formatted_data(%s) formatted_data.len(%d) res(%d)\n",csu, formatted_data->buf, formatted_data->len, res));
  UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_data(%s) trimmed_data.len(%d) res(%d)\n",csu, trimmed_data->buf, trimmed_data->len, res));

  return res;
}

static
int char_parse_data_prealloc(
  const struct ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const char * const source_string,
  const size_t source_len,
  trimmed_data_type * const trimmed_buf,
  formatted_data_type * const formatted_dest_buf
)
{
  static const char * const csu = "char_parse_data_prealloc";
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s start \t source_string(%s) source_len(%d) trimmed_buf->len(%d) formatted_dest_buf->len(%d)\n",csu, source_string, source_len, trimmed_buf->len, formatted_dest_buf->len));

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

  UBIQ_DEBUG(debug_flag, printf("%s sizeof(ffs->passthrough_rules_priority: %d) sizeof(passthrough_rules_priority_type: %d\n", csu,sizeof(ffs->passthrough_rules_priority), sizeof(passthrough_rules_priority_type)));

  // Build formatted string and trimmed buffer.
  // This will always happen.  Only difference is when prefix / postfix get applied, what gets trimmed from source.
  if (!res) {
    res = char_parsing_decompose_string(
      source_string, src_char_set, ffs->passthrough_character_set,
      dest_zeroth_char,
      (char *)trimmed_buf->buf, &trimmed_buf->len,
      (char *)formatted_dest_buf->buf, &formatted_dest_buf->len);
  }

  UBIQ_DEBUG(debug_flag, printf("%s BEFORE\t formatted_dest_buf(%s) formatted_dest_buf.len(%d) res(%d)\n",csu, formatted_dest_buf->buf, formatted_dest_buf->len, res));
  UBIQ_DEBUG(debug_flag, printf("%s BEFORE\t trimmed_buf(%s) trimmed_buf.len(%d) res(%d)\n",csu, trimmed_buf->buf, trimmed_buf->len, res));


  // Has passthrough been processed yet?
  int passthrough_processed = 0;
  for (int idx = 0; !res && idx < (sizeof(ffs->passthrough_rules_priority) / sizeof(passthrough_rules_priority_type)); idx++) {
    UBIQ_DEBUG(debug_flag, printf("%s \t formatted_dest_buf(%s) formatted_dest_buf.len(%d) res(%d)\n",csu, formatted_dest_buf->buf, formatted_dest_buf->len, res));
    UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_buf(%s) trimmed_buf.len(%d) res(%d)\n",csu, trimmed_buf->buf, trimmed_buf->len, res));
    if (ffs->passthrough_rules_priority[idx] == PREFIX && ffs->prefix_passthrough_length > 0)  {
      UBIQ_DEBUG(debug_flag, printf("%s process prefix\n", csu));
      char_process_prefix(
        trimmed_buf, ffs->passthrough_character_set, 
        dest_zeroth_char, ffs->prefix_passthrough_length, formatted_dest_buf,
        passthrough_processed);
    } else if (ffs->passthrough_rules_priority[idx] == SUFFIX && ffs->suffix_passthrough_length > 0)  {
      UBIQ_DEBUG(debug_flag, printf("%s process suffix\n", csu));
      char_process_suffix(
        trimmed_buf, ffs->passthrough_character_set, 
        dest_zeroth_char, ffs->suffix_passthrough_length, formatted_dest_buf,
        passthrough_processed);
    } else if (ffs->passthrough_rules_priority[idx] == PASSTHROUGH)  {
      // The prefix logic will set the first_empty_idx.  The buffers have already
      // been separated for formatted and trimmed.
      passthrough_processed = true;
    }
  }

  // Now we can validate the trimmed buffer against the input characterset
  char * s = (char *) trimmed_buf->buf;
  for (char * s = (char *) trimmed_buf->buf; *s && res == 0; s++) {
    if (strchr(src_char_set, *s) == NULL) {
      res = -EINVAL;
    }
  }

  UBIQ_DEBUG(debug_flag, printf("%s AFTER\t formatted_dest_buf(%s) formatted_dest_buf.len(%d) res(%d)\n",csu, formatted_dest_buf->buf, formatted_dest_buf->len, res));
  UBIQ_DEBUG(debug_flag, printf("%s AFTER\t trimmed_buf(%s) trimmed_buf.len(%d) res(%d)\n",csu, trimmed_buf->buf, trimmed_buf->len, res));

  return res;
} // char_parse_data_prealloc

static
int u32_parse_data_prealloc(
  const struct ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const uint32_t * const source_string,
  const size_t source_len,
  trimmed_data_type * const trimmed_buf,
  formatted_data_type * const formatted_dest_buf)
{
  static const char * const csu = "u32_parse_data_prealloc";
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s start \t source_string(%S) source_len(%d) trimmed_buf->len(%d) formatted_dest_buf->len(%d)\n",csu, source_string, source_len, trimmed_buf->len, formatted_dest_buf->len));

  uint32_t dest_zeroth_char;
  uint32_t * src_char_set = NULL;
  if (conversion_direction == PARSE_INPUT_TO_OUTPUT) {// input to output

    src_char_set = ffs->u32_input_character_set;
    dest_zeroth_char = ffs->u32_output_character_set[0];
    UBIQ_DEBUG(debug_flag, printf("%s PARSE_INPUT_TO_OUTPUT src(%S)\n", csu, src_char_set));
  } else if (conversion_direction == PARSE_OUTPUT_TO_INPUT) {
    src_char_set = ffs->u32_output_character_set;
    dest_zeroth_char = ffs->u32_input_character_set[0];
    UBIQ_DEBUG(debug_flag, printf("%s PARSE_OUTPUT_TO_INPUT src(%S)\n", csu, src_char_set));
  } else {
    res = -EINVAL;
  }

  UBIQ_DEBUG(debug_flag, printf("%s before u32_parsing_decompose_string res(%d)\n", csu, res));

  if (!res) {
    res = u32_parsing_decompose_string(
      source_string, src_char_set, ffs->u32_passthrough_character_set,
      dest_zeroth_char,
      trimmed_buf->buf, &trimmed_buf->len,
      formatted_dest_buf->buf,  &formatted_dest_buf->len);
  }
  UBIQ_DEBUG(debug_flag, printf("%s after u32_parsing_decompose_string res(%d)\n", csu, res));

// Has passthrough been processed yet?
  int passthrough_processed = 0;
  for (int idx = 0; !res && idx < (sizeof(ffs->passthrough_rules_priority) / sizeof(passthrough_rules_priority_type)); idx++) {
    if (ffs->passthrough_rules_priority[idx] == PREFIX && ffs->prefix_passthrough_length > 0)  {
      UBIQ_DEBUG(debug_flag, printf("%s process prefix\n", csu));
      u32_process_prefix(
        trimmed_buf, ffs->u32_passthrough_character_set, 
        dest_zeroth_char, ffs->prefix_passthrough_length, formatted_dest_buf,
        passthrough_processed);
    } else if (ffs->passthrough_rules_priority[idx] == SUFFIX && ffs->suffix_passthrough_length > 0)  {
      UBIQ_DEBUG(debug_flag, printf("%s process suffix\n", csu));
      u32_process_suffix(
        trimmed_buf, ffs->u32_passthrough_character_set, 
        dest_zeroth_char, ffs->suffix_passthrough_length, formatted_dest_buf,
        passthrough_processed);
    } else if (ffs->passthrough_rules_priority[idx] == PASSTHROUGH)  {
      passthrough_processed = true;
    }
  }

  // Now we can validate the trimmed buffer against the input characterset
  uint32_t * s = (uint32_t *) trimmed_buf->buf;
  for (uint32_t * s = (uint32_t *) trimmed_buf->buf; *s && res == 0; s++) {
    if (u32_strchr(src_char_set, *s) == NULL) {
      res = -EINVAL;
    }
  }

  return res;
} // u32_parse_data_prealloc

static
int
get_key_cache_string(const char * const ffs_name,
  const int key_number,
  char ** str) 
{
  size_t key_len = strlen(ffs_name) + 25; // magic number to accommodate a max int plus null terminator and colon
  char * key_str = calloc(1, key_len);

  snprintf(key_str, key_len, "%s:%d", ffs_name, key_number);

  *str = key_str;
  return 0;
}

static
int
create_and_add_ctx_cache(
  struct ubiq_platform_structured_enc_dec_obj * const e,
  const struct ffs * const ffs,
  int key_number,
  struct structured_key * key,
  struct ctx_cache_element ** element)
{
  static const char * const csu = "create_and_add_ctx_cache";

  int res = 0;

  struct ctx_cache_element * ctx_element = NULL;

  char * key_str = NULL;

  res = get_key_cache_string(ffs->name, key_number, &key_str);

  struct ff1_ctx * ctx = NULL;
  UBIQ_DEBUG(debug_flag, printf("%s ffs->input_character_set(%s) key_number(%d)\n", csu, ffs->input_character_set, key_number ));

  // ff1_ctx will recognize utf8 and handle accordingly.  That is why we need to keep 
  // input_character_set, even when utf8
  res = ff1_ctx_create_custom_radix(&ctx, key->buf, key->len, ffs->tweak.buf, ffs->tweak.len, ffs->tweak_min_len, ffs->tweak_max_len, ffs->input_character_set);

  if (!res) { res = ctx_cache_element_create(&ctx_element, ctx, key->key_number);}
  if (!res) {res = ubiq_platform_cache_add_element(e->ff1_ctx_cache, key_str, ctx_element, &ctx_cache_element_destroy);}

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
ubiq_platform_structured_encryption(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_structured_enc_dec_obj ** const enc)
{
    static const char * const csu = "ubiq_platform_structured_encryption";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_structured_enc_dec_obj * e = NULL;
    size_t len;
    int res;
    res = -ENOMEM;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    // const char * const papi = ubiq_platform_credentials_get_papi(creds);
    // const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    // const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

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
        res = 0;
        if (!res) {
          res = ubiq_platform_credentials_clone(creds, &(e->creds));
        }
        if (!res) {
          res = ubiq_platform_configuration_clone(cfg, &(e->cfg));
        }

        }

        if (!res && ubiq_platform_credentials_is_idp(e->creds)) {
          // Don't login again if the access token is already set.
          if (ubiq_platform_credentials_get_access_token(e->creds) == NULL) {
            if ((res = ubiq_platform_sso_login(e->creds, e->cfg)) != 0) {
              
            }
          }
        }

        if (!res) {
          ubiq_platform_snprintf_api_url(e->restapi, len, host, api_path);
          res = ubiq_platform_rest_handle_create(
            ubiq_platform_credentials_get_papi(e->creds),
            ubiq_platform_credentials_get_sapi(e->creds), &e->rest);
        }

        if (!res) {
          res = ubiq_platform_rest_uri_escape(e->rest, ubiq_platform_credentials_get_papi(e->creds), &e->encoded_papi);
        }


      // if (!res) {
      //   e->srsa = strdup(srsa);
      //   if (e->srsa == NULL) {
      //     res = -ENOMEM;
      //   }
      // }
      // if (!res) {
      //   e->papi = strdup(papi);
      //   if (e->papi == NULL) {
      //     res = -ENOMEM;
      //   }
      // }

      if (!res) {
          e->key_cache_ttl_seconds = ubiq_platform_configuration_get_key_caching_ttl_seconds(e->cfg);
          e->key_cache_structured = ubiq_platform_configuration_get_key_caching_structured_keys(e->cfg);
          e->key_cache_encrypt = ubiq_platform_configuration_get_key_caching_encrypt(e->cfg);
      }

      if (!res) {
        // htable size 500 - means slots for 500 possible key collisions - probably way more than the 
        // number of datasets being used here
        // Can still use cfg ttl for dataset, just not key
        res = ubiq_platform_cache_create(500, e->key_cache_ttl_seconds, &e->ffs_cache);
      }

      int ttl = 0;

      // If structured key caching, then use the supplied value.
      // If the ttl is 0, means key information will not be cached.
      if (e->key_cache_structured) {
        ttl = e->key_cache_ttl_seconds;
      }

      if (!res) {
        // htable size 500 - means slots for 500 possible key collisions
        // Reduces the likelihood of a key collision 
        // If we are storing the keys encrypted, then 
        // the ctx cannot cache data
        if (e->key_cache_encrypt) {
          ttl = 0;
        }
        res = ubiq_platform_cache_create(500, ttl, &e->ff1_ctx_cache);
      }
      if (!res) {
        // htable size 500 - means slots for 500 possible key collisions
        // Reduces the likelihood of a key collision 
        res = ubiq_platform_cache_create(500, ttl, &e->stuctured_key_cache);
      }
      if (!res) {
        res = ubiq_billing_ctx_create(&e->billing_ctx, host, 
              ubiq_platform_credentials_get_papi(e->creds),
              ubiq_platform_credentials_get_sapi(e->creds), e->cfg);
      }
    }

    if (res) {
      ubiq_platform_structured_enc_dec_destroy(e);
      e = NULL;
    }

    *enc = e;
    return res;
}

static int
key_cache_element_create(cached_key_t ** const e) {
  int res = -ENOMEM;
  cached_key_t * cached_key = NULL;
  cached_key = calloc(1, sizeof(*cached_key));
  if (cached_key) {
    *e = cached_key;
    res = 0;
  }
  return res;
}

static void
key_cache_element_destroy(void * const e) {
  cached_key_t * cached_key = (cached_key_t *) e;
  free(cached_key->wrapped_data_key.buf);
  free(cached_key->decrypted_data_key.buf);
  free(e);
}

static 
int
get_structured_key(
  struct ubiq_platform_structured_enc_dec_obj * const e,
  const struct ffs * const ffs,
  int * key_number,
  struct structured_key * key)
{
  const char * const csu = "get_structured_key";

  static const char * const fmt_encrypt_key = "%s/fpe/key?ffs_name=%s&papi=%s";
  static const char * const fmt_decrypt_key = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";

  int res = 0;
  // Will fetch from cache

  char * key_str = NULL;
  get_key_cache_string(ffs->name, *key_number, &key_str);
  UBIQ_DEBUG(debug_flag, printf("%s get_key_cache_string (%s)\n",csu, key_str));

  cached_key_t * tmp_key = NULL;

  tmp_key = (cached_key_t *)ubiq_platform_cache_find_element(e->stuctured_key_cache, key_str);
  UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_cache_find_element (%d)\n",csu, tmp_key == NULL));

  // Unable to find key - create a new key for the cache
  if (tmp_key == NULL && ((res = key_cache_element_create(&tmp_key)) == 0)) {
    UBIQ_DEBUG(debug_flag, printf("%s: key(%s) NOT found in Cache\n",csu, key_str));

    cJSON * rsp_json = NULL;
    const cJSON * j = NULL;
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
    
    if (!res && ubiq_platform_credentials_is_idp(e->creds)) {
      ubiq_platform_sso_renewIdpCert(e->creds, e->cfg);
      size_t len = strlen(url);
      url = realloc(url, len + 1 + strlen("&payload_cert=") + strlen(ubiq_platform_credentials_get_cert_b64(e->creds)));
      strcat(url, "&payload_cert=");
      strcat(url, ubiq_platform_credentials_get_cert_b64(e->creds));
    }
    if (!res) {
      UBIQ_DEBUG(debug_flag, printf("%s url %s\n", csu, url));
      res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL , 0);
    }
    free(url);
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_request res(%d)\n", csu, res));


    // If Success, simply proceed
    if (!res) {
      const http_response_code_t rc =
          ubiq_platform_rest_response_code(e->rest);

      UBIQ_DEBUG(debug_flag, printf("%s http_response_code_t res(%d)\n", csu, rc));

      if (rc != HTTP_RC_OK) {
        res = save_rest_error(e, e->rest, rc);
      } else {
        const void * rsp = ubiq_platform_rest_response_content(e->rest, &len);
        res = (rsp_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;
        UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_response_content rsp(%.*s)\n", csu, len, rsp));
        if (rsp_json) {
          if (ubiq_platform_credentials_is_idp(e->creds)) {
            // Make sure there isn't an existing encrypted private key.  Need to use this one.
            cJSON_DeleteItemFromObject(rsp_json, "encrypted_private_key");
            cJSON_AddStringToObject(rsp_json, "encrypted_private_key", ubiq_platform_credentials_get_encrypted_private_key(e->creds));
          }
        }
      }
    }

    // If response was valid json AND we don't already manage the encrypted_private_key
    // save it in the main enc_dec object.
    if (!res && rsp_json) {
      if (e->encrypted_private_key.len == 0) {
        j = cJSON_GetObjectItemCaseSensitive(
            rsp_json, "encrypted_private_key");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            e->encrypted_private_key.buf = strdup(j->valuestring);
            e->encrypted_private_key.len = strlen(e->encrypted_private_key.buf);
            UBIQ_DEBUG(debug_flag, printf("e->encrypted_private_key.buf %.*s\n" ,e->encrypted_private_key.len, e->encrypted_private_key.buf));
        } else {
            res = -EBADMSG;
        }
      }
    }

    if (!res && rsp_json) {
      j = cJSON_GetObjectItemCaseSensitive(rsp_json, "wrapped_data_key");
      if (cJSON_IsString(j) && j->valuestring != NULL) {
        tmp_key->wrapped_data_key.buf = strdup(j->valuestring);
        tmp_key->wrapped_data_key.len = strlen(tmp_key->wrapped_data_key.buf);
      }
    }


    // Decrypt the wrapped key IF we are storing unencrypted keys
    if (!res && !e->key_cache_encrypt) {
      res = ubiq_platform_common_decrypt_wrapped_key(
          e->encrypted_private_key.buf,
          ubiq_platform_credentials_get_srsa(e->creds),
          tmp_key->wrapped_data_key.buf,
          &tmp_key->decrypted_data_key.buf,
          &tmp_key->decrypted_data_key.len);
    }

    if (!CAPTURE_ERROR(e, res, "Unable to parse key from server")) {
        const cJSON * kn = cJSON_GetObjectItemCaseSensitive(
                          rsp_json, "key_number");
        if (cJSON_IsString(kn) && kn->valuestring != NULL) {
          const char * errstr = NULL;
          uintmax_t n = strtoumax(kn->valuestring, NULL, 10);
          if (n == UINTMAX_MAX && errno == ERANGE) {
            res = CAPTURE_ERROR(e, -ERANGE, "Invalid key range");
          } else {
            tmp_key->key_number = (unsigned int)n;
          }
        } else {
          res = CAPTURE_ERROR(e, -EBADMSG, "Invalid server response");
        }
    }

    // Add to cache
    if (!res) {res = ubiq_platform_cache_add_element(e->stuctured_key_cache, key_str, tmp_key, &key_cache_element_destroy);}
    cJSON_Delete(rsp_json);
  }

  if (!res) {
    // Key has been decrypted, so copy info to supplied output string
    if (tmp_key->decrypted_data_key.buf != NULL && tmp_key->decrypted_data_key.len != 0) {
      UBIQ_DEBUG(debug_flag, printf("%s decrypted_data_key exists\n", csu));
      key->buf = calloc(1, tmp_key->decrypted_data_key.len);
      memcpy(key->buf, tmp_key->decrypted_data_key.buf, tmp_key->decrypted_data_key.len);
      key->len = tmp_key->decrypted_data_key.len;
      key->key_number = tmp_key->key_number;
    } else {
        UBIQ_DEBUG(debug_flag, printf("%s wrapped data key being decrypted\n", csu));
        ubiq_platform_common_decrypt_wrapped_key(
          e->encrypted_private_key.buf,
          ubiq_platform_credentials_get_srsa(e->creds),
          tmp_key->wrapped_data_key.buf,
          &key->buf,
          &key->len);  
        key->key_number = tmp_key->key_number;  
    }
  }
  free(key_str);
  return res;
}

static
int
get_ctx(
  struct ubiq_platform_structured_enc_dec_obj * const e,
  const struct ffs * const ffs,
  int * key_number,
  struct ff1_ctx ** ff1_ctx 
) 
{
  const char * const csu = "get_ctx";
  int res = 0;
  struct ctx_cache_element * ctx_element = NULL;
  char * key_str = NULL;

  get_key_cache_string(ffs->name, *key_number, &key_str);
  UBIQ_DEBUG(debug_flag, printf("%s key_str(%s)\n",csu, key_str));

  ctx_element = (struct ctx_cache_element *)ubiq_platform_cache_find_element(e->ff1_ctx_cache, key_str);

  if (ctx_element != NULL) {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "key found in Cache"));
  } else {
    if (!res) {
    UBIQ_DEBUG(debug_flag, printf("%s key NOT found in cache\n",csu));
      struct structured_key * k = NULL;
      res = structured_key_create(&k);
      UBIQ_DEBUG(debug_flag, printf("%s structured_key_create res(%d)\n",csu, res));

      if (!res) {res = get_structured_key(e, ffs, key_number, k);}
      UBIQ_DEBUG(debug_flag, printf("%s get_structured_key res(%d)\n",csu, res));

      if (!res) {res = create_and_add_ctx_cache(e,ffs, k->key_number, k, &ctx_element);}

      if (!res && (*key_number == -1)) {
        res = create_and_add_ctx_cache(e,ffs, *key_number, k, &ctx_element);
      }

      structured_key_destroy(k);
    }
  }

  if (!res) {
      *ff1_ctx = ctx_element->fpe_ctx;
      *key_number = ctx_element->key_number;
  }

  free(key_str);

  return res;
}

// Parse the FFS definition and add to the cache

static
int
ffs_add_def(
  struct ubiq_platform_structured_enc_dec_obj * const e,
  cJSON * const ffs_json,
  const struct ffs ** ffs_definition)
{
  int res = 0;
  if (ffs_json) {
    struct ffs * f = NULL;
    res = ffs_create(ffs_json,  &f);
    if (!res) {
      ubiq_platform_cache_add_element(e->ffs_cache, f->name, f, &ffs_destroy);
      *ffs_definition = f;
    } else {
      // Error, so free resources.
      ffs_destroy(f);
    }
  }
  return res;
}


static
int
ffs_get_def(
  struct ubiq_platform_structured_enc_dec_obj * const e,
  const char * const ffs_name,
  const struct ffs ** ffs_definition)
{


  const char * const csu = "ffs_get_def";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";

  cJSON * json = NULL;
  char * url = NULL;
  size_t len;
  int res = 0;
  const void * rsp = NULL;
  const struct ffs * ffs = NULL;

  // The ubiq_platform_structured_enc_dec_obj was created using specific credentials,
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

        if (res == 0) {
          res = ffs_add_def(e, ffs_json, ffs_definition);
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
int u32_finalize_output_string_prealloc(
  const size_t original_data_len,
  const uint32_t * const data,
  const size_t data_len,
  const uint32_t zero_char,
  const size_t copy_back_start,
  formatted_data_type * const formatted_dest_buf
)
{
  static const char * const csu = "u32_finalize_output_string_prealloc";
  // To save a couple cycles - Use the parsed formatted destination buffer

  UBIQ_DEBUG(debug_flag, printf("%s data(%S) data_len(%d) formatted_dest_buf->len(%d) zero_char(%d)\n", csu, data, data_len, formatted_dest_buf->len, zero_char));
  int res = 0;

  // Data_len <= formatted_dest_buf.len
  
  size_t src_idx=0;
  size_t dest_idx=copy_back_start; // Start at index after any prefix and leading passthrough characters

  while (src_idx < data_len && dest_idx < formatted_dest_buf->len) {
  UBIQ_DEBUG(debug_flag, printf("%s char(%d) \n", csu, (uint32_t)((uint32_t *)formatted_dest_buf->buf)[dest_idx]));
    if (((uint32_t *)formatted_dest_buf->buf)[dest_idx] == zero_char) {
      ((uint32_t *)formatted_dest_buf->buf)[dest_idx] = data[src_idx++];
    }
    dest_idx++;
  }

  UBIQ_DEBUG(debug_flag, printf("%s dest_idx(%d) src_idx(%d) formatted_dest_buf->buf(%S)\n", csu, dest_idx, src_idx, formatted_dest_buf->buf));

  return res;
}


static
int char_finalize_output_string_prealloc(
  const size_t original_data_len,
  const char * const data,
  const size_t data_len,
  const char zero_char,
  const size_t copy_back_start,
  formatted_data_type * const formatted_dest_buf
)
{
  static const char * const csu = "char_finalize_output_string";
  // To save a couple cycles - Use the parsed formatted destination buffer

  UBIQ_DEBUG(debug_flag, printf("%s data(%s) data_len(%d) zero_char(%c) copy_back_start(%d)\n", csu, data, data_len, zero_char, copy_back_start));
  int res = 0;

  size_t src_idx=0;
  size_t dest_idx = copy_back_start;

  while (src_idx < data_len && dest_idx < formatted_dest_buf->len) {
    if (((char *)formatted_dest_buf->buf)[dest_idx] == zero_char) {
      ((char *)formatted_dest_buf->buf)[dest_idx] = data[src_idx++];
    }
    dest_idx++;
  }
  UBIQ_DEBUG(debug_flag, printf("%s formatted_dest_buf.buf(%s)\n", csu, formatted_dest_buf->buf));

  return res;
}

static
int char_structured_encrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  struct ff1_ctx * const ctx,
  const int key_number,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char * const ctbuf, size_t * const ctlen)
{
  static const char * const csu = "char_structured_encrypt_data_prealloc";
  int res = 0;
  // struct parsed_data * parsed = NULL;
  char * ct = NULL;

  trimmed_data_type trimmed_buf = {NULL, NULL, 0};
  formatted_data_type formatted_dest_buf = {ctbuf, *ctlen, 0};

  UBIQ_DEBUG(debug_flag, printf("%s start \t ptlen(%d) ctlen(%d)\n",csu, ptlen, *ctlen));

  if (*ctlen <= ptlen) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cipher text buffer is not large enough");
    *ctlen = ptlen + 1; // include NULL terminator - but returns count of actual data
  } else {
      *ctlen = ptlen;
      // CTLEN was at least as long on ptlen so has room for null terminator.
      // Set formatted to zeroth character of output characterset
      memset(formatted_dest_buf.buf, ffs_definition->output_character_set[0], *ctlen);
      ((char *)formatted_dest_buf.buf)[*ctlen] = '\0';
  }

  if (!res ) { res = CAPTURE_ERROR(enc, alloc(ptlen + 1, sizeof(char), (void **)&trimmed_buf.data), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) buf(%s)\n",csu, "alloc", res, trimmed_buf.data));
  trimmed_buf.len = ptlen + 1;
  trimmed_buf.buf = trimmed_buf.data;

  if (!res ) { res = CAPTURE_ERROR(enc, alloc(ptlen + 1, sizeof(char), (void **)&ct), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ct allocated\n",csu, "alloc", res));

  // Copy back start is after all initial passthrough characters and after an prefix characters.
  // This is the starting location for the first CT when copying back,
  if (!res) { res = CAPTURE_ERROR(enc, char_parse_data_prealloc(ffs_definition, PARSE_INPUT_TO_OUTPUT, ptbuf, ptlen, &trimmed_buf, &formatted_dest_buf), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed(%s) formatted(%s) \n",csu, "char_parse_data_prealloc", res, trimmed_buf.buf, formatted_dest_buf.buf));

  if (!res && (trimmed_buf.len < ffs_definition->min_input_length || trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  if (!res) { res = CAPTURE_ERROR(enc, ff1_encrypt(ctx, ct, trimmed_buf.buf, tweak, tweaklen), "Unable to encrypt data");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ct(%s)\n",csu, "ff1_encrypt", res, ct));

  if (!res) { res = CAPTURE_ERROR(enc, str_convert_radix(ct, ffs_definition->input_character_set, ffs_definition->output_character_set, ct), "Unable to convert to output character set");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ct(%s)\n",csu, "str_convert_radix", res, ct));

  if (!res) {res = CAPTURE_ERROR(enc, encode_keynum(ffs_definition, key_number, ct), "Unable to encode key number to cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "encode_keynum", res));

  if (!res) {res = CAPTURE_ERROR(enc, char_finalize_output_string_prealloc( ptlen, ct, strlen(ct), ffs_definition->output_character_set[0], formatted_dest_buf.first_empty_idx, &formatted_dest_buf), "Unable to produce cipher text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) \t ctbuf(%s) \t formatted_dest_buf(%s)\n",csu, "char_finalize_output_string_prealloc", res, ctbuf, formatted_dest_buf.buf));

  free(trimmed_buf.data);
  free(ct);

  return res;
}

static
int u32_structured_encrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  struct ff1_ctx * const ctx,
  const int key_number,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char * const ctbuf, size_t * const ctlen)
{
  static const char * const csu = "u32_structured_encrypt_data_prealloc";
  int res = 0;
  char * u8_ct = NULL;
  char * ctbuf_tmp = NULL;
  uint32_t * u32_ct = NULL;
  uint32_t * u32_ptbuf = NULL;
  uint8_t * u8_trimmed = NULL;
  size_t len = 0;

  // Need to allocate both of these to be u32 length
  trimmed_data_type trimmed_buf = {NULL, NULL, 0};
  formatted_data_type formatted_dest_buf = {NULL, 0, 0};

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf8_to_utf32(ptbuf, &u32_ptbuf),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s ptbuf(%s) u32_pt(%S) res(%i)\n",csu, "convert_utf8_to_utf32", ptbuf, u32_ptbuf, res));

  len = u32_strlen(u32_ptbuf);

  if (!res) { res = CAPTURE_ERROR(enc, alloc(len + 1, sizeof(uint32_t), &trimmed_buf.data), "Memory Allocation Error");}
  if (!res) { res = CAPTURE_ERROR(enc, alloc(len + 1, sizeof(uint32_t), &formatted_dest_buf.buf), "Memory Allocation Error");}

  formatted_dest_buf.len = len + 1;
  trimmed_buf.buf = trimmed_buf.data;
  trimmed_buf.len = len + 1;

  // Uint32 processing
  if (!res) { res = CAPTURE_ERROR(enc, u32_parse_data_prealloc(ffs_definition, PARSE_INPUT_TO_OUTPUT, u32_ptbuf, len, &trimmed_buf, &formatted_dest_buf  ), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed(%S) formatted(%S) \n",csu, "u32_parse_data_prealloc", res, trimmed_buf.buf, formatted_dest_buf.buf ));
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "u32_parse_data_prealloc", res));

  if (!res && (trimmed_buf.len < ffs_definition->min_input_length || trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( trimmed_buf.buf, &u8_trimmed),  "Unable to convert to UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s u32_trimmed(%S) u8_trimmed(%s) res(%i)\n",csu, "convert_utf32_to_utf8", trimmed_buf.buf, u8_trimmed, res));
  
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

  if (!res) {res = CAPTURE_ERROR(enc, u32_finalize_output_string_prealloc(ptlen, u32_ct, u32_strlen(u32_ct), ffs_definition->u32_output_character_set[0], formatted_dest_buf.first_empty_idx, &formatted_dest_buf), "Unable to produce cipher text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "u32_finalize_output_string_prealloc", res));

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( formatted_dest_buf.buf, (uint8_t **)&ctbuf_tmp),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s res(%i) ctbuf(%s)\n",csu, "convert_utf32_to_utf8", res, ctbuf_tmp));

  if (!res) {
    size_t len = u8_strlen(ctbuf_tmp);
    UBIQ_DEBUG(debug_flag, printf("%s \n \t %s len(%d) *ctlen(%d)\n",csu, "u8_strlen", len, *ctlen));
    if (len + 1> *ctlen) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Cipher text buffer is not large enough");
      *ctlen = len + 1;
    } else {
      strcpy(ctbuf, ctbuf_tmp);
      *ctlen = len;
    }
  }
  free(u8_ct);
  free(u32_ct);
  free(u32_ptbuf);
  free(u8_trimmed);
  // free(u32_finalized);
  free(formatted_dest_buf.buf);
  free(trimmed_buf.data);
  free(ctbuf_tmp);

  return res;
}


static
int char_structured_decrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char * const ptbuf, size_t * const ptlen,
  int * key_number)
{
  static const char * const csu = "char_structured_decrypt_data_prealloc";
  int res = 0;
  struct ff1_ctx * ctx = NULL;
  char * pt = NULL;

  trimmed_data_type trimmed_buf = {NULL, NULL, 0};
  formatted_data_type formatted_dest_buf = {ptbuf, *ptlen, 0};

  if (*ptlen <= ctlen) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text buffer is not large enough");
    *ptlen = ctlen + 1; // include NULL terminator - but returns count of actual data
  } else {
    *ptlen = ctlen;
    // CTLEN was at least as long on ptlen so has room for null terminator.
    ((char *)formatted_dest_buf.buf)[*ptlen] = '\0';
  }

  if (!res ) { res = CAPTURE_ERROR(enc, alloc(ctlen + 1, sizeof(char), (void **)&trimmed_buf.data), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) buf(%s)\n",csu, "alloc", res, trimmed_buf.data));
  trimmed_buf.len = ctlen;
  trimmed_buf.buf = trimmed_buf.data;

  if (!res ) { res = CAPTURE_ERROR(enc, alloc(ctlen + 1, sizeof(char), (void **)&pt), "Memory Allocation Error");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) pt allocated\n",csu, "alloc", res));

  if (!res) { res = CAPTURE_ERROR(enc, char_parse_data_prealloc(ffs_definition, PARSE_OUTPUT_TO_INPUT, ctbuf, ctlen, &trimmed_buf, &formatted_dest_buf), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed(%s) formatted(%s)\n",csu, "char_parse_data_prealloc", res, trimmed_buf.buf, formatted_dest_buf.buf));

  if (!res && (trimmed_buf.len < ffs_definition->min_input_length || trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  // decode keynum
  if (!res) { res = CAPTURE_ERROR(enc, decode_keynum(ffs_definition, trimmed_buf.buf, key_number ), "Unable to determine key number in cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) key(%d) buf(%s)\n",csu, "decode_keynum", res, *key_number, trimmed_buf.buf));

  // convert radix
  if (!res) {res = CAPTURE_ERROR(enc, str_convert_radix( trimmed_buf.buf, ffs_definition->output_character_set, ffs_definition->input_character_set, trimmed_buf.buf), "Invalid input string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed_buf.buf(%s)\n",csu, "str_convert_radix", res, trimmed_buf.buf));

  // get ctx
  if (!res) {res = get_ctx(enc, ffs_definition, key_number , &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "get_ctx", res));

  // decrypt
  if (!res) { res = CAPTURE_ERROR(enc, ff1_decrypt(ctx, pt, trimmed_buf.buf, tweak, tweaklen), "Unable to decrypt data");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) (%s)\n",csu, "ff1_decrypt", res, pt));

  if (!res) {res = CAPTURE_ERROR(enc, char_finalize_output_string_prealloc(ctlen, pt, strlen(pt), ffs_definition->input_character_set[0], formatted_dest_buf.first_empty_idx, &formatted_dest_buf), "Unable to produce plain text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ptbuf(%s)\n",csu, "char_finalize_output_string", res, ptbuf));

  free(trimmed_buf.data);
  free(pt);

  return res;
}

static
int u32_structured_decrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const struct ffs * const ffs_definition,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char * const ptbuf, size_t * const ptlen,
  int * key_number)
{
  static const char * const csu = "u32_structured_decrypt_data_prealloc";
  int res = 0;
  // size_t copy_back_start = 0;
  struct ff1_ctx * ctx = NULL;
  char * pt = NULL;

  uint32_t * u32_ctbuf = NULL;
  uint32_t * u32_pt = NULL;
  uint8_t * u8_trimmed = NULL;
  char * u8_pt = NULL;
  uint32_t * u32_finalized = NULL;

  size_t len = 0;

  // Need to allocate both of these to be u32 length
  trimmed_data_type trimmed_buf = {NULL, NULL, 0};
  formatted_data_type formatted_dest_buf = {NULL, 0,0};
  uint32_t * u32_trimmed_input_radix;

  char * ptbuf_tmp = NULL;

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf8_to_utf32(ctbuf, &u32_ctbuf),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s ctbuf(%s) u32_ctbuf(%S) res(%i)\n",csu, "convert_utf8_to_utf32", ctbuf, u32_ctbuf, res));

  len = u32_strlen(u32_ctbuf);

  if (!res) { res = CAPTURE_ERROR(enc, alloc(len + 1, sizeof(uint32_t), &trimmed_buf.data), "Memory Allocation Error");}
  if (!res) { res = CAPTURE_ERROR(enc, alloc(len + 1, sizeof(uint32_t), &formatted_dest_buf.buf), "Memory Allocation Error");}
  if (!res) { res = CAPTURE_ERROR(enc, alloc(len + 1, sizeof(uint32_t), (void**) &u32_trimmed_input_radix), "Memory Allocation Error");}

  formatted_dest_buf.len = len + 1;
  trimmed_buf.len = len + 1;
  trimmed_buf.buf = trimmed_buf.data;

  if (!res) { res = CAPTURE_ERROR(enc, u32_parse_data_prealloc(ffs_definition, PARSE_OUTPUT_TO_INPUT, u32_ctbuf, len, &trimmed_buf, &formatted_dest_buf), "Invalid input string character(s)");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed(%S) formatted(%S)\n",csu, "u32_parse_data_prealloc", res, trimmed_buf.buf, formatted_dest_buf.buf));
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s trimmed_buf.len(%i) \n",csu, "u32_parse_data_prealloc", trimmed_buf.len));

  if (!res && (trimmed_buf.len < ffs_definition->min_input_length || trimmed_buf.len > ffs_definition->max_input_length)) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Input length does not match FFS parameters");
  }

  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) \n",csu, "after", res));

  // decode keynum
  if (!res) { res = CAPTURE_ERROR(enc, u32_decode_keynum(ffs_definition, trimmed_buf.buf, key_number ), "Unable to determine key number in cipher text");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) key(%d) buf(%S)\n",csu, "u32_decode_keynum", res, *key_number, trimmed_buf.buf));

  // convert radix
  if (!res) {res = CAPTURE_ERROR(enc, u32_str_convert_u32_radix( trimmed_buf.buf, ffs_definition->u32_output_character_set, ffs_definition->u32_input_character_set, u32_trimmed_input_radix), "Invalid input string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) trimmed_buf.buf(%S)\n",csu, "u32_str_convert_u32_radix", res, trimmed_buf.buf));

  // Convert trimmed to UTF8
  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( u32_trimmed_input_radix, &u8_trimmed),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s u32_trimmed(%S) u8_trimmed(%s) res(%i)\n",csu, "convert_utf8_to_utf32", trimmed_buf.buf, u8_trimmed, res));

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
  if (!res) {res = CAPTURE_ERROR(enc, u32_finalize_output_string_prealloc(ctlen, u32_pt, u32_strlen(u32_pt), ffs_definition->u32_input_character_set[0], formatted_dest_buf.first_empty_idx, &formatted_dest_buf), "Unable to produce plain text string");}
  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i) ptbuf(%S)\n",csu, "formatted_dest_buf", res, formatted_dest_buf.buf));

  if (!res) { res = CAPTURE_ERROR(enc, convert_utf32_to_utf8( formatted_dest_buf.buf, (uint8_t **)&ptbuf_tmp),  "Unable to convert UTF8 string"); }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t %s res(%i) ptbuf(%s)\n",csu, "convert_utf32_to_utf8", res, ptbuf_tmp));
  if (!res) {
    size_t len = u8_strlen(ptbuf_tmp);
    if (len + 1> *ptlen) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Plain text buffer is not large enough");
      *ptlen = len + 1; // null terminator
    } else {
      strcpy(ptbuf, ptbuf_tmp);
      *ptlen = len;
    }
  }

  free(u32_ctbuf);
  free(u32_pt);
  free(u8_trimmed);
  free(u8_pt);
  free(u32_finalized);
  free(ptbuf_tmp);
  free(trimmed_buf.data);
  free(formatted_dest_buf.buf);
  free(u32_trimmed_input_radix);

  return res;
}

// Load the search keys for a specific FFS.  
// Will check for FFS or individual keys before adding to cache

static 
int 
  load_search_keys(
    struct ubiq_platform_structured_enc_dec_obj * const e,
    const char * const ffs_name,
    int * num_keys_loaded)
{

  const char * const csu = "load_search_keys";
  const char * const fmt = "%s/fpe/def_keys?ffs_name=%s&papi=%s";

  UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "started"));

  char * url = NULL;
  size_t len = 0;
  int res = 0;
  const void * rsp = NULL;

  const struct ffs * ffs_definition;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

  len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

  if (!res && ubiq_platform_credentials_is_idp(e->creds)) {
    ubiq_platform_sso_renewIdpCert(e->creds, e->cfg);
    size_t len = strlen(url);
    url = realloc(url, len + 1 + strlen("&payload_cert=") + strlen(ubiq_platform_credentials_get_cert_b64(e->creds)));
    strcat(url, "&payload_cert=");
    strcat(url, ubiq_platform_credentials_get_cert_b64(e->creds));
  }

  UBIQ_DEBUG(debug_flag, printf("%s url(%s)\n",csu, url));

  free(encoded_name);

  // Execute the query
  res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL, 0);


  UBIQ_DEBUG(debug_flag, printf("%s res(%d)\n",csu, res));

  if (!CAPTURE_ERROR(e, res, "Unable to process request to get Search Keys"))
    {
      // Get HTTP response code.  If not OK, return error value
      http_response_code_t rc = ubiq_platform_rest_response_code(e->rest);

      UBIQ_DEBUG(debug_flag, printf("%s http_response_code_t(%d)\n",csu, rc));


      if (rc != HTTP_RC_OK) {
        // Capture Error
        res = save_rest_error(e, e->rest, rc);
      } else {
        // Get the response payload, parse, and continue.
        cJSON * def_keys_json;
        rsp = ubiq_platform_rest_response_content(e->rest, &len);

        // UBIQ_DEBUG(debug_flag, printf("%s rsp(%s)\n",csu, rsp));
        res = (def_keys_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

        // UBIQ_DEBUG(debug_flag, printf("%s json(%s)\n",csu, cJSON_Print(def_keys_json)));

        if (res == 0 && cJSON_IsObject(def_keys_json)) {
          cJSON * top_lvl = cJSON_GetObjectItemCaseSensitive(def_keys_json, ffs_name);
          if (!cJSON_IsObject(top_lvl)) {
            printf("cJSON_GetObjectItemCaseSensitive(ffs_name\n");
            return -EINVAL;
          }

          if (ubiq_platform_credentials_is_idp(e->creds)) {
            // Make sure there isn't an existing encrypted private key.  Need to use this one.
            cJSON_DeleteItemFromObject(top_lvl, "encrypted_private_key");
            cJSON_AddStringToObject(top_lvl, "encrypted_private_key", ubiq_platform_credentials_get_encrypted_private_key(e->creds));
          }

          cJSON * ffs_json = cJSON_GetObjectItemCaseSensitive(top_lvl, "ffs");
          if (!cJSON_IsObject(ffs_json)) {
            printf("cJSON_GetObjectItemCaseSensitive(ffs\n");
            return -EINVAL;
          }

          cJSON * prv_key = cJSON_GetObjectItemCaseSensitive(top_lvl, "encrypted_private_key");
          if (!cJSON_IsString(prv_key)) {
            printf("cJSON_GetObjectItemCaseSensitive(encrypted_private_key\n");
            return -EINVAL;
          }

          cJSON * key_num = cJSON_GetObjectItemCaseSensitive(top_lvl, "current_key_number");
          if (!cJSON_IsNumber(key_num)) {
            printf("cJSON_GetObjectItemCaseSensitive(current_key_number\n");
            return -EINVAL;
          }

          cJSON * keys = cJSON_GetObjectItemCaseSensitive(top_lvl, "keys");
          if (!cJSON_IsArray(keys)) {
            printf("cJSON_GetObjectItemCaseSensitive(keys\n");
            return -EINVAL;
          }

          int key_count = cJSON_GetArraySize(keys);
          int current_key_number = cJSON_GetNumberValue(key_num);
          const char * const prvpem = cJSON_GetStringValue(prv_key);

          *num_keys_loaded = key_count;
          // Check cache first for FFS

          if (NULL == (ffs_definition = (struct ffs *)ubiq_platform_cache_find_element(e->ffs_cache, ffs_name))) {
            UBIQ_DEBUG(debug_flag, printf("%s FFS (%s) not in cache\n",csu, ffs_name));
            ffs_add_def(e, ffs_json, &ffs_definition);
          } else {
            UBIQ_DEBUG(debug_flag, printf("%s FFS (%s) already is cache\n",csu, ffs_name));
          }
            UBIQ_DEBUG(debug_flag, printf("%s key_count (%d) \n",csu, key_count));

          for (int i = 0; ((i < key_count) && (0 == res)); i++) {
            // Test cache to see if key already exists

            char * key_str = NULL;
            void * keybuf = NULL;
            size_t keylen = 0;
            struct ctx_cache_element * ctx_element = NULL;

            res = get_key_cache_string(ffs_name, i, &key_str);
            if ((0 == res) && (NULL == ubiq_platform_cache_find_element(e->ff1_ctx_cache, key_str))) {
              UBIQ_DEBUG(debug_flag, printf("%s key (%i) not in cache\n",csu, i));
              struct structured_key * k = NULL;
              res = structured_key_create(&k);
              if (!res) {

                cJSON * key = cJSON_GetArrayItem(keys, i);
                res = ubiq_platform_common_decrypt_wrapped_key(
                  prvpem, ubiq_platform_credentials_get_srsa(e->creds),
                  key->valuestring,
                  &k->buf, &k->len);

                if (!res) {
                    k->key_number = (unsigned int)i;

                    res = create_and_add_ctx_cache(e,ffs_definition, k->key_number, k, &ctx_element);

                    if (!res) {
                      // Add for the encrypt call - key_number isn't known
                      if (i == current_key_number) {
                        free(key_str);
                        res = get_key_cache_string(ffs_name, -1, &key_str);
                        if (!res) {
                          if (NULL == ubiq_platform_cache_find_element(e->ff1_ctx_cache, key_str)) {
                            UBIQ_DEBUG(debug_flag, printf("%s key (%d) not in cache\n",csu, -1));
                            res = create_and_add_ctx_cache(e,ffs_definition, -1, k, &ctx_element);
                          } else {
                            UBIQ_DEBUG(debug_flag, printf("%s key (%d) already in cache\n",csu, -1));
                          }
                        }
                      }
                    }
                  }
                }
                UBIQ_DEBUG(debug_flag, printf("%s before structured_key_destroy\n",csu));
                structured_key_destroy(k);
                UBIQ_DEBUG(debug_flag, printf("%s after structured_key_destroy\n",csu));

            } else {
              UBIQ_DEBUG(debug_flag, printf("%s key (%i) already in cache\n",csu, i));
            }
            free(key_str);
          }
          UBIQ_DEBUG(debug_flag, printf("%s End loop\n",csu));
        }
        cJSON_Delete(def_keys_json);
      }
    }
    UBIQ_DEBUG(debug_flag, printf("%s before free url\n",csu));
    free(url);
    UBIQ_DEBUG(debug_flag, printf("%s done (%i)\n",csu, res));
    return res;
}




/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/

int
ubiq_platform_structured_encrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char * const ctbuf, size_t * const ctlen)
{
  static const char * const csu = "ubiq_platform_structured_encrypt_data_prealloc";
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
      res = char_structured_encrypt_data_prealloc(enc, ffs_definition, ctx, key_number, tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
    } else {
      res = u32_structured_encrypt_data_prealloc(enc, ffs_definition, ctx, key_number, tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
    }
  }

  if (!res) {

    res = ubiq_billing_add_billing_event(
      enc->billing_ctx,
      ubiq_platform_credentials_get_papi(enc->creds),
      ffs_name, dataset_groups_name,
      ENCRYPTION,
      1, key_number );
  }


  return res;

}

int
ubiq_platform_structured_encrypt_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen)
{
  static const char * const csu = "ubiq_platform_structured_encrypt_data";
  int res = 0;
  const struct ffs * ffs_definition = NULL;
  struct ff1_ctx * ctx = NULL;
  int key_number = -1;

  char * dataset_groups_name = NULL; // TODO - change to parameter in the future for FQN

  char * buf = NULL;
  
  *ctlen = (ptlen * 4) + 1;
  if ((res = alloc(*ctlen, sizeof(uint32_t),(void **) &buf)) == 0) {
      UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "before ubiq_platform_structured_decrypt_data_prealloc", res));

      if ((res = ubiq_platform_structured_encrypt_data_prealloc(
        enc, ffs_name, tweak, tweaklen,
        ptbuf, ptlen, buf, ctlen)) == 0) {
          *ctbuf = buf;
        } else {
          UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "before free(buf)", res));
          free(buf);
          UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "after free(buf)", res));
        }
  }

  return res;

}



/**
 * @brief 
 * 
 * @param enc 
 * @param ffs_name 
 * @param tweak 
 * @param tweaklen 
 * @param ctbuf 
 * @param ctlen 
 * @param ptbuf has to be pre-allocated to a buffer.
 * @param ptlen Indicates the length of allocated buffer.  Will be set to the number of 
 * bytes of the ptbuf returned or necessary if ptbuf is not long enough
 * @return UBIQ_PLATFORM_API 
 */

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_data_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char * const ptbuf, size_t * const ptlen
)
{
  static const char * const csu = "ubiq_platform_structured_decrypt_data_prealloc";
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
      res = char_structured_decrypt_data_prealloc(enc, ffs_definition, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen, &key_number);
    } else {
      res = u32_structured_decrypt_data_prealloc(enc, ffs_definition, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen, &key_number);
    }
  }

  if (!res) {

    res = ubiq_billing_add_billing_event(
      enc->billing_ctx,
      ubiq_platform_credentials_get_papi(enc->creds),
      ffs_name, dataset_groups_name,
      DECRYPTION,
      1, key_number );
  }

  return res;

}

int
ubiq_platform_structured_decrypt_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen)
{
  static const char * const csu = "ubiq_platform_structured_decrypt_data";
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "start", res));

  // worst case but simplest for right now
  char * buf = NULL;
  
  *ptlen = (ctlen * 4) + 1;
  if (((res = alloc(*ptlen, sizeof(uint32_t),(void **) &buf)) == 0))
  {
    UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "before ubiq_platform_structured_decrypt_data_prealloc", res));
    if ((res = ubiq_platform_structured_decrypt_data_prealloc(
      enc, ffs_name, tweak, tweaklen,
      ctbuf, ctlen, buf,ptlen)) == 0) {
          *ptbuf = buf;
      } else {
        UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "before free(buf)", res));
        free(buf);
        UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "after free(buf)", res));
      }
  }

  // Reduce allocated buffer size to just the minimum.
  return res;
}

int
ubiq_platform_structured_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_structured_enc_dec_obj ** const enc) {

  struct ubiq_platform_configuration * cfg = NULL;

  ubiq_platform_configuration_load_configuration(NULL, &cfg);

  int ret = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, enc);
  ubiq_platform_configuration_destroy(cfg);
  return ret;

}

// Piecewise functions
int
ubiq_platform_structured_enc_dec_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_structured_enc_dec_obj ** const enc) {
      
    struct ubiq_platform_structured_enc_dec_obj * e;
    int res;

    // If library hasn't been initialized, fail fast.
    if (!ubiq_platform_initialized()) {
      return -EINVAL;
    }

    // This function will actually create and initialize the object
    res = ubiq_platform_structured_encryption(creds, cfg, &e);

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_structured_enc_dec_destroy(e);
    }

    return res;

}




void
ubiq_platform_structured_enc_dec_destroy(
    struct ubiq_platform_structured_enc_dec_obj * const e)
{
  const char * const csu = "ubiq_platform_structured_enc_dec_destroy";

  if (e) {

    // Need to make sure billing ctx is destroyed before other objects
    ubiq_billing_ctx_destroy(e->billing_ctx);
    ubiq_platform_rest_handle_destroy(e->rest);
    free(e->restapi);
    // free(e->papi);
    free(e->encoded_papi);
    // free(e->srsa);
    ubiq_platform_cache_destroy(e->ffs_cache);
    ubiq_platform_cache_destroy(e->ff1_ctx_cache);
    ubiq_platform_cache_destroy(e->stuctured_key_cache);
    ubiq_platform_credentials_destroy(e->creds);
    ubiq_platform_configuration_destroy(e->cfg);

    free(e->encrypted_private_key.buf);
    free(e->error.err_msg);
  }
  free(e);
}

int
ubiq_platform_structured_get_last_error(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
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

/*
*/
int
ubiq_platform_structured_encrypt_data_for_search_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctbuflen , size_t * const count
)
{
  static const char * const csu = "ubiq_platform_structured_encrypt_data_for_search_prealloc";
  const struct ffs * ffs_definition = NULL;
  struct ff1_ctx * ctx = NULL;
  // int key_number = -1;
  int res = 0;
  // char ** ret_ct = NULL;
  char * dataset_groups_name = NULL; // TODO - change to parameter in the future for FQN

  int key_count = 0;
  res = load_search_keys(enc, ffs_name, &key_count);

  if (*count < key_count) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Numbe of cipher text buffers is not large enough to hold all results");
  }
  *count = key_count;

  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "start", res));

  // Get the FFS Definition
  if (!res) {res = ffs_get_def(enc, ffs_name, &ffs_definition);}
  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "ffs_get_def", res));

  for (int i = 0; !res && i < key_count; i++) {
    size_t len = *ctbuflen;
    int x = i;
    if (!res) {res = get_ctx(enc, ffs_definition, &x , &ctx);}
    UBIQ_DEBUG(debug_flag, printf("%s i(%d) x(%d) res(%d)\n", csu, i, x, res));

    if (!res) {
      if (ffs_definition->character_types == UINT8) {
        res = char_structured_encrypt_data_prealloc(enc, ffs_definition, ctx, i, tweak, tweaklen, ptbuf, ptlen,  ctbuf[i], &len);
        UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) ctbuf[i](%s)\n", csu, "char_structured_encrypt_data_prealloc", res, ctbuf[i]));
        // If there was a failure and ctbuflen was not large enough, return how big the buffer needs to be
        if (!res && len > *ctbuflen) {
          *ctbuflen = len;
        }
      } else {
        res = u32_structured_encrypt_data_prealloc(enc, ffs_definition, ctx, i, tweak, tweaklen, ptbuf, ptlen, ctbuf[i], &len);
        UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) ret_ct[i](%s)\n", csu, "u32_structured_encrypt_data_prealloc", res, ctbuf[i]));
      }
    }

    // char_structured_encrypt_data does not add billing event - ubiq_platform_structured_enc_dec_obj adds billing but does not accept key number.
    // Therefore, need to add billing records here

    if (!res) {
      res = ubiq_billing_add_billing_event(
        enc->billing_ctx,
        ubiq_platform_credentials_get_papi(enc->creds),
        ffs_name, dataset_groups_name,
        ENCRYPTION,
        1, i );
    }
  }

  if (res) {
    *count = 0;
  }

  return res;
}

// Bulk version
int
ubiq_platform_structured_encrypt_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char *** const ctbuf, size_t * const count
)
{
  static const char * const csu = "ubiq_platform_structured_encrypt_data_for_search";
  const struct ffs * ffs_definition = NULL;
  struct ff1_ctx * ctx = NULL;
  // int key_number = -1;
  int res = 0;
  char ** ret_ct = NULL;
  // char * dataset_groups_name = NULL; // TODO - change to parameter in the future for FQN

  size_t ctbuflen = ptlen + 1;
  int key_count = 0;
  res = load_search_keys(enc, ffs_name, &key_count);

  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) key_count(%d)\n", csu, "start", res, key_count));

  // Get the FFS Definition
  if (!res) {res = ffs_get_def(enc, ffs_name, &ffs_definition);}
  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d)\n", csu, "ffs_get_def", res));

  // Get the ctx and the key number for the current key

  

  // Loop over all keys up to the current key, and encrypt the data using each key
  if (!res) {
    *count = key_count;
    // Single alloc of array and the space in the array.  Still need to point array to the available location
    // Need something slightly different for u32

    ret_ct = (char **)calloc(*count, sizeof(char*));
    UBIQ_DEBUG(debug_flag, printf("%s ret_ct(%p) \n", csu, ret_ct));
    if (!ret_ct) {
      res = -ENOMEM;
    } else {
      for (int i = 0; i < *count; i++) {
        ret_ct[i] = (char *)calloc((ptlen * 4)+ 1, sizeof(char)); // ret_ct + offset + i * ctbuflen ;
        UBIQ_DEBUG(debug_flag, printf("%s ret_ct[%d](%p) \n", csu, i, ret_ct[i]));
      }
      ctbuflen = (ptlen * 4) + 1;
    }
  }

  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) key_count(%d)\n", csu, "alloc", res, key_count));
  res = ubiq_platform_structured_encrypt_data_for_search_prealloc(
    enc, ffs_name, tweak, tweaklen,
    ptbuf, ptlen, ret_ct, &ctbuflen, count);
  
  UBIQ_DEBUG(debug_flag, printf("%s %s res(%d) ctbuflen(%d) count(%d)\n", csu, "ubiq_platform_structured_encrypt_data_for_search_prealloc", res, ctbuflen, *count));

  for (int i = 0; i < key_count; i++) {
    UBIQ_DEBUG(debug_flag, printf("%s key(%d) ret_ct(%s)\n", csu, i, ret_ct[i]));

  }

  if (res) {
    for (int i = 0; i < key_count; i++) {
      free(ret_ct[i]);
      ret_ct = NULL;
    }
    *count = 0;
  }
  *ctbuf = ret_ct;

  return res;
}


int
ubiq_platform_structured_enc_dec_get_copy_of_usage(
    struct ubiq_platform_structured_enc_dec_obj * const obj,
    char ** const buffer, size_t * const buffer_len) {

      if (obj == NULL || buffer == NULL || buffer_len == NULL) {
        return -EINVAL;
      }
      return ubiq_billing_get_copy_of_usage(obj->billing_ctx, buffer, buffer_len);
    }

int
ubiq_platform_structured_enc_dec_add_user_defined_metadata(
    struct ubiq_platform_structured_enc_dec_obj * const obj,
    const char * const jsonString)
{

      if (obj == NULL || jsonString == NULL) {
      return -EINVAL;
    }

    return ubiq_billing_add_user_defined_metadata(obj->billing_ctx,jsonString);
}


