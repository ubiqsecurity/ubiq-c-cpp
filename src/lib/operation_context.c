#include "ubiq/platform.h"


#include "ubiq/platform/internal/operation_context.h"
#include "ubiq/platform/internal/hashtable32.h"
#include "ubiq/platform/internal/dataset.h"

#include <stdlib.h>
#include <string.h>
#include <unistr.h>
#include <stdio.h>
#include <unistdio.h>

// #include <wchar.h>

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

/**************************************************************************************
 *
 * Constants
 *
**************************************************************************************/

const char32_t * const OPERATION_CONTEXT_PASSTHROUGH_TEMPLATE = U"PassthroughTemplate";
const char32_t * const OPERATION_CONTEXT_SUFFIX = U"Suffix";
const char32_t * const OPERATION_CONTEXT_PREFIX = U"Prefix";


/**************************************************************************************
 *
 * Structures
 *
************************************** ************************************************/

// typedef struct ubiq_platform_dataset {
//  int x;
// } ubiq_platform_dataset_t;

// All strings going to u32 (char32_t) representations
typedef struct ubiq_platform_operation_context {
  const ubiq_platform_dataset_t * dataset; // reference to an external object - do not free
  int key_number;
  int is_encrypt; // Whether this is doing an encrypt or decrypt, not whether the dataset can encrypt
  ubiq_platform_tweak_t * user_supplied_tweak;
  char32_t * original_value; // Memory managed here, null terminated
  char32_t * current_value; // Memory managed here, null terminated
  ubiq_platform_ff1_cache_t * ff1_ctx_cache; // reference to an external object - do not free - contains the structured_key_cache
  //ubiq_platform_structured_key_cache_t * stuctured_key_cache; // reference to an external object - do not free
  ubiq_platform_hashtable32 * data; // Memory managed here (key char32_t / value char32_t)
  
  // Passed in during creation.  Do not create or destroy
  ubiq_platform_error_t * error;
  // struct {
  //           char * err_msg;
  //           size_t err_num;
  //   } error;
} ubiq_platform_operation_context_t;

// typedef struct ctx_cache_element {
//   void * ff1_ctx;
//   unsigned int key_number;
// } ctx_cache_element_t;

// // wrapped_data_key is in base64
// // decrypted_data_key is byte array
// // decrypted_data_key will have length 0 if key_caching is stored encrypted and it needs to be decrypted
// // each time.
// typedef struct cached_key {
//   ubiq_key_t wrapped_data_key, decrypted_data_key;
//   unsigned int key_number;
// } cached_key_t;

/**************************************************************************************
 *
 * Static functions definitions
 *
**************************************************************************************/

static
int
get_key_cache_string(const char32_t * const ffs_name,
  const int key_number,
  char32_t ** const str);

/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/

int ubiq_platform_operation_context_create(
    ubiq_platform_error_t * const error_buffer,
    ubiq_platform_operation_context_t ** const ctx) {
  int res = -ENOMEM;
  ubiq_platform_operation_context_t * c = NULL;

  c = calloc(1, sizeof(*c));
  if (c) {
    ubiq_platform_ht32_create(20, &(c->data));
    c->key_number = -1; // Not Yet Set
    // c->is_encrypt = -1; // Not Yet Set
    c->user_supplied_tweak = calloc(1, sizeof(ubiq_platform_tweak_t));
    c->user_supplied_tweak->buf = NULL;
    c->user_supplied_tweak->len = 0;
    UBIQ_DEBUG(debug_flag, printf("c->user_supplied_tweak  NULL?(%d)\n", c->user_supplied_tweak  == NULL));
    UBIQ_DEBUG(debug_flag, printf("c->user_supplied_tweak->len(%d)\n",  c->user_supplied_tweak->len));
    UBIQ_DEBUG(debug_flag, printf("c->user_supplied_tweak->buf NULL?(%d)\n",  c->user_supplied_tweak->buf == NULL));

    c->error = error_buffer;
    *ctx = c;
    res = 0;
  }

  return res;
}

void ubiq_platform_operation_context_destroy(ubiq_platform_operation_context_t * const ctx) {
  
  if (ctx) {
    free(ctx->original_value);
    free(ctx->current_value);
    ubiq_platform_ht32_destroy(ctx->data, &free);
    free(ctx->user_supplied_tweak->buf);
    free(ctx->user_supplied_tweak);
    // free(ctx->error.err_msg);
    free(ctx);
  }
}


ubiq_platform_ff1_cache_t * const ubiq_platform_operation_context_get_ffx_cache(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->ff1_ctx_cache;
}

ubiq_platform_dataset_t const * const ubiq_platform_operation_context_get_dataset(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->dataset;
}

int const ubiq_platform_operation_context_get_key_number(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->key_number;
}

int const ubiq_platform_operation_context_set_key_number(ubiq_platform_operation_context_t  * const ctx, const int keyNumber) {
  ctx->key_number = keyNumber;
  return 0;
}

ubiq_platform_tweak_t const * const ubiq_platform_operation_context_get_user_supplied_tweak(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->user_supplied_tweak;
}

int ubiq_platform_operation_context_set_user_supplied_tweak(ubiq_platform_operation_context_t * const ctx, const uint8_t * const tweak, const size_t tweaklen) {
  int res = 0;

//  ubiq_platform_tweak_t * t = NULL;
 
//  t = calloc(1, sizeof(*t) + tweaklen * sizeof(uint8_t));
//  if (t) {

  free(ctx->user_supplied_tweak->buf);
  ctx->user_supplied_tweak->len = tweaklen;
  if (tweak) {
    if (NULL != (ctx->user_supplied_tweak->buf = calloc(1, tweaklen * sizeof(uint8_t)))) {
      memcpy(ctx->user_supplied_tweak->buf, tweak, tweaklen);
    } else {
      res = -ENOMEM;
    }
  }
  // Point buf to the memory immediately following the struct
  // t->buf = (uint8_t *) (t + 1);
  // memcpy(t->buf, tweak, t->len);
  // ctx->user_supplied_tweak = t;
 return res;
}


int const ubiq_platform_operation_context_get_is_encrypt(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->is_encrypt;
}

int ubiq_platform_operation_context_set_is_encrypt(ubiq_platform_operation_context_t  * const ctx, int isEncrypt) {
  ctx->is_encrypt = isEncrypt;
  return 0;
}

char32_t const * const ubiq_platform_operation_context_get_original_value(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->original_value;
}

char32_t const * const ubiq_platform_operation_context_get_current_value(const ubiq_platform_operation_context_t  * const ctx) {
  return ctx->current_value;
}

// struct ubiq_platform_hashtable * const getData(const operation_context_t  * const ctx) {
//   return ctx->data;
// }

int ubiq_platform_operation_context_set_ffx_cache(ubiq_platform_operation_context_t  * const ctx, 
  ubiq_platform_ff1_cache_t * const cache) {
  ctx->ff1_ctx_cache = cache;
  return 0;
}

int setDataset(ubiq_platform_operation_context_t  * const ctx, ubiq_platform_dataset_t * const dataset) {
  ctx->dataset = dataset;
}

int ubiq_platform_operation_context_set_current_value(ubiq_platform_operation_context_t  * const ctx, char32_t const * const value) {
  // This should be deep copy
  int res = -ENOMEM;
  // Free an existing value (if there is one)
  if (ctx->current_value) {
    free(ctx->current_value);
  }
  UBIQ_DEBUG(debug_flag, printf("value: %S\n", value));
  ctx->current_value = u32_strdup(value);
  UBIQ_DEBUG(debug_flag, printf("current_value: %S\n", ctx->current_value));
  if (ctx->current_value) {
    res = 0;
  }
  return res;
}

int ubiq_platform_operation_context_set_original_value(ubiq_platform_operation_context_t  * const ctx, char32_t const * const value) {
  // This should be deep copy
  int res = -ENOMEM;
  ctx->original_value = u32_strdup(value);
  if (ctx->original_value) {
    res = 0;
  }
  return res;
}

char32_t const * const ubiq_platform_operation_context_get_data_value(const ubiq_platform_operation_context_t  * const ctx, char32_t const * const key) {
  return ubiq_platform_ht32_get(ctx->data, key);
}

int ubiq_platform_operation_context_put_data_value(const ubiq_platform_operation_context_t  * const ctx, char32_t const * const key, char32_t const * const value) {
  static const char * csu = "ubiq_platform_operation_context_put_data_value";
  int res = -ENOMEM;
  void * existingData = NULL;
  char32_t * v = u32_strdup(value);
  if (v) {
    res = ubiq_platform_ht32_put(ctx->data, key, v, &existingData);
    if (existingData) {
      UBIQ_DEBUG(debug_flag, printf("%s Existing %S\n", csu, (uint32_t *)existingData));
      free(existingData);
    }
  }
  return res;
}

int ubiq_platform_operation_context_set_dataset(ubiq_platform_operation_context_t * const ctx, ubiq_platform_dataset_t const * const dataset) {
  int res = -EINVAL;
  if (dataset != NULL) {
    ctx->dataset = dataset;
    res = 0;
  }
  
  return res;

}

void ubiq_platform_operation_context_capture_error(ubiq_platform_operation_context_t * const ctx, int const res, char const * const msg) {
  if (res && ctx->error) {
    ctx->error->err_num = res;
    if (ctx->error->err_msg) {
      free(ctx->error->err_msg);
    }
    if (!msg || *msg == '\0') {
      ctx->error->err_msg = malloc(128);
      strerror_r(abs(ctx->error->err_num), ctx->error->err_msg, 128);
    } else {
      ctx->error->err_msg = strdup(msg);
    }
  }
}

/**************************************************************************************
 *
 * Static functions body
 *
**************************************************************************************/

static
int
get_key_cache_string(char32_t const * const ffs_name,
  const int key_number,
  char32_t ** const str) 
{
  size_t key_len = u32_strlen((uint32_t const * const )ffs_name) + 25; // magic number to accommodate a max int plus null terminator and colon
  char32_t * key_str = calloc(key_len + 1, sizeof(char32_t));

  u32_snprintf(key_str, key_len, "%S:%d", ffs_name, key_number);

  *str = key_str;
  return 0;
}