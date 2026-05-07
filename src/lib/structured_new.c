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
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/structured_private.h"

#include "ubiq/platform/internal/ff1_cache.h"
#include "ubiq/platform/internal/operation_context.h"
#include "ubiq/platform/internal/encryption_pipeline.h"
#include "ubiq/platform/internal/decryption_pipeline.h"

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

static int debug_flag = 0;

// Need to capture value of res, not test value
// since it may be a function and don't want it to get executed
// more than once
#define MSG_SIZE 128
#define CAPTURE_ERROR(e,res,msg) ({ \
  int result = res; \
  if (result) { \
    e->error->err_num = result; \
    if (e->error->err_msg) { \
      free (e->error->err_msg); \
    } \
    if (!msg) { \
      e->error->err_msg = malloc(MSG_SIZE); \
      strerror_r(abs(e->error->err_num), e->error->err_msg, MSG_SIZE); \
    } else { \
      e->error->err_msg = strdup(msg); \
    } \
  } \
  result; \
})


/**************************************************************************************
 *
 * Structures
 *
**************************************************************************************/


struct ubiq_platform_structured_enc_dec_obj
{
    ubiq_platform_error_t * error;

    ubiq_platform_ff1_cache_t * ff1_ctx_cache;
    ubiq_platform_dataset_cache_t * dataset_cache;
    ubiq_platform_structured_key_cache_t * key_cache;

    struct ubiq_billing_ctx * billing_ctx;

};


/**************************************************************************************
 *
 * Static functions
 *
**************************************************************************************/

static int load_search_keys(
    struct ubiq_platform_structured_enc_dec_obj * const enc,
    char const ** const dataset_names, size_t const count)
{
  int res = 0;
  
  // Use the FF1 cache to load the search keys since this is what 
  // actually needs to be loaded.  It also has access to the
  // dataset cache and the structured key cache.
  res = ubiq_platform_ff1_cache_load_def_keys(enc->ff1_ctx_cache, dataset_names, count);

  return res;
}




static int ubiq_platform_structured_encryption(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const config,
    struct ubiq_platform_structured_enc_dec_obj ** const enc)
{
    static const char * const csu = "ubiq_platform_structured_encryption";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_structured_enc_dec_obj * e = NULL;
    size_t len;
    int res;
    res = -ENOMEM;

    const char * const host = ubiq_platform_credentials_get_host(creds);

    e = calloc(1, sizeof(*e));
    if (e) {

      e->error = calloc(1, sizeof(ubiq_platform_error_t));
      res = ubiq_platform_dataset_cache_create(
        creds, config, e->error, &e->dataset_cache);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_dataset_cache_create res(%d) err(%s) num(%d)\n", csu, res,e->error->err_msg, e->error->err_num));
      
      res = ubiq_platform_structured_key_cache_create(
        creds, config, e->error, &e->key_cache);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_structured_key_cache_create res(%d)\n", csu, res));

      res = ubiq_platform_ff1_cache_create(
        creds, config, e->dataset_cache, e->key_cache, e->error, &e->ff1_ctx_cache);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_ff1_cache_create res(%d)\n", csu, res));

      if (!res) {
        res = ubiq_billing_ctx_create(&e->billing_ctx, host, 
              ubiq_platform_credentials_get_papi(creds),
              ubiq_platform_credentials_get_sapi(creds), config);
      }
    }

    if (res) {
      ubiq_platform_structured_enc_dec_destroy(e);
      e = NULL;
    }

    *enc = e;
    return res;
}

static 
int get_dataset_current_key_number(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  int * const key_number
)
{
  struct ff1_ctx * ff1_ctx = NULL;

  int res = ubiq_platform_ff1_cache_get_ff1_ctx(enc->ff1_ctx_cache,
        dataset_name,
        key_number,
        &ff1_ctx);
  return res;
}

static int encrypt_pipeline(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const int key_number,
  const uint8_t * const tweak, const size_t tweaklen,
  const char32_t * const ptbuf, const size_t ptlen,
  char32_t ** const ctbuf, size_t * const ctlen
)
{
  int debug_flag = 0;
  const char * const csu = "encrypt_pipeline";
  int res = -EINVAL;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_encryption_pipeline_t * pipeline = NULL;

  res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_dataset_cache_get_dataset res(%d) \n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_create res(%d) \n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_key_number(ctx, key_number);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_key_number res(%d) \n", csu,res));

  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_dataset res(%d) \n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_ffx_cache res(%d) \n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_is_encrypt res(%d) \n", csu,res));

  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ptbuf);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_current_value res(%d) \n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ptbuf);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_original_value res(%d) \n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_user_supplied_tweak res(%d) \n", csu,res));

  if (!res) {
    pipeline = ubiq_platform_encryption_pipeline_create(dataset);
  }
  if (pipeline) {
    res = ubiq_platform_encryption_pipeline_invoke(pipeline, ctx);
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_encryption_pipeline_invoke res(%d) \n", csu,res));
    if (!res) {
      *ctbuf = u32_strdup(ubiq_platform_operation_context_get_current_value(ctx));
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    dataset_name, dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_encryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}


static int validate_encrypt_int(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  int32_t const pt,
  ubiq_platform_dataset_t const ** dataset_ret)
{
  // Make sure the data can be used to encrypt
  // Validate dataset type
  // Validate pt value
  // Returns the dataset if valid
  // Will capture errors
  int res = 0;
  ubiq_platform_dataset_t const * d = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  const char * const csu = "validate_encrypt_int";

  res = CAPTURE_ERROR(enc, ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &d), "Unable to retrieve dataset");

  // Returns true if can encrypt, so logic looks a little different
  if (!res && !(ubiq_platform_dataset_get_can_encrypt(d))) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to encrypt");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot encrypt for this dataset\n", csu,res));
  }
  if (!res && (strcmp(ubiq_platform_dataset_get_data_type(d), DATA_TYPE_INTEGER) != 0)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset is not for encrypting integers");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != INTEGER \n", csu,res));
  }
  if (!res && ((data_type_config = ubiq_platform_dataset_get_data_type_config(d)) == NULL)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Unabled to fetch data_type_config for the dataset");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
  }
  if (!res && 32 != ubiq_platform_data_type_config_get_size(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "dataset size is not 32");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) get_size != 32 \n", csu,res));
  }
  if (!res && pt < ubiq_platform_data_type_config_get_min_input_value(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text is less than the dataset minimum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt < min_value\n", csu,res));
  }
  if (!res && pt > ubiq_platform_data_type_config_get_max_input_value(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text is greater than the dataset maximum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt > min_value\n", csu,res));
  }

  if (!res) {
    *dataset_ret = d;
  }

  return res;
}



// Pass in ptbuf as a char32_t since this is same code for search and no 
// reason to execute conversion each time through the loop
static int encrypt_int_pipeline(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  ubiq_platform_dataset_t const * const dataset,
  const uint8_t * const tweak, const size_t tweaklen,
  const int32_t pt, // For negative sign
  char32_t * ptbuf,
  int key_number,
  int32_t * ct)
{
  const char * const csu = "encrypt_int_pipeline";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_encryption_pipeline_t * pipeline = NULL;
  // size_t min_len = 0;
  int isNegative = (pt < 0);

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);}
  if (!res) {res = ubiq_platform_operation_context_set_key_number(ctx, key_number);}

  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));
  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  if (!res) {
    pipeline = ubiq_platform_encryption_pipeline_create(dataset);
  }
  UBIQ_DEBUG(debug_flag, printf("%s res(%d)\n", csu, res));
  if (pipeline) {
    res = ubiq_platform_encryption_pipeline_invoke(pipeline, ctx);
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: value(%Ls) \n", csu, value));
      UBIQ_DEBUG(debug_flag, printf("%s: output_chars(%Ls) \n", csu, ubiq_platform_dataset_get_output_characters(dataset)));
      UBIQ_DEBUG(debug_flag, printf("%s: input_chars(%Ls) \n", csu, ubiq_platform_dataset_get_input_characters(dataset)));
      char32_t * b10_value = calloc(25, sizeof(char32_t));
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)value, (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), 1, 0, (uint32_t*)b10_value);
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) b10_value(%s)\n", csu, res, b10_value));

      int64_t tmp = wcstol((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == value || tmp < INT32_MIN || tmp > INT32_MAX) {
        res = -EINVAL;
      } else {
        *ct = tmp;
      }
      if (!res && isNegative) {
        *ct = -1 * *ct;
      }
      free(b10_value);
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    ubiq_platform_dataset_get_name(dataset), 
    dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_encryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}

static int validate_encrypt_long(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  int64_t const pt,
  ubiq_platform_dataset_t const ** dataset_ret)
{
  // Make sure the data can be used to encrypt
  // Validate dataset type
  // Validate pt value
  // Returns the dataset if valid
  // Will capture errors
  int res = 0;
  ubiq_platform_dataset_t const * d = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  const char * const csu = "validate_encrypt_long";

  res = CAPTURE_ERROR(enc, ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &d), "Unable to retrieve dataset");

  // Returns true if can encrypt, so logic looks a little different
  if (!res && !(ubiq_platform_dataset_get_can_encrypt(d))) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to encrypt");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot encrypt for this dataset\n", csu,res));
  }
  if (!res && (strcmp(ubiq_platform_dataset_get_data_type(d), DATA_TYPE_INTEGER) != 0)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset is not for encrypting integers");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != INTEGER \n", csu,res));
  }
  if (!res && ((data_type_config = ubiq_platform_dataset_get_data_type_config(d)) == NULL)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Unabled to fetch data_type_config for the dataset");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
  }
  if (!res && 64 != ubiq_platform_data_type_config_get_size(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "dataset size is not 64");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) get_size != 64 \n", csu,res));
  }
  if (!res && pt < ubiq_platform_data_type_config_get_min_input_value(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plaint text is less than the dataset minimum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt < min_value\n", csu,res));
  }
  if (!res && pt > ubiq_platform_data_type_config_get_max_input_value(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plaint text is greater than the dataset maximum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt > min_value\n", csu,res));
  }

  if (!res) {
    *dataset_ret = d;
  }

  return res;
}

// Pass in ptbuf as a char32_t since this is same code for search and no 
// reason to execute conversion each time through the loop
static int encrypt_long_pipeline(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  ubiq_platform_dataset_t const * const dataset,
  const uint8_t * const tweak, const size_t tweaklen,
  const int64_t pt, // For negative sign
  char32_t * ptbuf,
  int key_number,
  int64_t * ct)
{
  const char * const csu = "encrypt_long_pipeline";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_encryption_pipeline_t * pipeline = NULL;
  // size_t min_len = 0;
  int isNegative = (pt < 0);

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);}
  if (!res) {res = ubiq_platform_operation_context_set_key_number(ctx, key_number);}

  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));
  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  if (!res) {
    pipeline = ubiq_platform_encryption_pipeline_create(dataset);
  }
  UBIQ_DEBUG(debug_flag, printf("%s res(%d)\n", csu, res));
  if (pipeline) {
    res = ubiq_platform_encryption_pipeline_invoke(pipeline, ctx);
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_encryption_pipeline_invoke res(%d)\n", csu, res));
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: value(%Ls) \n", csu, value));
      UBIQ_DEBUG(debug_flag, printf("%s: output_chars(%Ls) \n", csu, ubiq_platform_dataset_get_output_characters(dataset)));
      UBIQ_DEBUG(debug_flag, printf("%s: input_chars(%Ls) \n", csu, ubiq_platform_dataset_get_input_characters(dataset)));
      char32_t * b10_value = calloc(25, sizeof(char32_t));
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)value, (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), 1, 0, (uint32_t*)b10_value);
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) b10_value(%S)\n", csu, res, b10_value));

      int64_t tmp = wcstoll((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == value || tmp < INT64_MIN || tmp > INT64_MAX) {
        res = -EINVAL;
      } else {
        *ct = tmp;
      }
      if (!res && isNegative) {
        *ct = -1 * *ct;
      }
      free(b10_value);
    }
  } else {
    res = -EACCES;
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ct(%ld)\n", csu, res, *ct));

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    ubiq_platform_dataset_get_name(dataset), 
    dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_encryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}

static int validate_encrypt_date(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  time_t const pt_tm,
  ubiq_platform_dataset_t const ** dataset_ret)
{
    int debug_flag = 1;

  // Make sure the data can be used to encrypt
  // Validate dataset type
  // Validate pt value
  // Returns the dataset if valid
  // Will capture errors
  int res = 0;
  ubiq_platform_dataset_t const * d = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  const char * const csu = "validate_encrypt_date";

  res = CAPTURE_ERROR(enc, ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &d), "Unable to retrieve dataset");

  if (!res && !ubiq_platform_dataset_get_can_encrypt(d)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to encrypt");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot encrypt for this dataset\n", csu,res));
  }

  if (strcmp(ubiq_platform_dataset_get_data_type(d), DATA_TYPE_DATE) != 0) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset is not for encrypting dates");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != DATE \n", csu,res));
  }

  if (!res) {
    data_type_config = ubiq_platform_dataset_get_data_type_config(d);
    if (data_type_config == NULL) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Unabled to fetch data_type_config for the dataset");
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
    }
  }

  if (!res && 
   (0 > difftime(pt_tm, ubiq_platform_data_type_config_get_min_input_date_value_as_time_t(data_type_config)))) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text is less than the dataset minimum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt < min_value\n", csu,res));
  }

  if (!res && 
       (0 < difftime(pt_tm, ubiq_platform_data_type_config_get_max_input_date_value_as_time_t(data_type_config)))) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text is greater than the dataset maximum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt > max_value\n", csu,res));
  }

  if (!res) {
    *dataset_ret = d;
  }

  return res;
}


// Pass in ptbuf as a char32_t since this is same code for search and no 
// reason to execute conversion each time through the loop
static int encrypt_date_pipeline(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  ubiq_platform_dataset_t const * const dataset,
  const uint8_t * const tweak, const size_t tweaklen,
  int const is_negative,  // For negative sign
  char32_t * ptbuf, // Already in ICS and padded
  int key_number,
  struct tm * const ct)
{
  int debug_flag = 1;
  const char * const csu = "encrypt_date_pipeline";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_encryption_pipeline_t * pipeline = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);}
  if (!res) {res = ubiq_platform_operation_context_set_key_number(ctx, key_number);}

  data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);

  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));

  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  if (!res) {
    pipeline = ubiq_platform_encryption_pipeline_create(dataset);
  }

  UBIQ_DEBUG(debug_flag, printf("%s res(%d)\n", csu, res));
  if (pipeline) {
    res = ubiq_platform_encryption_pipeline_invoke(pipeline, ctx);
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_encryption_pipeline_invoke res(%d)\n", csu, res));
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: value:ct(%S) \n", csu, value));
      UBIQ_DEBUG(debug_flag, printf("%s: output_chars(%Ls) \n", csu, ubiq_platform_dataset_get_output_characters(dataset)));
      UBIQ_DEBUG(debug_flag, printf("%s: input_chars(%Ls) \n", csu, ubiq_platform_dataset_get_input_characters(dataset)));

      // We can go from OCS to Base10 directly
      char32_t * b10_value = calloc(25, sizeof(char32_t));
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)value, (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), L"0123456789", 1, 0, (uint32_t*)b10_value);
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) b10_value(%S)\n", csu, res, b10_value));

      int64_t tmp = wcstoll((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == value || tmp < INT64_MIN || tmp > INT64_MAX) {
        res = -EINVAL;
      } 
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) tmp(%lld)\n", csu, res, tmp));

      if (!res && is_negative) {
        tmp = -1 * tmp;
      }
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) tmp(%lld)    is_negative(%d)\n", csu, res, tmp, is_negative));
      free(b10_value);
      if (!res) {
        struct tm * ct_local;
        tmp = (tmp * 86400) + ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config);
        UBIQ_DEBUG(debug_flag, printf("%s: res(%d) tmp:seconds (%lld)\n", csu, res, tmp));
        ct_local = localtime_r(&tmp, ct);
      }
    }
  } else {
    res = -EACCES;
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ct(%ld)\n", csu, res, *ct));

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    ubiq_platform_dataset_get_name(dataset), 
    dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_encryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}

static int validate_encrypt_datetime(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  time_t const pt_tm,
  ubiq_platform_dataset_t const ** dataset_ret)
{
  int debug_flag = 1;
  // Make sure the data can be used to encrypt
  // Validate dataset type
  // Validate pt value
  // Returns the dataset if valid
  // Will capture errors
  int res = 0;
  ubiq_platform_dataset_t const * d = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  const char * const csu = "validate_encrypt_date";

  res = CAPTURE_ERROR(enc, ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &d), "Unable to retrieve dataset");

  if (!res && !ubiq_platform_dataset_get_can_encrypt(d)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to encrypt");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot encrypt for this dataset\n", csu,res));
  }

  if (strcmp(ubiq_platform_dataset_get_data_type(d), DATA_TYPE_DATETIME) != 0) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset is not for encrypting dates");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != DATE \n", csu,res));
  }

  if (!res) {
    data_type_config = ubiq_platform_dataset_get_data_type_config(d);
    if (data_type_config == NULL) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Unabled to fetch data_type_config for the dataset");
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
    }
  }

  if (!res && 
   (0 > difftime(pt_tm, ubiq_platform_data_type_config_get_min_input_date_value_as_time_t(data_type_config)))) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text is less than the dataset minimum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt < min_value\n", csu,res));
  }

  if (!res && 
       (0 < difftime(pt_tm, ubiq_platform_data_type_config_get_max_input_date_value_as_time_t(data_type_config)))) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Plain text is greater than the dataset maximum value");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) pt > max_value\n", csu,res));
  }

  if (!res) {
    *dataset_ret = d;
  } else {
    int err_num;
    char * err_msg;
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
  }
  UBIQ_DEBUG(debug_flag, printf("%s: enc res(%d)\n", csu,res));

  return res;
}

// Pass in ptbuf as a char32_t since this is same code for search and no 
// reason to execute conversion each time through the loop
static int encrypt_datetime_pipeline(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  ubiq_platform_dataset_t const * const dataset,
  const uint8_t * const tweak, const size_t tweaklen,
  int isNegative,  // For negative sign
  char32_t * ptbuf, // Already in ICS and padded
  int key_number,
  struct tm * const ct)
{
  static int debug_flag = 1;
  const char * const csu = "encrypt_datetime_pipeline";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_encryption_pipeline_t * pipeline = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 1);}
  if (!res) {res = ubiq_platform_operation_context_set_key_number(ctx, key_number);}

  data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);

  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));

  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ptbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  if (!res) {
    pipeline = ubiq_platform_encryption_pipeline_create(dataset);
  }
  UBIQ_DEBUG(debug_flag, printf("%s res(%d)\n", csu, res));
  if (pipeline) {
    res = ubiq_platform_encryption_pipeline_invoke(pipeline, ctx);
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_encryption_pipeline_invoke res(%d)\n", csu, res));
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: value:ct(%S) \n", csu, value));
      UBIQ_DEBUG(debug_flag, printf("%s: output_chars(%Ls) \n", csu, ubiq_platform_dataset_get_output_characters(dataset)));
      UBIQ_DEBUG(debug_flag, printf("%s: input_chars(%Ls) \n", csu, ubiq_platform_dataset_get_input_characters(dataset)));
      char32_t * b10_value = calloc(25, sizeof(char32_t));

      // We can go from OCS to Base10 directly
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)value, (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), (uint32_t*)L"0123456789", 1, 0, (uint32_t*)b10_value);
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) b10_value(%S)\n", csu, res, b10_value));

      int64_t tmp = wcstoll((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == value || tmp < INT64_MIN || tmp > INT64_MAX) {
        res = -EINVAL;
      } 
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) tmp(%lld)\n", csu, res, tmp));

      if (!res && isNegative) {
        tmp = -1 * tmp;
      }
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) tmp(%lld)    isNegative(%d)\n", csu, res, tmp, isNegative));
      free(b10_value);
      if (!res) {
        struct tm * ct_local;
        tmp = tmp + ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config);
        UBIQ_DEBUG(debug_flag, printf("%s: res(%d) tmp:seconds (%lld)\n", csu, res, tmp));
        ct_local = localtime_r(&tmp, ct);
      }
    }
  } else {
    res = -EACCES;
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ct(%ld)\n", csu, res, *ct));

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    ubiq_platform_dataset_get_name(dataset), 
    dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_encryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}

/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/

UBIQ_PLATFORM_API
int
ubiq_platform_structured_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_structured_enc_dec_obj ** const enc)
{
  struct ubiq_platform_configuration * cfg = NULL;

  ubiq_platform_configuration_load_configuration(NULL, &cfg);

  int ret = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, enc);
  ubiq_platform_configuration_destroy(cfg);
  return ret;

}
// Piecewise functions
UBIQ_PLATFORM_API
int
ubiq_platform_structured_enc_dec_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_structured_enc_dec_obj ** const enc)
{
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

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen
)
{
  const char * const csu = "ubiq_platform_structured_encrypt_data";
  char32_t * u32ctbuf = NULL;
  char32_t * u32pt = NULL;
  size_t u32ctlen = 0;
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s\n", csu));
  // For compatibility purposes.  Need to switch from char to char32_t

  res = convert_utf8_to_utf32((uint8_t *)ptbuf, (uint32_t**)&u32pt);
  UBIQ_DEBUG(debug_flag, printf("%s convert_utf8_to_utf32 enc == NULL? (%d) res(%d)\n", csu, enc == NULL, res));

  if (!res) {
    res = ubiq_platform_structured_encrypt_u32data(enc, ffs_name,
      tweak, tweaklen,
      u32pt, u32_strlen((uint32_t*)u32pt),
      &u32ctbuf, &u32ctlen);
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_structured_encrypt_data res(%d)\n", csu, res));
  }
  if (!res) {
    convert_utf32_to_utf8((uint32_t*)u32ctbuf, (uint8_t**)ctbuf);
    *ctlen = strlen(*ctbuf);
  }
  free(u32pt);
  free(u32ctbuf);
  return res;
}


UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_u32data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char32_t * const ptbuf, const size_t ptlen,
  char32_t ** const ctbuf, size_t * const ctlen
)
{
  static int debug_flag = 0;
  const char * const csu = "ubiq_platform_structured_encrypt_u32data";
  int res = -EINVAL;

  ubiq_platform_dataset_t const * dataset = NULL;
  UBIQ_DEBUG(debug_flag, printf("%s: start res(%d) \n", csu,res));

  res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_dataset_cache_get_dataset res(%d) err(%s) num(%d)\n", csu,res, enc->error->err_msg, enc->error->err_num));
  if (!res && !ubiq_platform_dataset_get_can_encrypt(dataset)) {
    res = -EINVAL;
      res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to encrypt data");
  }
  UBIQ_DEBUG(debug_flag, printf("%s: dataset(%i) res(%d) \n", csu, dataset == NULL, res));

  if (!res) {
    char const * const data_type = ubiq_platform_dataset_get_data_type(dataset);

    if (strcmp(data_type, DATA_TYPE_DATE) == 0 || strcmp(data_type, DATA_TYPE_DATETIME) == 0 || strcmp(data_type, DATA_TYPE_INTEGER) == 0) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Dataset is not of the correct type");
    } else {
      // Could optimize a little by passing dataset and not dataset name but leave for now
      res = encrypt_pipeline(enc, dataset_name, -1, tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
    }

  }

  return res;
}


UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_u32data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char32_t * const ctbuf, const size_t ctlen,
  char32_t ** const ptbuf, size_t * const ptlen)
{
  static int debug_flag = 0;
  const char * const csu = "ubiq_platform_structured_decrypt_u32data";
  int res = -EINVAL;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_decryption_pipeline_t * pipeline = NULL;

  res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_dataset_cache_get_dataset\n", csu,res));

  if (!res && !ubiq_platform_dataset_get_can_decrypt(dataset)) {
    res = -EINVAL;
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot decrypt for this dataset\n", csu,res));
    CAPTURE_ERROR(enc, res, "Cannot decrypt for this dataset");
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_dataset_get_can_decrypt\n", csu,res));

  if (!res) {
    char const * const data_type = ubiq_platform_dataset_get_data_type(dataset);

    if (strcmp(data_type, DATA_TYPE_DATE) == 0 || strcmp(data_type, DATA_TYPE_DATETIME) == 0 || strcmp(data_type, DATA_TYPE_INTEGER) == 0) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Dataset is not of the correct type");
    }
  }

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_create\n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_set_dataset\n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_set_ffx_cache\n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 0);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_set_is_encrypt\n", csu,res));

  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ctbuf);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_set_current_value\n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ctbuf);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_set_original_value\n", csu,res));
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_operation_context_set_user_supplied_tweak\n", csu,res));

  if (!res) {
    pipeline = ubiq_platform_decryption_pipeline_create(dataset);
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_decryption_pipeline_create\n", csu,res));
  if (pipeline) {
    res = ubiq_platform_decryption_pipeline_invoke(pipeline, ctx);
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ubiq_platform_decryption_pipeline_invoke\n", csu,res));
    if (!res) {
      *ptbuf = u32_strdup(ubiq_platform_operation_context_get_current_value(ctx));
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    dataset_name, dataset_groups_name,
    DECRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }

  if (pipeline) { ubiq_platform_decryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  // To keep API the same - caller needs to free ctbuf
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) end\n", csu,res));

  return res;
}


void
ubiq_platform_structured_enc_dec_destroy(
    struct ubiq_platform_structured_enc_dec_obj * const e)
{
  const char * const csu = "ubiq_platform_structured_enc_dec_destroy";

  if (e) {

    ubiq_billing_ctx_destroy(e->billing_ctx);
    ubiq_platform_ff1_cache_destroy(e->ff1_ctx_cache);
    ubiq_platform_structured_key_cache_destroy(e->key_cache);
    ubiq_platform_dataset_cache_destroy(e->dataset_cache);
    free(e->error->err_msg);
    free(e->error);
  }
  free(e);
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_int_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int32_t pt,
  int32_t * const ct
)
{
  const char * const csu = "ubiq_platform_structured_encrypt_int_data";
  int res = -EINVAL;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;

  size_t min_len = 0;
  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator

  UBIQ_DEBUG(debug_flag, printf("%s: start\n", csu));

  res = validate_encrypt_int(enc, dataset_name, pt, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: validate_encrypt_int res(%d), dataset == NULL ? (%d)\n", csu, res, dataset == NULL));

  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId32, abs(pt));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%s)\n", csu,min_len, ptbuf));
    if (u32_strlen(ptbuf) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ptbuf, (uint32_t**)&tmp);
      UBIQ_DEBUG(debug_flag, printf("%s: (%d) ptbuf(%s) tmp(%s)\n", csu,min_len, ptbuf, tmp));
      free(ptbuf);
      ptbuf = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));
  if (!res) {
    res = encrypt_int_pipeline(enc,
      dataset, tweak, tweaklen,
      pt, ptbuf, -1, ct);
  }
  free(ptbuf);

  return res;
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_int_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int32_t pt,
  int32_t ** const ctarr, size_t * const count
)
{
  const char * const csu = "ubiq_platform_structured_encrypt_int_data_for_search";
  int res = -EINVAL;
  int key_number = -1;

  ubiq_platform_dataset_t const * dataset = NULL;
  struct ff1_ctx * ff1_ctx = NULL;
  size_t min_len = 0;
  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator

  UBIQ_DEBUG(debug_flag, printf("%s: start\n", csu));

  // Make sure the dataset is valid for encrypt and the PT value is in the right range
  res = validate_encrypt_int(enc, dataset_name, pt, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: validate_encrypt_int res(%d), dataset == NULL ? (%d)\n", csu, res, dataset));

  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId32, abs(pt));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%s)\n", csu,min_len, ptbuf));
    if (u32_strlen(ptbuf) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ptbuf, (uint32_t**)&tmp);
      UBIQ_DEBUG(debug_flag, printf("%s: (%d) ptbuf(%s) tmp(%s)\n", csu,min_len, ptbuf, tmp));
      free(ptbuf);
      ptbuf = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));

  if (!res) {
    // Get the current key for encrypt
    res = ubiq_platform_ff1_cache_get_ff1_ctx(enc->ff1_ctx_cache,
        dataset_name, &key_number, &ff1_ctx);
    // Number is one greater than the current_key_number
    *count = key_number + 1;

    int32_t * ret_ct = NULL;
    ret_ct = (int32_t *)calloc(*count, sizeof(int32_t));
    for (int key = 0; !res && key <= key_number; key++) {
      res = encrypt_int_pipeline(enc,
        dataset, tweak, tweaklen,
        pt, ptbuf, key, &ret_ct[key]);
        UBIQ_DEBUG(debug_flag, printf("%s ret_ct[(%d)]: %d res(%d)\n", csu, key, ret_ct[key], res));
    }
    if (!res) {
      *ctarr = ret_ct;
    }
  }
  
  free(ptbuf);

  return res;
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_int_data(

  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int32_t ct,
  int32_t * const pt
)
{
  const char * const csu = "ubiq_platform_structured_decrypt_int_data";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_decryption_pipeline_t * pipeline = NULL;
  int isNegative = (ct < 0);
  size_t min_len = 0;
  char32_t * ctbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator

  res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);

  if (!res && !ubiq_platform_dataset_get_can_decrypt(dataset)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to decrypt data");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot decrypt for this dataset\n", csu,res));
  }

  if (!res && strcmp(ubiq_platform_dataset_get_data_type(dataset), DATA_TYPE_INTEGER) != 0) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset only works with integers");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != INTEGER\n", csu,res));
  }

  if (!res && ((data_type_config = ubiq_platform_dataset_get_data_type_config(dataset)) == NULL)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Unabled to fetch data_type_config for the dataset");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
  }

  if (!res && 32 != ubiq_platform_data_type_config_get_size(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "dataset size is not 32");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) get_size != 32 \n", csu,res));
  }

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 0);}
  if (!res) {
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
  }
  // Convert int to String
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d)\n", csu,res));
  if (!res) { 
    swprintf(ctbuf, 25, L"%" PRId32, abs(ct));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ctbuf(%s)\n", csu,min_len, ctbuf));
  }
  
  // Convert String to from Base10 int to output radix to get ready to decrypt
  if (!res) {
      char32_t * value = calloc(25, sizeof(char32_t));
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ctbuf, (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), 1, 0, (uint32_t*)value);
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) value(%s)\n", csu, res, value));
      free(ctbuf);
      ctbuf = value;

      if (!res && u32_strlen(value) < min_len) {
        uint32_t * tmp = NULL;
        res = ubiq_platform_pad_left(ubiq_platform_dataset_get_output_characters(dataset)[0], min_len, (uint32_t*)value, (uint32_t**)&tmp);
        UBIQ_DEBUG(debug_flag, printf("%s: (%d) ctbuf(%s) tmp(%s)\n", csu,min_len, value, tmp));
        free(value);
        ctbuf = tmp;
    }

    if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ctbuf);}
    if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ctbuf);}
    // free(value);
  }
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  free(ctbuf);
  if (!res) {
    pipeline = ubiq_platform_decryption_pipeline_create(dataset);
  }
  if (pipeline) {
    res = ubiq_platform_decryption_pipeline_invoke(pipeline, ctx);
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const b10_value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: b10_value(%Ls) \n", csu, b10_value));
      int64_t tmp = wcstol((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == b10_value || tmp < INT32_MIN || tmp > INT32_MAX) {
        res = -EINVAL;
      } else {
        *pt = tmp;
      }
      if (!res && isNegative) {
        *pt = -1 * *pt;
      }
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    dataset_name, dataset_groups_name,
    DECRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_decryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;  
}


UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_long_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int64_t pt,
  int64_t * const ct
)
{
  const char * const csu = "ubiq_platform_structured_encrypt_long_data";
  int res = -EINVAL;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;

  size_t min_len = 0;
  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator
  
  res = validate_encrypt_long(enc, dataset_name, pt, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: validate_encrypt_long res(%d), dataset == NULL ? (%d)\n", csu, res, dataset == NULL));

  UBIQ_DEBUG(debug_flag, printf("%s: res(%d)\n", csu,res));
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId64, llabs(pt));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%s)\n", csu,min_len, ptbuf));
    if (u32_strlen(ptbuf) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ptbuf, (uint32_t**)&tmp);
    UBIQ_DEBUG(debug_flag, printf("%s: (%d) ptbuf(%s) tmp(%s)\n", csu,min_len, ptbuf, tmp));
      free(ptbuf);
      ptbuf = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s pt(%ld) ptbuf(%d): %S\n", csu, pt, u32_strlen(ptbuf), ptbuf));
  if (!res) {
    res = encrypt_long_pipeline(enc,
      dataset, tweak, tweaklen,
      pt, ptbuf, -1, ct);
  }
  free(ptbuf);

  return res;
}


UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_long_data(

  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int64_t ct,
  int64_t * const pt
)
{
  const char * const csu = "ubiq_platform_structured_decrypt_long_data";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_decryption_pipeline_t * pipeline = NULL;
  int isNegative = (ct < 0);
  size_t min_len = 0;
  char32_t * ctbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator

  res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);

  if (!res && !ubiq_platform_dataset_get_can_decrypt(dataset)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to decrypt data");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot decrypt for this dataset\n", csu,res));
  }

  if (!res && strcmp(ubiq_platform_dataset_get_data_type(dataset), DATA_TYPE_INTEGER) != 0) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset only works with integers values");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != INTEGER \n", csu,res));
  }

  if (!res && ((data_type_config = ubiq_platform_dataset_get_data_type_config(dataset)) == NULL)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Unabled to fetch data_type_config for the dataset");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
  }

  if (!res && 64 != ubiq_platform_data_type_config_get_size(data_type_config)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "dataset size is not 64");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) get_size != 64 \n", csu,res));
  }

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 0);}
  min_len = ubiq_platform_dataset_get_input_min_length(dataset);

  // Convert int to String
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d)\n", csu,res));
  if (!res) { 
    swprintf(ctbuf, 25, L"%" PRId64, llabs(ct));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ctbuf(%S)\n", csu,min_len, ctbuf));
  }
  
  // Convert String to from Base10 int to output radix to get ready to decrypt
  if (!res) {
      char32_t * value = calloc(25, sizeof(char32_t));
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ctbuf, (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), 1, 0, (uint32_t*)value);
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) value(%s)\n", csu, res, value));
      free(ctbuf);
      ctbuf = value;

      if (!res && u32_strlen(value) < min_len) {
        uint32_t * tmp = NULL;
        res = ubiq_platform_pad_left(ubiq_platform_dataset_get_output_characters(dataset)[0], min_len, (uint32_t*)value, (uint32_t**)&tmp);
        UBIQ_DEBUG(debug_flag, printf("%s: (%d) ctbuf(%s) tmp(%s)\n", csu,min_len, value, tmp));
        free(value);
        ctbuf = tmp;
    }

    if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ctbuf);}
    if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ctbuf);}
    // free(value);
  }
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  free(ctbuf);
  if (!res) {
    pipeline = ubiq_platform_decryption_pipeline_create(dataset);
  }
  if (pipeline) {
    res = ubiq_platform_decryption_pipeline_invoke(pipeline, ctx);
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const b10_value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: b10_value(%LS) \n", csu, b10_value));
      int64_t tmp = wcstoll((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == b10_value || tmp < INT64_MIN || tmp > INT64_MAX) {
        res = -EINVAL;
      } else {
        *pt = tmp;
      }
      if (!res && isNegative) {
        *pt = -1 * *pt;
      }
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    dataset_name, dataset_groups_name,
    DECRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_decryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;  
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_long_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const int64_t pt,
  int64_t ** const ctarr, size_t * const count
)
{
  const char * const csu = "ubiq_platform_structured_encrypt_long_data_for_search";
  int res = -EINVAL;
  int key_number = -1;

  ubiq_platform_dataset_t const * dataset = NULL;
  struct ff1_ctx * ff1_ctx = NULL;
  size_t min_len = 0;
  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator

  UBIQ_DEBUG(debug_flag, printf("%s: start\n", csu));

  // Make sure the dataset is valid for encrypt and the PT value is in the right range
  res = validate_encrypt_long(enc, dataset_name, pt, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: validate_encrypt_long res(%d), dataset == NULL ? (%d)\n", csu, res, dataset));

  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId64, llabs(pt));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%s)\n", csu,min_len, ptbuf));
    if (u32_strlen(ptbuf) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ptbuf, (uint32_t**)&tmp);
      UBIQ_DEBUG(debug_flag, printf("%s: (%d) ptbuf(%s) tmp(%s)\n", csu,min_len, ptbuf, tmp));
      free(ptbuf);
      ptbuf = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s ptbuf(%d): %S\n", csu, u32_strlen(ptbuf), ptbuf));
  if (!res) {
    // Get the current key for encrypt
    res = ubiq_platform_ff1_cache_get_ff1_ctx(enc->ff1_ctx_cache,
        dataset_name, &key_number, &ff1_ctx);

    // Number is one greater than the current_key_number
    *count = key_number + 1;
    int64_t * ret_ct = NULL;
    ret_ct = (int64_t *)calloc(*count, sizeof(int64_t));
    for (int key = 0; !res && key <= key_number; key++) {
      res = encrypt_long_pipeline(enc,
        dataset, tweak, tweaklen,
        pt, ptbuf, key, &ret_ct[key]);
        UBIQ_DEBUG(debug_flag, printf("%s ret_ct[(%d)]: %d res(%d)\n", csu, key, ret_ct[key], res));
    }
    if (!res) {
      *ctarr = ret_ct;
    }
  }
  
  free(ptbuf);
  return res;
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_date_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const pt_const,
  struct tm * const ct
)
{
  int debug_flag = 1;
  const char * const csu = "ubiq_platform_structured_encrypt_date_data";
  int res = 0;

  // char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  // ubiq_platform_operation_context_t * ctx = NULL;
  // ubiq_platform_encryption_pipeline_t * pipeline = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  struct tm pt;
  int64_t days = 0;
  int is_negative = 0;
  size_t min_len = 0;

  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator
  char32_t * ics_value = calloc(25, sizeof(char32_t));

  memcpy(&pt, pt_const, sizeof(pt));
  
  time_t pt_tm = mktime(&pt);

  UBIQ_DEBUG(debug_flag, printf("%s: pt_tm(%ld)\n", csu, pt_tm));
  
  if (!res && pt_tm == -1) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cannot convert date to a time");
    UBIQ_DEBUG(debug_flag, printf("%s: cannot convert date (%s) to time_t\n", csu,asctime(&pt)));
  }

  if (!res && (pt.tm_hour || pt.tm_sec || pt.tm_min)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Does not work with days that include hours, minutes, or seconds");
    UBIQ_DEBUG(debug_flag, printf("%s: Does not work with days that include hours, minutes, or seconds (%s)\n", csu,asctime(&pt)));
  }

  if (!res) { res = validate_encrypt_date(enc, dataset_name, pt_tm, &dataset);}

  if (!res) {
      data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);

      min_len = 0;
      // Dates work by using number of days before or after epoch.
      // Positive means pt is AFTER epoch

      days = ((int64_t)(difftime(pt_tm, ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config))) / 86400); // 60.0 * 60 * 24.0)
      is_negative = (days < 0);
  }
  
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) days:pt(%lld) \n", csu,res, days));
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId64, llabs(days));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%S)\n", csu, min_len, ptbuf));
    // Convert Base 10 to ICS
    res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ptbuf, L"0123456789", (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), 1, 0, (uint32_t*)ics_value);
    UBIQ_DEBUG(debug_flag, printf("%s ics_value(%d): %S\n", csu, u32_strlen(ics_value), ics_value));
    if (!res && u32_strlen(ics_value) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ics_value, (uint32_t**)&tmp);
      free(ics_value);
      ics_value = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ptbuf(%S)\n", csu,res, ptbuf));

  if (!res) {
    res = encrypt_date_pipeline(enc, dataset, tweak, tweaklen,
      is_negative, ics_value, -1, ct);
  }
  free(ptbuf);
  free(ics_value);

  return res;
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_date_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const ct_const,
  struct tm * const pt
)
{
  int debug_flag = 1;
  const char * const csu = "ubiq_platform_structured_decrypt_date_data";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_decryption_pipeline_t * pipeline = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  struct tm ct;

  memcpy(&ct, ct_const, sizeof(ct));
  
  time_t ct_tm = mktime(&ct);

  UBIQ_DEBUG(debug_flag, printf("%s: start ct_tm(%lld)\n", csu, ct_tm));

  if (ct_tm == -1) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cannot convert the date to a time_t");
    UBIQ_DEBUG(debug_flag, printf("%s: cannot convert date (%s) to time_t\n", csu,asctime(&ct)));
  }

  if (ct.tm_hour || ct.tm_sec || ct.tm_min) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset does not work with timestamps that include hours, minutes, or seconds");
    UBIQ_DEBUG(debug_flag, printf("%s: Does not work with days that include hours, minutes, or seconds (%s)\n", csu,asctime(&ct)));
  }

  int64_t days = 0;
  int isNegative = 0;
  size_t min_len = 0;
  char32_t * ctbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator
  if (!res) {
    res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);
  }
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_dataset_cache_get_dataset res(%d)\n", csu, res));

  if (!res && !ubiq_platform_dataset_get_can_decrypt(dataset)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to decrypt data");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot decrypt for this dataset\n", csu,res));
  }

  if (!res && strcmp(ubiq_platform_dataset_get_data_type(dataset), DATA_TYPE_DATE) != 0) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset only works with dates");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != DATE \n", csu,res));
  }

  if (!res) {
    data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);
    if (data_type_config == NULL) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Dataset error - unable to fetch data_type_config");
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
    }
  }

  UBIQ_DEBUG(debug_flag, printf("%s ct: %lld\n", csu, (long long)ct_tm));

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 0);}

  // Dates work by using number of days before or after epoch.
  // Positive means pt is AFTER epoch

  if (!res) {
    days = ((int64_t)(difftime(ct_tm, ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config))) / 86400); // 60.0 * 60 * 24.0)
    isNegative = (days < 0);
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) days(%lld)\n", csu,res, days));

  UBIQ_DEBUG(debug_flag, printf("%s: res(%d)\n", csu,res));
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ctbuf, 25, L"%" PRId64, llabs(days));
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ctbuf(%S)\n", csu,res, ctbuf));

    char32_t * value = calloc(25, sizeof(char32_t));
    res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ctbuf, L"0123456789", (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), 1, 0, (uint32_t*)value);
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) value(%S)\n", csu, res, value));
    free(ctbuf);
    ctbuf = value;
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ctbuf(%S)\n", csu, res, ctbuf));
    if (u32_strlen(ctbuf) < min_len) {
      UBIQ_DEBUG(debug_flag, printf("%s: u32_strlen(%d) < min_len(%d)\n", csu, u32_strlen(ctbuf), min_len));

      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_output_characters(dataset)[0], min_len, (uint32_t*)ctbuf, (uint32_t**)&tmp);
      UBIQ_DEBUG(debug_flag, printf("%s: (%d) ctbuf(%s) tmp(%s)\n", csu,min_len, ctbuf, tmp));
      free(ctbuf);
      ctbuf = tmp;
    }
  }

  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ctbuf);}
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_current_value res(%d) ctbuf(%S)\n", csu, res, ctbuf));
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ctbuf);}
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_original_value res(%d) ctbuf(%S)\n", csu, res, ctbuf));
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_operation_context_set_user_supplied_tweak res(%d) ctbuf(%S)\n", csu, res, ctbuf));
  free(ctbuf);
  if (!res) {
    pipeline = ubiq_platform_decryption_pipeline_create(dataset);
  }
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_decryption_pipeline_create res(%d) \n", csu, res));
  if (pipeline && !res) {
    res = ubiq_platform_decryption_pipeline_invoke(pipeline, ctx);
    UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_decryption_pipeline_invoke res(%d) \n", csu, res));
    if (!res) {
      char32_t * endptr = NULL;
      char32_t const * const ics_value = ubiq_platform_operation_context_get_current_value(ctx);
      UBIQ_DEBUG(debug_flag, printf("%s: ics_value(%Ls) \n", csu, ics_value));
      char32_t * b10_value = calloc(25, sizeof(char32_t));
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ics_value, (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), L"0123456789", 1, 0, (uint32_t*)b10_value);

      UBIQ_DEBUG(debug_flag, printf("%s: value:pt(%Ls) \n", csu, b10_value));

      int64_t tmp = wcstoll((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == b10_value || tmp < INT64_MIN || tmp > INT64_MAX) {
        res = -EINVAL;
      } 
      if (!res && isNegative) {
        tmp = -1 * tmp;
      }
      free(b10_value);
      UBIQ_DEBUG(debug_flag, printf("%s: days:pt(%lld) \n", csu, tmp));
      if (!res) {
        struct tm * pt_local;
        tmp = (tmp * 86400) + ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config);
        UBIQ_DEBUG(debug_flag, printf("%s: seconds:pt(%lld) \n", csu, tmp));
        pt_local = localtime_r(&tmp, pt);
      }
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    dataset_name, dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_decryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_date_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const pt_const,
  struct tm ** const ctarr, size_t * const count
)
{
  const char * const csu = "ubiq_platform_structured_encrypt_date_data_for_search";
  int res = 0;
  int key_number = -1;

  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  struct ff1_ctx * ff1_ctx = NULL;
  size_t min_len = 0;
  struct tm pt;
  int64_t days = 0;
  int is_negative = 0;

  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator
  char32_t * ics_value = calloc(25, sizeof(char32_t));

  memcpy(&pt, pt_const, sizeof(pt));
  
  time_t pt_tm = mktime(&pt);

  if (!res && pt_tm == -1) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cannot convert date to a time");
    UBIQ_DEBUG(debug_flag, printf("%s: cannot convert date (%s) to time_t\n", csu,asctime(&pt)));
  }

  if (!res && (pt.tm_hour || pt.tm_sec || pt.tm_min)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Does not work with days that include hours, minutes, or seconds");
    UBIQ_DEBUG(debug_flag, printf("%s: Does not work with days that include hours, minutes, or seconds (%s)\n", csu,asctime(&pt)));
  }

  if (!res) { res = validate_encrypt_date(enc, dataset_name, pt_tm, &dataset);}

  if (!res) {
    data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);

    days = ((int64_t)(difftime(pt_tm, ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config))) / 86400); // 60.0 * 60 * 24.0)
    is_negative = (days < 0);

    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) days:pt(%lld)\n", csu,res, days));
  }
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId64, llabs(days));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%S)\n", csu, min_len, ptbuf));
    // Convert Base 10 to ICS
    res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ptbuf, L"0123456789", (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), 1, 0, (uint32_t*)ics_value);
    UBIQ_DEBUG(debug_flag, printf("%s ics_value(%d): %S\n", csu, u32_strlen(ics_value), ics_value));
    if (!res && u32_strlen(ics_value) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ics_value, (uint32_t**)&tmp);
      free(ics_value);
      ics_value = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ptbuf(%S)\n", csu,res, ptbuf));
  if (!res) {
    // Get the current key for encrypt
    res = ubiq_platform_ff1_cache_get_ff1_ctx(enc->ff1_ctx_cache,
        dataset_name, &key_number, &ff1_ctx);

  // Number is one greater than the current_key_number
    *count = key_number + 1;
    struct tm * ret_ct = NULL;
    ret_ct = (struct tm *)calloc(*count, sizeof(struct tm));
    for (int key = 0; !res && key <= key_number; key++) {

      res = encrypt_date_pipeline(enc, dataset, tweak, tweaklen,
        is_negative, ics_value, key, &ret_ct[key]);
    }
    if (!res) {
      *ctarr = ret_ct;
    }
  }
  
  free(ptbuf);
  free(ics_value);
  return res;
}

// C doesn't have timezone in struct tm, so this will need to be removed / added before and after calling encrypt / decrypt
UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_datetime_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const pt_const,
  struct tm * const ct
)
{
  static int debug_flag = 1;
  const char * const csu = "ubiq_platform_structured_encrypt_datetime_data";
  int res = 0;

  // char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  // ubiq_platform_operation_context_t * ctx = NULL;
  // ubiq_platform_encryption_pipeline_t * pipeline = NULL;
  // ubiq_platform_data_type_config_t const * data_type_config = NULL;
  struct tm pt;
  int64_t seconds = 0;
  int is_negative = 0;

  memcpy(&pt, pt_const, sizeof(pt));
  
  time_t pt_tm = mktime(&pt);

  if (pt_tm == -1) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cannot convert date to a time");
    UBIQ_DEBUG(debug_flag, printf("%s: cannot convert datetime (%s) to time_t\n", csu,asctime(&pt)));
  }

  if (!res) { res = validate_encrypt_datetime(enc, dataset_name, pt_tm, &dataset);}
  if (!res) { 
    ubiq_platform_data_type_config_t const * data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);
    seconds = (int64_t)difftime(pt_tm, ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config));
    is_negative = (seconds < 0);
  }

  // int isNegative = 0;
  size_t min_len = 0;
  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator
  char32_t * ics_value = calloc(25, sizeof(char32_t));

  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) seconds:pt(%lld) \n", csu,res, seconds));
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId64, llabs(seconds));

    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%S)\n", csu, min_len, ptbuf));

    res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ptbuf, L"0123456789", (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), 1, 0, (uint32_t*)ics_value);
    UBIQ_DEBUG(debug_flag, printf("%s ics_value(%d): %S\n", csu, u32_strlen(ics_value), ics_value));
    if (!res && u32_strlen(ics_value) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ics_value, (uint32_t**)&tmp);
      free(ics_value);
      ics_value = tmp;
    }


    // UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%S)\n", csu, min_len, ptbuf));
    // if (u32_strlen(ptbuf) < min_len) {
    //   uint32_t * tmp = NULL;
    //   res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ptbuf, (uint32_t**)&tmp);
    //   UBIQ_DEBUG(debug_flag, printf("%s: (%d) ptbuf(%S) tmp(%S)\n", csu,min_len, ptbuf, tmp));
    //   free(ptbuf);
    //   ptbuf = tmp;
    // }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ptbuf(%S)\n", csu,res, ptbuf));

  if (!res) {
    res = encrypt_datetime_pipeline(enc, dataset, tweak, tweaklen,
      is_negative, ics_value, -1, ct);
  }
  free(ptbuf);
  free(ics_value);

  return res;
}


UBIQ_PLATFORM_API
int
ubiq_platform_structured_decrypt_datetime_data(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const ct_const,
  struct tm * const pt
)
{
  const char * const csu = "ubiq_platform_structured_decrypt_datetime_data";
  int res = 0;

  char const * const dataset_groups_name = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;
  ubiq_platform_decryption_pipeline_t * pipeline = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  struct tm ct;

  memcpy(&ct, ct_const, sizeof(ct));
  
  time_t ct_tm = mktime(&ct);

  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ct_tm(%lld)\n", csu,res, ct_tm));

  if (ct_tm == -1) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cannot convert date to a time_t");
    UBIQ_DEBUG(debug_flag, printf("%s: cannot convert date (%s) to time_t\n", csu,asctime(&ct)));
  }

  int64_t seconds = 0;
  int isNegative = 0;
  size_t min_len = 0;
  char32_t * ctbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator

  if (!res) {
    res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);
  }

  if (!res && !ubiq_platform_dataset_get_can_decrypt(dataset)) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Dataset cannot be used to decrypt data");
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) cannot decrypt for this dataset\n", csu,res));
  }

  if (!res && strcmp(ubiq_platform_dataset_get_data_type(dataset), DATA_TYPE_DATETIME) != 0) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Dataset only works with datetime values.");
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) data_type != DATETIME \n", csu,res));
  }

  if (!res) {
    data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);
    if (data_type_config == NULL) {
      res = CAPTURE_ERROR(enc, -EINVAL, "Dataset error - unable to fetch data_type_config");
      UBIQ_DEBUG(debug_flag, printf("%s: res(%d) unable to fetch data_type_config\n", csu,res));
    }
  }

  UBIQ_DEBUG(debug_flag, printf("%s ct: %lld\n", csu, (long long)ct_tm));

  if (!res) {res = ubiq_platform_operation_context_create(enc->error, &ctx);}
  if (!res) {res = ubiq_platform_operation_context_set_dataset(ctx, dataset);}
  if (!res) {res = ubiq_platform_operation_context_set_ffx_cache(ctx, enc->ff1_ctx_cache);}
  if (!res) {res = ubiq_platform_operation_context_set_is_encrypt(ctx, 0);}

  // Dates work by using number of days before or after epoch.
  // Positive means pt is AFTER epoch

  if (!res)
  {
     seconds = (int64_t)(difftime(ct_tm, ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config))); // 60.0 * 60 * 24.0)
    isNegative = (seconds < 0);
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) seconds(%lld)\n", csu,res, seconds));


  UBIQ_DEBUG(debug_flag, printf("%s: res(%d)\n", csu,res));
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ctbuf, 25, L"%" PRId64, llabs(seconds));
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ctbuf(%S)\n", csu,res, ctbuf));

    char32_t * value = calloc(25, sizeof(char32_t));

    // Convert from seconds directly to OCS
    res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ctbuf, (uint32_t*)L"0123456789", (uint32_t*)ubiq_platform_dataset_get_output_characters(dataset), 1, 0, (uint32_t*)value);
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) value(%S)\n", csu, res, value));
    free(ctbuf);
    ctbuf = value;
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ctbuf(%S)\n", csu, res, ctbuf));
    if (u32_strlen(ctbuf) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_output_characters(dataset)[0], min_len, (uint32_t*)ctbuf, (uint32_t**)&tmp);
      UBIQ_DEBUG(debug_flag, printf("%s: (%d) ctbuf(%s) tmp(%s)\n", csu,min_len, ctbuf, tmp));
      free(ctbuf);
      ctbuf = tmp;
    }
  }

  if (!res) {res = ubiq_platform_operation_context_set_current_value(ctx, ctbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_original_value(ctx, ctbuf);}
  if (!res) {res = ubiq_platform_operation_context_set_user_supplied_tweak(ctx, tweak, tweaklen);}
  free(ctbuf);
  if (!res) {
    pipeline = ubiq_platform_decryption_pipeline_create(dataset);
  }
  if (pipeline) {
    res = ubiq_platform_decryption_pipeline_invoke(pipeline, ctx);
    if (!res) {
      char32_t * endptr = NULL;
      char32_t * b10_value = calloc(25, sizeof(char32_t));
      char32_t const * const ics_value = ubiq_platform_operation_context_get_current_value(ctx);
      // Convert from ICS to Base10
      res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ics_value, (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), L"0123456789", 1, 0, (uint32_t*)b10_value);

      UBIQ_DEBUG(debug_flag, printf("%s: value:pt(%Ls) \n", csu, b10_value));

      int64_t tmp = wcstoll((wchar_t*)b10_value, (wchar_t**)&endptr, 10);
      if (endptr == b10_value || tmp < INT64_MIN || tmp > INT64_MAX) {
        res = -EINVAL;
      } 
      if (!res && isNegative) {
        tmp = -1 * tmp;
      }
      free(b10_value);
      UBIQ_DEBUG(debug_flag, printf("%s: seconds:pt(%lld) \n", csu, tmp));
      if (!res) {
        struct tm * pt_local;
        tmp = tmp + ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config);
        UBIQ_DEBUG(debug_flag, printf("%s: seconds:pt(%lld) \n", csu, tmp));
        pt_local = localtime_r(&tmp, pt);
      }
    }
  } else {
    res = -EACCES;
  }

  if (!res) {
    res = ubiq_billing_add_billing_event(
    enc->billing_ctx,
    "",
    dataset_name, dataset_groups_name,
    ENCRYPTION,
    1, ubiq_platform_operation_context_get_key_number(ctx) );
  }
  // To keep API the same - caller needs to free ctbuf

  if (pipeline) { ubiq_platform_decryption_pipeline_delete(pipeline);}
  if (ctx) {ubiq_platform_operation_context_destroy(ctx);}

  return res;
}

UBIQ_PLATFORM_API
int
ubiq_platform_structured_encrypt_datetime_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const struct tm * const pt_const,
  struct tm ** const ctarr, size_t * const count
)
{
  static int debug_flag = 1;
  const char * const csu = "ubiq_platform_structured_encrypt_datetime_data_for_search";
  int res = 0;
  int key_number = -1;

  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_data_type_config_t const * data_type_config = NULL;
  struct ff1_ctx * ff1_ctx = NULL;
  size_t min_len = 0;
  struct tm pt;
  int64_t seconds = 0;
  int is_negative = 0;

  char32_t * ptbuf = calloc(25, sizeof(char32_t)); // 2^63-1.  Extra space provided for negative sign and null terminator
  char32_t * ics_value = calloc(25, sizeof(char32_t));

  memcpy(&pt, pt_const, sizeof(pt));
  
  time_t pt_tm = mktime(&pt);

  if (!res && pt_tm == -1) {
    res = CAPTURE_ERROR(enc, -EINVAL, "Cannot convert date to a time");
    UBIQ_DEBUG(debug_flag, printf("%s: cannot convert date (%s) to time_t\n", csu,asctime(&pt)));
  }

  if (!res) { res = validate_encrypt_datetime(enc, dataset_name, pt_tm, &dataset);}

  if (!res) {
    data_type_config = ubiq_platform_dataset_get_data_type_config(dataset);

    seconds = (int64_t)difftime(pt_tm, ubiq_platform_data_type_config_get_epoch_as_time_t(data_type_config));
    is_negative = (seconds < 0);
    UBIQ_DEBUG(debug_flag, printf("%s: res(%d) seconds:pt(%lld)\n", csu,res, seconds));
  }
  // Convert from Seconds to String (base10) to ICS with padding
  if (!res) { 
    min_len = ubiq_platform_dataset_get_input_min_length(dataset);
    swprintf(ptbuf, 25, L"%" PRId64, llabs(seconds));
    UBIQ_DEBUG(debug_flag, printf("%s: min_len(%d) ptbuf(%S)\n", csu, min_len, ptbuf));

    res = ubiq_platform_u32_str_convert_u32_radix((uint32_t*)ptbuf, L"0123456789", (uint32_t*)ubiq_platform_dataset_get_input_characters(dataset), 1, 0, (uint32_t*)ics_value);
    UBIQ_DEBUG(debug_flag, printf("%s ics_value(%d): %S\n", csu, u32_strlen(ics_value), ics_value));
    if (!res && u32_strlen(ics_value) < min_len) {
      uint32_t * tmp = NULL;
      res = ubiq_platform_pad_left(ubiq_platform_dataset_get_input_characters(dataset)[0], min_len, (uint32_t*)ics_value, (uint32_t**)&tmp);
      free(ics_value);
      ics_value = tmp;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) ics_value(%S)\n", csu,res, ics_value));
  if (!res) {
    // Get the current key for encrypt
    res = ubiq_platform_ff1_cache_get_ff1_ctx(enc->ff1_ctx_cache,
        dataset_name, &key_number, &ff1_ctx);

    // Number is one greater than the current_key_number
    *count = key_number + 1;
    struct tm * ret_ct = NULL;
    ret_ct = (struct tm *)calloc(*count, sizeof(struct tm));
    for (int key = 0; !res && key <= key_number; key++) {

      res = encrypt_datetime_pipeline(enc, dataset, tweak, tweaklen,
        is_negative, ics_value, key, &ret_ct[key]);
    }
    if (!res) {
      *ctarr = ret_ct;
    }
  }
  
  free(ptbuf);
  free(ics_value);
  return res;
}

int ubiq_platform_structured_load_cache_datasets(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  char const * dataset_names[],
  size_t count
) 
{
  return load_search_keys(enc, dataset_names, count);
}



int ubiq_platform_structured_load_cache_dataset(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  char * dataset_name) 
{
  char const * dataset_names[2];
  dataset_names[0] = dataset_name;
  dataset_names[1] = NULL;

  return ubiq_platform_structured_load_cache_datasets(enc, dataset_names, 1);
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
  
  char * tmp = NULL;
  size_t len = *ctlen;

  int res = ubiq_platform_structured_encrypt_data(enc, ffs_name, tweak, tweaklen,
    ptbuf, ptlen,
    &tmp, &len);

  if (!res) {
    if (len < *ctlen) {
      strcpy(ctbuf, tmp);
      *ctlen = len;
    } else {
      res = CAPTURE_ERROR(enc, -EINVAL, "buffer is not large enough");
      *ctlen = len + 1;
    }
  }
  free(tmp);

  return res;
}

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
  char * tmp = NULL;
  size_t len = *ptlen;

  int res = ubiq_platform_structured_decrypt_data(enc, ffs_name, tweak, tweaklen,
    ctbuf, ctlen,
    &tmp, &len);

  if (!res) {
    if (len < *ptlen) {
      strcpy(ptbuf, tmp);
      *ptlen = len;
    } else {
      res = CAPTURE_ERROR(enc, -EINVAL, "buffer is not large enough");
      *ptlen = len + 1;
    }
  }
  free(tmp);
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
  char32_t * u32ctbuf = NULL;
  char32_t * u32pt = NULL;
  size_t u32ptlen = 0;
  int res = 0;

 
  // For compatibility purposes.  Need to switch from char to char32_t

  res = convert_utf8_to_utf32((uint8_t *)ctbuf, (uint32_t**)&u32ctbuf);

  if (!res) {
    res = ubiq_platform_structured_decrypt_u32data(enc, ffs_name,
    tweak, tweaklen,
    u32ctbuf, u32_strlen((uint32_t*)u32ctbuf),
    &u32pt, &u32ptlen);
  }
  if (!res) {
    convert_utf32_to_utf8((uint32_t*)u32pt, (uint8_t**)ptbuf);
    *ptlen = strlen(*ptbuf);
  }
  free(u32pt);
  free(u32ctbuf);
  return res;
}

int
ubiq_platform_structured_get_last_error(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  int * const err_num,
  char ** const err_msg
)
{
  static const char * const csu = "ubiq_platform_structured_get_last_error";
  int res = -EINVAL;

  UBIQ_DEBUG(debug_flag, printf("%s err_msg(%S)\n",csu, enc->error->err_msg));

  if (enc != NULL) {
    res = 0;
    *err_num = enc->error->err_num;
    if (enc->error->err_msg != NULL) {
      *err_msg = strdup(enc->error->err_msg);
      if (*err_msg == NULL) {
        res = -errno;
      }
    } else {
      *err_msg = NULL;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s *err_msg (%S)\n",csu, *err_msg ));

  return res;
}
/*
*/
// int
// ubiq_platform_structured_old_encrypt_data_for_search_prealloc(
//   struct ubiq_platform_structured_old_enc_dec_obj * const enc,
//   const char * const ffs_name,
//   const uint8_t * const tweak, const size_t tweaklen,
//   const char * const ptbuf, const size_t ptlen,
//   char ** const ctbuf, size_t * const ctbuflen , size_t * const count
// )
// {
//   static const char * const csu = "ubiq_platform_structured_old_encrypt_data_for_search_prealloc";
//   printf("%s - NYI\n", csu);
//   return -1;
// }

int
ubiq_platform_structured_encrypt_data_for_search_prealloc(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctbuflen, size_t * const count
)
{
  static const char * const csu = "ubiq_platform_structured_encrypt_data_for_search_prealloc";

  char ** tmp_ctbuf = NULL;
  size_t tmp_count = 0;



  int res = ubiq_platform_structured_encrypt_data_for_search(enc, ffs_name, tweak, tweaklen,
    ptbuf, ptlen,
    &tmp_ctbuf, &tmp_count);

  if (!res) {
    if (tmp_count < *count) {
      // Determine if the individual buffer is large enough, otherwise
      // set the necessary length
      for (int i = 0; i < tmp_count; i++) {
        if (strlen(tmp_ctbuf[i]) >= *ctbuflen) {
          *ctbuflen = strlen(tmp_ctbuf[i]) + 1;
          res = CAPTURE_ERROR(enc, -EINVAL, "buffer is not large enough");
        }
      }

      for (int i = 0; !res && i < tmp_count; i++) {
        strcpy(ctbuf[i], tmp_ctbuf[i]);
        free(tmp_ctbuf[i]);
      } 
    } else {
      res = CAPTURE_ERROR(enc, -EINVAL, "buffer is not large enough");
      *count = tmp_count;
    }
  }
  free(tmp_ctbuf);
  return res;

}


int
ubiq_platform_structured_encrypt_data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char *** const ctbuf, size_t * const count
)
{
  static int debug_flag = 0;
  static const char * const csu = "ubiq_platform_structured_encrypt_data_for_search";
  int res = 0;
  char ** ret_ct = NULL;
  char32_t * u32pt = NULL;
  char32_t ** u32ctbuf = NULL;
  
  UBIQ_DEBUG(debug_flag, printf("%s start\n", csu));

  res = convert_utf8_to_utf32((uint8_t *)ptbuf, (uint32_t**)&u32pt);
  if (!res) {
    res = ubiq_platform_structured_encrypt_u32data_for_search(
      enc, ffs_name,
      tweak, tweaklen,
      u32pt, u32_strlen((uint32_t*)u32pt),
      &u32ctbuf, count);
  }
  UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_structured_encrypt_data_for_search count(%d) res(%d)\n", csu, *count, res));

  if (!res) {
    ret_ct = (char **)calloc(*count, sizeof(char*));
    for (int i = 0; !res && i < *count; i++) {
      UBIQ_DEBUG(debug_flag, printf("%s i(%d) res(%d) %S\n", csu, i, res, u32ctbuf[i]));
      res = convert_utf32_to_utf8((uint32_t*)u32ctbuf[i], (uint8_t**)&ret_ct[i]);
      UBIQ_DEBUG(debug_flag, printf("%s convert_utf32_to_utf8 i(%d) res(%d)\n", csu, i, res));
      free(u32ctbuf[i]);
    }
    free(u32ctbuf);
  }
  if (!res) {
    *ctbuf = ret_ct;
  }
  free(u32pt);

   return res;
}

int
ubiq_platform_structured_encrypt_u32data_for_search(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  const char * const dataset_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char32_t * const ptbuf, const size_t ptlen,
  char32_t *** const ctbuf, size_t * const count
)
{
  static int debug_flag = 0;
  static const char * const csu = "ubiq_platform_structured_encrypt_u32data_for_search";
  int res = -EINVAL;
  int key_number = -1;
  char32_t ** ret_ct = NULL;
  ubiq_platform_dataset_t const * dataset = NULL;
  ubiq_platform_operation_context_t * ctx = NULL;

  res = get_dataset_current_key_number(enc,
        dataset_name,
        &key_number);

  UBIQ_DEBUG(debug_flag, printf("%s current_key(%d) res(%d)\n", csu, key_number, res));

  *count = key_number + 1;
  ret_ct = (char32_t **)calloc(*count, sizeof(char32_t*));
  if (!ret_ct) {
      res = -ENOMEM;
  } else {
    for (int key = 0; !res && key <= key_number; key++) {
      // For prealloc, will need to get this passed in
      // Due to token and generic_string, ptlen cannot be used
      size_t ctlen = 0;
      UBIQ_DEBUG(debug_flag, printf("%s key(%d) res(%d)\n", csu, key, res));

      res = encrypt_pipeline(enc, dataset_name, key, tweak, tweaklen, ptbuf, ptlen, &ret_ct[key], &ctlen);
      UBIQ_DEBUG(debug_flag, printf("%s ret_ct[(%d)]: %S res(%d)\n", csu, key_number, ret_ct[key], res));
    }
  }
  if (!res) {
    *ctbuf = ret_ct;
  }
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


UBIQ_PLATFORM_API
ubiq_platform_error_t * const ubiq_platform_structured_get_error_buffer(
  struct ubiq_platform_structured_enc_dec_obj * const enc)
{
  return enc->error;
}

UBIQ_PLATFORM_API
ubiq_platform_dataset_t const * const ubiq_platform_structured_get_dataset(
  struct ubiq_platform_structured_enc_dec_obj * const enc,
  char const * const dataset_name
) {
  static const char * const csu = "ubiq_platform_structured_get_dataset";
  ubiq_platform_dataset_t const * dataset = NULL;
  int res = ubiq_platform_dataset_cache_get_dataset(enc->dataset_cache, dataset_name, &dataset);
  UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_dataset_cache_get_dataset res(%d) \n", csu,res));
  if (res) {
    dataset = NULL;
  }
  return dataset;
}
