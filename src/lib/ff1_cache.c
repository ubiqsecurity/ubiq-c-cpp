#include "ubiq/platform.h"


#include "ubiq/platform/internal/ff1_cache.h"
#include "ubiq/platform/internal/cache.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/ff1.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/sso.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/parsing.h"
#include "cJSON/cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <unistr.h>
#include <stdio.h>
#include <inttypes.h>

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
 * Constants
 *
**************************************************************************************/

/**************************************************************************************
 *
 * Structures
 *
************************************** ************************************************/

typedef struct ff1_cache_element {
  void * ff1_ctx; // points to ff1_ctx
  unsigned int key_number;
} ff1_cache_element_t;

typedef struct ubiq_platform_ff1_cache {
  struct ubiq_platform_cache * ff1_cache; // ffs_name:key_number => void * (ff1_ctx)

  // Creds are needed for IDP since cert can be updated and needs to be renewed
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_configuration * cfg;
  int key_cache_ttl_seconds;

  // Curl library is not thread safe.  Need separate one for Billing and non-billing.
  // Billing rest handle is created / managed in billing_ctx
  struct ubiq_platform_rest_handle * rest;

  /* http[s]://host/api/v0 */
  char * restapi;
  char * encoded_papi;

  // struct {
  //       char * err_msg;
  //       size_t err_num;
  // } error;
  // Passed in during creation.  Do not create or destroy
  ubiq_platform_error_t * error;

  ubiq_platform_dataset_cache_t *  dataset_cache; // points to external object - do not free
  ubiq_platform_structured_key_cache_t * stuctured_key_cache; // points to external object - do not free

} ubiq_platform_ff1_cache_t;

/**************************************************************************************
 *
 * Static functions definitions
 *
**************************************************************************************/

static void
cache_element_destroy(void * const e) {
  ff1_cache_element_t * element = (ff1_cache_element_t *) e;
  ff1_ctx_destroy(element->ff1_ctx);
  free(e);
}


static int get_key_cache_string(const char * const ffs_name,
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
save_rest_error(
  ubiq_platform_ff1_cache_t * const ctx,
  const http_response_code_t rc)
{
  char * msg = NULL;
  size_t len = 0;
  const void * rsp;

  rsp = ubiq_platform_rest_response_content(ctx->rest, &len);
  if (rsp != NULL && len > 0) {
    msg = strndup(rsp, len);
    CAPTURE_ERROR(ctx, -rc, msg);
    free(msg);
  }
  return -rc;
}

static int parse_def_keys(
  ubiq_platform_ff1_cache_t * const ctx_cache,
  char const ** const dataset_names, size_t const count,
  cJSON * const rsp_json)
{
  int debug_flag = 1;
  const char * const csu = "parse_def_keys";
  int res = 0;
  UBIQ_DEBUG(debug_flag, printf("%s start\n", csu));
  for (int i = 0; res == 0 && i< count; i++) {
    ubiq_platform_dataset_t const *  dataset = NULL;
    const char * const dataset_name = dataset_names[i];
    UBIQ_DEBUG(debug_flag, printf("%s processing dataset (%s)\n", csu, dataset_name));
    cJSON * top_lvl = cJSON_GetObjectItemCaseSensitive(rsp_json, dataset_name);
    if (!cJSON_IsObject(top_lvl)) {
      continue;
    }
    cJSON * dataset_json = cJSON_GetObjectItemCaseSensitive(top_lvl, "ffs");
    if (!cJSON_IsObject(dataset_json)) {
      res = CAPTURE_ERROR(ctx_cache, -EINVAL, "missing dataset definition");
      continue;
    }

    cJSON * prv_key = cJSON_GetObjectItemCaseSensitive(top_lvl, "encrypted_private_key");
    if (!cJSON_IsString(prv_key)) {
      res = CAPTURE_ERROR(ctx_cache, -EINVAL, "missing encrypted_private_key");
      continue;
    }
    const char * prvpem = NULL;
    if (ubiq_platform_credentials_is_idp(ctx_cache->creds)) {
      prvpem = ubiq_platform_credentials_get_encrypted_private_key(ctx_cache->creds);
    } else {
      prvpem = prv_key->valuestring;
    }

    cJSON * key_num = cJSON_GetObjectItemCaseSensitive(top_lvl, "current_key_number");
    if (!cJSON_IsNumber(key_num)) {
      res = CAPTURE_ERROR(ctx_cache, -EINVAL, "missing current_key_number");
      continue;
    }

    cJSON * keys = cJSON_GetObjectItemCaseSensitive(top_lvl, "keys");
    if (!cJSON_IsArray(keys)) {
      res = CAPTURE_ERROR(ctx_cache, -EINVAL, "missing keys array");
      continue;
    }

    int key_count = cJSON_GetArraySize(keys);
    int current_key_number = cJSON_GetNumberValue(key_num);

    res = ubiq_platform_structured_key_cache_set_encrypted_private_key(ctx_cache->stuctured_key_cache,
      prvpem);

    res = ubiq_platform_dataset_cache_add_dataset(ctx_cache->dataset_cache, dataset_json, &dataset);
    CAPTURE_ERROR(ctx_cache, res, "Unable to cache dataset");
    
    for (int key = 0; res == 0 && key < key_count; key++) {
    UBIQ_DEBUG(debug_flag, printf("%s processing key (%d) current_key_number(%d)\n", csu, key, current_key_number));
       cJSON * key_json = cJSON_GetArrayItem(keys, key);
    UBIQ_DEBUG(debug_flag, printf("%s processing key (%s) \n", csu, key_json->valuestring));
       res = ubiq_platform_structured_key_cache_add_key(ctx_cache->stuctured_key_cache,
          dataset_name, key, key == current_key_number, key_json->valuestring);
        CAPTURE_ERROR(ctx_cache, res, "Unable to cache structured key");

    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s END (%d) error(%s)\n", csu, res, ctx_cache->error->err_msg));
  return res;
}

/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/


int ubiq_platform_ff1_cache_create(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const cfg,
  ubiq_platform_dataset_cache_t * const dataset_cache, // Saves a copy - do not free
  ubiq_platform_structured_key_cache_t * const key_cache,
  ubiq_platform_error_t * const error_buffer,
  ubiq_platform_ff1_cache_t ** const ff1_cache) {

  static const char * const csu = "ubiq_platform_ff1_cache_create";
  static const char * const api_path = "api/v0";

  int res = -ENOMEM;
  ubiq_platform_ff1_cache_t * c = NULL;
  int ttl = 0;

  c = calloc(1, sizeof(*c));
  if (c) {
    res = ubiq_platform_credentials_clone(creds, &(c->creds));
    if (!res) {
      res = ubiq_platform_configuration_clone(cfg, &(c->cfg));
    }

    if (!res) {
      c->error = error_buffer;
      c->dataset_cache = dataset_cache;
      c->key_cache_ttl_seconds = ubiq_platform_configuration_get_key_caching_ttl_seconds(c->cfg);
      c->stuctured_key_cache = key_cache;
      // c->key_cache_encrypt = ubiq_platform_configuration_get_key_caching_encrypt(c->cfg);
    }
    if (ubiq_platform_configuration_get_key_caching_structured_keys(c->cfg)) {
      ttl = c->key_cache_ttl_seconds;
    }
    if (!res) {
      // htable size 500 - means slots for 500 possible key collisions
      // Reduces the likelihood of a key collision 
      // If we are storing the keys encrypted, then 
      // the ctx cannot cache data
      if (ubiq_platform_configuration_get_key_caching_encrypt(c->cfg)) {
        ttl = 0;
      }
      res = ubiq_platform_cache_create(500, ttl, &c->ff1_cache);
    }
    if (!res) {
      const char * const host = ubiq_platform_credentials_get_host(creds);

      size_t len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);
      if (((int)len) <= 0) { // error of some sort
        res = len;
      } else {
        len++; // null terminator
        c->restapi = calloc(len, 1);
        res = 0;
      }

      if (!res && ubiq_platform_credentials_is_idp(c->creds)) {
        // Don't login again if the access token is already set.
        if (ubiq_platform_credentials_get_access_token(c->creds) == NULL) {
          if ((res = ubiq_platform_sso_login(c->creds, c->cfg)) != 0) {
              
          }
        }
      }

      if (!res) {
        ubiq_platform_snprintf_api_url(c->restapi, len, host, api_path);
        res = ubiq_platform_rest_handle_create(
          ubiq_platform_credentials_get_papi(c->creds),
          ubiq_platform_credentials_get_sapi(c->creds), &c->rest);
      }

      if (!res) {
        res = ubiq_platform_rest_uri_escape(c->rest, ubiq_platform_credentials_get_papi(c->creds), &c->encoded_papi);
      }
    }

    if (!res) {
      *ff1_cache = c;
      res = 0;
    }
  }

  return res;
}

void ubiq_platform_ff1_cache_destroy(ubiq_platform_ff1_cache_t * const cache) {
  
  if (cache) {
    ubiq_platform_credentials_destroy(cache->creds);
    ubiq_platform_configuration_destroy(cache->cfg);
    ubiq_platform_cache_destroy(cache->ff1_cache);
    // ubiq_platform_cache_destroy(ctx->stuctured_key_cache);
    ubiq_platform_rest_handle_destroy(cache->rest);

    free(cache->restapi);
    free(cache->encoded_papi);

    free(cache);
  }
}


int ubiq_platform_ff1_cache_get_ff1_ctx(
  ubiq_platform_ff1_cache_t * const ff1_cache,
  const char * const dataset_name,
  int * const key_number, // Needed to know how to encode the ciphertext
  struct ff1_ctx ** ff1_ctx)
{
  const char * const csu = "ubiq_platform_ff1_cache_get_ff1_ctx";
  int res = 0;
  ff1_cache_element_t * ff1_cache_element = NULL;
  char * key_str = NULL;

  ubiq_platform_dataset_t const * dataset = NULL;
  
  UBIQ_DEBUG(debug_flag, printf("%s ff1_cache NULL?(%d)\n",csu, ff1_cache == NULL));
  UBIQ_DEBUG(debug_flag, printf("%s dataset_cache NULL?(%d)\n",csu, ff1_cache->dataset_cache == NULL));
  UBIQ_DEBUG(debug_flag, printf("%s dataset_name (%s))\n",csu, dataset_name));


  res = ubiq_platform_dataset_cache_get_dataset(ff1_cache->dataset_cache, dataset_name, &dataset);
  get_key_cache_string(dataset_name, *key_number, &key_str);
  UBIQ_DEBUG(debug_flag, printf("%s key_str(%s)\n",csu, key_str));

  ff1_cache_element = (ff1_cache_element_t *)ubiq_platform_cache_find_element(ff1_cache->ff1_cache, key_str);

  if (ff1_cache_element != NULL) {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "key found in Cache"));
  } else {
    if (!res) {
      UBIQ_DEBUG(debug_flag, printf("%s key NOT found in cache\n",csu));
      ubiq_platform_structured_key_t * structured_key = NULL;
      res = ubiq_platform_structured_key_cache_get_structured_key(ff1_cache->stuctured_key_cache, dataset_name, *key_number, &structured_key);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_structured_key_cache_get_structured_key res(%d)\n",csu, res));
      if (!res && structured_key != NULL) {
          // Create for encrypt (key_number == -1)
          if (!res && *key_number == -1) {
            UBIQ_DEBUG(debug_flag, printf("%s Creating entry for encrypt key_number(%d)\n",csu, *key_number));

            char * encrypt_key_str = NULL;
            get_key_cache_string(dataset_name, *key_number, &encrypt_key_str);

            struct ff1_ctx * local_ff1_ctx = NULL;
            ff1_cache_element_t * local_ff1_cache_element = NULL;
            res = ff1_ctx_create_custom_radix(&local_ff1_ctx, structured_key->buf, structured_key->len,
            ubiq_platform_dataset_get_tweak(dataset),
            ubiq_platform_dataset_get_tweak_len(dataset),
            ubiq_platform_dataset_get_tweak_min_len(dataset),
            ubiq_platform_dataset_get_tweak_max_len(dataset),
            ubiq_platform_dataset_get_input_characters(dataset));

            // Creating two separate objects since the cache destroy needs to free separately
            local_ff1_cache_element = calloc(1, sizeof(*local_ff1_cache_element));
            local_ff1_cache_element->ff1_ctx = local_ff1_ctx;
            local_ff1_cache_element->key_number = structured_key->key_number;
            res = ubiq_platform_cache_add_element(ff1_cache->ff1_cache, encrypt_key_str, local_ff1_cache_element, &cache_element_destroy);
            free(encrypt_key_str);
          }

          struct ff1_ctx * result_ff1_ctx = NULL;
          char * decrypt_key_string = NULL; // Actual key number
          get_key_cache_string(dataset_name, structured_key->key_number, &decrypt_key_string);
            UBIQ_DEBUG(debug_flag, printf("%s Creating entry for decrypt key_number(%d)\n",csu, structured_key->key_number));

          res = ff1_ctx_create_custom_radix(&result_ff1_ctx, structured_key->buf, structured_key->len,
            ubiq_platform_dataset_get_tweak(dataset),
            ubiq_platform_dataset_get_tweak_len(dataset),
            ubiq_platform_dataset_get_tweak_min_len(dataset),
            ubiq_platform_dataset_get_tweak_max_len(dataset),
            ubiq_platform_dataset_get_input_characters(dataset));
// ff1_ctx_destroy(ff1_ctx);
// res = -1;
          if (!res) {
            ff1_cache_element = calloc(1, sizeof(*ff1_cache_element));
            ff1_cache_element->ff1_ctx = result_ff1_ctx;
            ff1_cache_element->key_number = structured_key->key_number;
            *key_number = structured_key->key_number;
            res = ubiq_platform_cache_add_element(ff1_cache->ff1_cache, decrypt_key_string, ff1_cache_element, &cache_element_destroy);
          }
          free(decrypt_key_string);
      }
      ubiq_platform_structured_key_cache_structured_key_destroy(structured_key);

    }
  }

  if (!res) {
      *ff1_ctx = ff1_cache_element->ff1_ctx;
      *key_number = ff1_cache_element->key_number;
  }

  free(key_str);
  return res;
}


int ubiq_platform_ff1_cache_load_def_keys(
    ubiq_platform_ff1_cache_t * const ctx_cache,
    char const ** const dataset_names, size_t const count)
{
  int debug_flag = 1;
  const char * const csu = "ubiq_platform_ff1_cache_load_datasets";
  int res = 0;
  char * names = NULL;
  char * encoded_names = NULL;
  char * url = NULL;
  size_t len =0;
  cJSON * rsp_json = NULL;

  static const char * const fmt_def_keys = "%s/fpe/def_keys?ffs_name=%s&papi=%s";

  UBIQ_DEBUG(debug_flag, printf("%s start\n", csu));

  // Fetch the datasets using /fpe/def_keys

  res = ubiq_platform_join_array(",", dataset_names, count, &names);
  UBIQ_DEBUG(debug_flag, printf("%s dataset_names names(%s) res(%d)\n", csu, names, res));

  if (!res) {res = ubiq_platform_rest_uri_escape(ctx_cache->rest, names, &encoded_names);}
  UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_uri_escape res(%d)\n", csu, res));

  if (!res) {
    len = snprintf(NULL, 0, fmt_def_keys, ctx_cache->restapi, encoded_names, ctx_cache->encoded_papi);
    if ((url = malloc(len + 1)) == NULL) {
      res = -ENOMEM;
    } else {
      snprintf(url, len + 1, fmt_def_keys, ctx_cache->restapi, encoded_names, ctx_cache->encoded_papi);
    }
  }
  free(names);
  free(encoded_names);
  if (!res && ubiq_platform_credentials_is_idp(ctx_cache->creds)) {
      ubiq_platform_sso_renewIdpCert(ctx_cache->creds, ctx_cache->cfg);
      size_t len = strlen(url);
      url = realloc(url, len + 1 + strlen("&payload_cert=") + strlen(ubiq_platform_credentials_get_cert_b64(ctx_cache->creds)));
      strcat(url, "&payload_cert=");
      strcat(url, ubiq_platform_credentials_get_cert_b64(ctx_cache->creds));
    }
  if (!res) {
    UBIQ_DEBUG(debug_flag, printf("%s url %s\n", csu, url));
    res = ubiq_platform_rest_request(
      ctx_cache->rest,
      HTTP_RM_GET, url, "application/json", NULL , 0);
  }
  free(url);

  UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_request res(%d)\n", csu, res));

  if (!res) {
    const http_response_code_t rc =
        ubiq_platform_rest_response_code(ctx_cache->rest);

    UBIQ_DEBUG(debug_flag, printf("%s http_response_code_t res(%d)\n", csu, rc));

    if (rc != HTTP_RC_OK) {
      res = save_rest_error(ctx_cache, rc);
    } else {
      const void * rsp = ubiq_platform_rest_response_content(ctx_cache->rest, &len);
      res = (rsp_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_response_content rsp(%.*s)\n", csu, len, rsp));
      
      if (rsp_json) {
        if (ubiq_platform_credentials_is_idp(ctx_cache->creds)) {
          // Make sure there isn't an existing encrypted private key.  Need to use this one.
          cJSON_DeleteItemFromObject(rsp_json, "encrypted_private_key");
          cJSON_AddStringToObject(rsp_json, "encrypted_private_key", ubiq_platform_credentials_get_encrypted_private_key(ctx_cache->creds));
        }
      }
    }
  }

  // It is possible that the results don't have all the requested names
  if (!res) {res = parse_def_keys(ctx_cache, dataset_names, count, rsp_json);}

  cJSON_Delete(rsp_json);
  UBIQ_DEBUG(debug_flag, printf("%s END res(%d)\n", csu, res));


  return res;
}
