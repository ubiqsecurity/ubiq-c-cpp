#include "ubiq/platform.h"


#include "ubiq/platform/internal/structured_key_cache.h"
#include "ubiq/platform/internal/cache.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/sso.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/dataset.h"

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

// struct ffx_ctx;

// struct ff1_ctx
// {
//     struct ffx_ctx * ffx; // defined in ffx.h
// };

// wrapped_data_key is in base64
// decrypted_data_key is byte array
// decrypted_data_key will have length 0 if key_caching is stored encrypted and it needs to be decrypted
// each time.
typedef struct cached_key_element {
  ubiq_key_t wrapped_data_key, decrypted_data_key;
  unsigned int key_number;
} cached_key_element_t;



typedef struct ubiq_platform_structured_key_cache {
  struct ubiq_platform_cache * stuctured_key_cache; // ffs_name:key_number => void * (cached_key_element_t)

  // Creds are needed for IDP since cert can be updated and needs to be renewed
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_configuration * cfg;
  int key_cache_ttl_seconds;
  int key_cache_encrypt;
  int key_cache_structured;

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

  // PEM format
  ubiq_key_t encrypted_private_key;


} ubiq_platform_structured_key_cache_t;

/**************************************************************************************
 *
 * Static functions definitions
 *
**************************************************************************************/

static int http_fetch_cached_element(
  ubiq_platform_structured_key_cache_t * const key_cache, 
  char const * const dataset_name, 
  int const key_number,
  cached_key_element_t ** const cache_element);

static int clone_cached_element( cached_key_element_t const * const src,
   cached_key_element_t ** const dest);

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

static void
key_cache_element_destroy(void * const e) {
  cached_key_element_t * cached_key = (cached_key_element_t *) e;
  free(cached_key->wrapped_data_key.buf);
  free(cached_key->decrypted_data_key.buf);
  free(e);
}

static
int
save_rest_error(
  ubiq_platform_structured_key_cache_t * const key_cache,
  const http_response_code_t rc)
{
  char * msg = NULL;
  size_t len = 0;
  const void * rsp;

  rsp = ubiq_platform_rest_response_content(key_cache->rest, &len);
  if (rsp != NULL && len > 0) {
    msg = strndup(rsp, len);
    CAPTURE_ERROR(key_cache, -rc, msg);
    free(msg);
  }
  return -rc;
}

static
int
structured_key_create(ubiq_platform_structured_key_t ** const key){
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
structured_key_destroy(ubiq_platform_structured_key_t * const key){
  if (key && key->buf) {
    if (key->len > 0) {
      memset(key->buf, 0, key->len);
    }
    free(key->buf);
  }
  free(key);
}

// Retrieve the cached dataset key from the server.
static 
int get_cached_key_element(
  ubiq_platform_structured_key_cache_t * const key_cache,
  const char * const dataset_name,
  int const key_number,
  cached_key_element_t ** const cache_element)
{
  const char * const csu = "get_cached_key_element";

  int res = 0;
  
  char * key_str = NULL;
  get_key_cache_string(dataset_name, key_number, &key_str);
  UBIQ_DEBUG(debug_flag, printf("%s get_key_cache_string (%s)\n",csu, key_str));

  cached_key_element_t * tmp_key = NULL;

  tmp_key = (cached_key_element_t *)ubiq_platform_cache_find_element(key_cache->stuctured_key_cache, key_str);
  UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_cache_find_element (%d)\n",csu, tmp_key == NULL));

  if (tmp_key != NULL) {

  } else {
    res = http_fetch_cached_element(key_cache, dataset_name, key_number, &tmp_key);
    UBIQ_DEBUG(debug_flag, printf("%s http_fetch_cached_element (%d)\n",csu, res));
    if (!res) {res = ubiq_platform_cache_add_element(key_cache->stuctured_key_cache, key_str, tmp_key, &key_cache_element_destroy);}
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_cache_add_element (%d)\n",csu, res));

    // If this is encrypt and the key number is -1, also add the key for the cache using the true key number
    if (!res && key_number == -1) {
      char * dup_str = NULL;
      cached_key_element_t * dup_element = NULL;
      clone_cached_element(tmp_key, &dup_element);

      get_key_cache_string(dataset_name, dup_element->key_number, &dup_str);
      res = ubiq_platform_cache_add_element(key_cache->stuctured_key_cache, dup_str, dup_element, &key_cache_element_destroy);
      free(dup_str);
    }

  }
  if (!res) {
    *cache_element = tmp_key;
  }

  free(key_str);
  UBIQ_DEBUG(debug_flag, printf("%s end res(%d) cache_element(%d) tmp_key(%d)\n", csu, res, *cache_element != NULL, tmp_key != NULL));
  return res;
}

static int clone_cached_element( cached_key_element_t const * const src,
   cached_key_element_t ** const dest)
{
  int res = -ENOMEM;
  cached_key_element_t * d = NULL;
  if ((d = calloc(1, sizeof(*d))) != NULL) {
    d->wrapped_data_key.buf = calloc(1, src->wrapped_data_key.len);
    memcpy(d->wrapped_data_key.buf, src->wrapped_data_key.buf, src->wrapped_data_key.len);
    d->wrapped_data_key.len = src->wrapped_data_key.len;

    d->decrypted_data_key.buf = calloc(1, src->decrypted_data_key.len);
    memcpy(d->decrypted_data_key.buf, src->decrypted_data_key.buf, src->decrypted_data_key.len);
    d->decrypted_data_key.len = src->decrypted_data_key.len;

    d->key_number = src->key_number;
    res = 0;
  }
  if (!res) {
    *dest = d;
  }
  return res;
}


static int http_fetch_cached_element(
  ubiq_platform_structured_key_cache_t * const key_cache, 
  char const * const dataset_name, 
  int const key_number,
  cached_key_element_t ** const cache_element) 
{
  static const char * const fmt_encrypt_key = "%s/fpe/key?ffs_name=%s&papi=%s";
  static const char * const fmt_decrypt_key = "%s/fpe/key?ffs_name=%s&papi=%s&key_number=%d";
  const char * const csu = "http_fetch_cached_element";

  cached_key_element_t * element = NULL;
  element = calloc(1, sizeof(*element));

  cJSON * rsp_json = NULL;
  const cJSON * j = NULL;
  char * url = NULL;
  size_t len;
  int res = 0;

  char * encoded_name = NULL;
  res = ubiq_platform_rest_uri_escape(key_cache->rest, dataset_name, &encoded_name);

  if (!res) {
    if (key_number >= 0) {
      len = snprintf(NULL, 0, fmt_decrypt_key, key_cache->restapi, encoded_name, key_cache->encoded_papi, key_number);
    } else {
      len = snprintf(NULL, 0, fmt_encrypt_key, key_cache->restapi, encoded_name, key_cache->encoded_papi);
    }
    if ((url = malloc(len + 1)) == NULL) {
      res = -ENOMEM;
    } else {
      if (key_number >= 0) {
        snprintf(url, len + 1, fmt_decrypt_key, key_cache->restapi, encoded_name, key_cache->encoded_papi, key_number);
      } else {
        snprintf(url, len + 1, fmt_encrypt_key, key_cache->restapi, encoded_name, key_cache->encoded_papi);
      }
    }
  }
  free(encoded_name);
  if (!res && ubiq_platform_credentials_is_idp(key_cache->creds)) {
      ubiq_platform_sso_renewIdpCert(key_cache->creds, key_cache->cfg);
      size_t len = strlen(url);
      url = realloc(url, len + 1 + strlen("&payload_cert=") + strlen(ubiq_platform_credentials_get_cert_b64(key_cache->creds)));
      strcat(url, "&payload_cert=");
      strcat(url, ubiq_platform_credentials_get_cert_b64(key_cache->creds));
    }
  if (!res) {
    UBIQ_DEBUG(debug_flag, printf("%s url %s\n", csu, url));
    res = ubiq_platform_rest_request(
      key_cache->rest,
      HTTP_RM_GET, url, "application/json", NULL , 0);
  }
  free(url);

  UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_request res(%d)\n", csu, res));

  // If Success, simply proceed
  if (!res) {
    const http_response_code_t rc =
        ubiq_platform_rest_response_code(key_cache->rest);

    UBIQ_DEBUG(debug_flag, printf("%s http_response_code_t res(%d)\n", csu, rc));

    if (rc != HTTP_RC_OK) {
      res = save_rest_error(key_cache, rc);
    } else {
      const void * rsp = ubiq_platform_rest_response_content(key_cache->rest, &len);
      res = (rsp_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_response_content rsp(%.*s)\n", csu, len, rsp));
      
      if (rsp_json) {
        if (ubiq_platform_credentials_is_idp(key_cache->creds)) {
          // Make sure there isn't an existing encrypted private key.  Need to use this one.
          cJSON_DeleteItemFromObject(rsp_json, "encrypted_private_key");
          cJSON_AddStringToObject(rsp_json, "encrypted_private_key", ubiq_platform_credentials_get_encrypted_private_key(key_cache->creds));
        }
      }
    }
  }
  // If response was valid json AND we don't already manage the encrypted_private_key
  // save it in the main enc_dec object.
  if (!res && rsp_json) {
    if (key_cache->encrypted_private_key.len == 0) {
      j = cJSON_GetObjectItemCaseSensitive(
          rsp_json, "encrypted_private_key");
      if (cJSON_IsString(j) && j->valuestring != NULL) {
          key_cache->encrypted_private_key.buf = strdup(j->valuestring);
          key_cache->encrypted_private_key.len = strlen(key_cache->encrypted_private_key.buf);
          UBIQ_DEBUG(debug_flag, printf("key_cache->encrypted_private_key.buf %.*s\n" ,key_cache->encrypted_private_key.len, key_cache->encrypted_private_key.buf));
      } else {
          res = -EBADMSG;
      }
    }
  }

  // Save the wrapped data key.
  if (!res && rsp_json) {
    j = cJSON_GetObjectItemCaseSensitive(rsp_json, "wrapped_data_key");
    if (cJSON_IsString(j) && j->valuestring != NULL) {
      element->wrapped_data_key.buf = strdup(j->valuestring);
      element->wrapped_data_key.len = strlen(element->wrapped_data_key.buf);
      UBIQ_DEBUG(debug_flag, printf("element->wrapped_data_key.buf %.*s\n" ,element->wrapped_data_key.len, element->wrapped_data_key.buf));
    }
  }

  // Decrypt the wrapped key IF we are storing unencrypted keys
  if (!res && !key_cache->key_cache_encrypt) {
    res = ubiq_platform_common_decrypt_wrapped_key(
        key_cache->encrypted_private_key.buf,
        ubiq_platform_credentials_get_srsa(key_cache->creds),
        element->wrapped_data_key.buf,
        &element->decrypted_data_key.buf,
        &element->decrypted_data_key.len);
    UBIQ_DEBUG(debug_flag, printf("res(%d) element->decrypted_data_key.len %d\n", res, element->decrypted_data_key.len));
  }

  if (!CAPTURE_ERROR(key_cache, res, "Unable to parse key from server")) {
    const cJSON * kn = cJSON_GetObjectItemCaseSensitive(
                      rsp_json, "key_number");
    if (cJSON_IsString(kn) && kn->valuestring != NULL) {
      const char * errstr = NULL;
      uintmax_t n = strtoumax(kn->valuestring, NULL, 10);
      if (n == UINTMAX_MAX && errno == ERANGE) {
        res = CAPTURE_ERROR(key_cache, -ERANGE, "Invalid key range");
      } else {
        element->key_number = (unsigned int)n;
        UBIQ_DEBUG(debug_flag, printf("res(%d) element->key_number %d\n", res, element->key_number));
      }
    } else {
      res = CAPTURE_ERROR(key_cache, -EBADMSG, "Invalid server response");
    }
  }

  cJSON_Delete(rsp_json);
  if (!res) {
    *cache_element = element;
  }
  return res;
}


/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/


int ubiq_platform_structured_key_cache_create(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const cfg,
  ubiq_platform_error_t * const error_buffer,
  ubiq_platform_structured_key_cache_t ** const key_cache) {

  static const char * const csu = "ubiq_platform_structured_key_cache_create";
  static const char * const api_path = "api/v0";

  int res = -ENOMEM;
  ubiq_platform_structured_key_cache_t * c = NULL;
  int ttl = 0;

  c = calloc(1, sizeof(*c));
  if (c) {
    res = ubiq_platform_credentials_clone(creds, &(c->creds));
    if (!res) {
      res = ubiq_platform_configuration_clone(cfg, &(c->cfg));
    }

    if (!res) {
      c->error = error_buffer;
      c->key_cache_ttl_seconds = ubiq_platform_configuration_get_key_caching_ttl_seconds(c->cfg);
      c->key_cache_structured = ubiq_platform_configuration_get_key_caching_structured_keys(c->cfg);
      c->key_cache_encrypt = ubiq_platform_configuration_get_key_caching_encrypt(c->cfg);
    }
    if (c->key_cache_structured) {
      ttl = c->key_cache_ttl_seconds;
    }

    if (!res) {
      // htable size 500 - means slots for 500 possible key collisions
      // Reduces the likelihood of a key collision 
      res = ubiq_platform_cache_create(500, ttl, &c->stuctured_key_cache);
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
      *key_cache = c;
      res = 0;
    }
  }

  return res;
}

void ubiq_platform_structured_key_cache_destroy(ubiq_platform_structured_key_cache_t * const ctx) {
  
  if (ctx) {
    ubiq_platform_credentials_destroy(ctx->creds);
    ubiq_platform_configuration_destroy(ctx->cfg);
    ubiq_platform_cache_destroy(ctx->stuctured_key_cache);
    ubiq_platform_rest_handle_destroy(ctx->rest);

    free(ctx->restapi);
    free(ctx->encoded_papi);
    free(ctx->encrypted_private_key.buf);
    free(ctx);
  }
}


int ubiq_platform_structured_key_cache_get_structured_key(
  ubiq_platform_structured_key_cache_t * const key_cache,
  const char * const dataset_name,
  int const key_number,
  ubiq_platform_structured_key_t ** key)
{
  const char * const csu = "ubiq_platform_structured_key_cache_get_structured_key";
  int res = 0;
  cached_key_element_t * key_element = NULL;
  ubiq_platform_structured_key_t * structured_key = NULL;

  structured_key = calloc(1, sizeof(*structured_key));
  UBIQ_DEBUG(debug_flag, printf("%s start dataset_name(%s) key_number(%d)\n",csu, dataset_name, key_number));

  // If the keys are stored decrypted, then the key_element will already have the decrypted key
  res = get_cached_key_element(key_cache, dataset_name, key_number, &key_element);
  UBIQ_DEBUG(debug_flag, printf("%s get_cached_key_element res(%d) key_element(%d)\n",csu, res, key_element != NULL));

  if (!res && key_element)
  {
    if (key_element->decrypted_data_key.len != 0) {
      UBIQ_DEBUG(debug_flag, printf("%s already decrypted(%d)\n",csu, key_element->decrypted_data_key.len));
      structured_key->buf = calloc(1, key_element->decrypted_data_key.len);
      memcpy(structured_key->buf, key_element->decrypted_data_key.buf, key_element->decrypted_data_key.len);
      structured_key->len = key_element->decrypted_data_key.len;
      structured_key->key_number = key_element->key_number;
    } else {
      // Decrypt the wrapped key each time which also means decrypting the private key
      ubiq_platform_common_decrypt_wrapped_key(
            key_cache->encrypted_private_key.buf,
            ubiq_platform_credentials_get_srsa(key_cache->creds),
            key_element->wrapped_data_key.buf,
            &structured_key->buf,
            &structured_key->len);  
      structured_key->key_number = key_element->key_number;  
      UBIQ_DEBUG(debug_flag, printf("%s decrypted(%d)\n",csu, key_element->decrypted_data_key.len));
    }
  }
  if (!res) {
    *key = structured_key;
  } else {
    ubiq_platform_structured_key_cache_structured_key_destroy(structured_key);
  }
  return res;
}

void ubiq_platform_structured_key_cache_structured_key_destroy(
  ubiq_platform_structured_key_t * const key)
{
  if (key) {
    free(key->buf);
  }
  free(key);
}



int ubiq_platform_structured_key_cache_set_encrypted_private_key(
  ubiq_platform_structured_key_cache_t * const key_cache,
  char const * const encrypted_private_key) 
{
  int res = -ENOMEM;
  if (key_cache->encrypted_private_key.buf) {
    free(key_cache->encrypted_private_key.buf);
  }
  if (NULL != (key_cache->encrypted_private_key.buf = strdup(encrypted_private_key))) {

    key_cache->encrypted_private_key.len = strlen(key_cache->encrypted_private_key.buf);
    res = 0;
  }
}

int ubiq_platform_structured_key_cache_add_key(
  ubiq_platform_structured_key_cache_t * const key_cache,
  const char * const dataset_name,
  int const key_number,
  int const current_key_flag,
  char const * const wrapped_data_key)
{
    const char * const csu = "ubiq_platform_structured_key_cache_add_key";

    int res = 0;
    char * key_str = NULL;

    UBIQ_DEBUG(debug_flag, printf("%s start\n", csu));

    res = get_key_cache_string(dataset_name, key_number, &key_str);

    UBIQ_DEBUG(debug_flag, printf("%s get_key_cache_string (%s) res(%d)\n", csu, key_str, res));

    cached_key_element_t * element = NULL;
    cached_key_element_t * dup_element = NULL;
    element = calloc(1, sizeof(*element));

    element->wrapped_data_key.buf = strdup(wrapped_data_key);
    element->wrapped_data_key.len = strlen(element->wrapped_data_key.buf);

    res = ubiq_platform_common_decrypt_wrapped_key(
        key_cache->encrypted_private_key.buf,
        ubiq_platform_credentials_get_srsa(key_cache->creds),
        element->wrapped_data_key.buf,
        &element->decrypted_data_key.buf,
        &element->decrypted_data_key.len);
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_common_decrypt_wrapped_key res(%d)\n", csu, res));

    element->key_number = key_number;

    // It is possible that the element added will be a duplicate in which case, this element 
    // will freed.  Therefore, if the current_key_flag is set, clone the element before it is added
    // so we don't have to re-create from scratch.
    if (!res && current_key_flag) {
      res = clone_cached_element(element, &dup_element);
      UBIQ_DEBUG(debug_flag, printf("%s clone_cached_element res(%d)\n", csu, res));
    }

    if (!res) {res = ubiq_platform_cache_add_element(key_cache->stuctured_key_cache, key_str, element, &key_cache_element_destroy);}
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_cache_add_element res(%d)\n", csu, res));
    if (res && element) {
      UBIQ_DEBUG(debug_flag, printf("%s checking key_cache_element_destroy res(%d) element == NULL(%d)\n", csu, res, element == NULL));
      key_cache_element_destroy(element);
    }

    // If the the current key flag is set, then also add for key_string with -1 for encrypt
    if (!res && current_key_flag) {
      free(key_str);

      res = get_key_cache_string(dataset_name, -1, &key_str);
      UBIQ_DEBUG(debug_flag, printf("%s get_key_cache_string key_str(%s) res(%d)\n", csu, key_str, res));

      if (!res) {res = ubiq_platform_cache_add_element(key_cache->stuctured_key_cache, key_str, dup_element, &key_cache_element_destroy);}
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_cache_add_element res(%d)\n", csu, res));
    }
    if (res && dup_element) {
      UBIQ_DEBUG(debug_flag, printf("%s checking key_cache_element_destroy res(%d) dup_element == NULL(%d)\n", csu, res, dup_element == NULL));
      key_cache_element_destroy(dup_element);
    }
    free(key_str);
    return res;
}
