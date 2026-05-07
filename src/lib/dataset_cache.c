#include "ubiq/platform.h"

#include "ubiq/platform/internal/dataset_cache.h"
#include "ubiq/platform/internal/cache.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/sso.h"
#include "ubiq/platform/internal/common.h"

#include "cJSON/cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <unistr.h>
#include <stdio.h>


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
  if (result && e->error) { \
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

// struct dataset_ctx
// {
//     struct ffx_ctx * ffx; // defined in ffx.h
// };

typedef struct ctx_cache_element {
  void * dataset; // points to ubiq_platform_dataset_t
} dataset_cache_element_t;



typedef struct ubiq_platform_dataset_cache {
  struct ubiq_platform_cache * dataset_cache; // ffs_name: => void * (dataset_t)

  // Creds are needed for IDP since cert can be updated and needs to be renewed
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_configuration * cfg;
  int cache_ttl_seconds;
  char * encoded_papi;

  // Curl library is not thread safe.  Need separate one for Billing and non-billing.
  // Billing rest handle is created / managed in billing_ctx
  struct ubiq_platform_rest_handle * rest;

  /* http[s]://host/api/v0 */
  char * restapi;

  // Passed in during creation.  Do not create or destroy
  ubiq_platform_error_t * error;

  // struct {
  //       char * err_msg;
  //       size_t err_num;
  // } error;

} ubiq_platform_dataset_cache_t;

/**************************************************************************************
 *
 * Static functions definitions
 *
**************************************************************************************/

// This is simple right now but provides easy ability to extend if needed in the future
static int get_cache_key_string(const char * const dataset_name,
  char ** const str) 
{
  int res = -ENOMEM;
  if ((*str = strdup(dataset_name)) != NULL) {
    res = 0;
  }
  return res;
}

static
int
save_rest_error(
  ubiq_platform_dataset_cache_t * const ctx,
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

static void
cache_element_destroy(void * const e) {
  int debug_flag = 1;
  static const char * const csu = "dataset_cache.cache_element_destroy";

  dataset_cache_element_t * element = (dataset_cache_element_t *) e;
  // UBIQ_DEBUG(debug_flag, printf("%s dataset (%s) \n", csu, ubiq_platform_dataset_get_name(element->dataset)));
  ubiq_platform_dataset_destroy(element->dataset);
  free(e);
}

/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/


int ubiq_platform_dataset_cache_create(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const cfg,
  ubiq_platform_error_t * const error,
  ubiq_platform_dataset_cache_t ** const dataset_cache) {

  static const char * const csu = "ubiq_platform_dataset_cache_create";
  static const char * const api_path = "api/v0";

  int res = -ENOMEM;
  ubiq_platform_dataset_cache_t * c = NULL;

  c = calloc(1, sizeof(*c));
  if (c) {
    res = ubiq_platform_credentials_clone(creds, &(c->creds));
    if (!res) {
      res = ubiq_platform_configuration_clone(cfg, &(c->cfg));
    }

    if (!res) {
      c->cache_ttl_seconds = ubiq_platform_configuration_get_key_caching_ttl_seconds(c->cfg);
      res = ubiq_platform_cache_create(500, c->cache_ttl_seconds, &c->dataset_cache);
    }
      c->error = error;
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
      *dataset_cache = c;
      res = 0;
    }
  }

  return res;
}

void ubiq_platform_dataset_cache_destroy(ubiq_platform_dataset_cache_t * const dataset_cache) {
  
  if (dataset_cache) {
    ubiq_platform_credentials_destroy(dataset_cache->creds);
    ubiq_platform_configuration_destroy(dataset_cache->cfg);
    ubiq_platform_cache_destroy(dataset_cache->dataset_cache);
    ubiq_platform_rest_handle_destroy(dataset_cache->rest);

    free(dataset_cache->restapi);
    free(dataset_cache->encoded_papi);

    free(dataset_cache);
  }
}


// Used for the Rest Interfaces that retrieve a dataset and keys
// but we want the dataset added to the cache without a separate http request
// Return the dataset that was added to the cache.  Don't force a re-retrieve
int ubiq_platform_dataset_cache_add_dataset(
  ubiq_platform_dataset_cache_t * const cache,
  cJSON const * const dataset_json,
  ubiq_platform_dataset_t const ** const dataset)
{
  int debug_flag = 1;
  const char * const csu = "ubiq_platform_dataset_cache_add_dataset";
  int res = -EINVAL;
  ubiq_platform_dataset_t * d = NULL;

  res = ubiq_platform_dataset_create(dataset_json, &d);
  if (!res && d != NULL) {
    const char * const name = ubiq_platform_dataset_get_name(d);
    char * key_str = NULL;
    res = get_cache_key_string(name, &key_str);
    UBIQ_DEBUG(debug_flag, printf("%s key_str (%s) res(%d)\n", csu, key_str, res));
    if (!res) {
      // Using element rather than just dataset for future expansion if necessary
      dataset_cache_element_t * element = calloc(1, sizeof(dataset_cache_element_t));
      element->dataset = d;
      res = ubiq_platform_cache_add_element(
        cache->dataset_cache, key_str, element, &cache_element_destroy);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_cache_add_element (%s) res(%d)\n", csu, key_str, res));
    }
    free(key_str);
  }
  if (!res) {
    *dataset = d;
  }
  UBIQ_DEBUG(debug_flag, printf("%s end res(%d)\n", csu, res));
  return res;
}

int ubiq_platform_dataset_cache_get_dataset(
  ubiq_platform_dataset_cache_t * const cache,
  const char * const dataset_name,
  ubiq_platform_dataset_t const * * const dataset)
{
  const char * const csu = "ubiq_platform_dataset_cache_get_dataset";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";
  int res = 0;
  dataset_cache_element_t * cache_element = NULL;
  char * key_str = NULL;
  char * encoded_name = NULL;
  char * url = NULL;
  size_t len = 0;
  int debug_flag = 1;
  *dataset = NULL;
  res = get_cache_key_string(dataset_name, &key_str);
  UBIQ_DEBUG(debug_flag, printf("%s key_str(%s)\n",csu, key_str));

  cache_element = (dataset_cache_element_t *)ubiq_platform_cache_find_element(cache->dataset_cache, key_str);

  if (cache_element != NULL) {
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "key found in Cache"));
    *dataset = cache_element->dataset;
    res = 0;
  } else {
    if (!res) {
      UBIQ_DEBUG(debug_flag, printf("%s key NOT found in cache\n",csu));

      // Fetch dataset
      res = ubiq_platform_rest_uri_escape(cache->rest, dataset_name, &encoded_name);

      len = snprintf(NULL, 0, fmt, cache->restapi, encoded_name, cache->encoded_papi);
      url = malloc(len + 1);
      snprintf(url, len + 1, fmt, cache->restapi, encoded_name, cache->encoded_papi);
      free(encoded_name);

      res = ubiq_platform_rest_request(
          cache->rest,
          HTTP_RM_GET, url, "application/json", NULL, 0);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_request res(%d)\n",csu, res));

      if (!(res = CAPTURE_ERROR(cache, res, "Unable to process request to get dataset")))
      {
        // Get HTTP response code.  If not OK, return error value
        http_response_code_t rc = ubiq_platform_rest_response_code(cache->rest);
      UBIQ_DEBUG(debug_flag, printf("%s rc(%d) res(%d)\n",csu, rc, res));

        if (rc != HTTP_RC_OK) {
          // Capture Error
          res = save_rest_error(cache, rc);
        } else {
          // Get the response payload, parse, and continue.
          cJSON * dataset_json = NULL;
          const void * rsp = ubiq_platform_rest_response_content(cache->rest, &len);
          res = (dataset_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

          if (res == 0) {

            res = ubiq_platform_dataset_cache_add_dataset(cache, dataset_json, dataset);
      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_dataset_cache_add_dataset res(%d)\n",csu, rc, res));
          }
          cJSON_Delete(dataset_json);
        }
      }
      free(url);

    }
  }
  free(key_str);
  UBIQ_DEBUG(debug_flag, printf("%s END res(%d) error_msg: %s\n",csu, res, cache->error->err_msg));

  return res;

}


