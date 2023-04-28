/*
 * Caching of FFS information based on FFS name.  Including pAPI in the
 * cache since in theory, this could used to go to different accounts
 * which could have same FFS name but for different Ubiq accounts, and therefore
 * different data.
 *
 * Since the universe of FFS values will be small, but the linux hash table is an
 * immutable size, going to use a simple b-tree
*/

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <search.h>
#include <pthread.h>


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

/**************************************************************************************
 *
 * Constants
 *
**************************************************************************************/

// 7 days.  Really want way to identify a cache which should not age out items.
// We are using CACHE but really want just a tree / hash storage
static const time_t CACHE_DURATION = 7 * 24 * 60 * 60;


/**************************************************************************************
 *
 * Structures
 *
**************************************************************************************/

struct ubiq_billing_ctx {
    struct ubiq_platform_cache * billing_elements_cache; // key => api_key / dataset / dataset_group / key_number / action, return structure with count
    pthread_mutex_t billing_lock;
    pthread_t process_billing_thread;
    pthread_cond_t process_billing_cond;
    // Used to sign requests - still need URL to call
    struct ubiq_platform_rest_handle * rest;
    char * billing_url;
    int    reporting_wake_interval; // seconds
    int    reporting_flush_interval; // seconds
    int    reporting_minimum_count;
    int    reporting_trap_exceptions; // true means ignore errors
};

// Just the fields that MAY be different between calls.  Right now API_KEY will be the same but
// This could be changed in the future
struct billing_element {
  char * dataset_name;
  char * dataset_group_name; // may be null
  char * api_key;
  ubiq_billing_action_type billing_action;
  unsigned long count;
  unsigned int key_number;
  struct tm last_call_timestamp;
  struct tm first_call_timestamp;
};

/**************************************************************************************
 *
 * Static functions definitions
 *
**************************************************************************************/

static
int
billing_element_create(
  struct billing_element ** e,
  const char * const api_key,
  const char * const dataset_name,
  const char * const dataset_group_name,
  const unsigned int    key_number,
  const unsigned long   count,
  const ubiq_billing_action_type billing_action);

void billing_element_destroy(
  void * const element);

static
void
billing_walk_r(const void *nodep, VISIT which, void *__closure);

static
int
process_billing_btree(
  struct ubiq_billing_ctx * ctx,
  struct ubiq_platform_cache * billing_btree
  );


static
int
send_billing_data(
  const struct ubiq_billing_ctx * const e,
  cJSON * json_array);

static 
int
serialize_billing_element(
  const struct billing_element * const billing_element,
  cJSON ** element
  );

/**************************************************************************************
 *
 * Local functions
 *
**************************************************************************************/


// Local function to create element
static
int
billing_element_create(
  struct billing_element ** e,
  const char * const api_key,
  const char * const dataset_name,
  const char * const dataset_group_name,
  const unsigned int    key_number,
  const unsigned long   count,
  const ubiq_billing_action_type billing_action)
{
  int res = -ENOMEM;

  struct billing_element * element = NULL;
  size_t dataset_name_len = 0;
  size_t api_key_len = 0;
  size_t dataset_group_name_len = 0;


  if (api_key != NULL) {
    api_key_len = strlen(api_key) + 1;
  }
  if (dataset_name != NULL) {
    dataset_name_len = strlen(dataset_name) + 1;
  }
  if (dataset_group_name != NULL) {
    dataset_group_name_len = strlen(dataset_group_name) + 1;
  }
  // One continous block of memory.
  element = calloc(1, sizeof(*element) + api_key_len + dataset_name_len + dataset_group_name_len);
  if (element != NULL) {
    element->key_number =  key_number;
    element->count = count;
    element->billing_action = billing_action;
    if (api_key != NULL) {
      element->api_key = ((void *)element) + sizeof(*element);
      strcpy(element->api_key, api_key);
    }
    if (dataset_name != NULL) {
      element->dataset_name = ((void *)element) + sizeof(*element) + api_key_len;
      strcpy(element->dataset_name, dataset_name);
    }
    if (dataset_group_name != NULL) {
      element->dataset_group_name = ((void *)element) + sizeof(*element) + api_key_len + dataset_name_len;
      strcpy(element->dataset_group_name, dataset_group_name);
    }

    const time_t now = time(NULL);

    res = ubiq_support_gmtime_r(&now, &element->first_call_timestamp);
    res = ubiq_support_gmtime_r(&now, &element->last_call_timestamp);
    if (!res) {
      *e = element;
    }

    UBIQ_DEBUG(debug_flag, printf("element %p %d\n", element, sizeof(*element)));
    UBIQ_DEBUG(debug_flag, printf("api_key %p dataset_name %p dataset_group_name %p\n", element->api_key, element->dataset_name, element->dataset_group_name));
    UBIQ_DEBUG(debug_flag, printf("count %d  key_number %d\n", element->count, element->key_number));

    if (element->api_key != NULL) {
      UBIQ_DEBUG(debug_flag, printf("debug api_key '%s'\n", element->api_key));
    }
    if (element->dataset_name != NULL) {
      UBIQ_DEBUG(debug_flag, printf("debug dataset_name '%s'\n", element->dataset_name));
    }
    if (element->dataset_group_name != NULL) {
      UBIQ_DEBUG(debug_flag, printf("debug dataset_group_name '%s'\n", element->dataset_group_name));
    }
  }
  return res;
}

// Referenced by the pthread_create - This is what process is called async
static
void *
process_billing_task(void * data) {
//  int debug_flag = 1;
  const char * csu = "process_billing_task";
  struct ubiq_billing_ctx * e = (struct ubiq_billing_ctx *)data;
  unsigned int element_count = 0;
  struct timespec wake_time;
  struct timespec flush_time;
  int rc = 0;


  clock_gettime(CLOCK_REALTIME, &flush_time);
  flush_time.tv_sec += e->reporting_flush_interval;

  while (1) {
    UBIQ_DEBUG(debug_flag, printf("%s start\n", csu));
    // Test to see if done using simple mutex rather than the conditional
    pthread_mutex_lock(&e->billing_lock);
    UBIQ_DEBUG(debug_flag, printf("%s after lock\n", csu));

    // Only break if the cache is NULL
    if (e->billing_elements_cache == NULL) {
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    // Would only break if something is wrong
    if (ubiq_platform_cache_get_element_count(e->billing_elements_cache, &element_count) != 0) {
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    UBIQ_DEBUG(debug_flag, printf("%s after data valid element_count(%d)\n", csu, element_count));

    // Locked above.

//TODO - Need to schedule to wake up and process based on count, or flush time
// TODO - use pthread_cond_timedwait to force it to wake itself up

    clock_gettime(CLOCK_REALTIME, &wake_time);
    wake_time.tv_sec += e->reporting_wake_interval;

    rc = pthread_cond_timedwait(&e->process_billing_cond, &e->billing_lock, &wake_time);

    UBIQ_DEBUG(debug_flag, printf("%s after pthread_cond_wait rc(%d) ETIMEDOUT(%d)\n", csu, rc, ETIMEDOUT));

    // woke up or was signaled
    if (ETIMEDOUT != rc && 0 != rc) {
      // ERROR 
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    // Should we exit?  Need here to since was getting deadlock for simple create and destroy object
    if (e->billing_elements_cache == NULL) {
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    // get count, and if necessary process or loop back to sleep.
    if (ubiq_platform_cache_get_element_count(e->billing_elements_cache, &element_count) != 0) {
      pthread_mutex_unlock(&e->billing_lock);
      break;
    }

    struct timespec now_time;
    clock_gettime(CLOCK_REALTIME, &now_time);

    UBIQ_DEBUG(debug_flag, printf("element_count(%d)\n", element_count));
    UBIQ_DEBUG(debug_flag, printf("now_time.tv_sec(%ld)\n", now_time.tv_sec));
    UBIQ_DEBUG(debug_flag, printf("flush_time.tv_sec(%ld)\n", flush_time.tv_sec));
    UBIQ_DEBUG(debug_flag, printf("e->reporting_minimum_count(%d)\n", e->reporting_minimum_count));
   
    // Flush reached or number of records reached
    if (now_time.tv_sec > flush_time.tv_sec || 
      element_count >= e->reporting_minimum_count) {

      UBIQ_DEBUG(debug_flag, printf("   PROCESSING billing\n"));

      struct ubiq_platform_cache * local_cache  = e->billing_elements_cache;
      e->billing_elements_cache = NULL;
      ubiq_platform_cache_create(&e->billing_elements_cache );

      // Can unlock since cache is now local
      pthread_mutex_unlock(&e->billing_lock);

      clock_gettime(CLOCK_REALTIME, &flush_time);
      flush_time.tv_sec += e->reporting_flush_interval;

      process_billing_btree(e, local_cache);

      ubiq_platform_cache_destroy(local_cache);
    } else {
      // No wake so unlock for next time through
      pthread_mutex_unlock(&e->billing_lock);

    }

    UBIQ_DEBUG(debug_flag, printf("%s end loop\n", csu));

    }
    UBIQ_DEBUG(debug_flag, printf("%s end\n", csu));

}

static
int
process_billing_btree(
  struct ubiq_billing_ctx * ctx,
  struct ubiq_platform_cache * billing_btree
  )
{
  static const char * const csu = "process_billing_btree";

  int res = -EINVAL;
  unsigned int element_count = 0;


  // Convert BTREE into json array

  if (billing_btree != NULL) {

    res = ubiq_platform_cache_get_element_count(billing_btree, &element_count);
    UBIQ_DEBUG(debug_flag, printf("%s  element_count(%d)\n", csu, element_count));
    if (!res && element_count > 0) {
      cJSON * json_array = cJSON_CreateArray();

      // Conver the tree to a json array
      ubiq_platform_cache_walk_r(billing_btree, billing_walk_r, (void *)json_array);

      cJSON * json_usage = cJSON_CreateObject();
      cJSON_AddItemToObject(json_usage, "usage", json_array);

      // Could improve by skipping the json array and simply using a long string.
      send_billing_data(ctx, json_usage);

      cJSON_Delete(json_usage);
      // cJSON_Delete(json_array);
    }
  }
  return res;

}

static
void
billing_walk_r(const void *nodep, VISIT which, void *__closure)
{
  static const char * const csu = "billing_walk_r";

  cJSON * json_array = (cJSON*) __closure;

  struct billing_element * billing_element;
  cJSON * element = NULL;

  switch (which) {
  case leaf:

    billing_element = *(struct billing_element **) nodep;
    serialize_billing_element(billing_element, &element);
    cJSON_AddItemToArray(json_array, element);

    UBIQ_DEBUG(debug_flag, printf("leaf %s \n \t%p \n",csu, billing_element));
    UBIQ_DEBUG(debug_flag, printf("leaf %s \n \tkey(%d) \n",csu, billing_element->key_number));
    UBIQ_DEBUG(debug_flag, printf("leaf %s \n \tdataset_ptr(%s) \n",csu, billing_element->dataset_name));
    
    // UBIQ_DEBUG(debug_flag, printf("%s \n \t%s \n",csu, billing_element->dataset_name));

    break;
  case postorder:
    billing_element = *(struct billing_element **) nodep;
    serialize_billing_element(billing_element, &element);
    cJSON_AddItemToArray(json_array, element);

    UBIQ_DEBUG(debug_flag, printf("postorder %s \n \t%p \n",csu, billing_element));
    UBIQ_DEBUG(debug_flag, printf("postorder %s \n \tkey(%d) \n",csu, billing_element->key_number));
    UBIQ_DEBUG(debug_flag, printf("postorder %s \n \tdataset_ptr(%p) \n",csu, billing_element->dataset_name));
    
    break;

  default:
    UBIQ_DEBUG(debug_flag, printf("%s OTHER \n",csu));
  // Nothing to do except for leaf
    break;
  }
    UBIQ_DEBUG(debug_flag, printf("%s \n \t END \n",csu));
}

// This what processes the billing data.  It is run from a separate thread and does not have to worry about 
// locks.  the data element should be completely issolated from anything else.
static
int
send_billing_data(
  const struct ubiq_billing_ctx * const e,
  cJSON * json_array)
{
  static const char * const csu = "send_billing_data";

 // http://localhost:8080/billing/decryption  -H "content-type: application/json" 
 //   -d '{  "public_value": "public_api_key_value",  "count": 123,  "datasets": "dataset name",  "dataset_groups": "dataset groups name",  "type": "encrypt"}
 //   -d '{  "public_value": "public_api_key_value",  "count": 123,  "datasets": "dataset name",  "dataset_groups": "dataset groups name",  "type": "decrypt"}

  // TODO - Need to change this once the GO library is supported.
  // static const char * const fmt = "%s";
  time_t now;

  cJSON * json = NULL;
  // char * url = NULL;
  // size_t len;
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s start\n", csu));

  char * str = cJSON_PrintUnformatted(json_array);
  UBIQ_DEBUG(debug_flag, printf("%s  str(%s)\n", csu,  str));



  // UBIQ_DEBUG(debug_flag, printf("%s  e->papi(%s)\n", csu,  e->papi));
  // UBIQ_DEBUG(debug_flag, printf("%s  e->restapi(%s)\n", csu,  e->restapi));


  // len = snprintf(NULL, 0, fmt, e->billing_url);
  // url = malloc(len + 1);
  // snprintf(url, len + 1, fmt, e->billing_url);



  unsigned int array_size = cJSON_GetArraySize(json_array);

  UBIQ_DEBUG(debug_flag, printf("%s  array_size(%u)\n", csu,  array_size));


  if (array_size > 0) {
    http_response_code_t rc;


    UBIQ_DEBUG(debug_flag, printf("%s  e->rest(%p)\n", csu,  e->rest));
    UBIQ_DEBUG(debug_flag, printf("%s  e->billing_url(%s)\n", csu,  e->billing_url));

    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_POST, e->billing_url, "application/json", str, strlen(str));

    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_request res(%d)\n", csu,  res));

    // If Success, simply proceed
    if (res == 0) {
      rc = ubiq_platform_rest_response_code(e->rest);

      UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_rest_response_code rc(%d)\n", csu,  rc));

      if (rc == HTTP_RC_BAD_REQUEST) {
        // TODO - Should we log
      } else if (rc == HTTP_RC_CREATED) {
        // TODO - All good - should delete json _array
          res = 0;
      } else {
        res = ubiq_platform_http_error(rc);
      }
    }
  }
  free(str);
  // free(url);
  return res;

}
  

static 
int
serialize_billing_element(
  const struct billing_element * const billing_element,
  cJSON ** element
  )
{
  static const char * const csu = "serialize_billing_element";


  // TODO - Change user agent into discreet platform and version fields for convenience
  static const char * const json_fmt = "{\"datasets\":\"%s\", \"dataset_groups\":\"%s\", \"api_key\":\"%s\", \"count\":\"%lu\",  \"key_number\":\"%u\",  \"action\":\"%s\", \"product\":\"%s\", \"product_version\":\"%s\", \"user-agent\":\"%s\", \"api_version\":\"%s\", \"last_call_timestamp\":\"%s\", \"first_call_timestamp\":\"%s\"}";
  int res = 0;

  char * json_str;
  char * name = "";
  char * dataset_group = "";
  char * action_type = "encrypt";

  if (billing_element->dataset_name != NULL) {
    name = billing_element->dataset_name;
  }
  if (billing_element->dataset_group_name != NULL) {
    dataset_group = billing_element->dataset_group_name;
  }
  if (billing_element->billing_action == DECRYPTION) {
    action_type = "decrypt";
  }

  char last_call_date_str[500];
  char first_call_date_str[500];
  strftime(last_call_date_str, sizeof(last_call_date_str), "%FT%T+00:00", &billing_element->last_call_timestamp);
  strftime(first_call_date_str, sizeof(first_call_date_str), "%FT%T+00:00", &billing_element->first_call_timestamp);

  size_t len = snprintf(NULL, 0, json_fmt, name, dataset_group, billing_element->api_key, billing_element->count, billing_element->key_number, action_type, ubiq_support_product, ubiq_support_version, ubiq_support_user_agent, "V3", last_call_date_str, first_call_date_str);
  if ((json_str = malloc(len + 1)) == NULL) {
    res = -ENOMEM;
  } else {
    snprintf(json_str, len+1, json_fmt, name, dataset_group, billing_element->api_key, billing_element->count, billing_element->key_number, action_type, ubiq_support_product, ubiq_support_version, ubiq_support_user_agent, "V3", last_call_date_str, first_call_date_str);
    UBIQ_DEBUG(debug_flag, printf("%s \n \t%s \n",csu, json_str));
    
    cJSON *e = cJSON_ParseWithLength(json_str, len);
    if (e == NULL) {
      res = -ENOMEM;
    } else {
      *element = e;
      free(json_str);
    }
  }
    UBIQ_DEBUG(debug_flag, printf("%s \n \tres(%d) \n",csu, res));
  return res;
}

void billing_element_destroy(
  void * const element
)
{
    struct billing_element * const e = (struct billing_element * const) element;

  free(e);
}

/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/


int
ubiq_billing_ctx_create(
  struct ubiq_billing_ctx ** ctx,
  const char * const host_path,
  void * const rest,
  const struct ubiq_platform_configuration * const cfg
  )
{
  struct ubiq_billing_ctx * local_ctx;
  int res = -ENOMEM;

  local_ctx = calloc(1, sizeof(*local_ctx) + strlen(host_path) + 1 + strlen("/api/v3/tracking/events"));
  if (local_ctx) {

    // Just a way to determine if it has been created correctly later
    local_ctx->process_billing_thread = pthread_self();

    local_ctx->billing_url = ((void *)local_ctx) + sizeof(*local_ctx);
    strcpy(local_ctx->billing_url, host_path);
    strcat(local_ctx->billing_url, "/api/v3/tracking/events");

    res = ubiq_platform_cache_create(&local_ctx->billing_elements_cache);
    if (!res) {
      local_ctx->rest = (struct ubiq_platform_rest_handle * const) rest;
    }
    if (!res) {
      if ((res = pthread_mutex_init(&local_ctx->billing_lock, NULL)) != 0) {
        res = -errno;
      }
    }
    if (!res) {
      if ((res = pthread_cond_init(&local_ctx->process_billing_cond, NULL)) != 0) {
        res = -res;
      }
    }
    if (!res) {
      if ((res = pthread_create(&local_ctx->process_billing_thread, NULL, &process_billing_task, local_ctx)) != 0) {
        res = -res;
      }
    }

    if (!res && cfg != NULL) {
      local_ctx->reporting_wake_interval = ubiq_platform_configuration_get_event_reporting_wake_interval(cfg);
      local_ctx->reporting_flush_interval = ubiq_platform_configuration_get_event_reporting_min_count(cfg);
      local_ctx->reporting_minimum_count = ubiq_platform_configuration_get_event_reporting_flush_interval(cfg);
      local_ctx->reporting_trap_exceptions = ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg);
    }

    if (res) {
      ubiq_billing_ctx_destroy(local_ctx);
      local_ctx = NULL;
    }

  }
  *ctx = local_ctx;
  return res;
}


void
ubiq_billing_ctx_destroy(struct ubiq_billing_ctx * const ctx){

  if (ctx) {
    pthread_mutex_lock(&ctx->billing_lock);

    struct ubiq_platform_cache * billing_elements_cache =  ctx->billing_elements_cache;

    ctx->billing_elements_cache = NULL; // 
    pthread_mutex_unlock(&ctx->billing_lock);
    pthread_cond_signal(&ctx->process_billing_cond);

    // If the billing thread is this, thread than we know there
    // was a problem during setup so no need to join.
    if (!pthread_equal(ctx->process_billing_thread,pthread_self())) {
      pthread_join(ctx->process_billing_thread, NULL);
    }

    process_billing_btree(ctx, billing_elements_cache);
    pthread_cond_destroy(&ctx->process_billing_cond);
    pthread_mutex_destroy(&ctx->billing_lock);

    ubiq_platform_cache_destroy(billing_elements_cache);
    free(ctx);
  }
}

int
ubiq_billing_add_billing_event(
  struct ubiq_billing_ctx * const e,
  const char * const api_key,
  const char * const dataset_name,
  const char * const dataset_group_name,
  const ubiq_billing_action_type billing_action,
  unsigned long count,
  unsigned int key_number)
{
  // Hash lookup based on dataset, group, action, key_number
  // if found, update count
  static const char * const csu = "ubiq_billing_add_billing_event";
  static const char * const key_fmt = "api_key='%s' datasets='%s' billing_action='%d' dataset_groups='%s' key_number='%d'";

  int res = 0;

  struct billing_element *billing_element = NULL;

  char * key_str;

  const char * ds = "";
  const char * dsg = "";
  if (dataset_name != NULL) {
    ds = dataset_name;
  }
  if (dataset_group_name != NULL) {
    dsg = dataset_group_name;
  }


  size_t len = snprintf(NULL, 0, key_fmt, api_key, ds, billing_action, dsg, key_number);
  if ((key_str = malloc(len + 1)) == NULL) {
    res = -ENOMEM;
  } else {
    snprintf(key_str, len + 1, key_fmt, api_key, ds, billing_action, dsg, key_number);
  }

  // Check billing element cache based on key

  billing_element = (struct billing_element *)ubiq_platform_cache_find_element(e->billing_elements_cache, key_str);
  if (billing_element != NULL) {
    pthread_mutex_lock(&e->billing_lock);
    UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "key found in Cache"));

    billing_element->count += count;

    const time_t now = time(NULL);

    res = ubiq_support_gmtime_r(&now, &billing_element->last_call_timestamp);

    pthread_mutex_unlock(&e->billing_lock);
  }
  else {

    UBIQ_DEBUG(debug_flag, printf("%s \n \t%s len(%i)\n",csu, key_str, len));

    res = billing_element_create(
      &billing_element,
      api_key,
      dataset_name,
      dataset_group_name,
      key_number,
      count,
      billing_action);

    pthread_mutex_lock(&e->billing_lock);

    ubiq_platform_cache_add_element(e->billing_elements_cache, key_str, CACHE_DURATION, billing_element, &billing_element_destroy);

    pthread_mutex_unlock(&e->billing_lock);
  }
  if (key_str != NULL) {
    free(key_str);
  }

  return res;

}

