#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "cJSON/cJSON.h"


const char * const EVENT_REPORTING = "event_reporting";
const char * const WAKE_INTERVAL = "wake_interval";
const char * const MINIMUM_COUNT = "minimum_count";
const char * const FLUSH_INTERVAL = "flush_interval";
const char * const TRAP_EXCEPTIONS = "trap_exceptions";
const char * const TIMESTAMP_GRANULARITY = "timestamp_granularity";

const char * const KEY_CACHING = "key_caching";
const char * const KEY_CACHING_TTL_SECONDS = "ttl_seconds";
const char * const KEY_CACHING_UNSTRUCTURED = "unstructured";
const char * const KEY_CACHING_STRUCTURED = "structured";
const char * const KEY_CACHING_ENCRYPT = "encrypt";

const char * const IDP = "idp";
const char * const IDP_TYPE = "provider";
const char * const IDP_CUSTOMER_ID = "ubiq_customer_id";
const char * const IDP_TOKEN_ENDPOINT_URL = "idp_token_endpoint_url";
const char * const IDP_TENANT_ID = "idp_tenant_id";
const char * const IDP_CLIENT_SECRET = "idp_client_secret";

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;

typedef struct configuration_event_reporting
{
  int wake_interval;
  int minimum_count;
  int flush_interval;
  int trap_exceptions;
  reporting_granularity_t timestamp_granularity;
} configuration_event_reporting_t;

typedef struct configuration_key_caching
{
  int ttl_seconds;
  int unstructured;
  int structured;
  int encrypt;
} configuration_key_caching_t;

typedef struct configuration_idp
{
  char * type;
  char * customer_id;
  char * token_endpoint_url;
  char * tenant_id;
  char * client_secret;
} configuration_idp_t;

typedef struct ubiq_platform_configuration
{
  configuration_event_reporting_t event_reporting;
  configuration_key_caching_t key_caching;
  configuration_idp_t idp;
} ubiq_platform_configuration_t;


static
void
ubiq_platform_configuration_init(
    struct ubiq_platform_configuration * const c)
{
  c->event_reporting.wake_interval = 1;
  c->event_reporting.minimum_count = 5;
  c->event_reporting.flush_interval = 10;
  c->event_reporting.trap_exceptions = 0;
  c->event_reporting.timestamp_granularity = NANOS;

  c->key_caching.ttl_seconds = 1800;
  c->key_caching.unstructured = 1;
  c->key_caching.structured = 1;
  c->key_caching.encrypt = 0;

  c->idp.type = NULL;
  c->idp.customer_id = NULL;
  c->idp.token_endpoint_url = NULL;
  c->idp.tenant_id = NULL;
  c->idp.client_secret = NULL;
}

static
const reporting_granularity_t
find_event_reporting_granularity(const char * const event_reporting_timestamp_granularity)
{
  reporting_granularity_t value = NANOS;
  char * dup = strdup(event_reporting_timestamp_granularity);
  char *s = dup;
  while (*s) {
    *s = toupper((unsigned char) *s);
    s++;
  }
  if (strcmp(dup, "DAYS") == 0) {
    value = DAYS;
  } else if (strcmp(dup, "HALF_DAYS") == 0) {
    value = HALF_DAYS;
  } else if (strcmp(dup, "HOURS") == 0) {
    value = HOURS;
  } else if (strcmp(dup, "MINUTES") == 0) {
    value = MINUTES;
  } else if (strcmp(dup, "SECONDS") == 0) {
    value = SECONDS;
  } else if (strcmp(dup, "MILLIS") == 0) {
    value = MILLIS;
  }
  free(dup);
  return value;
}

// Deep copy
int ubiq_platform_configuration_clone(
  const struct ubiq_platform_configuration * const src,
  struct ubiq_platform_configuration ** const config)
{
  static const char * csu = "ubiq_platform_configuration_clone";

  UBIQ_DEBUG(debug_flag, printf("%s: %s' \n", csu, "started"));

  int res = 0;

  res = ubiq_platform_configuration_create(config);
  if (!res) {
    (*config)->event_reporting.wake_interval = src->event_reporting.wake_interval;
    (*config)->event_reporting.minimum_count = src->event_reporting.minimum_count;
    (*config)->event_reporting.flush_interval = src->event_reporting.flush_interval;
    (*config)->event_reporting.trap_exceptions = src->event_reporting.trap_exceptions;
    (*config)->event_reporting.timestamp_granularity = src->event_reporting.timestamp_granularity;

    (*config)->key_caching.ttl_seconds = src->key_caching.ttl_seconds;
    (*config)->key_caching.unstructured = src->key_caching.unstructured;
    (*config)->key_caching.structured = src->key_caching.structured;
    (*config)->key_caching.encrypt = src->key_caching.encrypt;

    if (src->idp.type) {ubiq_platform_configuration_set_idp_type(*config, src->idp.type);}
    if (src->idp.customer_id) {ubiq_platform_configuration_set_idp_customer_id(*config, src->idp.customer_id);}
    if (src->idp.token_endpoint_url) {ubiq_platform_configuration_set_idp_token_endpoint_url(*config, src->idp.token_endpoint_url);}
    if (src->idp.tenant_id) {ubiq_platform_configuration_set_idp_tenant_id(*config, src->idp.tenant_id);}
    if (src->idp.client_secret) {ubiq_platform_configuration_set_idp_client_secret(*config, src->idp.client_secret);}
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d' \n", csu, res));

  return res;
}

const int
ubiq_platform_configuration_get_event_reporting_wake_interval(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting.wake_interval;
}

const int
ubiq_platform_configuration_get_event_reporting_min_count(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting.minimum_count;
}

const int
ubiq_platform_configuration_get_event_reporting_flush_interval(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting.flush_interval;
}

const int
ubiq_platform_configuration_get_event_reporting_trap_exceptions(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting.trap_exceptions;
}

const reporting_granularity_t
ubiq_platform_configuration_get_event_reporting_timestamp_granularity(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting.timestamp_granularity;
}

const int
ubiq_platform_configuration_get_key_caching_encrypt(
    const struct ubiq_platform_configuration * const config)
{
  return config->key_caching.encrypt;
}
const int
ubiq_platform_configuration_get_key_caching_structured_keys(
    const struct ubiq_platform_configuration * const config)
{
  return config->key_caching.structured;
}
const int
ubiq_platform_configuration_get_key_caching_unstructured_keys(
    const struct ubiq_platform_configuration * const config)
{
  return config->key_caching.unstructured;
}
const int
ubiq_platform_configuration_get_key_caching_ttl_seconds(
    const struct ubiq_platform_configuration * const config)
{
  return config->key_caching.ttl_seconds;
}

const char *
ubiq_platform_configuration_get_idp_type(
    const struct ubiq_platform_configuration * const config)
{
  return config->idp.type; 
}
const char *
ubiq_platform_configuration_get_idp_customer_id(
    const struct ubiq_platform_configuration * const config)
{
  return config->idp.customer_id; 
}
const char *
ubiq_platform_configuration_get_idp_token_endpoint_url(
    const struct ubiq_platform_configuration * const config)
{
  return config->idp.token_endpoint_url; 
}
const char *
ubiq_platform_configuration_get_idp_tenant_id(
    const struct ubiq_platform_configuration * const config)
{
  return config->idp.tenant_id; 
}
const char *
ubiq_platform_configuration_get_idp_client_secret(
    const struct ubiq_platform_configuration * const config)
{
  return config->idp.client_secret; 
}

int
ubiq_platform_configuration_is_idp_set(
    const struct ubiq_platform_configuration * const config)
{
  int res = config->idp.type != NULL && config->idp.type[0] != '\0' &&
            config->idp.customer_id != NULL && config->idp.customer_id[0] != '\0' &&
            config->idp.token_endpoint_url != NULL && config->idp.token_endpoint_url[0] != '\0' &&
            config->idp.tenant_id != NULL && config->idp.tenant_id[0] != '\0' &&
            config->idp.client_secret != NULL && config->idp.client_secret[0] != '\0';

  return res;
}


void
ubiq_platform_configuration_set_idp_type(
    struct ubiq_platform_configuration * const config,
    const char * idp_type)
{
  free(config->idp.type);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_configuration_set_idp_type : %s\n", idp_type));

  config->idp.type = strdup(idp_type);
}
void
ubiq_platform_configuration_set_idp_customer_id(
    struct ubiq_platform_configuration * const config,
    const char * idp_customer_id)
{
  free(config->idp.customer_id);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_configuration_set_idp_customer_id : %s\n", idp_customer_id));
  config->idp.customer_id = strdup(idp_customer_id);
}    
void
ubiq_platform_configuration_set_idp_token_endpoint_url(
    struct ubiq_platform_configuration * const config,
    const char * idp_token_endpoint_url)
{
  free(config->idp.token_endpoint_url);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_configuration_set_idp_token_endpoint_url : %s\n", idp_token_endpoint_url));
  config->idp.token_endpoint_url = strdup(idp_token_endpoint_url);
}    
void
ubiq_platform_configuration_set_idp_tenant_id(
    struct ubiq_platform_configuration * const config,
    const char * idp_tenant_id)
{
  free(config->idp.tenant_id);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_configuration_set_idp_tenant_id : %s\n", idp_tenant_id));
  config->idp.tenant_id = strdup(idp_tenant_id);
}        
void
ubiq_platform_configuration_set_idp_client_secret(
    struct ubiq_platform_configuration * const config,
    const char * idp_client_secret)
{
  free(config->idp.client_secret);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_configuration_set_idp_client_secret : %s\n", idp_client_secret));
  config->idp.client_secret = strdup(idp_client_secret);
}

void
ubiq_platform_configuration_destroy(
    struct ubiq_platform_configuration * const config)
{
    free(config->idp.type);
    free(config->idp.customer_id);
    free(config->idp.token_endpoint_url);
    free(config->idp.tenant_id);
    free(config->idp.client_secret);
    free(config);
}

int
ubiq_platform_configuration_create_explicit(
    const int event_reporting_wake_interval,
    const int event_reporting_minimum_count,
    const int event_reporting_flush_interval,
    const int event_reporting_trap_exceptions,
    const char * const event_reporting_timestamp_granularity,
    struct ubiq_platform_configuration ** const config)
{
  int res = 0;
  ubiq_platform_configuration_create(config);
  if (event_reporting_wake_interval != 0) {
    (*config)->event_reporting.wake_interval = event_reporting_wake_interval;
  }
  if (event_reporting_minimum_count != 0) {
    (*config)->event_reporting.minimum_count = event_reporting_minimum_count;
  }
  if (event_reporting_flush_interval != 0) {
    (*config)->event_reporting.flush_interval = event_reporting_flush_interval;
  }
  (*config)->event_reporting.trap_exceptions = event_reporting_trap_exceptions;

  if (event_reporting_timestamp_granularity != NULL) {
    (*config)->event_reporting.timestamp_granularity = find_event_reporting_granularity(event_reporting_timestamp_granularity);
  }

  return res;
}


int
ubiq_platform_configuration_create_explicit2(
    const int event_reporting_wake_interval,
    const int event_reporting_minimum_count,
    const int event_reporting_flush_interval,
    const int event_reporting_trap_exceptions,
    const char * const event_reporting_timestamp_granularity,
    const int key_caching_encrypt_keys,
    const int key_caching_structured_keys,
    const int key_caching_unstructured_keys,
    const int key_caching_ttl_seconds,
    struct ubiq_platform_configuration ** const config)
{
  int res = 0;
  ubiq_platform_configuration_create(config);
  if (event_reporting_wake_interval != 0) {
    (*config)->event_reporting.wake_interval = event_reporting_wake_interval;
  }
  if (event_reporting_minimum_count != 0) {
    (*config)->event_reporting.minimum_count = event_reporting_minimum_count;
  }
  if (event_reporting_flush_interval != 0) {
    (*config)->event_reporting.flush_interval = event_reporting_flush_interval;
  }
  (*config)->event_reporting.trap_exceptions = event_reporting_trap_exceptions;
  if (event_reporting_timestamp_granularity != NULL) {
    (*config)->event_reporting.timestamp_granularity = find_event_reporting_granularity(event_reporting_timestamp_granularity);
  }

  (*config)->key_caching.encrypt = (key_caching_encrypt_keys != 0);
  (*config)->key_caching.structured = (key_caching_structured_keys != 0);
  (*config)->key_caching.unstructured = (key_caching_unstructured_keys != 0);
  (*config)->key_caching.ttl_seconds = key_caching_ttl_seconds;

  return res;
}

int
ubiq_platform_configuration_set_idp(
  struct ubiq_platform_configuration * const config,
  const char * idp_type,
  const char * idp_customer_id,
  const char * idp_token_endpoint_url,
  const char * idp_tenant_id,
  const char * idp_client_secret)
{
   int res;

    res = -EINVAL;
    if (idp_type && idp_customer_id && idp_token_endpoint_url && idp_tenant_id && idp_client_secret) {
          ubiq_platform_configuration_set_idp_type(config, idp_type);
          ubiq_platform_configuration_set_idp_customer_id(config, idp_customer_id);
          ubiq_platform_configuration_set_idp_token_endpoint_url(config, idp_token_endpoint_url);
          ubiq_platform_configuration_set_idp_tenant_id(config, idp_tenant_id);
          ubiq_platform_configuration_set_idp_client_secret(config, idp_client_secret);

          if (config->idp.type && config->idp.customer_id && config->idp.token_endpoint_url
              && config->idp.client_secret && config->idp.tenant_id) {
              res = 0;
          } else {
              free(config->idp.type);
              free(config->idp.customer_id);
              free(config->idp.token_endpoint_url);
              free(config->idp.client_secret);
              free(config->idp.tenant_id);
          }
    }

    return res;
}

/*
 * try to create a set of configuration from the environment
 * and then from the default file, using the default profile.
 */
int
ubiq_platform_configuration_create(
    struct ubiq_platform_configuration ** const config)
{
    int res = -ENOMEM;

    struct ubiq_platform_configuration * cfg = NULL;
    cfg = calloc(1, sizeof(*cfg));
    if (cfg != NULL) {
      ubiq_platform_configuration_init(cfg);

      *config = cfg;
      res = 0;
    }

    return res;
}

/*
 * loads a configuration file into memory
 */
int
ubiq_platform_configuration_load_configuration(
    const char * const path,
    struct ubiq_platform_configuration ** const config)
{
    static const char * csu = "ubiq_platform_configuration_load_configuration";

    const char * _path = NULL;
    int res = 1;

    res = ubiq_platform_configuration_create(config);
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_configuration_create (%s) %d\n", csu, path, res));

    _path = path;
    if (!_path || _path[0] == '\0') {
      static const char * const cred_path = ".ubiq/configuration";
      char * homedir;
      int err;

      err = ubiq_support_get_home_dir(&homedir);
      if (!err) {
        int len;

        len = snprintf(NULL, 0, "%s/%s", homedir, cred_path) + 1;
        _path = malloc(len);
        if (_path) {
            snprintf((char *)_path, len, "%s/%s", homedir, cred_path);
        }

        free(homedir);
      }
    }

    if (_path) {
      FILE * fp = NULL;

      fp = fopen(_path, "rb");
      if (fp) {
        fseek( fp , 0L , SEEK_END);
        long fp_size = ftell( fp );
        rewind( fp );
        char * buffer = calloc( 1, fp_size + 1 );

        if (buffer != NULL) {
          if( 1 == fread( buffer , fp_size, 1 , fp) ) {
            UBIQ_DEBUG(debug_flag, printf("%s buffer : %s\n", csu, buffer));
            cJSON * json = cJSON_ParseWithLength(buffer, fp_size);
            if (json != NULL) {
              const cJSON * er =  cJSON_GetObjectItem(
                          json, EVENT_REPORTING);

              if (cJSON_IsObject(er)) {
                cJSON * element = NULL;
                int value = 0;
                element = cJSON_GetObjectItem(er, WAKE_INTERVAL);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) != 0)) {
                  (*config)->event_reporting.wake_interval = value;
                }

                element = cJSON_GetObjectItem(er, MINIMUM_COUNT);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) != 0)) {
                  (*config)->event_reporting.minimum_count = value;
                }

                element = cJSON_GetObjectItem(er, FLUSH_INTERVAL);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) != 0)) {
                  (*config)->event_reporting.flush_interval = value;
                }

                element = cJSON_GetObjectItem(er, TRAP_EXCEPTIONS);
                if (cJSON_IsBool(element)) {
                  (*config)->event_reporting.trap_exceptions = cJSON_IsTrue(element);
                }

                element = cJSON_GetObjectItem(er, TIMESTAMP_GRANULARITY);
                if (cJSON_IsString(element)) {
                  (*config)->event_reporting.timestamp_granularity = find_event_reporting_granularity(cJSON_GetStringValue(element));
                }
              }

              const cJSON * kc =  cJSON_GetObjectItem(
                          json, KEY_CACHING);

              if (cJSON_IsObject(kc)) {
                cJSON * element = NULL;
                int value = 0;
                element = cJSON_GetObjectItem(kc, KEY_CACHING_TTL_SECONDS);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) >= 0)) {
                  (*config)->key_caching.ttl_seconds = value;
                }
                element = cJSON_GetObjectItem(kc, KEY_CACHING_UNSTRUCTURED);
                if (cJSON_IsBool(element)) {
                  (*config)->key_caching.unstructured = cJSON_IsTrue(element);
                }
                element = cJSON_GetObjectItem(kc, KEY_CACHING_STRUCTURED);
                if (cJSON_IsBool(element)) {
                  (*config)->key_caching.structured = cJSON_IsTrue(element);
                }
                element = cJSON_GetObjectItem(kc, KEY_CACHING_ENCRYPT);
                if (cJSON_IsBool(element)) {
                  (*config)->key_caching.encrypt = cJSON_IsTrue(element);
                }
              }


              const cJSON * idp =  cJSON_GetObjectItem(
                          json, IDP);
    UBIQ_DEBUG(debug_flag, printf("%s idp \n(%s) %d\n", csu, cJSON_Print(idp), res));
              if (cJSON_IsObject(idp)) {
                cJSON * element = NULL;
                char * value = NULL;
                element = cJSON_GetObjectItem(idp, IDP_TYPE);
                if (cJSON_IsString(element)) {
                  ubiq_platform_configuration_set_idp_type((*config),cJSON_GetStringValue(element));
                }
                element = cJSON_GetObjectItem(idp, IDP_CUSTOMER_ID);
                if (cJSON_IsString(element)) {
                  ubiq_platform_configuration_set_idp_customer_id((*config),cJSON_GetStringValue(element));
                }
                element = cJSON_GetObjectItem(idp, IDP_TENANT_ID);
                if (cJSON_IsString(element)) {
                  ubiq_platform_configuration_set_idp_tenant_id((*config),cJSON_GetStringValue(element));
                }
                element = cJSON_GetObjectItem(idp, IDP_CLIENT_SECRET);
                if (cJSON_IsString(element)) {
                  ubiq_platform_configuration_set_idp_client_secret((*config),cJSON_GetStringValue(element));
                }
                element = cJSON_GetObjectItem(idp, IDP_TOKEN_ENDPOINT_URL);
                if (cJSON_IsString(element)) {
                  ubiq_platform_configuration_set_idp_token_endpoint_url((*config),cJSON_GetStringValue(element));
                }
              }

              cJSON_Delete(json);
            }
          }
        }
        fclose(fp);
        free(buffer);
      }
      if (path != _path) {
          free((void *)_path);
      }
    }
  return res;
}
