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


struct ubiq_platform_configuration
{
  int event_reporting_wake_interval;
  int event_reporting_minimum_count;
  int event_reporting_flush_interval;
  int event_reporting_trap_exceptions;
  reporting_granularity_t event_reporting_timestamp_granularity;
};

static
void
ubiq_platform_configuration_init(
    struct ubiq_platform_configuration * const c)
{
  c->event_reporting_wake_interval = 1;
  c->event_reporting_minimum_count = 5;
  c->event_reporting_flush_interval = 10;
  c->event_reporting_trap_exceptions = 0;
  c->event_reporting_timestamp_granularity = NANOS;
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


const int
ubiq_platform_configuration_get_event_reporting_wake_interval(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting_wake_interval;
}

const int
ubiq_platform_configuration_get_event_reporting_min_count(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting_minimum_count;
}

const int
ubiq_platform_configuration_get_event_reporting_flush_interval(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting_flush_interval;
}

const int
ubiq_platform_configuration_get_event_reporting_trap_exceptions(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting_trap_exceptions;
}

const reporting_granularity_t
ubiq_platform_configuration_get_event_reporting_timestamp_granularity(
    const struct ubiq_platform_configuration * const config)
{
    return config->event_reporting_timestamp_granularity;
}

void
ubiq_platform_configuration_destroy(
    struct ubiq_platform_configuration * const config)
{
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
    (*config)->event_reporting_wake_interval = event_reporting_wake_interval;
  }
  if (event_reporting_minimum_count != 0) {
    (*config)->event_reporting_minimum_count = event_reporting_minimum_count;
  }
  if (event_reporting_flush_interval != 0) {
    (*config)->event_reporting_flush_interval = event_reporting_flush_interval;
  }
  (*config)->event_reporting_trap_exceptions = event_reporting_trap_exceptions;

  if (event_reporting_timestamp_granularity != NULL) {
    (*config)->event_reporting_timestamp_granularity = find_event_reporting_granularity(event_reporting_timestamp_granularity);
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
    const char * _path = NULL;
    int res = 1;

    res = ubiq_platform_configuration_create(config);

    _path = path;
    if (!_path) {
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
            cJSON * json = cJSON_ParseWithLength(buffer, fp_size);

            if (json != NULL) {
              const cJSON * er =  cJSON_GetObjectItem(
                          json, EVENT_REPORTING);

              if (cJSON_IsObject(er)) {
                cJSON * element = NULL;
                int value = 0;
                element = cJSON_GetObjectItem(er, WAKE_INTERVAL);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) != 0)) {
                  (*config)->event_reporting_wake_interval = value;
                }

                element = cJSON_GetObjectItem(er, MINIMUM_COUNT);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) != 0)) {
                  (*config)->event_reporting_minimum_count = value;
                }

                element = cJSON_GetObjectItem(er, FLUSH_INTERVAL);
                if (cJSON_IsNumber(element) && ((value = cJSON_GetNumberValue(element)) != 0)) {
                  (*config)->event_reporting_flush_interval = value;
                }

                element = cJSON_GetObjectItem(er, TRAP_EXCEPTIONS);
                if (cJSON_IsBool(element)) {
                  (*config)->event_reporting_trap_exceptions = cJSON_IsTrue(element);
                }

                element = cJSON_GetObjectItem(er, TIMESTAMP_GRANULARITY);
                if (cJSON_IsString(element)) {
                  (*config)->event_reporting_timestamp_granularity = find_event_reporting_granularity(cJSON_GetStringValue(element));
                }
              }

              cJSON_Delete(json);
            }
          }
          free(buffer);
        }
        fclose(fp);
      }
      if (path != _path) {
          free((void *)_path);
      }
    }
  return res;
}
