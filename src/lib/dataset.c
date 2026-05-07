#define _XOPEN_SOURCE // Needed because of strptime


#include <ubiq/platform/internal/parsing.h>
#include <ubiq/platform/internal/dataset.h>
#include <ubiq/platform/internal/support.h>
#include <ubiq/platform/internal/debug.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>

// #define UBIQ_DEBUG_ON // UNCOMMENT to Enable UBIQ_DEBUG macro


#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif



typedef enum {NONE = 0, PASSTHROUGH = 1, PREFIX = 2, SUFFIX = 3} passthrough_rules_priority_type;


static int debug_flag = 0;

const char * const ENCODING_BASE64 = "base64";
const char * const ENCODING_BASE32 = "base32";
// const size_t UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PREFIX = PREFIX;
// const size_t UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_SUFFIX = SUFFIX;
// const size_t UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PASSTHROUGH = PASSTHROUGH;
// const size_t UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_NONE = NONE;

const char * const DATA_TYPE_INTEGER = "integer";
const char * const DATA_TYPE_DATE = "date";
const char * const DATA_TYPE_DATETIME = "datetime";
const char * const DATA_TYPE_TOKEN = "token";
const char * const DATA_TYPE_FORMATTED_STRING = "formatted_string";
const char * const DATA_TYPE_GENERIC_STRING = "generic_string";

typedef struct {
    struct tm tm;
    int ms;
    int tz_offset_min; /* UTC offset in minutes */
} ISO8601_datetime_t;


static int comparator(const void* p1, const void* p2);

static int parse_passthrough_rules(
  cJSON const * const dataset_json,
  ubiq_platform_dataset_t * d) ;

static int set_rule_priority(
  ubiq_platform_dataset_t * d,
  int idx,
  cJSON* rule,
  const UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PRIORITY rule_type);

static int get_json_size_t(
  cJSON const * const json,
  char const * const field_name,
  size_t * const destination);

static int parse_datatype_config(
  cJSON const * const config_json,
  ubiq_platform_data_type_config_t ** const cfg);  

// static int get_json_tm(
//   cJSON const * const json,
//   char const * const field_name,
//   struct tm ** const destination);

// static int parse_tz(const char *s, int *offset_min);


// static
// int
// parse_iso8601(char const * const s, struct tm * const out);

static void printISO8601(const struct tm * const date);

struct ubiq_platform_data_type_config {
  size_t size;
  int64_t min_input_int_value; // cJSON only handles int
  int64_t max_input_int_value;
  // Internal times will not have timezone
  // We will parse the data_type_config and add / subtract the timezone if necessary
  // but it should not exists
  struct tm * epoch;
  struct tm * min_input_date_value;
  struct tm * max_input_date_value;
  time_t epoch_as_time_t;
  time_t min_input_date_value_as_time_t;
  time_t max_input_date_value_as_time_t;
};

struct ubiq_platform_dataset {
  char * name;
  size_t min_input_length;
  size_t max_input_length;
  char * tweak_source;
  // char32_t * regex;
  char32_t * u32_input_character_set; // Will be set if any of char sets are multi-byte utf8
  char32_t * u32_output_character_set;  // Will be set if any of char sets are multi-byte utf8
  char32_t * u32_passthrough_character_set;// Will be set if any of char sets are multi-byte utf8
  size_t prefix_passthrough_length;
  size_t suffix_passthrough_length;
  size_t msb_encoding_bits;
  UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PRIORITY passthrough_rules_priority[UBIQ_PASSTHROUGH_RULES_COUNT]; // Three known rules.  Ordered list of 
  struct {
          void * buf;
          size_t len;
  } tweak;
  size_t tweak_min_len;
  size_t tweak_max_len;
//  dataset_character_types character_types; // Set if any of the character sets contain utf8
  char * input_encoding;
  char * data_type;
  uint32_t input_pad_character;
  int can_encrypt;
  int can_decrypt;
  ubiq_platform_data_type_config_t * data_type_config;
};

int const ubiq_platform_dataset_get_can_encrypt(ubiq_platform_dataset_t const * const dataset)
{
  return dataset->can_encrypt;
}

int const ubiq_platform_dataset_get_can_decrypt(ubiq_platform_dataset_t const * const dataset)
{
  return dataset->can_decrypt;
}

char32_t const * const ubiq_platform_dataset_get_input_characters(ubiq_platform_dataset_t const * const dataset) {
return dataset->u32_input_character_set;
}

char32_t const * const ubiq_platform_dataset_get_output_characters(ubiq_platform_dataset_t const * const dataset) {
return dataset->u32_output_character_set;
}

char32_t const * const ubiq_platform_dataset_get_passthrough_characters(ubiq_platform_dataset_t const * const dataset) {
return dataset->u32_passthrough_character_set;
}

char const * const ubiq_platform_dataset_get_input_encoding(ubiq_platform_dataset_t const * const dataset) {
return dataset->input_encoding;
}

unsigned int const ubiq_platform_dataset_get_msb_encoding_bits(ubiq_platform_dataset_t const * const dataset) {
  return dataset->msb_encoding_bits;
}

char32_t const ubiq_platform_dataset_get_input_pad_char(ubiq_platform_dataset_t const * const dataset) {
  return dataset->input_pad_character;
}

size_t const ubiq_platform_dataset_get_input_min_length(ubiq_platform_dataset_t const * const dataset) {
  return dataset->min_input_length;
}
size_t const ubiq_platform_dataset_get_input_max_length(ubiq_platform_dataset_t const * const dataset) {
  return dataset->max_input_length;
}

size_t const ubiq_platform_dataset_get_passthrough_prefix_length(ubiq_platform_dataset_t const * const dataset) {
  return dataset->prefix_passthrough_length;
}

size_t const ubiq_platform_dataset_get_passthrough_suffix_length(ubiq_platform_dataset_t const * const dataset)  {
  return dataset->suffix_passthrough_length;
}

char const * const ubiq_platform_dataset_get_name(ubiq_platform_dataset_t const * const dataset) {
  return dataset->name;
}

void const * const ubiq_platform_dataset_get_tweak(ubiq_platform_dataset_t const * const dataset) {
  return dataset->tweak.buf;
}

size_t const ubiq_platform_dataset_get_tweak_len(ubiq_platform_dataset_t const * const dataset) {
  return dataset->tweak.len;
}

size_t const ubiq_platform_dataset_get_tweak_min_len(ubiq_platform_dataset_t const * const dataset) {
  return dataset->tweak_min_len;
}

size_t const ubiq_platform_dataset_get_tweak_max_len(ubiq_platform_dataset_t const * const dataset) {
  return dataset->tweak_max_len;
}

char const * const ubiq_platform_dataset_get_data_type(ubiq_platform_dataset_t const * const dataset) {
  return dataset->data_type;
}

ubiq_platform_data_type_config_t const * const ubiq_platform_dataset_get_data_type_config(ubiq_platform_dataset_t const * const dataset) {
  return dataset->data_type_config;
}

size_t const ubiq_platform_data_type_config_get_size(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->size;
}

int64_t const ubiq_platform_data_type_config_get_min_input_value(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->min_input_int_value;
}

int64_t const ubiq_platform_data_type_config_get_max_input_value(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->max_input_int_value;
}

struct tm const * const ubiq_platform_data_type_config_get_epoch(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->epoch;
}

struct tm const * const ubiq_platform_data_type_config_get_min_input_date_value(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->min_input_date_value;
}

struct tm const * const ubiq_platform_data_type_config_get_max_input_date_value(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->max_input_date_value;
}

time_t const ubiq_platform_data_type_config_get_epoch_as_time_t(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->epoch_as_time_t;
}
time_t const ubiq_platform_data_type_config_get_min_input_date_value_as_time_t(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->min_input_date_value_as_time_t;
}
time_t const ubiq_platform_data_type_config_get_max_input_date_value_as_time_t(ubiq_platform_data_type_config_t const * const cfg) {
  return cfg->max_input_date_value_as_time_t;
}

static int set_rule_priority(
  ubiq_platform_dataset_t * const  dataset,
  int idx,
  cJSON* rule,
  const UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PRIORITY rule_type)
{
  int res = 0;
  if (!res && idx >= 0 && idx < sizeof(dataset->passthrough_rules_priority)) {
    dataset->passthrough_rules_priority[idx] = rule_type;
  } else {
    res = -EINVAL;
  }
  return res;
}


static int parse_passthrough_rules(
  cJSON const * const dataset_json,
  ubiq_platform_dataset_t * const dataset) 
{
  static const char * const csu = "parse_passthrough_rules";

  int res = 0;
  int rules_idx = 0;
  UBIQ_DEBUG(debug_flag, printf("%s %s\n",csu, "started"));

  const cJSON * passthrough_rules = cJSON_GetObjectItemCaseSensitive(dataset_json, "passthrough_rules");

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

      res = ubiq_platform_get_json_string(rule, "type", &value);
      UBIQ_DEBUG(debug_flag, printf("%s type(%s)\t idx(%d) ret(%d) %s\n",csu, value, idx, res, cJSON_Print(rule)));
      if (!res && value) {
        if (strcmp(value, "passthrough") == 0) {
          free(dataset->u32_passthrough_character_set);
          res = ubiq_platform_get_json_u32string(rule, "value", &dataset->u32_passthrough_character_set);
          if (!res) {
            res = set_rule_priority(dataset, idx, rule, UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PASSTHROUGH);
          }
          UBIQ_DEBUG(debug_flag, printf("%s dataset->passthrough_character_set(%s) \t res(%d)\n",csu, dataset->u32_passthrough_character_set, res));
        } else if (strcmp(value, "prefix") == 0) {
          res = get_json_size_t(rule, "value", &dataset->prefix_passthrough_length);
          if (!res) {
            res = set_rule_priority(dataset, idx, rule, UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PREFIX);
          }
          UBIQ_DEBUG(debug_flag, printf("%s dataset->prefix_passthrough_length(%d) \t ret(%d)\n",csu, dataset->prefix_passthrough_length, res));
        } else if (strcmp(value, "suffix") == 0) {
          res = get_json_size_t(rule, "value", &dataset->suffix_passthrough_length);
          if (!res) {
            res = set_rule_priority(dataset, idx, rule, UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_SUFFIX);
          }
          UBIQ_DEBUG(debug_flag, printf("%s dataset->suffix_passthrough_length(%d) \t ret(%d)\n",csu, dataset->suffix_passthrough_length, res));
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


int ubiq_platform_dataset_create(
    cJSON const * const dataset_json,
    ubiq_platform_dataset_t ** const dataset)
{
  static const char * const csu = "dataset_create";
  int res = 0;

  ubiq_platform_dataset_t * d = NULL;
  d = calloc(1, sizeof(*d));
  if (!d) {
    res = -ENOMEM;
  }

  if (!res) {res = ubiq_platform_get_json_string(dataset_json, "tweak_source", &d->tweak_source);}
  if (!res) {res = ubiq_platform_get_json_string(dataset_json, "data_type", &d->data_type);}
  if (!res) {res = ubiq_platform_get_json_string(dataset_json, "input_encoding", &d->input_encoding);}
  
  if (!res) {res = ubiq_platform_get_json_string(dataset_json, "name", &d->name);}
  // if (!res) {res = ubiq_platform_get_json_u32string(dataset_json, "regex", &d->regex);}
  if (!res) {res = ubiq_platform_get_json_u32string(dataset_json, "input_character_set", &d->u32_input_character_set);}
  if (!res) {res = ubiq_platform_get_json_u32string(dataset_json, "output_character_set", &d->u32_output_character_set);}

  if (!res) {res = get_json_size_t(dataset_json, "min_input_length", &d->min_input_length);}
  if (!res) {res = get_json_size_t(dataset_json, "max_input_length", &d->max_input_length);}
  if (!res) {res = get_json_size_t(dataset_json, "msb_encoding_bits", &d->msb_encoding_bits);}
  if (!res) {res = get_json_size_t(dataset_json, "tweak_min_len", &d->tweak_min_len);}
  if (!res) {res = get_json_size_t(dataset_json, "tweak_max_len", &d->tweak_max_len);}

  if (!res && d->tweak_source != NULL && strcmp(d->tweak_source, "constant") == 0) {
    char * tmp = NULL;
    if ((res = ubiq_platform_get_json_string(dataset_json, "tweak", &tmp)) == 0) {
      d->tweak.len = ubiq_support_base64_decode(
          &d->tweak.buf, tmp, strlen(tmp));
    }
    free(tmp);
  }

  if (!res) {
    if (!res) {res = ubiq_platform_get_json_u32string(dataset_json, "passthrough", &d->u32_passthrough_character_set);}
    if (!d->u32_passthrough_character_set) {
      d->u32_passthrough_character_set = u32_strdup((uint32_t*)U"");
    }

    res = parse_passthrough_rules(dataset_json, d);
  }

  if (!res) {
    uint32_t * tmp = NULL;
    res = ubiq_platform_get_json_u32string(dataset_json, "input_pad_character", &tmp);
    if (!res && tmp != NULL && u32_strlen(tmp) == 1) {
      d->input_pad_character = tmp[0];
      free(tmp);
    } else {
      free(tmp);
    }
  }

  cJSON * const data_type_config = cJSON_GetObjectItemCaseSensitive(dataset_json, "data_type_config");
  if (data_type_config != NULL && !cJSON_IsNull(data_type_config) && cJSON_IsObject(data_type_config)) {
    res = parse_datatype_config(data_type_config, &d->data_type_config);
  }

  cJSON * const permissions = cJSON_GetObjectItemCaseSensitive(dataset_json, "permissions");
  if (permissions != NULL && !cJSON_IsNull(permissions) && cJSON_IsObject(permissions)) {
    if (!res) {res = ubiq_platform_get_json_boolean(permissions, "encrypt", &d->can_encrypt);}
    if (!res) {res = ubiq_platform_get_json_boolean(permissions, "decrypt", &d->can_decrypt);}
  }

  if (!res) {
    *dataset = d;
  } else {
    ubiq_platform_dataset_destroy(d);
  }

  return res;
}

void ubiq_platform_dataset_destroy(
    ubiq_platform_dataset_t * const dataset)
{

  if (dataset) {
    free (dataset->name);
    free (dataset->tweak_source);
    free(dataset->data_type);
    free(dataset->input_encoding);
//    free (dataset->regex);
    free (dataset->u32_input_character_set);
    free (dataset->u32_output_character_set);
    free (dataset->u32_passthrough_character_set);
    free (dataset->tweak.buf);

    if (dataset->data_type_config) {
      free(dataset->data_type_config->epoch);
      free(dataset->data_type_config->max_input_date_value);
      free(dataset->data_type_config->min_input_date_value);
    }
    free(dataset->data_type_config);

  }
  free(dataset);

}

int ubiq_platform_dataset_get_passthrough_rule_priorities(
  ubiq_platform_dataset_t const * const dataset,
  size_t priorities[],
  size_t size)
{
  int res = -EINVAL;
  if (size >= UBIQ_PASSTHROUGH_RULES_COUNT) {
    for (int i = 0;i < size; i++) {
      priorities[i] = dataset->passthrough_rules_priority[i];
    }
    res = 0;
  }
  return res;
}

static int comparator(const void* p1, const void* p2) {
  static const char * const csu = "comparator";

  cJSON ** e1 = (cJSON ** )p1;
  cJSON ** e2 = (cJSON ** )p2;

  int priority1;
  int priority2;
  
  ubiq_platform_get_json_int(*e1, "priority", &priority1);
  ubiq_platform_get_json_int(*e2, "priority", &priority2);

  // Negative if p1 < p2, positive if p2 > p1
  return (priority1 - priority2);
}


static int BAD_parse_passthrough_rules_BAD(
  cJSON * dataset_json,
  ubiq_platform_dataset_t * d) 
{
  static const char * const csu = "DATASET: parse_passthrough_rules";

  int res = 0;
  int rules_idx = 0;
  STRUCTURED_DEBUG(debug_flag, printf("%s %s\n",csu, "started"));

  cJSON * passthrough_rules = NULL;
  
  res = ubiq_platform_get_json_array(dataset_json, "passthrough_rules", &passthrough_rules);

  if (!res && passthrough_rules != NULL) {
    STRUCTURED_DEBUG(debug_flag, printf("%s %s\n",csu, "passthrough_rules is array"));

    int arraySize = cJSON_GetArraySize(passthrough_rules);
    STRUCTURED_DEBUG(debug_flag, printf("%s %s %d\n",csu, "arraySize", arraySize));
    cJSON * array[arraySize];
    cJSON * rule;
    int idx = 0;
    cJSON_ArrayForEach(rule, passthrough_rules) {
      array[idx] = rule;
      idx++;
    }

    STRUCTURED_DEBUG(debug_flag, printf("%s %s\n",csu, "before qsort"));
    qsort((void *)array, arraySize, sizeof(cJSON *), comparator);
    STRUCTURED_DEBUG(debug_flag, printf("%s %s\n",csu, "after qsort"));

    char * value = NULL;

    for (int idx = 0; res == 0 && idx < arraySize; idx++ ) {
      cJSON * rule = array[idx];

      res = ubiq_platform_get_json_string(rule, "type", &value);
      STRUCTURED_DEBUG(debug_flag, printf("%s type(%s)\t idx(%d) ret(%d) %s\n",csu, value, idx, res, cJSON_Print(rule)));
      if (!res && value) {
        if (strcmp(value, "passthrough") == 0) {
          res = ubiq_platform_get_json_u32string(rule, "value", &d->u32_passthrough_character_set);
          if (!res) {
            res = set_rule_priority(d, idx, rule, PASSTHROUGH);
          }
          STRUCTURED_DEBUG(debug_flag, printf("%s d->passthrough_character_set(%S) \t res(%d)\n",csu, d->u32_passthrough_character_set, res));
        } else if (strcmp(value, "prefix") == 0) {
          res = get_json_size_t(rule, "value", &d->prefix_passthrough_length);
          if (!res) {
            res = set_rule_priority(d, idx, rule, PREFIX);
          }
          STRUCTURED_DEBUG(debug_flag, printf("%s e->prefix_passthrough_length(%d) \t ret(%d)\n",csu, d->prefix_passthrough_length, res));
        } else if (strcmp(value, "suffix") == 0) {
          res = get_json_size_t(rule, "value", &d->suffix_passthrough_length);
          if (!res) {
            res = set_rule_priority(d, idx, rule, SUFFIX);
          }
          STRUCTURED_DEBUG(debug_flag, printf("%s e->suffix_passthrough_length(%d) \t ret(%d)\n",csu, d->suffix_passthrough_length, res));
        } else {
          STRUCTURED_DEBUG(debug_flag, printf("%s ignored\n",csu));
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
  STRUCTURED_DEBUG(debug_flag, printf("%s %s %d\n",csu, "end", res));
  return res;
}

// size_t and int could be different size
static int get_json_size_t(
  cJSON const * const json,
  char const * const field_name,
  size_t * const destination) {
    
    int tmp = 0;

    int res = ubiq_platform_get_json_int(json, field_name, &tmp);
    if (!res) {
      *destination = (size_t)tmp;
    }
    return res;
  }

// JSON has iso8601 string, so convert to tm
// static int get_json_tm(
//   cJSON const * const json,
//   char const * const field_name,
//   struct tm ** const destination) 
// {
//     static const char * const csu = "DATASET: get_json_tm";
    
//     int debug_flag = 1;
//     char * tmp = NULL;
//     struct tm * t = calloc(1, sizeof(*t));

//     int res = ubiq_platform_get_json_string(json, field_name, &tmp);
//     if (!res) {
//       char * c = strptime(tmp, "%FT%T%z", t);
//       if (c == NULL) { // ERROR
//         STRUCTURED_DEBUG(debug_flag, printf("%s unable to strptime(%s)\n",csu,tmp));
//       } else if (*c == '\0') { // Processed the whole string
//         STRUCTURED_DEBUG(debug_flag, printf("%s Entire string processed strptime(%s)\n",csu,tmp));
//         res = 0;
//       } else {
//         STRUCTURED_DEBUG(debug_flag, printf("%s Unable to process part of the string beginning at %s strptime(%s)\n",csu,c, tmp));
//       }
//       free(tmp);
//     }
//     if (!res) {
//       *destination = t;
//     } else {
//       free(t);
//     }
//     return res;
// }

static int parse_datatype_config(
  cJSON const * const config_json,
  ubiq_platform_data_type_config_t ** const cfg) {
    static const char * csu = "dataset.parse_datatype_config";

    // static int debug_flag = 1;
    int res = -EINVAL;

    UBIQ_DEBUG(debug_flag, printf("%s\n", cJSON_Print(config_json)));

    ubiq_platform_data_type_config_t * c;
    c = calloc(1, sizeof(*c));
    if (!c) {
      res = -ENOMEM;
    } else {
      res = 0;
      if (!res) {
        char * tmp = NULL;
        char * endptr = NULL;
        res = ubiq_platform_get_json_string(config_json, "min_input_int_value_as_string", &tmp);
        UBIQ_DEBUG(debug_flag, printf("%s res(%d) tmp: %s\n", csu, res, tmp));
        if (!res && tmp != NULL) {
          int64_t i = strtol(tmp, &endptr, 10);
        UBIQ_DEBUG(debug_flag, printf("%s i(%ld) tmp: %s endptr(%s)\n", csu, i, tmp, endptr));

          if (endptr == tmp ) {
            res = -EINVAL;
          } else {
            c->min_input_int_value = i;
          }
          free(tmp);
        }
        UBIQ_DEBUG(debug_flag, printf("%s res(%d) min_input_int_value: %ld\n", csu, res, c->min_input_int_value));
      }
      if (!res) {
        char * tmp = NULL;
        char * endptr = NULL;
        res = ubiq_platform_get_json_string(config_json, "max_input_int_value_as_string", &tmp);
        if (!res && tmp != NULL) {
          int64_t i = strtol(tmp, &endptr, 10);
          if (endptr == tmp ) {
            res = -EINVAL;
          } else {
            c->max_input_int_value = i;
          }
          free(tmp);
        }
        UBIQ_DEBUG(debug_flag, printf("%s res(%d) max_input_int_value: %ld\n", csu, res, c->max_input_int_value));
      }

      if (!res) {
        char * str = NULL;
        res = ubiq_platform_get_json_string(config_json, "epoch", &str);
        if (!res && str != NULL) {
          c->epoch = calloc(sizeof(*c->epoch), 1);
          res = ubiq_platform_parse_iso8601(str, c->epoch);
          UBIQ_DEBUG(debug_flag, printf("%s EPOCH: %s\n", csu, asctime(c->epoch)));
          if (-1 == (c->epoch_as_time_t = mktime(c->epoch))) {
            res = -EINVAL;
          }
        }
        free(str);
      }

      if (!res) {
        char * str = NULL;
        res = ubiq_platform_get_json_string(config_json, "max_input_date_value", &str);
        if (!res && str != NULL) {
          c->max_input_date_value = calloc(sizeof(*c->max_input_date_value), 1);
          res = ubiq_platform_parse_iso8601(str, c->max_input_date_value);
          UBIQ_DEBUG(debug_flag, printf("%s max_input_date_value: %s\n", csu, asctime(c->max_input_date_value)));
          if (-1 == (c->max_input_date_value_as_time_t = mktime(c->max_input_date_value))) {
            res = -EINVAL;
          }
        }
        free(str);
      }

      if (!res) {
        char * str = NULL;
        res = ubiq_platform_get_json_string(config_json, "min_input_date_value", &str);
        if (!res && str != NULL) {
          c->min_input_date_value = calloc(sizeof(*c->min_input_date_value), 1);
          res = ubiq_platform_parse_iso8601(str, c->min_input_date_value);
          UBIQ_DEBUG(debug_flag, printf("%s min_input_date_value: %s\n", csu, asctime(c->min_input_date_value)));
          if (-1 == (c->min_input_date_value_as_time_t = mktime(c->min_input_date_value))) {
            res = -EINVAL;
          }
        }
        free(str);
      }


      if (!res) {res = ubiq_platform_get_json_int(config_json, "size", (int *)&c->size);}
      *cfg = c;

    }
    return res;
  }

static void printISO8601(const struct tm * const date) {
  static int debug_flag = 1;
  UBIQ_DEBUG(debug_flag, 
      printf("date: %s\n", asctime(date)));
}