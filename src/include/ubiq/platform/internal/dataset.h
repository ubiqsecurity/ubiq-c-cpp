#pragma once

#include <unistr.h>
#include <errno.h>
#include <uchar.h>
#include <time.h>

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/internal/ff1.h>

#include "cJSON/cJSON.h"

__BEGIN_DECLS

// Currently only three passthrough rules.  Has to be define 
#define UBIQ_PASSTHROUGH_RULES_COUNT 3


// typedef enum {UINT32=0, UINT8=1}  dataset_character_types ;
// typedef enum {PARSE_INPUT_TO_OUTPUT = 0, PARSE_OUTPUT_TO_INPUT = 1} conversion_direction_type;
typedef enum {
  UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_NONE = 0, 
  UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PASSTHROUGH = 1, 
  UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PREFIX = 2, 
  UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_SUFFIX = 3} UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PRIORITY;

extern const char * const ENCODING_BASE64;
extern const char * const ENCODING_BASE32;

extern const char * const DATA_TYPE_INTEGER;
extern const char * const DATA_TYPE_DATE;
extern const char * const DATA_TYPE_DATETIME;
extern const char * const DATA_TYPE_TOKEN;
extern const char * const DATA_TYPE_FORMATTED_STRING;
extern const char * const DATA_TYPE_GENERIC_STRING;


typedef struct ubiq_platform_error {
    char * err_msg;
    size_t err_num;
} ubiq_platform_error_t;

struct ubiq_platform_data_type_config;
typedef struct ubiq_platform_data_type_config ubiq_platform_data_type_config_t;

struct ubiq_platform_dataset;
typedef struct ubiq_platform_dataset ubiq_platform_dataset_t;
// {
//   char * name;
//   size_t min_input_length;
//   size_t max_input_length;
//   char * tweak_source;
//   char32_t * regex;
//   char32_t * u32_input_character_set; // Will be set if any of char sets are multi-byte utf8
//   char32_t * u32_output_character_set;  // Will be set if any of char sets are multi-byte utf8
//   char32_t * u32_passthrough_character_set;// Will be set if any of char sets are multi-byte utf8
//   uint32_t prefix_passthrough_length;
//   uint32_t suffix_passthrough_length;
//   int msb_encoding_bits;
//   passthrough_rules_priority_type passthrough_rules_priority[3]; // Three known rules.  Ordered list of 
//   struct {
//           void * buf;
//           size_t len;
//   } tweak;
//   size_t tweak_min_len;
//   size_t tweak_max_len;
//   dataset_character_types character_types; // Set if any of the character sets contain utf8
//   char * input_encoding;
//   char * data_type;
//   char32_t input_pad_character;
//   data_type_config_t * data_type_config;


// } ubiq_platform_dataset_t;

int ubiq_platform_dataset_create(
    cJSON const * const dataset_json,
    ubiq_platform_dataset_t ** const dataset);

void ubiq_platform_dataset_destroy(ubiq_platform_dataset_t * const f);


char32_t const * const ubiq_platform_dataset_get_input_characters(ubiq_platform_dataset_t const * const dataset);
char32_t const * const ubiq_platform_dataset_get_output_characters(ubiq_platform_dataset_t const * const dataset);
char32_t const * const ubiq_platform_dataset_get_passthrough_characters(ubiq_platform_dataset_t const * const dataset);
char const * const ubiq_platform_dataset_get_input_encoding(ubiq_platform_dataset_t const * const dataset);
char const * const ubiq_platform_dataset_get_name(ubiq_platform_dataset_t const * const dataset);


unsigned int const ubiq_platform_dataset_get_msb_encoding_bits(ubiq_platform_dataset_t const * const dataset);
char32_t const ubiq_platform_dataset_get_input_pad_char(ubiq_platform_dataset_t const * const dataset);
size_t const ubiq_platform_dataset_get_input_min_length(ubiq_platform_dataset_t const * const dataset);
size_t const ubiq_platform_dataset_get_input_max_length(ubiq_platform_dataset_t const * const dataset);

size_t const ubiq_platform_dataset_get_passthrough_prefix_length(ubiq_platform_dataset_t const * const dataset);
size_t const ubiq_platform_dataset_get_passthrough_suffix_length(ubiq_platform_dataset_t const * const dataset);

void const * const ubiq_platform_dataset_get_tweak(ubiq_platform_dataset_t const * const dataset);
size_t const ubiq_platform_dataset_get_tweak_len(ubiq_platform_dataset_t const * const dataset);
size_t const ubiq_platform_dataset_get_tweak_min_len(ubiq_platform_dataset_t const * const dataset);
size_t const ubiq_platform_dataset_get_tweak_max_len(ubiq_platform_dataset_t const * const dataset);

int const ubiq_platform_dataset_get_can_encrypt(ubiq_platform_dataset_t const * const dataset);
int const ubiq_platform_dataset_get_can_decrypt(ubiq_platform_dataset_t const * const dataset);

char const * const ubiq_platform_dataset_get_data_type(ubiq_platform_dataset_t const * const dataset);

ubiq_platform_data_type_config_t const * const ubiq_platform_dataset_get_data_type_config(ubiq_platform_dataset_t const * const dataset);

size_t const ubiq_platform_data_type_config_get_size(ubiq_platform_data_type_config_t const * const cfg);
int64_t const ubiq_platform_data_type_config_get_min_input_value(ubiq_platform_data_type_config_t const * const cfg);
int64_t const ubiq_platform_data_type_config_get_max_input_value(ubiq_platform_data_type_config_t const * const cfg);

struct tm const * const ubiq_platform_data_type_config_get_epoch(ubiq_platform_data_type_config_t const * const cfg);
struct tm const * const ubiq_platform_data_type_config_get_min_input_date_value(ubiq_platform_data_type_config_t const * const cfg);
struct tm const * const ubiq_platform_data_type_config_get_max_input_date_value(ubiq_platform_data_type_config_t const * const cfg);

// Convenience functions that have already converted struct tm to time_t
time_t const ubiq_platform_data_type_config_get_epoch_as_time_t(ubiq_platform_data_type_config_t const * const cfg);
time_t const ubiq_platform_data_type_config_get_min_input_date_value_as_time_t(ubiq_platform_data_type_config_t const * const cfg);
time_t const ubiq_platform_data_type_config_get_max_input_date_value_as_time_t(ubiq_platform_data_type_config_t const * const cfg);

int ubiq_platform_dataset_get_passthrough_rule_priorities(
  ubiq_platform_dataset_t const * const dataset,
  size_t priorities[],
  size_t size // SIZE MUST be GE to PASSTHROUGH_RULES_COUNT
);
__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
