#pragma once


#include <stdint.h>
#include <unistr.h>
#include <uchar.h>
#include <time.h>

#include <ubiq/platform/compat/cdefs.h>

#include "cJSON/cJSON.h"

__BEGIN_DECLS


int
ubiq_platform_efpe_parsing_parse_input(
    const uint32_t * const input_string, // Null terminated
    const uint32_t * const input_character_set, // Null terminated
    const uint32_t * const passthrough_character_set, // Null terminated
    uint32_t * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    uint32_t * empty_formatted_output // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
  );

int
char_parsing_decompose_string(
    const char * const input_string, // Null terminated
    const char * const input_character_set, // Null terminated
    const char * const passthrough_character_set, // Null terminated
    const char zeroth_char,
    char * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    size_t * trimmed_len,
    char * empty_formatted_output, // Return should either have zeroth character or passthrough character
    size_t * formatted_len
  );

int
u32_parsing_decompose_string(
    const uint32_t * const input_string, // Null terminated
    const uint32_t * const input_character_set, // Null terminated
    const uint32_t * const passthrough_character_set, // Null terminated
    const uint32_t zeroth_char,
    uint32_t * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    size_t * trimmed_len,
    uint32_t * empty_formatted_output, // Return should either have zeroth character or passthrough character
    size_t * formatted_len
  );

int
convert_utf8_to_utf32(
  const uint8_t * const utf8_src,
  uint32_t ** const utf32_dst);

int
convert_utf8_len_to_utf32(
  const char * const utf8_src,
  const size_t len, // no null terminator
  uint32_t ** const utf32_dst);

int convert_utf32_to_utf8(
  const uint32_t * const utf32_src,
  uint8_t ** const utf8_dst);

int strcmp32(const char32_t *s1, const char32_t *s2);

int strncmp32(const char32_t *s1, const char32_t *s2, size_t n);

int ubiq_platform_decode_keynum(
  uint32_t const * const alphabet,
  unsigned int const msb_encoding_bits,
  unsigned int * const key_number,
  uint32_t * const str);

  int ubiq_platform_encode_keynum(
  uint32_t const * const alphabet,
  unsigned int const msb_encoding_bits,
  unsigned int const key_number,
  uint32_t * const str);

// always returns a NEW string, even if original string is longer than the minimum string
int ubiq_platform_pad_left(
  uint32_t pad_char,
  size_t length,
  uint32_t const * const src,
  uint32_t ** const padded_str);

// always returns a NEW string, even if original string doesn't require unpadding
int ubiq_platform_trim_left_pad(
  uint32_t pad_char,
  uint32_t const * const src,
  uint32_t ** const unpadded_str);

int ubiq_platform_format_to_template(
  uint32_t const * const src,
  uint32_t const * const t,
  uint32_t const * const passthrough_characters,
  uint32_t ** const formated);

int ubiq_platform_get_json_int(
  cJSON const * const json,
  char const * const field_name,
  int * const destination);

int ubiq_platform_get_json_string(
  cJSON const * const json,
  char const * const field_name,
  char ** const destination);

int ubiq_platform_get_json_u32string(
  cJSON const * const json,
  char const * const field_name,
  uint32_t ** const destination);

int ubiq_platform_get_json_array(
  cJSON const * const json,
  char const * const field_name,
  cJSON ** const destination);

int ubiq_platform_get_json_boolean(
  cJSON const * const json,
  char const * const field_name,
  int * const destination);

int ubiq_platform_join_array(char const * const separator,
  char const ** const str, 
  size_t const count, 
  char ** merged);

int
ubiq_platform_parse_iso8601(
  char const * const s, 
  struct tm * const out);


__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
