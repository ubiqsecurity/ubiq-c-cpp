#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stdint.h>
#include <unistr.h>
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
  const char * const utf8_src,
  uint32_t ** const utf32_dst);

int
convert_utf8_len_to_utf32(
  const char * const utf8_src,
  const size_t len, // no null terminator
  uint32_t ** const utf32_dst);

int convert_utf32_to_utf8(
  const uint32_t * const utf32_src,
  uint8_t ** const utf8_dst);


__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
