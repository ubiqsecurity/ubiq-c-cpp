#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS


int
ubiq_platform_efpe_parsing_parse_input(
    const char * const input_string, // Null terminated
    const char * const input_character_set, // Null terminated
    const char * const passthrough_character_set, // Null terminated
    char * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    char * empty_formatted_output // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
  );


__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
