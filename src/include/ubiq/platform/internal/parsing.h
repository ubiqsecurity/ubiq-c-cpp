#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stdint.h>
__BEGIN_DECLS


int
ubiq_platform_efpe_parsing_parse_input(
    const uint32_t * const input_string, // Null terminated
    const uint32_t * const input_character_set, // Null terminated
    const uint32_t * const passthrough_character_set, // Null terminated
    uint32_t * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    uint32_t * empty_formatted_output // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
  );


__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
