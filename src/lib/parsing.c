#include <ubiq/platform/internal/parsing.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistr.h>

int
ubiq_platform_efpe_parsing_parse_input(
    const uint32_t * const input_string, // Null terminated
    const uint32_t * const input_character_set, // Null terminated
    const uint32_t * const passthrough_character_set, // Null terminated
    uint32_t * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    uint32_t * empty_formatted_output // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
  )
  {
    int err;

    const uint32_t * i = input_string;
    uint32_t * f = empty_formatted_output;
    uint32_t * t = trimmed_characters;

    err = 0;

    while (*i && (0 == err))
    {
      // If the input string matches a passthrough character, copy
      // to empty formatted output string
      if (passthrough_character_set && u32_strchr(passthrough_character_set, *i))
      {
        *f = *i;
      }
      // If the string is in the input characterset,
      // copy to trimmed characters
      else if (u32_strchr(input_character_set, *i))
      {
        *t = *i;
        t++;
        // Trimmed may be shorter than input so make sure to include null terminator
        // after last character
        *t = 0;
      } else {
        err = -EINVAL;
      }

      i++;
      f++;
    }
    return err;
  }
