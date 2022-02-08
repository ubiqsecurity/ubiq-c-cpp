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

// Null terminated
int
convert_utf8_to_utf32(
  const char * const utf8_src,
  uint32_t ** const utf32_dst)
{
  int res = -ENOMEM;

  printf("u8_strlen (%d)\n", u8_strlen(utf8_src));


  uint32_t * tmp = NULL;
  size_t lengthp = 0;
  tmp = u8_to_u32(utf8_src, u8_strlen(utf8_src) , NULL, &lengthp);
  tmp[lengthp] = 0;
  printf("lengthp (%d)\n", lengthp);
  printf("u32_strlen (%d)\n", u32_strlen(tmp));
  if (NULL != tmp) {
    *utf32_dst = tmp;
    res = 0;
  } else {
    res = -errno; //printf("errno %d\n", errno);
  }
  return res;
}

// No Null Terminator
int
convert_utf8_len_to_utf32(
  const char * const utf8_src,
  const size_t len, // no null terminator
  uint32_t ** const utf32_dst)
{
  int res = -ENOMEM;

  uint32_t * tmp = NULL;
  size_t lengthp = 0;
//  size_t str_bytes = u8_strlen(utf8_src);

  // printf("u8_strlen %d\n", u8_strlen(utf8_src));
  // Convert the utf8 to utf32, up to u8_width + 1
  tmp = u8_to_u32(utf8_src, len , NULL, &lengthp);
  if (NULL != tmp) {
    tmp = realloc(tmp, (lengthp + 1) * sizeof(uint32_t));
    if (tmp != NULL) {
      tmp[lengthp] = 0;
      *utf32_dst = tmp;
      res = 0;
    }
  } else {
    res = -errno; //printf("errno %d\n", errno);
  }
  return res;
}

int convert_utf32_to_utf8(
  const uint32_t * const utf32_src,
  uint8_t ** const utf8_dst)
{
  int res = 0;

  uint8_t * tmp = NULL;
  size_t lengthp = 0;
  size_t str_bytes = u32_strlen(utf32_src);

  // Convert the utf8 to utf32, up to u8_width + 1
  tmp = u32_to_u8(utf32_src, u32_strlen(utf32_src) +1 , NULL, &lengthp);
  tmp[lengthp] = 0;
  if (NULL != tmp) {
    *utf8_dst = tmp;
    res = 0;
  } else {
    res = -errno; //printf("errno %d\n", errno);
  }
  // Extend and set null terminator
  // tmp = realloc(tmp, (lengthp + 1)* sizeof(uint8_t));
  // tmp[lengthp] = '\0';


  return res;
}
