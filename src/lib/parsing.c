#include <ubiq/platform/internal/parsing.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistr.h>

// #define UBIQ_DEBUG_ON // UNCOMMENT to Enable UBIQ_DEBUG macro

#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

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
  )
{
  static const char * const csu = "char_parsing_decompose_string";
  int debug_flag = 0;
  int err;

  const char * i = input_string;
  char * f = empty_formatted_output;
  char * t = trimmed_characters;

  err = 0;

  // Due to partial encryption, we cannot make any assumption regarding source characterset.
  // Only passthrough or non-passthrough at this time.  We will validate timmed characters
  // against input characterset later after all processing.

  while (*i && (0 == err)) {
      UBIQ_DEBUG(debug_flag, printf("%s \t i(%s) trimmed_characters(%s) \t empty_formatted_output(%s) \t err(%d)\n",csu, i, trimmed_characters, empty_formatted_output, err));

    if (passthrough_character_set && strchr(passthrough_character_set, *i))
    {
      *f++ = *i;
    } else {
      *t++ = *i;
      *f++ = zeroth_char;
      // Trimmed may be shorter than input so make sure to include null terminator
      // after last character
      *t = 0;
    }
    i++;
  }
  *trimmed_len = t - trimmed_characters;
  *formatted_len = f - empty_formatted_output;
  return err;
}

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
  )
{
  static const char * const csu = "u32_parsing_decompose_string";
  int debug_flag = 1;

  int err;

  UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_len(%d) formatted_len(%d) \t err(%d)\n",csu, *trimmed_len, *formatted_len, err));
  UBIQ_DEBUG(debug_flag, printf("%s \t passthrough_character_set(%S)\tinput_string(%S) \tinput_character_set(%S) \t err(%d)\n",csu, passthrough_character_set, input_string, input_character_set, err));

  const uint32_t * i = input_string;
  uint32_t * f = empty_formatted_output;
  uint32_t * t = trimmed_characters;

  err = 0;

  // Due to partial encryption, we cannot make any assumption regarding source characterset.
  // Only passthrough or non-passthrough at this time.  We will validate timmed characters
  // against input characterset later after all processing.

  while (*i && (0 == err)) {
      UBIQ_DEBUG(debug_flag, printf("%s \t i(%S) trimmed_characters(%S) \t empty_formatted_output(%S) \t err(%d)\n",csu, i, trimmed_characters, empty_formatted_output, err));

    // Making assumption that input character is more likely to be in input character set, not
    // passthrough, so check input character set first, even though check may take longer.
    if (passthrough_character_set && u32_strchr(passthrough_character_set, *i))
    {
      UBIQ_DEBUG(debug_flag, printf("passthrough_character_set %C\n", *i));
      *f++ = *i;
    } else {
      UBIQ_DEBUG(debug_flag, printf("input_character_set %C\n", *i));
      *t++ = *i;
      *f++ = zeroth_char;
      // Trimmed may be shorter than input so make sure to include null terminator
      // after last character
      *t = 0;
    }
    i++;
  }
  UBIQ_DEBUG(debug_flag, printf("%s end \t t(%S) \t f(%S) \t err(%d)\n",csu, t, f, err));
  UBIQ_DEBUG(debug_flag, printf("%s \t len(%ld) \t len(%ld) \t err(%d)\n",csu, t - trimmed_characters, f - empty_formatted_output, err));

  *trimmed_len = t - trimmed_characters;
  *formatted_len = f - empty_formatted_output;
  UBIQ_DEBUG(debug_flag, printf("%s \t trimmed_len(%d) formatted_len(%d) \t err(%d)\n",csu, *trimmed_len, *formatted_len, err));

  return err;
}



// Null terminated
int
convert_utf8_to_utf32(
  const char * const utf8_src,
  uint32_t ** const utf32_dst)
{
  int res = -ENOMEM;

  uint32_t * tmp = NULL;
  size_t lengthp = 0;
  // +1 for null terminator in input
  tmp = u8_to_u32(utf8_src, u8_strlen(utf8_src) + 1, NULL, &lengthp);
  if (NULL != tmp) {
    *utf32_dst = tmp;
    res = 0;
  } else {
    res = -errno;
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

  // Convert the utf8 to utf32, No null terminator so need to realloc and add
  tmp = u8_to_u32(utf8_src, len , NULL, &lengthp);
  if (NULL != tmp) {
    tmp = realloc(tmp, (lengthp + 1) * sizeof(uint32_t));
    if (tmp != NULL) {
      tmp[lengthp] = 0;
      *utf32_dst = tmp;
      res = 0;
    }
  } else {
    res = -errno;
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

  // Convert the utf8 to utf32, up to u8_width + 1.  +1 for null terminator to output
  tmp = u32_to_u8(utf32_src, u32_strlen(utf32_src) + 1 , NULL, &lengthp);
  if (NULL != tmp) {
    *utf8_dst = tmp;
    res = 0;
  } else {
    res = -errno;
  }

  return res;
}
