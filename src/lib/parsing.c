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
  int err;

  const char * i = input_string;
  char * f = empty_formatted_output;
  char * t = trimmed_characters;

  err = 0;

  while (*i && (0 == err)) {
    // Making assumption that input character is more likely to be in input character set, not
    // passthrough, so check input character set first, even though check may take longer.
    if (strchr(input_character_set, *i))
    {
      *t++ = *i;
      *f++ = zeroth_char;
      // Trimmed may be shorter than input so make sure to include null terminator
      // after last character
      *t = 0;
    }
    // If the input string matches a passthrough character, copy
    // to empty formatted output string
    else if (passthrough_character_set && strchr(passthrough_character_set, *i))
    {
      *f++ = *i;
    }
    // If the string is in the input characterset,
    // copy to trimmed characters
    else  {
      err = -EINVAL;
    }
    i++;
  }
  *trimmed_len = t - trimmed_characters;
  *formatted_len = f - empty_formatted_output;
  return err;
}

int
parsing_decompose_string(
    const char * const input_string, // Null terminated
    const char * const input_character_set, // Null terminated
    const char * const passthrough_character_set, // Null terminated
    const char zeroth_char,
    char * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    char * empty_formatted_output // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
  )
  {
    int err;

    const char * i = input_string;
    char * f = empty_formatted_output;
    char * t = trimmed_characters;

    err = 0;

    while (*i && (0 == err)) {
      // Making assumption that input character is more likely to be in input character set, not
      // passthrough, so check input character set first, even though check may take longer.
      if (strchr(input_character_set, *i))
      {
        *t++ = *i;
        *f++ = zeroth_char;
        // Trimmed may be shorter than input so make sure to include null terminator
        // after last character
        *t = 0;
      }
      // If the input string matches a passthrough character, copy
      // to empty formatted output string
      else if (passthrough_character_set && strchr(passthrough_character_set, *i))
      {
        *f++ = *i;
      }
      // If the string is in the input characterset,
      // copy to trimmed characters
      else  {
        err = -EINVAL;
      }
      i++;
    }
    return err;
  }

int
u32_parsing_decompose_string(
    const uint8_t * const input_string, // Null terminated
    const uint32_t * const input_character_set, // Null terminated
    const uint32_t * const passthrough_character_set, // Null terminated
    const uint32_t zeroth_char,
    uint8_t * trimmed_characters, // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    uint32_t * empty_formatted_output // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
  )
{
  static const char * csu = "u32_parsing_decompose_string";
  int err;
  err = 0;

  uint32_t * u32_src = NULL;
  uint32_t * f = empty_formatted_output;
  uint32_t * u32_trimmed = (uint32_t *)calloc(strlen(input_string), sizeof(uint32_t));
  uint32_t * t = u32_trimmed;

  err = convert_utf8_to_utf32(input_string, &u32_src);

  printf("%s input_string(%s)\n",csu, input_string);
  printf("%s u32_src(%S)\n",csu, u32_src);
  printf("%s passthrough_character_set(%S)\n",csu, passthrough_character_set);

  if (!err && !u32_trimmed) {
    err = -ENOMEM;
  }

  const uint32_t * i = u32_src;

  while ((0 == err) && *i) {
    // Making assumption that input character is more likely to be in input character set, not
    // passthrough, so check input character set first, even though check may take longer.
    if (u32_strchr(input_character_set, *i))
    {
      *t++ = *i;
      *f++ = zeroth_char;
      // Trimmed may be shorter than input so make sure to include null terminator
      // after last character
      *t = 0;
        printf("%s i(%d) u32_trimmed(%S) empty_formatted_output(%S)\n",csu, i, u32_trimmed,empty_formatted_output);

    }
    // If the input string matches a passthrough character, copy
    // to empty formatted output string
    else if (passthrough_character_set && u32_strchr(passthrough_character_set, *i))
    {
      *f++ = *i;
        printf("%s i(%d) empty_formatted_output(%S)\n",csu, i, empty_formatted_output);
    }
    // If the string is in the input characterset,
    // copy to trimmed characters
    else  {
      err = -EINVAL;
    }
    i++;
  }

  if (!err) {
    uint8_t * tmp = NULL;
    err = convert_utf32_to_utf8(u32_trimmed, &tmp);
    u8_strcpy(trimmed_characters, tmp);
    free(tmp);
  }
        printf("%s err(%d) trimmed_characters(%s) empty_formatted_output(%S)\n",csu, err, trimmed_characters,empty_formatted_output);
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
