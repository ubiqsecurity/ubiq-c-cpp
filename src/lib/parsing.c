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

static int debug_flag = 0;

int ubiq_platform_efpe_parsing_parse_input(
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
  int debug_flag = 0;

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
  const uint8_t * const utf8_src,
  uint32_t ** const utf32_dst)
{
  static const char * const csu = "convert_utf8_to_utf32";
  int res = -ENOMEM;
  size_t slen = strlen(utf8_src);
  UBIQ_DEBUG(debug_flag, printf("%s: slen(%d) utf8_src(%s)\n", csu, slen, utf8_src));
   
  size_t u32_len = 0;
  uint32_t * u32 = NULL;//calloc(slen, sizeof(uint32_t));;
  u32 = u8_to_u32(utf8_src, slen, NULL, &u32_len);
  UBIQ_DEBUG(debug_flag, printf("%s: u32(%S)\n", csu, u32));
  if (u32 == NULL) {
    res = -errno;
  } else {
    free(u32);
    
    u32_len ++;
    u32 = calloc(u32_len, sizeof(uint32_t));
    uint32_t * u32_tmp = u8_to_u32(utf8_src, slen, u32, &u32_len);
    
    if (u32_tmp == u32 && u32 != NULL) {
        u32[u32_len] = 0;
        *utf32_dst = u32;
  UBIQ_DEBUG(debug_flag, wprintf("%s: u32_len(%d) *utf32_dst(%S)\n", csu, u32_len, *utf32_dst));

        res = 0;
    } else {
        free(u32);
        free(u32_tmp);
    }
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

// Will make sure a null terminator is added to the end of the u8 string
int convert_utf32_to_utf8(
  const uint32_t * const utf32_src,
  uint8_t ** const utf8_dst)
{
  int res = -ENOMEM;

  size_t u32_len = u32_strlen(utf32_src);
  uint8_t * u8 = NULL;
  size_t u8_len = 0;
  u8 = u32_to_u8(utf32_src, u32_len, NULL, &u8_len);
  if (u8 == NULL) {
    res = -errno;
  } else {
    free(u8);
    
    u8_len ++;
    uint8_t * u8_tmp = calloc(u8_len, sizeof(uint8_t));
    u8 = u32_to_u8(utf32_src, u32_len, u8_tmp, &u8_len);
    
    if (u8_tmp == u8 && u8 != NULL) {
      u8[u8_len] = 0;
      UBIQ_DEBUG(debug_flag, printf("utf32_src(%S)  u8 str (%s) u8_len(%d)\n", utf32_src, u8, u8_len));
      *utf8_dst= u8;
      res = 0;
    } else {
      free(u8_tmp);
      free(u8);
      res = -errno;
    }
  }

  return res;
}

// Simply to avoid casts
int strcmp32(const char32_t *s1, const char32_t *s2)
{
  char32_t ch;
  int d = 0;
  while ( 1 ) {
    d = (int)(ch = *s1++) - (int)*s2++;
    if ( d || !ch )
      break;
  }
  return d;
}

int strncmp32(const char32_t *s1, const char32_t *s2, size_t n)
{
  char32_t ch;
  int d = 0;
  while ( n-- ) {
    d = (int)(ch = *s1++) - (int)*s2++;
    if ( d || !ch )
      break;
  }
  return d;
}

int ubiq_platform_decode_keynum(
  uint32_t const * const alphabet,
  unsigned int const msb_encoding_bits,
  unsigned int * const key_number,
  uint32_t * const str
)
{
  int res = -EINVAL;
  uint32_t encoded_char = str[0];

  uint32_t * pos = u32_strchr(alphabet, encoded_char);
  if (pos != NULL && *pos != 0) {
    unsigned int const encoded_value = pos - alphabet;

    unsigned int const key_num = encoded_value >> msb_encoding_bits;

    str[0] = alphabet[encoded_value - (key_num << msb_encoding_bits)];
    *key_number = key_num;
    res = 0;
  }
  return res;
}


int ubiq_platform_encode_keynum(
  uint32_t const * const alphabet,
  unsigned int const msb_encoding_bits,
  unsigned int const key_number,
  uint32_t * const str
)
{
  int res = -EINVAL;

  uint32_t * pos = u32_strchr(alphabet, *str);

  // If *buf is null terminator or if the character cannot be found,
  // it would be an error.
  if (pos != NULL && *pos != 0){
    size_t ct_value = pos - alphabet;
    ct_value += (key_number << msb_encoding_bits);
    *str = alphabet[ct_value];
    res = 0;
  }
  return res;
}


// always returns a NEW string, even if original string is longer than the minimum string
int ubiq_platform_pad_left(
  uint32_t pad_char,
  size_t length,
  uint32_t const * const src,
  uint32_t ** const padded_str)
{
  static const char * const csu = "ubiq_platform_pad_left";

  int res = -EINVAL;
  int debug_flag = 0;

  if (pad_char != '\0') {
    uint32_t * out = NULL;
    size_t len = u32_strlen(src);
    UBIQ_DEBUG(debug_flag, printf("%s \t length(%d) str(%S) len(%d)\n", csu, length, src, len));

    if (len < length) {
      out = calloc(length + 1, sizeof(uint32_t)); // null terminator
      uint32_t * ptr = out;
      for (size_t i = 0; i < length - len; i++) {
        *ptr++ = pad_char;
      }
      int i = 0;
      while (src[i] != '\0') {
        *ptr++ = src[i++]; // Copy from src up to null terminator which is already set with calloc
      }
      res = 0;
    } else {
      out = u32_strdup(src);
      res = 0;
    }
    if (!res && out) {
      *padded_str = out;
    }
  }
  return res;
}

// always returns a NEW string, even if original string doesn't require unpadding
int ubiq_platform_trim_left_pad(
  uint32_t pad_char,
  uint32_t const * const src,
  uint32_t ** const unpadded_str)
{
  int res = -EINVAL;

  if (pad_char != '\0') {
    uint32_t * out = NULL;
    int i = 0;
    while (src[i] == pad_char && src[i] != '\0') {
      i++;
    }
    out = u32_strdup(&src[i]);
    if (!out) {
      res = -ENOMEM;
    } else {
      res = 0;
      *unpadded_str = out;
    }
  }
  return res;
}

int ubiq_platform_format_to_template(
  uint32_t const * const src,
  uint32_t const * const template,
  uint32_t const * const passthrough_characters,
  uint32_t ** const formated)
{
  int res = -EINVAL;

  uint32_t * const out = u32_strdup(template);
  size_t j = 0;
  size_t const template_len = u32_strlen(template);
  size_t const src_len = u32_strlen(src);

  uint32_t const * src_ptr = src;
  uint32_t * out_ptr = NULL;
  for (out_ptr = out; *out_ptr != '\0'; out_ptr++) {
    // Is the current template character a passthrough character?
    if (u32_strchr(passthrough_characters, *out_ptr) != NULL) {
      continue;
    }

    // Attempting to get a character from the src but src is not long enough
    if (*src_ptr == '\0') {
      break;
    }

    *out_ptr = *src_ptr++;
  }

  // All input characters were used and template was fully processed
  if (*out_ptr == '\0' && *src_ptr == '\0') {
    *formated = out;
    res = 0;
  }

  return res;
}

int ubiq_platform_get_json_int(
  cJSON const * const json,
  char const * const field_name,
  int * const destination)
{
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(json, field_name);
  if (cJSON_IsNumber(j)) {
    *destination = j->valueint;
  }
  return res;
}

int ubiq_platform_get_json_string(
  cJSON const * const json,
  char const * const field_name,
  char ** const destination)
{
  *destination = NULL;
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(json, field_name);
  if (cJSON_IsString(j) && j->valuestring != NULL) {
    *destination = strdup(j->valuestring);
    if (!*destination) {
      res = -errno;
    }
  }
  return res;
}

int ubiq_platform_get_json_u32string(
  cJSON const * const json,
  char const * const field_name,
  uint32_t ** const destination)
{
  char * tmp = NULL;
  int res = 0;
  res = ubiq_platform_get_json_string(json, field_name, &tmp);
  if (!res && tmp != NULL) {
    res = convert_utf8_to_utf32(tmp, destination);
    free(tmp);
  }
  return res;
}

int ubiq_platform_get_json_array(
  cJSON const * const json,
  char const * const field_name,
  cJSON ** const destination)
{
  *destination = NULL;
  int res = 0;
  cJSON * j = cJSON_GetObjectItemCaseSensitive(json, field_name);
  if (cJSON_IsArray(j)) {
    *destination = j;
  }
  return res;  
}

int ubiq_platform_get_json_boolean(
  cJSON const * const json,
  char const * const field_name,
  int * const destination)
{
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(json, field_name);
  *destination = cJSON_IsBool(j) && cJSON_IsTrue(j);
  return res;

}


int ubiq_platform_join_array(
  char const * const separator,
  char const ** const str, 
  size_t const count, 
  char ** merged)
{
  int res = 0;
  char * out = NULL;
  size_t sep_len = strlen(separator);
  size_t len = sep_len * (count - 1);

  for (int i = 0; i < count; i++) {
    len += strlen(str[i]);
  }
  UBIQ_DEBUG(debug_flag, printf("len: %d\n", len));
  if (NULL == (out = calloc(len + 1, sizeof(char)))) {
    res = -ENOMEM;
  } else {
    char * pos = out;
    for (int i = 0; i < count; i++) {
      size_t len = strlen(str[i]);
      strcpy(pos, str[i]);
      UBIQ_DEBUG(debug_flag, printf("i(%d) out: %s\n", i, out));
      UBIQ_DEBUG(debug_flag, printf("pos: %s\n", pos));
      pos += len;
      if (i < count - 1) {
        strcpy(pos, separator);
        pos += sep_len;
      }
    }
  }
  *merged = out;
  return res;
}

static int parse_tz(const char *s, int *offset_min) {
    if (!s || *s == '\0' || *s == 'Z') {
        *offset_min = 0;
        return 0;
    }
    int sign = 1;
    if      (*s == '+') sign =  1;
    else if (*s == '-') sign = -1;
    else return -1;
    s++;

    int h = 0, m = 0;
    int len = (int)strlen(s);

    if (len == 4 && sscanf(s, "%2d%2d", &h, &m) == 2)        /* +0000  */
        ;
    else if (len == 5 && sscanf(s, "%d:%d", &h, &m) == 2)    /* +00:00 */
        ;
    else if (len == 2 && sscanf(s, "%d", &h) == 1)            /* +00    */
        ;
    else
        return -1;

    *offset_min = sign * (h * 60 + m);
    return 0;
}

int
ubiq_platform_parse_iso8601(char const * const s, struct tm * const out)
{
  int res = -EINVAL;
  int tz_offset_min = 0;
  if (!s || !out) goto done;
    memset(out, 0, sizeof(*out));
    out->tm_mday = 1;  /* sane defaults */
    out->tm_mon  = 0;
    out->tm_isdst = -1;
    UBIQ_DEBUG(debug_flag, printf("iso : %s\n", s));


    const char *p = s;
    int year = 0, month = 1, day = 1;
    int hour = 0, min = 0, sec = 0, ms = 0;
    int has_time = 0;

    /* ── Year ── */
    if (sscanf(p, "%4d", &year) != 1) goto done;
    UBIQ_DEBUG(debug_flag, printf("year: %d\n", year));
    p += 4;

    /* Basic format: YYYYMMDD */
    if (*p != '-' && *p != '\0' && *p != 'T' && *p != ' ' && *p != 'Z'
            && *p != '+' && *p != '-') {
        if (sscanf(p, "%2d%2d", &month, &day) != 2) goto done;
        p += 4;
    } else {
        if (*p == '-') p++;
        if (*p == '\0' || *p == 'Z' || *p == '+' || *p == '-') goto finish;
        if (sscanf(p, "%2d", &month) != 1) goto done;
        p += 2;
        if (*p == '-') p++;
        if (*p == '\0' || *p == 'Z' || *p == '+' || *p == '-') goto finish;
        if (sscanf(p, "%2d", &day) != 1) goto done;
        p += 2;
    }
    UBIQ_DEBUG(debug_flag, printf("month: %d  day: %d\n", month, day));

    /* ── Time separator ── */
    if (*p != 'T' && *p != ' ') goto done;
    p++;
    has_time = 1;

    /* ── Hour ── */
    if (sscanf(p, "%2d", &hour) != 1) goto done;
    UBIQ_DEBUG(debug_flag, printf("hour: %d\n", hour));
    p += 2;
    if (*p == ':') p++;
    if (*p == '\0' || *p == 'Z' || *p == '+' || *p == '-') goto finish;

    /* ── Minute ── */
    if (sscanf(p, "%2d", &min) != 1) goto done;
    UBIQ_DEBUG(debug_flag, printf("min: %d\n", min));
    p += 2;
    if (*p == ':') p++;
    if (*p == '\0' || *p == 'Z' || *p == '+' || *p == '-') goto finish;

    /* ── Second ── */
    if (sscanf(p, "%2d", &sec) != 1) goto done;
    UBIQ_DEBUG(debug_flag, printf("sec: %d\n", sec));
    p += 2;

    /* ── Fractional seconds (ms) ── */
    if (*p == '.') {
        p++;
        char frac[4] = "000";
        int i = 0;
        while (*p >= '0' && *p <= '9' && i < 3) frac[i++] = *p++;
        while (*p >= '0' && *p <= '9') p++;  /* consume extra digits */
        ms = atoi(frac);
    }

finish:
    /* ── Timezone ── */
    if (parse_tz(p, &tz_offset_min) != 0) goto done;
    UBIQ_DEBUG(debug_flag, printf("tz_offset_min: %d\n", tz_offset_min));

    out->tm_year = year - 1900;
    out->tm_mon  = month - 1;
    out->tm_mday = day;
    out->tm_hour = hour;
    out->tm_min  = min + tz_offset_min;
    out->tm_sec  = sec;
    // out->ms         = ms;
    // Adjust for timezone offset
    mktime(out);
    res = 0;
    UBIQ_DEBUG(debug_flag, printf("after parse: %s\n", asctime(out)));

done:
    return res;
}