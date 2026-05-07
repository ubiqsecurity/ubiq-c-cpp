#include <ubiq/platform/internal/support.h>
#include <ubiq/platform/internal/parsing.h>

#include <errno.h>

#if defined(_WIN32)
#  include <userenv.h>
#else
#  include <pwd.h>
#  include <unistd.h>
#  include <stdlib.h>
#  include <string.h>
#  include <stdio.h>
#  include <ctype.h>
#endif

// #define UBIQ_DEBUG_ON // UNCOMMENT to Enable UBIQ_DEBUG macro


#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;


const char * ubiq_support_user_agent = NULL;
const char * ubiq_support_product = NULL;
const char * ubiq_support_version = NULL;

int
ubiq_support_gmtime_r(
    const time_t * const t, struct tm * const tm)
{
    int err;
#if defined(_WIN32)
    err = -gmtime_s(tm, t);
#else
    err = 0;
    if (!gmtime_r(t, tm)) {
        err = -errno;
    }
#endif
    return err;
}

int
ubiq_support_get_home_dir(
    char ** const _dir)
{
    char * dir;
    int err;

#if defined(_WIN32)
    HANDLE token;
    DWORD len;

    err = INT_MIN;

    token = GetCurrentProcessToken();
    len = 0;
    /*
     * windows documentation says NULL should work here, but
     * it doesn't. the pointer doesn't really matter since
     * the length says there are zero bytes there, anyway
     */
    GetUserProfileDirectoryA(token, (PUCHAR)1, &len);
    if (len > 0) {
        err = -ENOMEM;
        dir = malloc(sizeof(*dir) * len);
        if (dir) {
            if (GetUserProfileDirectoryA(token, dir, &len)) {
                *_dir = dir;
                err = 0;
            } else {
                free(dir);
                err = INT_MIN;
            }
        }
    }
#else
    const struct passwd * const pw = getpwuid(geteuid());

    err = -errno;
    if (pw) {
        err = -ENOMEM;
        dir = malloc(strlen(pw->pw_dir) + 1);
        if (dir) {
            strcpy(dir, pw->pw_dir);
            *_dir = dir;
            err = 0;
        }
    }
#endif

    return err;
}

int ubiq_support_u32_base64_encode(uint32_t ** const dest, const uint32_t * const src) {
  int res = -EINVAL;
  uint8_t * utf8 = NULL;
  uint8_t * utf8_base64 = NULL;

  // Input will be considered a string of UTF32, not a binary array
  // Convert to UTF8, then encode and then convert to UTF32

  if (src && dest) {
    res = convert_utf32_to_utf8(src, &utf8);
    UBIQ_DEBUG(debug_flag, printf("res(%d) src(%S) utf8(%s)\n", res, src, utf8));
    if (!res) {
      // Returns the length of the utf8 string, but it already has the null terminator
      res = ubiq_support_base64_encode((char **)&utf8_base64, utf8, strlen(utf8));
      if (res > 0) {
        res = 0;
      }
      UBIQ_DEBUG(debug_flag, printf("res(%d) utf8_base64(%s)\n", res, utf8_base64));
      if (!res) {
        res = convert_utf8_to_utf32(utf8_base64, dest);
        UBIQ_DEBUG(debug_flag, printf("res(%d) dest(%S)\n", res, *dest));
      }
    }
  }

  if (utf8_base64) {
    free(utf8_base64);
  }
  if (utf8) {
    free(utf8);
  }

  return res;
}
int ubiq_support_u32_base64_decode(uint32_t ** const dest, const uint32_t * const src) {
    // Input will be considered a string.  Convert to UTF8, then decode and then convert to UTF32
  int res = -EINVAL;
  uint8_t * utf8 = NULL;
  uint8_t * utf8_base64 = NULL;

  if (src && dest) {
    res = convert_utf32_to_utf8(src, &utf8_base64);
    UBIQ_DEBUG(debug_flag, printf("res(%d) utf8_base64(%s) src(%S)\n", res, utf8_base64, src));
    if (!res) {
      // Returns the length of the utf8
      res = ubiq_support_base64_decode((void **)&utf8, (char *)utf8_base64, strlen(utf8_base64));
      if (res > 0) {
        res = 0;
      }
      UBIQ_DEBUG(debug_flag, printf("strlen(utf8_base64): %d\n", strlen(utf8_base64)));
      UBIQ_DEBUG(debug_flag, printf("strlen(utf8): %d\n", strlen(utf8)));
      UBIQ_DEBUG(debug_flag, printf("res(%d) utf8_base64(%s) utf8(%s)\n", res, utf8_base64, utf8));
      if (!res) {
        res = convert_utf8_to_utf32(utf8, dest);
        UBIQ_DEBUG(debug_flag, printf("res(%d) dest(%S) utf8(%s)\n", res, *dest, utf8));
      }
    }
  }

  if (utf8_base64) {
    free(utf8_base64);
  }
  if (utf8) {
    free(utf8);
  }

  return res;
}

int ubiq_support_base32_encode(char ** const dest, const uint8_t * const src, const size_t len)
{
  static const char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  // Calculate output length: every 5 bytes produces 8 characters
  size_t out_len = ((len + 4) / 5) * 8;
  char *out = calloc(out_len + 1, sizeof(uint8_t));
  if (!out) return -ENOMEM;

  size_t i = 0, j = 0;
  while (i < len) {
      uint64_t buffer = 0;
      int count = 0;

      // Load up to 5 bytes (40 bits) into a buffer
      for (int k = 0; k < 5; ++k) {
          buffer <<= 8;
          if (i < len) {
              buffer |= src[i++];
              count++;
          }
      }

      // Calculate how many 5-bit groups we have in this 40-bit chunk
      int bits = count * 8;
      for (int k = 0; k < 8; ++k) {
          int shift = 35 - (k * 5);
          if (k * 5 < bits) {
              out[j++] = b32_alphabet[(buffer >> shift) & 0x1F];
          } else {
              out[j++] = '='; // RFC 4648 Padding
          }
      }
  }

  out[j] = '\0';
  *dest = out;
  return 0;
}

int ubiq_support_base32_decode(void ** const dest, size_t * const dest_len, const char * const src, const size_t len) {
  size_t in_len = len;

  while (in_len > 0 && src[in_len - 1] == '=') in_len--;

  *dest_len = (in_len * 5) / 8;
  uint8_t *out = calloc(1, *dest_len + 1);
  if (!out) return -ENOMEM;

  uint32_t buffer = 0;
  int bits_left = 0;
  size_t count = 0;

  for (size_t i = 0; i < in_len; i++) {
      char c = toupper((unsigned char)src[i]);
      int val;

      if (c >= 'A' && c <= 'Z') val = c - 'A';
      else if (c >= '2' && c <= '7') val = c - '2' + 26;
      else continue; // Skip invalid characters

      buffer = (buffer << 5) | (val & 0x1F);
      bits_left += 5;

      if (bits_left >= 8) {
          out[count++] = (uint8_t)(buffer >> (bits_left - 8));
          bits_left -= 8;
      }
    }
    *dest = out;
    return 0;  
}

int ubiq_support_u32_base32_encode(uint32_t ** const dest, const uint32_t * const src) {
    // Input will be considered a string.  Convert to UTF8, then encode and then convert to UTF32
  int res = -EINVAL;
  uint8_t * utf8 = NULL;
  uint8_t * utf8_base32 = NULL;

  static const char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  // Input will be considered a string of UTF32, not a binary array
  // Convert to UTF8, then encode and then convert to UTF32

  if (src && dest) {
    res = convert_utf32_to_utf8(src, &utf8);
    UBIQ_DEBUG(debug_flag, printf("res(%d) src(%S) utf8(%s)\n", res, src, utf8));
    if (!res) {
      // Returns the length of the utf8 string, but it already has the null terminator
      res = ubiq_support_base32_encode((char **)&utf8_base32, utf8, strlen(utf8));
      if (res > 0) {
        res = 0;
      }
      UBIQ_DEBUG(debug_flag, printf("res(%d) utf8_base32(%s)\n", res, utf8_base32));
      if (!res) {
        res = convert_utf8_to_utf32(utf8_base32, dest);
        UBIQ_DEBUG(debug_flag, printf("res(%d) dest(%S)\n", res, *dest));
      }
    }
  }

  if (utf8_base32) {
    free(utf8_base32);
  }
  if (utf8) {
    free(utf8);
  }
  return res;
}

int ubiq_support_u32_base32_decode(uint32_t ** const dest, const uint32_t * const src) {
  // Input will be considered a string.  Convert to UTF8, then decode and then convert to UTF32
  int res = -EINVAL;
  uint8_t * utf8 = NULL;
  uint8_t * utf8_base32 = NULL;
  size_t out_len = 0;

  if (src && dest) {
    res = convert_utf32_to_utf8(src, &utf8_base32);
    if (!res) {
      res = ubiq_support_base32_decode((void **)&utf8, &out_len, (char *)utf8_base32, strlen(utf8_base32));
      if (!res) {
        res = convert_utf8_to_utf32(utf8, dest);
      }
    }
  }

  if (utf8_base32) {
    free(utf8_base32);
  }
  if (utf8) {
    free(utf8);
  }

  return res;

}
