#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
#include "ubiq/platform/internal/cache.h"
#include <ubiq/fpe/ff1.h>
#include <ubiq/fpe/internal/ffx.h>

#include "ubiq/fpe/internal/bn.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <unistr.h>
#include <string.h>
#include <stdlib.h>
#include <uniwidth.h>

#include "cJSON/cJSON.h"

/**************************************************************************************
 *
 * Defines
 *
**************************************************************************************/

// Need to capture value of res, not test value
// since it may be a function and don't want it to get executed
// more than once
#define MSG_SIZE 128
#define CAPTURE_ERROR(e,res,msg) ({ \
  int result = res; \
  if (result) { \
    e->error.err_num = result; \
    if (e->error.err_msg) { \
      free (e->error.err_msg); \
    } \
    if (!msg) { \
      e->error.err_msg = malloc(MSG_SIZE); \
      strerror_r(abs(e->error.err_num), e->error.err_msg, MSG_SIZE); \
    } else { \
      e->error.err_msg = strdup(msg); \
    } \
  } \
  result; \
})

/**************************************************************************************
 *
 * Constants
 *
**************************************************************************************/

static const time_t CACHE_DURATION = 3 * 24 * 60 * 60;

typedef enum {MULTIBYTE=0, SIMPLE_CHAR=1}  ffs_character_types ;
typedef enum {PARSE_INPUT_TO_OUTPUT = 0, PARSE_OUTPUT_TO_INPUT = 1} conversion_direction_type;

/**************************************************************************************
 *
 * Structures
 *
**************************************************************************************/

/* Used if the FFS supports UTF8 characters */
struct u32_fpe_ffs_parsed
{
  uint32_t * u32_trimmed_buf;
  uint32_t * u32_formatted_dest_buf;
};

struct fpe_ffs_parsed
{
  char * trimmed_buf;
  char * formatted_dest_buf;
};

struct parsed_data
{
  void * trimmed_buf;
  void * formatted_dest_buf;
  int element_size;
  ffs_character_types char_types;
};

struct ubiq_platform_fpe_enc_dec_obj
{
    /* http[s]://host/api/v0 */
    char * restapi;
    char * encoded_papi;
    char * srsa;
    struct ubiq_platform_rest_handle * rest;

    cJSON * billing_elements;
    pthread_mutex_t billing_lock;
    pthread_t process_billing_thread;
    pthread_cond_t process_billing_cond;

    struct ubiq_platform_cache * ffs_cache; // URL / ffs
    struct ubiq_platform_cache * key_cache; // ffs_name:key_number => void * (either ff1_ctx or ff3_ctx)

    struct {
            char * err_msg;
            size_t err_num;
    } error;

};

struct ffs {
  char * name;
  int min_input_length;
  int max_input_length;
  char * tweak_source;
  char * regex;
  char * input_character_set;
  char * output_character_set;
  char * passthrough_character_set;
  uint32_t * u32_input_character_set;
  uint32_t * u32_output_character_set;
  uint32_t * u32_passthrough_character_set;
  int msb_encoding_bits;
//   int efpe_flag;
  struct {
          void * buf;
          size_t len;
  } tweak;
  int tweak_min_len;
  int tweak_max_len;
  ffs_character_types character_types;
};

// struct u32_ffs {
//   char * name;
//   int min_input_length;
//   int max_input_length;
//   char * tweak_source;
//   char * regex;
//   uint32_t * input_character_set;
//   uint32_t * output_character_set;
//   uint32_t * passthrough_character_set;
//   int msb_encoding_bits;
//   int efpe_flag;
//   struct {
//           void * buf;
//           size_t len;
//   } tweak;
//   int tweak_min_len;
//   int tweak_max_len;
// };

/*
*
*
*/ 


/**************************************************************************************
 *
 * Static functions
 *
**************************************************************************************/

static void debug(const char * const csu, const char * const msg) {
  printf("DEBUG %s: %s\n", csu, msg);
}


static
int
save_rest_error(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  struct ubiq_platform_rest_handle * const rest,
  const http_response_code_t rc)
{
  char * msg = NULL;
  size_t len = 0;
  const void * rsp;

  rsp = ubiq_platform_rest_response_content(rest, &len);
  if (rsp != NULL && len > 0) {
    msg = strndup(rsp, len);
    CAPTURE_ERROR(e, -rc, msg);
    free(msg);
  }
  return -rc;
}


static int get_json_string(
  cJSON * ffs_data,
  char * field_name,
  char **  destination)
{
  *destination = NULL;
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(ffs_data, field_name);
  if (cJSON_IsString(j) && j->valuestring != NULL) {
    *destination = strdup(j->valuestring);
    if (!*destination) {
      res = -errno;
    }
  }
  return res;
}

static int get_json_int(
  cJSON * ffs_data,
  char * field_name,
  int *  destination)
{
  int res = 0;
  const cJSON * j = cJSON_GetObjectItemCaseSensitive(ffs_data, field_name);
  if (cJSON_IsNumber(j)) {
    *destination = j->valueint;
  }
  return res;
}

static
void
ffs_destroy(
    void * const f)
{
  struct ffs * const ffs = (struct ffs * const) f;
  if (ffs) {
    free (ffs->name);
    free (ffs->tweak_source);
    free (ffs->regex);
    free (ffs->input_character_set);
    free (ffs->output_character_set);
    free (ffs->passthrough_character_set);
    free (ffs->u32_input_character_set);
    free (ffs->u32_output_character_set);
    free (ffs->u32_passthrough_character_set);
    free (ffs->tweak.buf);
  }
  free(ffs);
}

static
int
ffs_create(
    cJSON * ffs_data,
    struct ffs ** const ffs)
{
  static const char * const csu = "ffs_create";
  int res = 0;

  // Going to allocate memory as a single block
  // First with the structure.  Then with the
  // length of strings.  This will allow simple copy and
  // avoid fragmented memory

  struct ffs * e = NULL;
  e = calloc(1, sizeof(*e));
  if (!e) {
    res = -ENOMEM;
  }

  if (!res) {res = get_json_string(ffs_data, "name", &e->name);}
  if (!res) {res = get_json_string(ffs_data, "tweak_source", &e->tweak_source);}
  if (!res) {res = get_json_string(ffs_data, "regex", &e->regex);}
  if (!res) {res = get_json_string(ffs_data, "input_character_set", &e->input_character_set);}
  if (!res) {res = get_json_string(ffs_data, "output_character_set", &e->output_character_set);}
  if (!res) {res = get_json_string(ffs_data, "passthrough", &e->passthrough_character_set);}

  // Test the input_character_set, output_character_set, passthrough characterset
  // to see if they are UTF8 multibyte strings or simply contain single byte characters.
  // if at least one is multibyte, move the strings to the u32 version for the associated elements

  if (!res && ((strlen(e->input_character_set) != u8_mbsnlen(e->input_character_set, strlen(e->input_character_set))) ||
      (strlen(e->output_character_set) != u8_mbsnlen(e->output_character_set, strlen(e->output_character_set))) ||
      (strlen(e->passthrough_character_set) != u8_mbsnlen(e->passthrough_character_set, strlen(e->passthrough_character_set))))) {
      debug(csu, "Multibyte UTF8 found");
        res = convert_utf8_to_utf32(e->input_character_set, &e->u32_input_character_set);
        if (!res) {res = convert_utf8_to_utf32(e->output_character_set, &e->u32_output_character_set);}
        if (!res) {res = convert_utf8_to_utf32(e->passthrough_character_set, &e->u32_passthrough_character_set);}

        free(e->input_character_set);
        free(e->output_character_set);
        free(e->passthrough_character_set);
        e->input_character_set = NULL;
        e->output_character_set = NULL;
        e->passthrough_character_set = NULL;
        e->character_types = MULTIBYTE;
  } else {
          debug(csu, "No Multibyte UTF8 found");
        e->character_types = SIMPLE_CHAR;
  }


  if (!res) {res = get_json_int(ffs_data, "min_input_length", &e->min_input_length);}
  if (!res) {res = get_json_int(ffs_data, "max_input_length", &e->max_input_length);}
  if (!res) {res = get_json_int(ffs_data, "msb_encoding_bits", &e->msb_encoding_bits);}

  if (!res) {res = get_json_int(ffs_data, "tweak_min_len", &e->tweak_min_len);}
  if (!res) {res = get_json_int(ffs_data, "tweak_max_len", &e->tweak_max_len);}

  if (!res && strcmp(e->tweak_source, "constant") == 0) {
    char * s = NULL;
    if ((res = get_json_string(ffs_data, "tweak", &s)) == 0) {
      e->tweak.len = ubiq_support_base64_decode(
          &e->tweak.buf, s, strlen(s));
    }
    free(s);
  }

  if (!res) {
    *ffs = e;
  } else {
    ffs_destroy(e);
  }

  return res;
}


static
void
parsed_destroy(
  void * const parsed
)
{
  free((void *)parsed);
}

static
int parse_data(
  const struct ffs * ffs,
  const conversion_direction_type conversion_direction, // input to output, or output to input
  const char * const source_string,
  const size_t source_len,
  struct parsed_data * const parsed
)
{
  static const char * csu = "parse_data";
  int res = 0;
  const void * src_char_set = NULL;
  uint32_t dest_zeroth_char = 0;
  // struct fpe_ffs_parsed * p;

  if (ffs->character_types == MULTIBYTE) {
 debug(csu, "(uint32_t *)parsed->trimmed_buf");

  } else {
    char dest_zeroth_char;
    char * src_char_set = NULL;
    if (conversion_direction == PARSE_INPUT_TO_OUTPUT) {// input to output
      src_char_set = ffs->input_character_set;
      dest_zeroth_char = ffs->output_character_set[0];
    } else if (conversion_direction == PARSE_OUTPUT_TO_INPUT) {
      src_char_set = ffs->output_character_set;
      dest_zeroth_char = ffs->input_character_set[0];
    } else {
      res = -EINVAL;
    }

    if (!res) {
      

      // for (int i = 0; i < source_len; i++) {
      //   ((char *)parsed->trimmed_buf)[i] = src_char_set[0];
      //   ((char *)parsed->formatted_dest_buf)[i] = dest_zeroth_char;
      // }
      // memset(parsed->trimmed_buf, src_char_set[0], source_len);
      // memset(parsed->formatted_dest_buf, dest_zeroth_char, source_len);

      res = parsing_decompose_string(
        source_string, src_char_set, ffs->passthrough_character_set,
        dest_zeroth_char,
        parsed->trimmed_buf, parsed->formatted_dest_buf);

    }
    debug(csu, (char *)parsed->trimmed_buf);
    debug(csu, (char *)parsed->formatted_dest_buf);
    // Standard acsii
  }


  // Using uint32, so not bytes, but unicode characters.  Initialize the
  // values, leaving the null terminator
  // if (!res) {
  //   for (int i = 0; i < source_len; i++) {
  //     parsed->trimmed_buf[i] = src_char_set[0];
  //     parsed->formatted_dest_buf[i] = dest_zeroth_char;
  //   }
  //   // memset(parsed->trimmed_buf, src_char_set[0], source_len);
  //   // memset(parsed->formatted_dest_buf, dest_zeroth_char, source_len);

  //   res = ubiq_platform_efpe_parsing_parse_input(
  //     source_string, src_char_set, ffs->passthrough_character_set,
  //     parsed->trimmed_buf, parsed->formatted_dest_buf);

  // }

  return res;
}

#ifdef NODEF
static
int fpe_u32_ffs_parsed_create(
  struct u32_fpe_ffs_parsed ** parsed,
  const size_t buf_len
)
{
  struct u32_fpe_ffs_parsed *p;

  int res = -ENOMEM;

  // Single alloc and just point to locations in the object
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1) * sizeof(uint32_t));
  if (p) {

    p->u32_trimmed_buf = (uint32_t *) (p + 1);
    p->u32_formatted_dest_buf = (uint32_t *)  p->u32_trimmed_buf + buf_len + 1;

    if (p->u32_trimmed_buf && p->u32_formatted_dest_buf) {
      res = 0;
    } else {
      fpe_ffs_parsed_destroy(p);
      p = NULL;
    }
  }
  *parsed = p;
  return res;
}

static
int fpe_ffs_parsed_create(
  struct fpe_ffs_parsed ** parsed,
  const size_t buf_len
)
{
  struct fpe_ffs_parsed *p;

  int res = -ENOMEM;

  // Single alloc and just point to locations in the object
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1) * sizeof(char));
  if (p) {

    p->trimmed_buf = (char *) (p + 1);
    p->formatted_dest_buf = (char *)  p->trimmed_buf + buf_len + 1;

    if (p->trimmed_buf && p->formatted_dest_buf) {
      res = 0;
    } else {
      fpe_ffs_parsed_destroy(p);
      p = NULL;
    }
  }
  *parsed = p;
  return res;
}
#endif

static
int parsed_create(
  struct parsed_data ** const parsed,
  const ffs_character_types char_types,
  const size_t buf_len
)
{
  struct parsed_data *p;

  int res = -ENOMEM;
  size_t element_size = sizeof(char);

  if (char_types == MULTIBYTE) {
    element_size = sizeof(uint32_t);
  }

  // Single alloc and just point to locations in the object.  The element size will
  // automatically help align to right boundaries
  p = calloc(1, sizeof(*p) + 2 * (buf_len + 1) * element_size);
  if (p) {

    p->trimmed_buf = (p + 1);
    p->formatted_dest_buf = p->trimmed_buf + (buf_len + 1) * element_size;
    p->element_size = element_size;
    p->char_types = char_types;
    if (p->trimmed_buf && p->formatted_dest_buf) {
      res = 0;
    } else {
      parsed_destroy(p);
      p = NULL;
    }
  }
  *parsed = p;
  return res;
}


static
void *
process_billing(void * data) {
    // TODO
}

static
int
ubiq_platform_process_billing(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  cJSON ** json_array)
{
  static const char * const fmt = "%s/fpe/billing/%s";
  time_t now;

  cJSON * json;
  char * url;
  size_t len;
  int res = 0;


  len = snprintf(NULL, 0, fmt, e->restapi, e->encoded_papi);
  url = malloc(len + 1);
  snprintf(url, len + 1, fmt, e->restapi, e->encoded_papi);

  char guid_hex[37]; // 8 - 4 - 4 - 4 - 12
  uint16_t guid[8];

  char * str = cJSON_Print(*json_array);


  unsigned int array_size = cJSON_GetArraySize(*json_array);

  if (array_size > 0) {

    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_POST, url, "application/json", str, strlen(str));

    // If Success, simply proceed
    if (res == 0) {
      const http_response_code_t rc =
          ubiq_platform_rest_response_code(e->rest);

      if (rc == HTTP_RC_BAD_REQUEST) {
          const void * rsp;
          size_t len;
          cJSON * json;

          rsp = ubiq_platform_rest_response_content(e->rest, &len);
          res = (json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

          if (res == 0) {
            cJSON * last_valid = cJSON_GetObjectItemCaseSensitive(json, "last_valid");
            if (cJSON_IsObject(last_valid)) {
              cJSON * id = cJSON_GetObjectItemCaseSensitive(last_valid, "id");
              if (cJSON_IsString(id) && id->valuestring != NULL) {

                int match = 0;
                while (array_size > 0 && !match){
                  cJSON * item = cJSON_DetachItemFromArray(*json_array, 0);
                  if (cJSON_IsObject(item)) {
                    cJSON * element_id = cJSON_GetObjectItemCaseSensitive(item, "id");
                    if (cJSON_IsString(element_id) && element_id->valuestring != NULL) {
                      match = (strcmp(id->valuestring, element_id->valuestring) == 0);
                    }
                  }
                  cJSON_Delete(item);
                  array_size--;
                }
              }
            }
          }
          cJSON_Delete(json);
      } else if (rc == HTTP_RC_CREATED) {
          cJSON_Delete(*json_array);
          *json_array = cJSON_CreateArray();
          res = 0;
      } else {
        res = ubiq_platform_http_error(rc);
      }
    }

//    const char * content = ubiq_platform_rest_response_content(e->rest, &len);
  }
  free(str);
  free(url);
  return res;

}

static
int
ubiq_platform_fpe_encryption(
    const char * const host,
    const char * const papi, const char * const sapi,
    const char * const srsa,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc)
{
    static const char * const csu = "ubiq_platform_fpe_encryption";
    static const char * const api_path = "api/v0";

    struct ubiq_platform_fpe_enc_dec_obj * e;
    size_t len;
    int res;
    res = -ENOMEM;
    e = calloc(1, sizeof(*e));
    if (e) {
      // Just a way to determine if it has been created correctly later
      e->process_billing_thread = pthread_self();

      len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);
      if (((int)len) <= 0) { // error of some sort
        res = len;
      } else {
        len++; // null terminator
        e->restapi = calloc(len, 1);
        ubiq_platform_snprintf_api_url(e->restapi, len, host, api_path);
        res = ubiq_platform_rest_handle_create(papi, sapi, &e->rest);
      }
      if (!res) {
        res = ubiq_platform_rest_uri_escape(e->rest, papi, &e->encoded_papi);
      }
      if (!res) {
        e->srsa = strdup(srsa);
        if (e->srsa == NULL) {
          res = -ENOMEM;
        }
      }
      if (!res) {
        res = ubiq_platform_cache_create(&e->ffs_cache);
      }
      if (!res) {
        res = ubiq_platform_cache_create(&e->key_cache);
      }
      if (!res) {
        e->billing_elements = cJSON_CreateArray();
      }
      if (!res) {
        if ((res = pthread_mutex_init(&e->billing_lock, NULL)) != 0) {
          res = -errno;
        }
      }
      if (!res) {
        if ((res = pthread_cond_init(&e->process_billing_cond, NULL)) != 0) {
          res = -res;
        }
      }
      if (!res) {
        if ((res = pthread_create(&e->process_billing_thread, NULL, &process_billing, e)) != 0) {
          res = -res;
        }
      }
    }

    if (res) {
      ubiq_platform_fpe_enc_dec_destroy(e);
      e = NULL;
    }

    *enc = e;
    return res;
}

static
int
ffs_get_def(
  struct ubiq_platform_fpe_enc_dec_obj * const e,
  const char * const ffs_name,
  const struct ffs ** ffs_definition)
{
  const char * const csu = "ffs_get_def";
  const char * const fmt = "%s/ffs?ffs_name=%s&papi=%s";

  cJSON * json;
  char * url;
  size_t len;
  int res = 0;
  const void * rsp;
  const struct ffs * ffs = NULL;

  // The ubiq_platform_fpe_enc_dec_obj was created using specific credentials,
  // so can simply use the ffs_name to look for a key, not the full URL.  This will save
  // having to encode the URL each time

  ffs = (const struct ffs *)ubiq_platform_cache_find_element(e->ffs_cache, ffs_name);
  if (ffs != NULL) {
    debug(csu, "Found in Cache");
    *ffs_definition = ffs;
  } else {
    debug(csu, "Fetching from server");
    char * encoded_name = NULL;
    res = ubiq_platform_rest_uri_escape(e->rest, ffs_name, &encoded_name);

    len = snprintf(NULL, 0, fmt, e->restapi, encoded_name, e->encoded_papi);
    url = malloc(len + 1);
    snprintf(url, len + 1, fmt, e->restapi, encoded_name, e->encoded_papi);

    free(encoded_name);

    res = ubiq_platform_rest_request(
        e->rest,
        HTTP_RM_GET, url, "application/json", NULL, 0);


    if (!CAPTURE_ERROR(e, res, "Unable to process request to get FFS"))
    {
      // Get HTTP response code.  If not OK, return error value
      http_response_code_t rc = ubiq_platform_rest_response_code(e->rest);

      if (rc != HTTP_RC_OK) {
        // Capture Error
        res = save_rest_error(e, e->rest, rc);
      } else {
        // Get the response payload, parse, and continue.
        cJSON * ffs_json;
        rsp = ubiq_platform_rest_response_content(e->rest, &len);
        res = (ffs_json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

        if (res == 0 && ffs_json) {
          struct ffs * f = NULL;
          res = ffs_create(ffs_json,  &f);
          if (!res) {
            ubiq_platform_cache_add_element(e->ffs_cache, ffs_name, CACHE_DURATION, f, &ffs_destroy);
            *ffs_definition = f;
          }
        }
        cJSON_Delete(ffs_json);
      }
    }
    free(url);
  }

  return res;
} // ffs_get_def


/**************************************************************************************
 *
 * Public functions
 *
**************************************************************************************/

int
ubiq_platform_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen)
{
  static const char * csu = "ubiq_platform_fpe_encrypt_data";
  int res = 0;
  const struct ffs * ffs_definition = NULL;
  struct parsed_data * parsed = NULL;

  // Get FFS (cache or otherwise)
  res = ffs_get_def(enc, ffs_name, &ffs_definition);

  // Create an object to hold the parsed data, 
  if (!res) { res = CAPTURE_ERROR(enc, parsed_create(&parsed, ffs_definition->character_types, ptlen),  NULL); }

  if (!res) { res = CAPTURE_ERROR(enc, parse_data(ffs_definition, PARSE_INPUT_TO_OUTPUT, ptbuf, ptlen, parsed ), "Invalid input string characters");}
    // Get Encryption object (cache or otherwise - returns ff1_ctx object (ffs_name and current key_number)

    // For encrypt - get FFS and get encryption object could be same call
    // For decrypt - need to get FFS first so know how to decode key num
    //               Then get Decryption Object (ff1_ctx) (ffs_name and key number)


    // ff1_encrypt

    // change radix

    // encrypt object includes key encoding data

    // Merge encoded key with cipher text

    // if (!res) {
    //     *ffs = ffs_definition;
    //     *parsed_data = parsed;
    // }


    parsed_destroy(parsed);


    return res;
}

// Piecewise functions
int
ubiq_platform_fpe_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc) {
      
    struct ubiq_platform_fpe_enc_dec_obj * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    // This function will actually create and initialize the object
    res = ubiq_platform_fpe_encryption(host, papi, sapi, srsa, &e);

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_fpe_enc_dec_destroy(e);
    }

    return res;

}



void
ubiq_platform_fpe_enc_dec_destroy(
    struct ubiq_platform_fpe_enc_dec_obj * const e)
{
  const char * csu = "ubiq_platform_fpe_enc_dec_destroy";

  if (e) {
    int i= 0;
    pthread_mutex_lock(&e->billing_lock);
    cJSON * json_array = e->billing_elements;
    e->billing_elements = NULL;
    pthread_mutex_unlock(&e->billing_lock);
    pthread_cond_signal(&e->process_billing_cond);
    // If the billing thread is this, thread than we know there
    // was a problem during setup so no need to join.
    if (!pthread_equal(e->process_billing_thread,pthread_self())) {
      pthread_join(e->process_billing_thread, NULL);
    }
    ubiq_platform_process_billing(e, &json_array);
    pthread_cond_destroy(&e->process_billing_cond);
    pthread_mutex_destroy(&e->billing_lock);
    cJSON_Delete(json_array);
    ubiq_platform_rest_handle_destroy(e->rest);
    free(e->restapi);
    free(e->encoded_papi);
    free(e->srsa);
    ubiq_platform_cache_destroy(e->ffs_cache);
    ubiq_platform_cache_destroy(e->key_cache);
    free(e->error.err_msg);
  }
  free(e);
}