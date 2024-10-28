#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/parsing.h"
#include "ubiq/platform/internal/billing.h"
#include "ubiq/platform/internal/cache.h"
#include <ubiq/platform/internal/ff1.h>
#include <ubiq/platform/internal/ffx.h>

#include "ubiq/platform/internal/bn.h"

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
#include <wchar.h>
#include <locale.h>

#include "cJSON/cJSON.h"

#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif


struct ubiq_platform_fpe_enc_dec_obj
{
  struct ubiq_platform_structured_enc_dec_obj * obj;
};


int
ubiq_platform_fpe_enc_dec_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc) {

  struct ubiq_platform_configuration * cfg = NULL;

  ubiq_platform_configuration_load_configuration(NULL, &cfg);
  int ret = ubiq_platform_fpe_enc_dec_create_with_config(creds, cfg, enc);

  ubiq_platform_configuration_destroy(cfg);
  return ret;

}


int
ubiq_platform_fpe_enc_dec_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_fpe_enc_dec_obj ** const enc) {
      
    struct ubiq_platform_fpe_enc_dec_obj * e2;
    struct ubiq_platform_structured_enc_dec_obj * e;

    int res;
    
    res = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, &e);

    if (res == 0) {
      e2 = calloc(1, sizeof(*e2));
      if (e2) {
        e2->obj = e;
        *enc = e2;
      } else {
        ubiq_platform_structured_enc_dec_destroy(e);
      }
    }

    return res;

}


void
ubiq_platform_fpe_enc_dec_destroy(
    struct ubiq_platform_fpe_enc_dec_obj * const e)
{
    if (e) {
      ubiq_platform_structured_enc_dec_destroy(e->obj);
    }
    free(e);
}

int
ubiq_platform_fpe_get_last_error(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  int * const err_num,
  char ** const err_msg
)
{
    if (enc == NULL) {
        return -EINVAL;
    } else {
      return ubiq_platform_structured_get_last_error(
        enc->obj, err_num, err_msg);
    }
}

int
ubiq_platform_fpe_encrypt_data_prealloc(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char * const ctbuf, size_t * const ctlen)
{
    if (enc == NULL) {
      return -EINVAL;
    } else {
      return ubiq_platform_structured_encrypt_data_prealloc(
        enc->obj, ffs_name, 
        tweak, tweaklen,
        ptbuf, ptlen,
        ctbuf, ctlen);
    }
}

int
ubiq_platform_fpe_decrypt_data_prealloc(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char * const ptbuf, size_t * const ptlen
)
{
    if (enc == NULL) {
      return -EINVAL;
    } else {
      return ubiq_platform_structured_decrypt_data_prealloc(
        enc->obj, ffs_name, 
        tweak, tweaklen,
        ctbuf, ctlen,
        ptbuf, ptlen);
    }
}
int
ubiq_platform_fpe_encrypt_data_for_search_prealloc(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctbuflen , size_t * const count
)
{
      if (enc == NULL) {
        return -EINVAL;
      } else {
        return ubiq_platform_structured_encrypt_data_for_search_prealloc(
          enc->obj, ffs_name, 
          tweak, tweaklen,
          ptbuf, ptlen,
          ctbuf, ctbuflen, count);
      }
}

int
ubiq_platform_fpe_encrypt_data_for_search(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char *** const ctbuf, size_t * const count
)
{
      if (enc == NULL) {
        return -EINVAL;
      } else {
        return ubiq_platform_structured_encrypt_data_for_search(
          enc->obj, ffs_name, 
          tweak, tweaklen,
          ptbuf, ptlen,
          ctbuf, count);
      }
}

int
ubiq_platform_fpe_enc_dec_get_copy_of_usage(
    struct ubiq_platform_fpe_enc_dec_obj * const obj,
    char ** const buffer, size_t * const buffer_len) {

      if (obj == NULL || buffer == NULL || buffer_len == NULL) {
        return -EINVAL;
      }
      return ubiq_platform_structured_enc_dec_get_copy_of_usage(obj->obj, buffer, buffer_len);
    }

int
ubiq_platform_fpe_enc_dec_add_user_defined_metadata(
    struct ubiq_platform_fpe_enc_dec_obj * const obj,
    const char * const jsonString)
{

    if (obj == NULL || jsonString == NULL) {
      return -EINVAL;
    }

    return ubiq_platform_structured_enc_dec_add_user_defined_metadata(obj->obj,jsonString);
}

int
ubiq_platform_fpe_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char ** const ctbuf, size_t * const ctlen)
{

  struct ubiq_platform_structured_enc_dec_obj * enc;
  int res = 0;

  // Create Structure that will handle REST calls.
  // Std voltron gets additional information, this will
  // simply allocate structure.  Mapping creds to individual strings
  enc = NULL;
  res = ubiq_platform_structured_enc_dec_create(creds,  &enc);

  if (!res) {
     res = ubiq_platform_structured_encrypt_data(enc, ffs_name,
       tweak, tweaklen, ptbuf, ptlen, ctbuf, ctlen);
  }
  ubiq_platform_structured_enc_dec_destroy(enc);

  return res;
}

int
ubiq_platform_fpe_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const void * const ctbuf, const size_t ctlen,
    char ** const ptbuf, size_t * const ptlen)
{
  static const char * const csu = "ubiq_platform_fpe_decrypt";
  int debug_flag = 0;
  struct ubiq_platform_structured_enc_dec_obj * enc;
  int res = 0;

  enc = NULL;
  res = ubiq_platform_structured_enc_dec_create(creds, &enc);

  UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "start", res));

  if (!res) {
    res  = ubiq_platform_structured_decrypt_data(enc, ffs_name, tweak, tweaklen, ctbuf, ctlen, ptbuf, ptlen);
    UBIQ_DEBUG(debug_flag, printf("%s \n \t%s res(%i)\n",csu, "after ubiq_platform_fpe_decrypt_data", res));
  }
  ubiq_platform_structured_enc_dec_destroy(enc);
  return res;
}

int
ubiq_platform_fpe_encrypt_for_search(
    const struct ubiq_platform_credentials * const creds,
    const char * const ffs_name,
    const void * const tweak, const size_t tweaklen,
    const char * const ptbuf, const size_t ptlen,
    char *** const ctbuf, size_t * const count)
{
  static const char * const csu = "ubiq_platform_fpe_encrypt_for_search";
struct ubiq_platform_structured_enc_dec_obj * enc;
    int res = 0;

  enc = NULL;
  res = ubiq_platform_structured_enc_dec_create(creds, &enc);

   if (!res) {
    res  = ubiq_platform_structured_encrypt_data_for_search(enc, ffs_name, tweak, tweaklen, ptbuf, ptlen, ctbuf, count);
  }

  ubiq_platform_structured_enc_dec_destroy(enc);
  return res;

}

int
ubiq_platform_fpe_encrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ptbuf, const size_t ptlen,
  char ** const ctbuf, size_t * const ctlen)
{
    if (enc == NULL) {
      return -EINVAL;
    } else {
      return ubiq_platform_structured_encrypt_data(
        enc->obj, ffs_name, 
        tweak, tweaklen,
        ptbuf, ptlen,
        ctbuf, ctlen);
    }
}


int
ubiq_platform_fpe_decrypt_data(
  struct ubiq_platform_fpe_enc_dec_obj * const enc,
  const char * const ffs_name,
  const uint8_t * const tweak, const size_t tweaklen,
  const char * const ctbuf, const size_t ctlen,
  char ** const ptbuf, size_t * const ptlen)
{
    if (enc == NULL) {
      return -EINVAL;
    } else {
      return ubiq_platform_structured_decrypt_data(
        enc->obj, ffs_name, 
        tweak, tweaklen,
        ctbuf, ctlen,
        ptbuf, ptlen);
    }
}