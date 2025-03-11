#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/billing.h"
#include "ubiq/platform/internal/cache.h"
#include "ubiq/platform/internal/sso.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "cJSON/cJSON.h"
// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;


typedef struct {
     void * buf;
     size_t len;
} ubiq_key_t;

// wrapped_data_key is in base64
// decrypted_data_key is byte array
// decrypted_data_key will have length 0 if key_caching is stored encrypted and it needs to be decrypted
// each time.
typedef struct cached_key {
  ubiq_key_t wrapped_data_key, decrypted_data_key;
} cached_key_t;

struct ubiq_platform_decryption
{
    /* http[s]://host/api/v0 */
    const char * restapi;
    // const char * papi;
    struct ubiq_platform_rest_handle * rest;
    struct ubiq_billing_ctx * billing_ctx;

    struct ubiq_platform_cache * key_cache; // key will be the base64 encoded encrypted data key (came from KMS)
    // Payload will be a cached_key_t.  The result MAY need to be decrypted using the encrypted_private_key and the srsa value.

    // const char * srsa;

    struct {
      void * buf;
      size_t len;
    } encrypted_private_key;

    const struct ubiq_platform_algorithm * algo;
    struct ubiq_support_cipher_context * ctx;
    void * buf;
    size_t len;

    int key_cache_encrypt;
    int key_cache_ttl_seconds;
    int key_cache_unstructured;

    // Creds are needed for IDP since cert can be updated and needs to be renewed
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * cfg;

};

int
ubiq_platform_decryption_create(
    const struct ubiq_platform_credentials * const creds,
    struct ubiq_platform_decryption ** const dec)
{
  struct ubiq_platform_configuration * cfg = NULL;

  ubiq_platform_configuration_load_configuration(NULL, &cfg);

  int ret = ubiq_platform_decryption_create_with_config(creds, cfg, dec);
  ubiq_platform_configuration_destroy(cfg);
  return ret;
}

int
ubiq_platform_decryption_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_decryption ** const dec)
{
    static const char * csu = "ubiq_platform_decryption_create_with_config";

    static const char * const api_path = "api/v0";

    const char * const host = ubiq_platform_credentials_get_host(creds);
    // const char * const papi = ubiq_platform_credentials_get_papi(creds);
    // const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    // const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    struct ubiq_platform_decryption * d;
    size_t len;
    int res;

    // If library hasn't been initialized, fail fast.
    if (!ubiq_platform_initialized()) {
      return -EINVAL;
    }

    res = -ENOMEM;

    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);

    if (((int)len) <= 0) { // error of some sort
      res = len;
    } else {
      len++;
      d = calloc(1, sizeof(*d) + len + 1);
      if (d) {
        res = 0;
        if (!res) {
          res = ubiq_platform_configuration_clone(cfg, &(d->cfg));
          UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_configuration_clone %d\n", csu, res));
        }
        if (!res) {
          res = ubiq_platform_credentials_clone(creds, &(d->creds));
          UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_credentials_clone %d\n", csu, res));
        }

        if (!res && ubiq_platform_credentials_is_idp(d->creds)) {
            // Don't login again if the access token is already set.
            if (ubiq_platform_credentials_get_access_token(d->creds) == NULL) {
              if ((res = ubiq_platform_sso_login(d->creds, d->cfg)) != 0) {
                
              }
            }
          }

        d->restapi = (char *)(d + 1);
        ubiq_platform_snprintf_api_url((char *)d->restapi, len, host, api_path);

        /*
         * decryption has to hang onto the srsa since the encrypted
         * data key can't be retrieved (and therefore decrypted) until
         * after the cipher text has started "flowing".
         */
        // d->srsa = d->restapi + len;
        // strcpy((char *)d->srsa, srsa);

        // d->papi = d->restapi + len + strlen(srsa) + 1;
        // strcpy((char *)d->papi, papi);

        res = ubiq_platform_rest_handle_create(
          ubiq_platform_credentials_get_papi(d->creds),
          ubiq_platform_credentials_get_sapi(d->creds), &d->rest);
        // res = ubiq_platform_rest_handle_create(papi, sapi, &d->billing_rest);

        if (!res) {
          res = ubiq_billing_ctx_create(&d->billing_ctx, host, 
          ubiq_platform_credentials_get_papi(d->creds),
          ubiq_platform_credentials_get_sapi(d->creds), d->cfg);
        }
        if (!res) {
          d->key_cache_ttl_seconds = ubiq_platform_configuration_get_key_caching_ttl_seconds(d->cfg);
          d->key_cache_unstructured = ubiq_platform_configuration_get_key_caching_unstructured_keys(d->cfg);
          d->key_cache_encrypt = ubiq_platform_configuration_get_key_caching_encrypt(d->cfg);
          UBIQ_DEBUG(debug_flag, printf("key_cache_unstructured: %d\n", d->key_cache_unstructured));
          UBIQ_DEBUG(debug_flag, printf("key_cache_ttl_seconds: %d\n", d->key_cache_ttl_seconds));
          UBIQ_DEBUG(debug_flag, printf("key_cache_encrypt: %d\n", d->key_cache_encrypt));
        }

        if (!res) {
          int ttl = 0;

          // If unstructured key caching, then use the supplied value.
          // If the ttl is 0, means key information will not be cached.
          if (d->key_cache_unstructured) {
            ttl = d->key_cache_ttl_seconds;
          }
          UBIQ_DEBUG(debug_flag, printf("ttl: %d\n", ttl));
          // htable size 500 - means slots for 500 possible key collisions - probably way more than the 
          // number of keys being used here
          res = ubiq_platform_cache_create(500, ttl, &d->key_cache);
        }

        if (!res) {
            char * tmp = NULL;
            UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

            UBIQ_DEBUG(debug_flag, printf("%s: %s %d \n", csu, "ubiq_platform_credentials_is_idp", ubiq_platform_credentials_is_idp(d->creds)));

            if (ubiq_platform_credentials_is_idp(d->creds)) {
            UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_credentials_get_encrypted_private_key: %s\n", csu, ubiq_platform_credentials_get_encrypted_private_key(d->creds)));

              tmp = strdup(ubiq_platform_credentials_get_encrypted_private_key(d->creds));
              UBIQ_DEBUG(debug_flag, printf("%s: dup: %s\n", csu, tmp));
              UBIQ_DEBUG(debug_flag, printf("%s: len: %d\n", csu, strlen(tmp)));
            }
            // Deep copy of credentials

            // res = ubiq_platform_credentials_clone(creds, &(d->creds));
            // res = ubiq_platform_configuration_clone(cfg, &(d->cfg));

            UBIQ_DEBUG(debug_flag, printf("%s: %s \n", csu, "after d->creds"));
            if (ubiq_platform_credentials_is_idp(d->creds)) {
              UBIQ_DEBUG(debug_flag, printf("%s: is_idp\n", csu));

              d->encrypted_private_key.buf = tmp;
              d->encrypted_private_key.len = strlen(tmp);
            }
            UBIQ_DEBUG(debug_flag, printf("%s: after is_idp\n", csu));
            UBIQ_DEBUG(debug_flag, printf("%s: %s \n", csu, "after ubiq_platform_credentials_is_idp"));
        }

      }
    }

    if (res != 0) {
        free(d);
        d = NULL;
    }

    *dec = d;
    return res;
}

static
void
ubiq_platform_decryption_reset(
    struct ubiq_platform_decryption * const d)
{
    d->algo = NULL;
    if (d->ctx) {
        UBIQ_DEBUG(debug_flag, printf("d->ctx != NULL\n"));
        ubiq_support_cipher_destroy(d->ctx);
    }
}

static int
key_cache_element_create(cached_key_t ** const e) {
  int res = -ENOMEM;
  cached_key_t * cached_key = NULL;
  cached_key = calloc(1, sizeof(*cached_key));
  if (cached_key) {
    *e = cached_key;
    res = 0;
  }
  return res;
}

static void
key_cache_element_destroy(void * const e) {
  cached_key_t * cached_key = (cached_key_t *) e;
  free(cached_key->wrapped_data_key.buf);
  free(cached_key->decrypted_data_key.buf);
  free(e);
}

/*
 * send the encrypted data key to the server to
 * be decrypted
 */
static
int
ubiq_platform_decryption_new_key(
    struct ubiq_platform_decryption * const d,
    const void * const enckey, const size_t keylen,
    cached_key_t ** key)
{
    const char * const fmt = "%s/decryption/key";

    char * base64_encrypted_data_key;
    int res;

    // Encode the encrypted key to base64 for the cache key lookup
    ubiq_support_base64_encode(&base64_encrypted_data_key, enckey, keylen);

    // Does the key already exist ?
    cached_key_t * cached_key = (cached_key_t *)ubiq_platform_cache_find_element(d->key_cache, base64_encrypted_data_key);

    // Key doesn't exist
    if (NULL != cached_key) {
      UBIQ_DEBUG(debug_flag, printf("Key found\n"));
      *key = cached_key;
    } else {
      UBIQ_DEBUG(debug_flag, printf("Key NOT found\n"));
      cJSON * json;
      res = key_cache_element_create(key);
      UBIQ_DEBUG(debug_flag, printf("Key(%p) res(%d)\n", *key, res));
      if (0 == res) {
          char * url, * str;
          size_t len = 0;

          len = snprintf(NULL, 0, fmt, d->restapi);
          url = malloc(len + 1);
          snprintf(url, len + 1, fmt, d->restapi);

          json = cJSON_CreateObject();
          cJSON_AddItemToObject(
              json, "encrypted_data_key", cJSON_CreateStringReference(base64_encrypted_data_key));
          if (ubiq_platform_credentials_is_idp(d->creds)) {
            ubiq_platform_sso_renewIdpCert(d->creds, d->cfg);
            cJSON_AddStringToObject(json, "payload_cert", ubiq_platform_credentials_get_cert_b64(d->creds));
          }
          str = cJSON_Print(json);
          cJSON_Delete(json);

          UBIQ_DEBUG(debug_flag, printf("url(%s) \n", url));
          UBIQ_DEBUG(debug_flag, printf("str(%s) \n", str));
          
          res = ubiq_platform_rest_request(
              d->rest,
              HTTP_RM_POST, url, "application/json", str, strlen(str));

          UBIQ_DEBUG(debug_flag, printf("res(%d)\n" ,res));

          free(str);
          free(url);
          if (res == 0) {
              const http_response_code_t rc =
                  ubiq_platform_rest_response_code(d->rest);

              UBIQ_DEBUG(debug_flag, printf("rc %d\n" ,rc));

              if (rc == HTTP_RC_OK) {
                  size_t len = 0;
                  const void * rsp =
                      ubiq_platform_rest_response_content(d->rest, &len);

                  UBIQ_DEBUG(debug_flag, printf("rsp %.*s\n" ,len, rsp));

                  res = 0;
                  json = cJSON_ParseWithLength(rsp, len);
                  if (json) {
                    if (ubiq_platform_credentials_is_idp(d->creds)) {
                      // Make sure there isn't an existing encrypted private key.  Need to use this one.
                      cJSON_DeleteItemFromObject(json, "encrypted_private_key");
                      cJSON_AddStringToObject(json, "encrypted_private_key", ubiq_platform_credentials_get_encrypted_private_key(d->creds));
                    }


                    const cJSON * j = NULL;
                    // Extract encrypted_private_key and stored in dec object.  
                    // Since private key is tied to API Key, it will always be the same, regardless of 
                    // actual data encryption key.
                    if (d->encrypted_private_key.len == 0) {
                      j = cJSON_GetObjectItemCaseSensitive(
                          json, "encrypted_private_key");
                      if (cJSON_IsString(j) && j->valuestring != NULL) {
                          d->encrypted_private_key.buf = strdup(j->valuestring);
                          d->encrypted_private_key.len = strlen(d->encrypted_private_key.buf);
                          UBIQ_DEBUG(debug_flag, printf("d->encrypted_private_key.buf %.*s\n" ,d->encrypted_private_key.len, d->encrypted_private_key.buf));
                      } else {
                          res = -EBADMSG;
                      }
                    }

                    // Extract wrapped data key and stored in cache_key object
                    j = cJSON_GetObjectItemCaseSensitive(
                          json, "wrapped_data_key");
                    if (cJSON_IsString(j) && j->valuestring != NULL) {
                      (*key)->wrapped_data_key.buf = strdup(j->valuestring);
                      (*key)->wrapped_data_key.len = strlen((*key)->wrapped_data_key.buf);

                          UBIQ_DEBUG(debug_flag, printf("(*key)->wrapped_data_key.buf %.*s\n" ,(*key)->wrapped_data_key.len, (*key)->wrapped_data_key.buf));

                      // If caching unencrypted data, decrypt wrapped data key and store that in cache_key
                      if (!d->key_cache_encrypt) {
                        UBIQ_DEBUG(debug_flag, printf("Key Decrypted before cache\n"));
                        res = ubiq_platform_common_decrypt_wrapped_key(
                          d->encrypted_private_key.buf,
                          ubiq_platform_credentials_get_srsa(d->creds),
                          (*key)->wrapped_data_key.buf,
                          &((*key)->decrypted_data_key.buf),
                          &((*key)->decrypted_data_key.len));
                      }
                      UBIQ_DEBUG(debug_flag, printf("BEFORE ubiq_platform_cache_add_element res(%d)\n", res));
                      if (!res) {
                        res = ubiq_platform_cache_add_element(d->key_cache, base64_encrypted_data_key, 
                          *key, &key_cache_element_destroy);
                        UBIQ_DEBUG(debug_flag, printf("Key ADDED res(%d)\n",res));
                      }
                    } else {
                      res = -EBADMSG;
                    }
                  }
                  cJSON_Delete(json);
              } else {
                  res = ubiq_platform_http_error(rc);
              }
            }
          }
    }
    free(base64_encrypted_data_key);

    return res;
}

void
ubiq_platform_decryption_destroy(
    struct ubiq_platform_decryption * const d)
{
  if (d) {

      ubiq_platform_decryption_reset(d);
      ubiq_billing_ctx_destroy(d->billing_ctx);
      ubiq_platform_rest_handle_destroy(d->rest);
      ubiq_platform_cache_destroy(d->key_cache);

      ubiq_platform_credentials_destroy(d->creds);
      ubiq_platform_configuration_destroy(d->cfg);

      free(d->encrypted_private_key.buf);

      free(d->buf);
    }

    free(d);
}

int
ubiq_platform_decryption_begin(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen)
{
    int res;

    if (dec->ctx) {
        res = -EINPROGRESS;
    } else {
        *ptbuf = NULL;
        *ptlen = 0;

        res = 0;
    }

    return res;
}

int
ubiq_platform_decryption_update(
    struct ubiq_platform_decryption * const dec,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    static const char * csu = "ubiq_platform_decryption_update";

    void * buf;
    size_t off;
    int res;

    off = 0;
    res = 0;

    /*
     * this function works by appending incoming
     * cipher text to an internal buffer. when enough
     * data has been received to get the initialization
     * vector and the encrypted data key, the encrypted
     * data key is sent to the server for decryption
     * and then decryption can begin in earnest.
     */

    buf = realloc(dec->buf, dec->len + ctlen);
    if (!buf) {
        return -ENOMEM;
    }

    dec->buf = buf;
    memcpy((char *)dec->buf + dec->len, ctbuf, ctlen);
    dec->len += ctlen;

    if (!dec->ctx) {
        const union ubiq_platform_header * const h = dec->buf;

        /* has the header "preamble" been received? */
        if (dec->len >= sizeof(h->pre)) {
            if (h->pre.version != 0) {
                return -EBADMSG;
            }

            /* has the fixed-size portion of the header been received? */
            if (dec->len >= sizeof(h->v0)) {
                const struct ubiq_platform_algorithm * algo;
                unsigned int ivlen, keylen;
                int err;

                if ((h->v0.flags & ~UBIQ_HEADER_V0_FLAG_AAD) != 0) {
                    return -EBADMSG;
                }

                err = ubiq_platform_algorithm_get_byid(
                    h->v0.algorithm, &algo);
                if (err) {
                    return err;
                }

                ivlen = h->v0.ivlen;
                keylen = ntohs(h->v0.keylen);

                off += sizeof(h->v0);

                /* has the entire header been received? */
                if (dec->len >= sizeof(h->v0) + ivlen + keylen) {
                    cached_key_t * cached_key = NULL;
                    const void * iv = NULL, * key = NULL;

                    iv = (const char *)h + off;
                    off += ivlen;
                    key = (const char *)h + off;
                    off += keylen;

                    // Decrypt the key or retrieve from the cache.
                    // key and keylen are raw bytes
                    res = ubiq_platform_decryption_new_key(
                            dec, key, keylen, &cached_key);

                    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_decryption_new_key res(%d)\n", res));

                    // ubiq_platform_decryption_reset(dec);

                    ubiq_key_t decryption_key;
                    int mem_manage_decryption_key = 0;

                    if (!res && cached_key != NULL) {
                      UBIQ_DEBUG(debug_flag, printf("cached_key != NULL\n"));

                      if (cached_key->decrypted_data_key.buf != NULL && cached_key->decrypted_data_key.len) {
                        UBIQ_DEBUG(debug_flag, printf("cached_key->decrypted_data_key.buf != NULL\n"));
                        decryption_key.buf = cached_key->decrypted_data_key.buf;
                        decryption_key.len = cached_key->decrypted_data_key.len;

                        UBIQ_DEBUG(debug_flag, printf("decryption_key.buf (%p)\n", decryption_key.buf));
                        UBIQ_DEBUG(debug_flag, printf("cached_key->decrypted_data_key.buf (%p)\n", cached_key->decrypted_data_key.buf));
                        UBIQ_DEBUG(debug_flag, printf("decryption_key.len (%d)\n", decryption_key.len));
                        UBIQ_DEBUG(debug_flag, printf("cached_key->decrypted_data_key.len (%d)\n", cached_key->decrypted_data_key.len));

                      } else {
                        UBIQ_DEBUG(debug_flag, printf("cached_key->decrypted_data_key.buf == NULL\n"));
                          mem_manage_decryption_key = 1;
                          res = ubiq_platform_common_decrypt_wrapped_key(
                          dec->encrypted_private_key.buf,
                          ubiq_platform_credentials_get_srsa(dec->creds),
                          cached_key->wrapped_data_key.buf,
                          &decryption_key.buf,
                          &decryption_key.len);

                      }
                    }
                    /*
                     * if the key is present now, create the
                     * decryption context
                     */
                    UBIQ_DEBUG(debug_flag, printf("%s res(%d)\n", csu, res));

                    if (res == 0 && decryption_key.len) {
                        const void * aadbuf;
                        size_t aadlen;

                        dec->algo = algo;

                        aadbuf = NULL;
                        aadlen = 0;
                        if ((h->v0.flags & UBIQ_HEADER_V0_FLAG_AAD) != 0) {
                            aadbuf = h;
                            aadlen = sizeof(*h) + ivlen + keylen;
                        }

                        res = ubiq_support_decryption_init(
                            algo,
                            decryption_key.buf, decryption_key.len,
                            iv, ivlen,
                            aadbuf, aadlen,
                            &dec->ctx);

                        UBIQ_DEBUG(debug_flag, printf("%s after %s res(%d)\n", csu, "ubiq_support_decryption_init", res));

                        if (mem_manage_decryption_key) {
                                UBIQ_DEBUG(debug_flag, printf("Freeing decryption_key.buf\n"));
                          free(decryption_key.buf);
                        }


                        if (res == 0) {
                            res = ubiq_billing_add_billing_event(
                                dec->billing_ctx,
                                ubiq_platform_credentials_get_papi(dec->creds),
                                "", "",
                                DECRYPTION,
                                1, 0 ); // key number not used for unstructured

                        }
                        UBIQ_DEBUG(debug_flag, printf("%s after %s res(%d)\n", csu, "ubiq_billing_add_billing_event", res));
                    }
                }
            }
        }
    }

    if (res == 0 && dec->ctx) {
        /*
         * decrypt whatever data is available, but always leave
         * enough data in the buffer to form a complete tag. the
         * tag is not part of the cipher text, but there's no
         * indication of when the tag will arrive. the code just
         * has to assume that the last bytes are the tag.
         */

        const int declen = dec->len - (off + dec->algo->len.tag);

        if (declen > 0) {
            res = ubiq_support_decryption_update(
                dec->ctx,
                (char *)dec->buf + off, declen,
                ptbuf, ptlen);
            if (res == 0) {
                memmove(dec->buf,
                        (char *)dec->buf + off + declen,
                        dec->algo->len.tag);
                dec->len = dec->algo->len.tag;
            }
        }
                        UBIQ_DEBUG(debug_flag, printf("%s after %s res(%d)\n", csu, "ubiq_support_decryption_update", res));

    }

    return res;
}

int
ubiq_platform_decryption_end(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen)
{
    int res;

    res = -ESRCH;
    if (dec->ctx) {
        const int sz = dec->len - dec->algo->len.tag;

        if (sz != 0) {
            /*
             * if sz < 0, then the update function was never even
             * provided with enough data to form a tag. based on
             * the logic in the update function, it should not be
             * possible for sz to be greater than 0
             */
            res = -ENODATA;
        } else {
            res = ubiq_support_decryption_finalize(
                dec->ctx,
                dec->buf, dec->len,
                ptbuf, ptlen);
            if (res == 0) {
                free(dec->buf);
                dec->buf = NULL;
                dec->len = 0;

                dec->ctx = NULL;
            }
        }
    }

    return res;
}

int
ubiq_platform_decrypt(
    const struct ubiq_platform_credentials * const creds,
    const void * ptbuf, const size_t ptlen,
    void ** ctbuf, size_t * ctlen)
{
    struct ubiq_platform_decryption * dec;
    int res;

    struct {
        void * buf;
        size_t len;
    } pre, upd, end;

    pre.buf = upd.buf = end.buf = NULL;

    dec = NULL;
    res = ubiq_platform_decryption_create(creds, &dec);

    if (res == 0) {
        res = ubiq_platform_decryption_begin(
            dec, &pre.buf, &pre.len);
    }

    if (res == 0) {
        res = ubiq_platform_decryption_update(
            dec, ptbuf, ptlen, &upd.buf, &upd.len);
    }

    if (res == 0) {
        res = ubiq_platform_decryption_end(
            dec, &end.buf, &end.len);
    }

    if (dec) {
        ubiq_platform_decryption_destroy(dec);
    }

    if (res == 0) {
        *ctlen = pre.len + upd.len + end.len;
        *ctbuf = malloc(*ctlen);

        memcpy(*ctbuf, pre.buf, pre.len);
        memcpy((char *)*ctbuf + pre.len, upd.buf, upd.len);
        memcpy((char *)*ctbuf + pre.len + upd.len, end.buf, end.len);
    }

    free(end.buf);
    free(upd.buf);
    free(pre.buf);

    return res;
}

int
ubiq_platform_decryption_add_user_defined_metadata(
    struct ubiq_platform_decryption * const dec,
    const char * const jsonString)
{
    if (dec == NULL || jsonString == NULL) {
      return -EINVAL;
    } 
    return ubiq_billing_add_user_defined_metadata(dec->billing_ctx, jsonString);
}


int
ubiq_platform_decryption_get_copy_of_usage(
    struct ubiq_platform_decryption * const dec,
    char ** const buffer, size_t * const buffer_len)
{
    if (dec == NULL || buffer == NULL || buffer_len == NULL) {
      return -EINVAL;
    }
    return ubiq_billing_get_copy_of_usage(dec->billing_ctx, buffer, buffer_len);
}
