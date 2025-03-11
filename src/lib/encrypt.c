#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/billing.h"
#include "ubiq/platform/internal/sso.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cJSON/cJSON.h"

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;

struct ubiq_platform_encryption
{
    /* http[s]://host/api/v0 */
    // Order of fields is important since single alloc is performed.
    const char * restapi;
    // char * papi;
    struct ubiq_platform_rest_handle * rest;
    struct ubiq_billing_ctx * billing_ctx;

    int fragment;

    struct {
        struct {
            void * buf;
            size_t len;
        } raw, enc;
    } key;

    const struct ubiq_platform_algorithm * algo;
    struct ubiq_support_cipher_context * ctx;
    struct ubiq_platform_configuration * cfg;

    // Creds are needed for IDP since cert can be updated and needs to be renewed
    struct ubiq_platform_credentials * creds;
};

void
ubiq_platform_encryption_destroy(
    struct ubiq_platform_encryption * const e)
{
    /*
     * if there is a session and a fingerprint
     * and the key was used less times than requested,
     * then update the server with the actual number
     * of uses
     */

    if (e) {
      ubiq_billing_ctx_destroy(e->billing_ctx);

      if (e->key.raw.len) {
        memset(e->key.raw.buf, 0, e->key.raw.len);
      }
      if (e->key.enc.len) {
        memset(e->key.enc.buf, 0, e->key.enc.len);
      }


      ubiq_platform_rest_handle_destroy(e->rest);

      free(e->key.enc.buf);
      free(e->key.raw.buf);

      if (e->ctx) {
          ubiq_support_cipher_destroy(e->ctx);
      }

      if (e->creds) {
        ubiq_platform_credentials_destroy(e->creds);
      }
      if (e->cfg) {
        ubiq_platform_configuration_destroy(e->cfg);
      }
    }
    free(e);
}

static
int
ubiq_platform_encryption_new(
    struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_encryption ** const enc)
{
    static const char * const csu = "ubiq_platform_encryption_new";

    static const char * const api_path = "api/v0";

    struct ubiq_platform_encryption * e;
    size_t len;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    // const char * const papi = ubiq_platform_credentials_get_papi(creds);
    // const char * const sapi = ubiq_platform_credentials_get_sapi(creds);

    res = -ENOMEM;
    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);

    if (((int)len) <= 0) { // error of some sort
      res = len;
    } else {
      len++;

      e = calloc(1, sizeof(*e) + len + 1);
      if (e) {
        res = 0;
        UBIQ_DEBUG(debug_flag, printf("%s: res %d\n", csu, res));
        if (!res) {
          res = ubiq_platform_configuration_clone(cfg, &(e->cfg));
          UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_configuration_clone %d\n", csu, res));
        }
        if (!res) {
          res = ubiq_platform_credentials_clone(creds, &(e->creds));
          UBIQ_DEBUG(debug_flag, printf("%s: ubiq_platform_credentials_clone %d\n", csu, res));
        }

        if (!res && ubiq_platform_credentials_is_idp(e->creds)) {
            // Don't login again if the access token is already set.
            if (ubiq_platform_credentials_get_access_token(e->creds) == NULL) {
              if ((res = ubiq_platform_sso_login(e->creds, e->cfg)) != 0) {
                
              }
            }
          }
        UBIQ_DEBUG(debug_flag, printf("%s: after login %d\n", csu, res));

        UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_credentials_get_papi(e->creds) %s\n", csu, ubiq_platform_credentials_get_papi(e->creds)));

        UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_credentials_get_sapi(e->creds) %s\n", csu, ubiq_platform_credentials_get_sapi(e->creds)));
          
        ubiq_platform_snprintf_api_url((char *)(e + 1), len, host, api_path);
        e->restapi = (char *)(e + 1);
        UBIQ_DEBUG(debug_flag, printf("%s restapi %s\n", csu, e->restapi));
        // e->papi = (void *)e + sizeof(*e) + len;
        // strcpy(e->papi, papi);
        // UBIQ_DEBUG(debug_flag, printf("%s papi %s\n", csu, e->papi));

        res = ubiq_platform_rest_handle_create(
          ubiq_platform_credentials_get_papi(e->creds),
          ubiq_platform_credentials_get_sapi(e->creds), &e->rest);


        if (!res) {
          res = ubiq_billing_ctx_create(&e->billing_ctx, host, 
          ubiq_platform_credentials_get_papi(e->creds), 
          ubiq_platform_credentials_get_sapi(e->creds), e->cfg);
        }


      }
    }

    if (res != 0) {
        free(e);
        e = NULL;
    }

    *enc = e;
    UBIQ_DEBUG(debug_flag, printf("%s: %d\n", csu, res));
    return res;
}

static
int
ubiq_platform_encryption_parse_new_key(
    struct ubiq_platform_encryption * const e,
    const char * const srsa, const cJSON * const json)
{
    const cJSON * j;
    int res;

    res = ubiq_platform_common_parse_new_key(
        json, srsa,
        &e->key.raw.buf, &e->key.raw.len);

    if (res == 0) {
        /*
         * the encrypted data key is stored at the front end of
         * any encrypted data. base64 decode it and just store
         * the result
         */
        j = cJSON_GetObjectItemCaseSensitive(json, "encrypted_data_key");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            e->key.enc.len = ubiq_support_base64_decode(
                &e->key.enc.buf, j->valuestring, strlen(j->valuestring));
        } else {
            res = -EBADMSG;
        }
    }

    if (res == 0) {
        j = cJSON_GetObjectItemCaseSensitive(json, "security_model");
        if (cJSON_IsObject(j)) {
            const cJSON * k;

            if (res == 0) {
                k = cJSON_GetObjectItemCaseSensitive(j, "algorithm");
                if (cJSON_IsString(k) && k->valuestring != NULL) {
                    res = ubiq_platform_algorithm_get_byname(
                        k->valuestring, &e->algo);
                } else {
                    res = -EBADMSG;
                }
            }

            if (res == 0) {
                /*
                 * keep track of whether fragmentation is enabled
                 */
                k = cJSON_GetObjectItemCaseSensitive(
                    j, "enable_data_fragmentation");
                if (cJSON_IsBool(k)) {
                    e->fragment = cJSON_IsTrue(k);
                } else {
                    res = -EBADMSG;
                }
            }
        } else {
            res = -EBADMSG;
        }
    }

    return res;
}

int ubiq_platform_encryption_create(
    const struct ubiq_platform_credentials * const creds,
    const unsigned int uses,
    struct ubiq_platform_encryption ** const enc) 
{
  struct ubiq_platform_configuration * cfg = NULL;

  ubiq_platform_configuration_load_configuration(NULL, &cfg);

  int ret = ubiq_platform_encryption_create_with_config(creds, cfg, uses, enc);
  ubiq_platform_configuration_destroy(cfg);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_encryption_create: %d\n", ret));

  return ret;

}


int ubiq_platform_encryption_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    const unsigned int uses,
    struct ubiq_platform_encryption ** const enc)
{
    static const char * csu = "ubiq_platform_encryption_create_with_config";

    struct ubiq_platform_encryption * e;
    int res;

    UBIQ_DEBUG(debug_flag, printf("%s: started %d\n", csu, res));

    // If library hasn't been initialized, fail fast.
    if (!ubiq_platform_initialized()) {
      return -EINVAL;
    }

    UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

    // Creates e->rest
    res = ubiq_platform_encryption_new((struct ubiq_platform_credentials * const) creds, cfg, &e);
    if (res == 0) {
        const char * const fmt = "%s/encryption/key";

        cJSON * json;
        char * url, * str;
        int len;

        /*
         * create the url for the request
         */
        len = snprintf(NULL, 0, fmt, e->restapi);
        url = malloc(len + 1);
        snprintf(url, len + 1, fmt, e->restapi);

        /*
         * request body just contains the number of
         * desired uses of the key
         */
        json = cJSON_CreateObject();
        cJSON_AddItemToObject(json, "uses", cJSON_CreateNumber(uses));
        if (ubiq_platform_credentials_is_idp(e->creds)) {
          ubiq_platform_sso_renewIdpCert(e->creds, e->cfg);
          cJSON_AddStringToObject(json, "payload_cert", ubiq_platform_credentials_get_cert_b64(e->creds));
        }

        str = cJSON_Print(json);
        cJSON_Delete(json);

        UBIQ_DEBUG(debug_flag, printf("%s str %s\n", csu, str));


        res = ubiq_platform_rest_request(
            e->rest,
            HTTP_RM_POST, url, "application/json", str, strlen(str));

        free(str);
        free(url);

        UBIQ_DEBUG(debug_flag, printf("ubiq_platform_rest_request - Unable to process http request: %s %s %d\n", url, str, res));


        /*
         * if the request was successful, parse the response
         */

        if (res == 0) {
            const http_response_code_t rc =
                ubiq_platform_rest_response_code(e->rest);

            if (rc == HTTP_RC_CREATED) {
                const void * rsp;
                size_t len;
                cJSON * json;

                rsp = ubiq_platform_rest_response_content(e->rest, &len);
                res = (json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

                if (res == 0) {
                  // If IDP, replace the encrypted private key with the one in the credentials
                  if (ubiq_platform_credentials_is_idp(e->creds)) {
                    // Make sure there isn't an existing encrypted private key.  Need to use this one.
                    cJSON_DeleteItemFromObject(json, "encrypted_private_key");
                    cJSON_AddStringToObject(json, "encrypted_private_key", ubiq_platform_credentials_get_encrypted_private_key(e->creds));
                  }

                  const char * const srsa = ubiq_platform_credentials_get_srsa(e->creds);
                  res = ubiq_platform_encryption_parse_new_key(e, srsa, json);
                  cJSON_Delete(json);
                }
            } else {
                res = ubiq_platform_http_error(rc);
                UBIQ_DEBUG(debug_flag, printf("ubiq_platform_encryption_create_with_config - Unable to process http request: %d\n", res));
            }
        }
    }

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_encryption_destroy(e);
    }

    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_encryption_create_with_config: %d\n", res));
    return res;
}

int
ubiq_platform_encryption_begin(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    if (enc->ctx) {
        /* encryption already in progress */
        res = -EINPROGRESS;
    } else {
        /*
         * good to go, build a header; create the context
         */
        const size_t ivlen = enc->algo->len.iv;
        union ubiq_platform_header * hdr;
        size_t len;

        len = sizeof(*hdr) + ivlen + enc->key.enc.len;
        hdr = malloc(len);

        /* the fixed-size portion of the header */

        hdr->pre.version = 0;
        hdr->v0.flags = enc->algo->len.tag ? UBIQ_HEADER_V0_FLAG_AAD : 0;
        hdr->v0.algorithm = enc->algo->id;
        hdr->v0.ivlen = (uint8_t)ivlen;
        hdr->v0.keylen = htons((uint16_t)enc->key.enc.len);

        /* add on the initialization vector */
        res = ubiq_support_getrandom(hdr + 1, ivlen);
        if (res == 0) {
            const void * aadbuf;
            size_t aadlen;

            /* add the encrypted key */
            memcpy((char *)(hdr + 1) + ivlen, enc->key.enc.buf,
                   enc->key.enc.len);

            *ctbuf = (void *)hdr;
            *ctlen = len;

            aadbuf = (hdr->v0.flags & UBIQ_HEADER_V0_FLAG_AAD) ? hdr : NULL;
            aadlen = aadbuf ? (sizeof(*hdr) + ivlen + enc->key.enc.len) : 0;

            res = ubiq_support_encryption_init(
                enc->algo,
                enc->key.raw.buf, enc->key.raw.len,
                hdr + 1, ivlen,
                aadbuf, aadlen,
                &enc->ctx);
            if (res == 0) {
                  res = ubiq_billing_add_billing_event(
                    enc->billing_ctx,
                    ubiq_platform_credentials_get_papi(enc->creds),
                    "", "",
                    ENCRYPTION,
                    1, 0 ); // key number not used for unstructured
            }
        } else {
            free(hdr);
        }
    }

    return res;
}

int
ubiq_platform_encryption_update(
    struct ubiq_platform_encryption * const enc,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    res = -ESRCH;
    if (enc->ctx) {
        res = ubiq_support_encryption_update(
            enc->ctx, ptbuf, ptlen, ctbuf, ctlen);
    }

    return res;
}

int
ubiq_platform_encryption_end(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    res = -ESRCH;
    if (enc->ctx) {
        void * tagbuf;
        size_t taglen;

        tagbuf = NULL;
        taglen = 0;
        res = ubiq_support_encryption_finalize(
            enc->ctx, ctbuf, ctlen, &tagbuf, &taglen);
        if (res == 0) {
            enc->ctx = NULL;
        }

        if (res == 0 && tagbuf && taglen) {
            void * buf;

            res = -ENOMEM;
            buf = realloc(*ctbuf, *ctlen + taglen);
            if (buf) {
                memcpy((char *)buf + *ctlen, tagbuf, taglen);
                *ctbuf = buf;
                *ctlen += taglen;
                res = 0;
            } else {
                free(*ctbuf);
            }

            free(tagbuf);
        }
    }

    return res;
}

int
ubiq_platform_encrypt(
    const struct ubiq_platform_credentials * const creds,
    const void * ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    struct ubiq_platform_encryption * enc;
    int res;

    struct {
        void * buf;
        size_t len;
    } pre, upd, end;

    pre.buf = upd.buf = end.buf = NULL;

    enc = NULL;
    res = ubiq_platform_encryption_create(creds, 1, &enc);

    if (res == 0) {
        res = ubiq_platform_encryption_begin(
            enc, &pre.buf, &pre.len);
    }

    if (res == 0) {
        res = ubiq_platform_encryption_update(
            enc, ptbuf, ptlen, &upd.buf, &upd.len);
    }

    if (res == 0) {
        res = ubiq_platform_encryption_end(
            enc, &end.buf, &end.len);
    }

    if (enc) {
        ubiq_platform_encryption_destroy(enc);
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
ubiq_platform_encryption_get_copy_of_usage(
    struct ubiq_platform_encryption * const enc,
    char ** const buffer, size_t * const buffer_len) 
{
    if (enc == NULL || buffer == NULL || buffer_len == NULL) {
      return -EINVAL;
    }
    return ubiq_billing_get_copy_of_usage(enc->billing_ctx, buffer, buffer_len);
}

int
ubiq_platform_encryption_add_user_defined_metadata(
    struct ubiq_platform_encryption * const enc,
    const char * const jsonString)
{
    if (enc == NULL || jsonString == NULL) {
      return -EINVAL;
    }
    return ubiq_billing_add_user_defined_metadata(enc->billing_ctx, jsonString);
}
