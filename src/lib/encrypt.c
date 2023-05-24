#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/billing.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cJSON/cJSON.h"


struct ubiq_platform_encryption
{
    /* http[s]://host/api/v0 */
    // Order of fields is important since single alloc is performed.
    const char * restapi;
    char * papi;
    struct ubiq_platform_rest_handle * rest;
    struct ubiq_billing_ctx * billing_ctx;

    // char * session;
    int fragment;

    struct {
        struct {
            void * buf;
            size_t len;
        } raw, enc;

        // char * fingerprint;

        struct {
            unsigned int max, cur;
        } uses;
    } key;

    const struct ubiq_platform_algorithm * algo;
    struct ubiq_support_cipher_context * ctx;
    const struct ubiq_platform_configuration * cfg;
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

    ubiq_billing_ctx_destroy(e->billing_ctx);

    if (e->key.raw.len) {
      memset(e->key.raw.buf, 0, e->key.raw.len);
    }
    if (e->key.enc.len) {
      memset(e->key.enc.buf, 0, e->key.enc.len);
    }


    ubiq_platform_rest_handle_destroy(e->rest);

    // free(e->key.fingerprint);
    free(e->key.enc.buf);
    free(e->key.raw.buf);

    // free(e->session);

    if (e->ctx) {
        ubiq_support_cipher_destroy(e->ctx);
    }

    free(e);
}

static
int
ubiq_platform_encryption_new(
    const char * const host,
    const char * const papi, const char * const sapi,
    const struct ubiq_platform_configuration * const cfg,
    struct ubiq_platform_encryption ** const enc)
{
    static const char * const api_path = "api/v0";

    struct ubiq_platform_encryption * e;
    size_t len;
    int res;

    res = -ENOMEM;
    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);

    if (((int)len) <= 0) { // error of some sort
      res = len;
    } else {
      len++;

      e = calloc(1, sizeof(*e) + len + strlen(papi) + 1);
      if (e) {
        ubiq_platform_snprintf_api_url((char *)(e + 1), len, host, api_path);
        e->restapi = (char *)(e + 1);
        e->papi = (void *)e + sizeof(*e) + len;
        strcpy(e->papi, papi);

        res = ubiq_platform_rest_handle_create(papi, sapi, &e->rest);

        if (!res) {
          res = ubiq_billing_ctx_create(&e->billing_ctx, host, e->rest, cfg);
        }
      }
    }

    if (res != 0) {
        free(e);
        e = NULL;
    }

    *enc = e;
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
        // &e->session, &e->key.fingerprint,
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
        /*
         * save the maximum number of uses of the key
         */
        j = cJSON_GetObjectItemCaseSensitive(json, "max_uses");
        if (cJSON_IsNumber(j)) {
            e->key.uses.max = j->valueint;
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
  return ret;

}


int ubiq_platform_encryption_create_with_config(
    const struct ubiq_platform_credentials * const creds,
    const struct ubiq_platform_configuration * const cfg,
    const unsigned int uses,
    struct ubiq_platform_encryption ** const enc)
{
    struct ubiq_platform_encryption * e;
    int res;

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    // Creates e->rest
    res = ubiq_platform_encryption_new(host, papi, sapi, cfg, &e);
    if (res == 0) {
        e->cfg = cfg;
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
        str = cJSON_Print(json);
        cJSON_Delete(json);

        res = ubiq_platform_rest_request(
            e->rest,
            HTTP_RM_POST, url, "application/json", str, strlen(str));

        free(str);
        free(url);

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
                    res = ubiq_platform_encryption_parse_new_key(e, srsa, json);
                    cJSON_Delete(json);
                }
            } else {
                res = ubiq_platform_http_error(rc);
            }
        }
    }

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_encryption_destroy(e);
    }

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
    } else if (enc->key.uses.cur >= enc->key.uses.max) {
        /* key is all used up */
        res = -ENOSPC;
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
                    enc->papi,
                    "", "",
                    ENCRYPTION,
                    1, 0 ); // key number not used for unstructured

                enc->key.uses.cur++;
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
