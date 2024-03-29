#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/billing.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "cJSON/cJSON.h"

struct ubiq_platform_decryption
{
    /* http[s]://host/api/v0 */
    const char * restapi;
    const char * papi;
    struct ubiq_platform_rest_handle * rest;
    struct ubiq_billing_ctx * billing_ctx;

    const char * srsa;

    // char * session;

    struct {
        struct {
            void * buf;
            size_t len;
        } raw, enc;

        // char * fingerprint;
        unsigned int uses;
    } key;

    const struct ubiq_platform_algorithm * algo;
    struct ubiq_support_cipher_context * ctx;
    void * buf;
    size_t len;
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
    static const char * const api_path = "api/v0";

    const char * const host = ubiq_platform_credentials_get_host(creds);
    const char * const papi = ubiq_platform_credentials_get_papi(creds);
    const char * const sapi = ubiq_platform_credentials_get_sapi(creds);
    const char * const srsa = ubiq_platform_credentials_get_srsa(creds);

    struct ubiq_platform_decryption * d;
    size_t len;
    int res;

    res = -ENOMEM;

    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path);

    if (((int)len) <= 0) { // error of some sort
      res = len;
    } else {
      len++;
      d = calloc(1, sizeof(*d) + len + strlen(srsa) + 1 + strlen(papi) + 1);
      if (d) {
        d->restapi = (char *)(d + 1);
        ubiq_platform_snprintf_api_url((char *)d->restapi, len, host, api_path);

        /*
         * decryption has to hang onto the srsa since the encrypted
         * data key can't be retrieved (and therefore decrypted) until
         * after the cipher text has started "flowing".
         */
        d->srsa = d->restapi + len;
        strcpy((char *)d->srsa, srsa);

        d->papi = d->restapi + len + strlen(srsa) + 1;
        strcpy((char *)d->papi, papi);

        res = ubiq_platform_rest_handle_create(papi, sapi, &d->rest);

        if (!res) {
          res = ubiq_billing_ctx_create(&d->billing_ctx, host, d->rest, cfg);
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
    if (d->key.raw.len) {
        /*
         * if the key has been used at all, discarding it
         */

        memset(d->key.raw.buf, 0, d->key.raw.len);
        memset(d->key.enc.buf, 0, d->key.enc.len);

        free(d->key.raw.buf);
        free(d->key.enc.buf);

        d->key.raw.buf = d->key.enc.buf = NULL;
        d->key.raw.len = d->key.raw.len = 0;

        // free(d->key.fingerprint);
        // d->key.fingerprint = NULL;

        // free(d->session);
        // d->session = NULL;

        d->key.uses = 0;

        d->algo = NULL;
        if (d->ctx) {
            ubiq_support_cipher_destroy(d->ctx);
        }
    }
}

/*
 * send the encrypted data key to the server to
 * be decrypted
 */
static
int
ubiq_platform_decryption_new_key(
    struct ubiq_platform_decryption * const d,
    const void * const enckey, const size_t keylen)
{
    const char * const fmt = "%s/decryption/key";

    cJSON * json;
    char * url, * str, * enc;
    size_t len;
    int res;

    len = snprintf(NULL, 0, fmt, d->restapi);
    url = malloc(len + 1);
    snprintf(url, len + 1, fmt, d->restapi);

    ubiq_support_base64_encode(&enc, enckey, keylen);

    json = cJSON_CreateObject();
    cJSON_AddItemToObject(
        json, "encrypted_data_key", cJSON_CreateStringReference(enc));
    str = cJSON_Print(json);
    cJSON_Delete(json);

    res = ubiq_platform_rest_request(
        d->rest,
        HTTP_RM_POST, url, "application/json", str, strlen(str));

    free(str);
    free(enc);
    free(url);

    if (res == 0) {
        const http_response_code_t rc =
            ubiq_platform_rest_response_code(d->rest);

        if (rc == HTTP_RC_OK) {
            const void * rsp =
                ubiq_platform_rest_response_content(d->rest, &len);

            res = INT_MIN;
            json = cJSON_ParseWithLength(rsp, len);
            if (json) {
                res = ubiq_platform_common_parse_new_key(
                    json, d->srsa,
                    // &d->session, &d->key.fingerprint,
                    &d->key.raw.buf, &d->key.raw.len);

                cJSON_Delete(json);
            }
        } else {
            res = ubiq_platform_http_error(rc);
        }
    }

    return res;
}

void
ubiq_platform_decryption_destroy(
    struct ubiq_platform_decryption * const d)
{
    ubiq_platform_decryption_reset(d);
    ubiq_billing_ctx_destroy(d->billing_ctx);
    ubiq_platform_rest_handle_destroy(d->rest);

    free(d->buf);

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
                    const void * iv, * key;

                    iv = (const char *)h + off;
                    off += ivlen;
                    key = (const char *)h + off;
                    off += keylen;

                    /*
                     * if there is an existing decrypted data key,
                     * check if it is the same as the one used for
                     * the prior decryption. if not, reset the key
                     */
                    if (dec->key.enc.len != keylen ||
                        memcmp(dec->key.enc.buf, key, keylen) != 0) {
                        ubiq_platform_decryption_reset(dec);
                    }

                    /*
                     * if no key is already present, decrypt the
                     * current one. if a key is present, it's because
                     * it's the same as the one used for the previous
                     * encryption, and there's no need to get the
                     * server to decrypt it again
                     */
                    if (!dec->key.enc.len) {
                        res = ubiq_platform_decryption_new_key(
                            dec, key, keylen);
                    }

                    /*
                     * if the key is present now, create the
                     * decryption context
                     */
                    if (res == 0 && dec->key.raw.len) {
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
                            dec->key.raw.buf, dec->key.raw.len,
                            iv, ivlen,
                            aadbuf, aadlen,
                            &dec->ctx);
                        if (res == 0) {
                            res = ubiq_billing_add_billing_event(
                                dec->billing_ctx,
                                dec->papi,
                                "", "",
                                DECRYPTION,
                                1, 0 ); // key number not used for unstructured

                            dec->key.uses++;
                        }
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
