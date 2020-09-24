#include "ubiq/platform.h"

#include "ubiq/platform/internal/header.h"
#include "ubiq/platform/internal/request.h"
#include "ubiq/platform/internal/algorithm.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/common.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "cJSON/cJSON.h"

#include <openssl/evp.h>

struct ubiq_platform_decryption
{
    /* http[s]://host/api/v0 */
    const char * restapi;
    struct ubiq_platform_rest_handle * rest;

    const char * srsa;

    char * session;

    struct {
        struct {
            void * buf;
            size_t len;
        } raw, enc;

        char * fingerprint;
        unsigned int uses;
    } key;

    const struct ubiq_platform_algorithm * algo;
    EVP_CIPHER_CTX * ctx;
    void * buf;
    size_t len;
};

int
ubiq_platform_decryption_create(
    const struct ubiq_platform_credentials * const creds,
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
    len = ubiq_platform_snprintf_api_url(NULL, 0, host, api_path) + 1;
    d = calloc(1, sizeof(*d) + len + strlen(srsa) + 1);
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

        res = ubiq_platform_rest_handle_create(papi, sapi, &d->rest);
        if (res != 0) {
            free(d);
        }
    }

    if (res == 0) {
        *dec = d;
    }

    return res;
}

static
void
ubiq_platform_decryption_reset(
    struct ubiq_platform_decryption * const d)
{
    if (d->key.raw.len) {
        /*
         * if the key has been used at all, then notify
         * the server of the number of uses before
         * discarding it
         */

        if (d->key.uses > 0) {
            const char * const fmt = "%s/decryption/key/%s/%s";

            cJSON * json;
            char * url, * str;
            int len, res;

            len = snprintf(
                NULL, 0, fmt, d->restapi, d->key.fingerprint, d->session);
            url = malloc(len + 1);
            snprintf(
                url, len + 1, fmt, d->restapi, d->key.fingerprint, d->session);

            json = cJSON_CreateObject();
            cJSON_AddItemToObject(
                json, "uses", cJSON_CreateNumber(d->key.uses));
            str = cJSON_Print(json);
            cJSON_Delete(json);

            res = ubiq_platform_rest_request(
                d->rest,
                HTTP_RM_PATCH, url, "application/json", str, strlen(str));

            free(str);
            free(url);

            if (res != 0 ||
                ubiq_platform_rest_response_code(
                    d->rest) != HTTP_RC_NO_CONTENT) {
                /* should signal this to the caller/user somehow */
            }
        }

        free(d->key.raw.buf);
        free(d->key.enc.buf);

        d->key.raw.buf = d->key.enc.buf = NULL;
        d->key.raw.len = d->key.raw.len = 0;

        free(d->key.fingerprint);
        d->key.fingerprint = NULL;

        free(d->session);
        d->session = NULL;

        d->key.uses = 0;

        d->algo = NULL;
        if (d->ctx) {
            EVP_CIPHER_CTX_free(d->ctx);
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
    int len, res;

    len = snprintf(NULL, 0, fmt, d->restapi);
    url = malloc(len + 1);
    snprintf(url, len + 1, fmt, d->restapi);

    /*
     * the key has to be base64 encode for transmission which
     * is 4/3rds larger than the unencoded data. Adding 2 bytes
     * prior to the division by 3 rounds up the allocation to
     * handle any padding that is necessary. an extra byte is
     * added for the nul terminator.
     */
    enc = malloc(4 * ((keylen + 2) / 3) + 1);
    EVP_EncodeBlock(enc, enckey, keylen);

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
        const int rc = ubiq_platform_rest_response_code(d->rest);

        if (rc == HTTP_RC_OK) {
            res = ubiq_platform_parse_new_key(
                d->rest, d->srsa,
                &d->session, &d->key.fingerprint,
                &d->key.raw.buf, &d->key.raw.len);
        } else if (rc == HTTP_RC_UNAUTHORIZED) {
            /* something's wrong with the credentials */
            res = -EACCES;
        } else if (rc >= 400 && rc < 500) {
            /* something's wrong with the library */
            res = -EBADMSG;
        } else if (rc >= 500 && rc < 600) {
            /* something's wrong with the server */
            res = -ECONNABORTED;
        } else {
            /* something is very wrong somewhere */
            res = -EPROTO;
        }
    }

    return res;
}

void
ubiq_platform_decryption_destroy(
    struct ubiq_platform_decryption * const d)
{
    ubiq_platform_decryption_reset(d);
    ubiq_platform_rest_handle_destroy(d->rest);

    free(d->buf);

    free(d);
}

int
ubiq_platform_decryption_begin(
    struct ubiq_platform_decryption * dec,
    void ** ptbuf, size_t * ptlen)
{
    int res;

    if (dec->ctx) {
        res = -EEXIST;
    } else {
        *ptbuf = NULL;
        *ptlen = 0;

        res = 0;
    }

    return res;
}

int
ubiq_platform_decryption_update(
    struct ubiq_platform_decryption * dec,
    const void * ctbuf, const size_t ctlen,
    void ** ptbuf, size_t * ptlen)
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
                return -EINVAL;
            }

            /* has the fixed-size portion of the header been received? */
            if (dec->len >= sizeof(h->v0)) {
                const struct ubiq_platform_algorithm * algo;
                unsigned int ivlen, keylen;
                int err;

                if (h->v0.sbz != 0) {
                    return -EINVAL;
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
                        dec->algo = algo;

                        dec->ctx = EVP_CIPHER_CTX_new();
                        EVP_DecryptInit(
                            dec->ctx, dec->algo->cipher, dec->key.raw.buf, iv);

                        dec->key.uses++;
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

        const ssize_t declen = dec->len - (off + dec->algo->taglen);

        if (declen > 0) {
            int outl;

            *ptbuf = malloc(declen + EVP_CIPHER_CTX_block_size(dec->ctx));
            EVP_DecryptUpdate(
                dec->ctx, *ptbuf, &outl, (char *)dec->buf + off, declen);
            *ptlen = outl;

            memmove(dec->buf,
                    (char *)dec->buf + off + declen,
                    dec->algo->taglen);
            dec->len = dec->algo->taglen;
        }
    }

    return res;
}

int
ubiq_platform_decryption_end(
    struct ubiq_platform_decryption * dec,
    void ** ptbuf, size_t * ptlen)
{
    int res;

    res = -EBADF;
    if (dec->ctx) {
        const ssize_t sz = dec->len - dec->algo->taglen;

        if (sz != 0) {
            /*
             * if sz < 0, then the update function was never even
             * provided with enough data to form a tag. based on
             * the logic in the update function, it should not be
             * possible for sz to be greater than 0
             */
            res = -EINVAL;
        } else if (dec->algo->taglen != 0) {
            /*
             * if the algorithm in use requires a tag, treat the
             * remaining data as the tag.
             */
            EVP_CIPHER_CTX_ctrl(dec->ctx, EVP_CTRL_GCM_SET_TAG,
                                dec->algo->taglen, dec->buf);
            res = 0;
        }

        if (res == 0) {
            int outl;

            /*
             * depending on the algorithm, finalization may produce
             * one more block of plain text.
             */
            *ptbuf = malloc(EVP_CIPHER_CTX_block_size(dec->ctx));
            if (EVP_DecryptFinal(dec->ctx, *ptbuf, &outl)) {
                *ptlen = outl;
            } else {
                free(*ptbuf);
                res = INT_MIN;
            }
        }

        free(dec->buf);
        dec->buf = NULL;
        dec->len = 0;

        EVP_CIPHER_CTX_free(dec->ctx);
        dec->ctx = NULL;
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
