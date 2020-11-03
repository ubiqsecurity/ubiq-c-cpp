#include <ubiq/platform/internal/common.h>
#include <ubiq/platform/internal/support.h>

#include <ubiq/platform/compat/sys/param.h>
#include <string.h>
#include <errno.h>

#include "cJSON/cJSON.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

/*
 * openssl requires a callback to retrieve the password
 * for decrypting a private key. this function receives
 * the password in the void pointer and passes it through.
 */
static
int
get_password_callback(char * const buf, const int size,
                      const int rw,
                      void * const udata)
{
    const char * const pwstr = udata;
    const int pwlen = strlen(pwstr);
    const int len = MIN(size, pwlen);
    memcpy(buf, pwstr, len);
    return len;
}

int
ubiq_platform_common_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    char ** const session, char ** const fingerprint,
    void ** const keybuf, size_t * const keylen)
{
    const cJSON * j;
    const void * rsp;
    size_t len;
    int res;
    EVP_PKEY * prvkey;

    prvkey = NULL;
    res = 0;

    if (res == 0) {
        /*
         * decrypt the private key using the srsa as a password
         */
        j = cJSON_GetObjectItemCaseSensitive(
            json, "encrypted_private_key");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            BIO * const bp = BIO_new_mem_buf(j->valuestring, -1);
            prvkey = PEM_read_bio_PrivateKey(
                bp, NULL, get_password_callback, (void *)srsa);
            BIO_free(bp);
            if (!prvkey) {
                res = -EACCES;
            }
        } else {
            res = -EBADMSG;
        }
    }

    if (res == 0) {
        /*
         * save the session id
         */
        j = cJSON_GetObjectItemCaseSensitive(
            json, "encryption_session");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            *session = strdup(j->valuestring);
        } else {
            res = -EBADMSG;
        }
    }

    if (res == 0) {
        /*
         * save the key fingerprint
         */
        j = cJSON_GetObjectItemCaseSensitive(
            json, "key_fingerprint");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            *fingerprint = strdup(j->valuestring);
        } else {
            res = -EBADMSG;
        }
    }

    if (res == 0) {
        /*
         * unwrap the data key
         */
        j = cJSON_GetObjectItemCaseSensitive(
            json, "wrapped_data_key");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            EVP_PKEY_CTX * pctx;
            void * buf;
            int len;

            len = ubiq_platform_base64_decode(
                &buf, j->valuestring, strlen(j->valuestring));

            /*
             * unwrap the data key using the private rsa key that
             * was decrypted earlier
             */
            pctx = EVP_PKEY_CTX_new(prvkey, NULL);
            EVP_PKEY_decrypt_init(pctx);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
            EVP_PKEY_decrypt(pctx, NULL, keylen, NULL, 0);
            *keybuf = malloc(*keylen);
            if (EVP_PKEY_decrypt(
                    pctx, *keybuf, keylen, buf, len) <= 0) {
                res = -EACCES;
            }
            EVP_PKEY_CTX_free(pctx);

            free(buf);
        } else {
            res = -EBADMSG;
        }
    }

    if (prvkey) {
        EVP_PKEY_free(prvkey);
    }

    return res;
}

int
ubiq_platform_http_error(
    const http_response_code_t rc)
{
    if (rc == HTTP_RC_UNAUTHORIZED) {
        /* something's wrong with the credentials */
        return -EACCES;
    } else if (rc >= 400 && rc < 500) {
        /* something's wrong with the library */
        return -EBADMSG;
    } else if (rc >= 500 && rc < 600) {
        /* something's wrong with the server */
        return -ECONNABORTED;
    }

    /* something is very wrong somewhere */
    return -EPROTO;
}
