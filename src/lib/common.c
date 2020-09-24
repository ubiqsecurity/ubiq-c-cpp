#include "ubiq/platform/internal/common.h"

#include <sys/param.h>
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
ubiq_platform_parse_new_key(
    const struct ubiq_platform_rest_handle * const rest,
    const char * const srsa,
    char ** const session, char ** const fingerprint,
    void ** const keybuf, size_t * const keylen)
{
    const void * rsp;
    size_t len;
    cJSON * json;
    int res;

    rsp = ubiq_platform_rest_response_content(rest, &len);
    res = (json = cJSON_ParseWithLength(rsp, len)) ? 0 : INT_MIN;

    if (res == 0) {
        EVP_PKEY * prvkey;
        const cJSON * j;

        prvkey = NULL;

        /*
         * the code below is very similar to the encryption
         * response handling. see the comments there, and
         * consider trying to make the code more common.
         */

        if (res == 0) {
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
            j = cJSON_GetObjectItemCaseSensitive(
                json, "encryption_session");
            if (cJSON_IsString(j) && j->valuestring != NULL) {
                *session = strdup(j->valuestring);
            } else {
                res = -EBADMSG;
            }
        }

        if (res == 0) {
            j = cJSON_GetObjectItemCaseSensitive(
                json, "key_fingerprint");
            if (cJSON_IsString(j) && j->valuestring != NULL) {
                *fingerprint = strdup(j->valuestring);
            } else {
                res = -EBADMSG;
            }
        }

        if (res == 0) {
            j = cJSON_GetObjectItemCaseSensitive(
                json, "wrapped_data_key");
            if (cJSON_IsString(j) && j->valuestring != NULL) {
                EVP_ENCODE_CTX * ectx;
                EVP_PKEY_CTX * pctx;
                void * buf;
                size_t len;
                int outl;

                len = strlen(j->valuestring);
                buf = malloc(len);

                ectx = EVP_ENCODE_CTX_new();
                EVP_DecodeInit(ectx);
                EVP_DecodeUpdate(ectx, buf, &outl, j->valuestring, len);
                len = outl;
                EVP_DecodeFinal(ectx, (char *)buf + len, &outl);
                len += outl;
                EVP_ENCODE_CTX_free(ectx);

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

        cJSON_Delete(json);
    }

    return res;
}
