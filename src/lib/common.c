#include <ubiq/platform/internal/common.h>
#include <ubiq/platform/internal/support.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "cJSON/cJSON.h"

int
ubiq_platform_common_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    char ** const session, char ** const fingerprint,
    void ** const keybuf, size_t * const keylen)
{
    const cJSON * j;
    const void * rsp;
    const char * prvpem;
    size_t len;
    int res;

    prvpem = NULL;
    res = 0;

    if (res == 0) {
        /*
         * decrypt the private key using the srsa as a password
         */
        j = cJSON_GetObjectItemCaseSensitive(
            json, "encrypted_private_key");
        if (cJSON_IsString(j) && j->valuestring != NULL) {
            prvpem = j->valuestring;
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
            void * buf;
            int len;

            len = ubiq_support_base64_decode(
                &buf, j->valuestring, strlen(j->valuestring));

            res = ubiq_support_asymmetric_decrypt(
                prvpem, srsa, buf, len, keybuf, keylen);

            free(buf);
        } else {
            res = -EBADMSG;
        }
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
