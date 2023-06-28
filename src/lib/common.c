#include <ubiq/platform/internal/common.h>
#include <ubiq/platform/internal/support.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "cJSON/cJSON.h"

void
ubiq_url_init(
    struct ubiq_url * const url)
{
    url->scheme = NULL;
    url->hostname = NULL;
    url->path = NULL;
    url->port = NULL;
    url->query = NULL;
}

void
ubiq_url_reset(
    struct ubiq_url * const url)
{
    free(url->scheme);
    free(url->hostname);
    free(url->path);
    free(url->query);
    ubiq_url_init(url);
}

/*
 * parse a url
 *
 * this function is not capable of parsing a fully featured url.
 * in particular the use of inline usernames and passwords is not
 * supported, nor are fragments.
 *
 * see the format documented in struct ubiq_url.
 */
int
ubiq_url_parse(
    struct ubiq_url * const url, const char * const str)
{
    char scheme[8];
    char hostname[256];
    char path[2048];
    char query[1024];

    int res, err;

    ubiq_url_init(url);

    err = INT_MIN;
    res = sscanf(str, "%7[^:]://%255[^/]%2047[^?]?%1023s",
                 scheme, hostname, path, query);
    /*
     * sscanf returns the number of elements parsed/set/returned by
     * the call. if less than 3, then the call has failed to parse
     * a meaningful amount of data from the URL. free any allocated
     * data and reinitialize the url object.
     *
     * if 3 is returned, no query is present, which is ok.
     * if 4, then all parts are present.
     */
    if (res >= 3) {
        err = -ENOMEM;

        url->scheme = strdup(scheme);
        url->hostname = strdup(hostname);
        url->path = strdup(path);
        if (res > 3) {
            url->query = strdup(query);
        }

        if (url->scheme && url->hostname && url->path &&
            (res < 4 || url->query) ) {
            char * chr;
            /*
             * if the port is present in the hostname, overwrite the ':'
             * with a NUL and point the port pointer at the next character.
             * therefore the port member is never freed. it's either NULL,
             * or it points into the hostname string.
             */
            if ((chr = strchr(url->hostname, ':'))) {
                url->port = chr + 1;
                *chr = '\0';
            }

            err = 0;
        } else {
            free(url->query);
            free(url->path);
            free(url->hostname);
            free(url->scheme);

            ubiq_url_init(url);
        }
    }

    return err;
}

int
ubiq_platform_common_parse_key(
  const cJSON * const json,
  const char * const srsa,
  void ** const keybuf, size_t * const keylen)
{
  const char * prvpem = NULL;
  int res = 0;
  const cJSON * j;

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
       * unwrap the data key
       */
      j = cJSON_GetObjectItemCaseSensitive(
          json, "wrapped_data_key");
      if (cJSON_IsString(j) && j->valuestring != NULL) {

        res = ubiq_platform_common_decrypt_wrapped_key(
          prvpem, srsa, 
          j->valuestring,
          keybuf, keylen);

      } else {
          res = -EBADMSG;
      }
  }
  return res;
}


int
ubiq_platform_common_decrypt_wrapped_key(
    const char * const prvpem,
    const char * const srsa,
    const char * const base64_wrapped_data_key,
    void ** const keybuf, size_t * const keylen)
{
  int res = 0;
  void * buf;
  int len;

  len = ubiq_support_base64_decode(
      &buf, base64_wrapped_data_key, strlen(base64_wrapped_data_key));

  res = ubiq_support_asymmetric_decrypt(
      prvpem, srsa, buf, len, keybuf, keylen);

  free(buf);

  return res;
}

int
ubiq_platform_common_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    // char ** const session, char ** const fingerprint,
    void ** const keybuf, size_t * const keylen)
{
    const cJSON * j;
    int res;

    res = 0;
    if (res == 0) {
        /*
         * save the session id
         */
        // j = cJSON_GetObjectItemCaseSensitive(
        //     json, "encryption_session");
        // if (cJSON_IsString(j) && j->valuestring != NULL) {
        //     *session = strdup(j->valuestring);
        // } else {
        //     res = -EBADMSG;
        // }
    }

    if (res == 0) {
        /*
         * save the key fingerprint
         */
        // j = cJSON_GetObjectItemCaseSensitive(
        //     json, "key_fingerprint");
        // if (cJSON_IsString(j) && j->valuestring != NULL) {
        //     *fingerprint = strdup(j->valuestring);
        // } else {
        //     res = -EBADMSG;
        // }
    }

    if (res == 0) {
      res = ubiq_platform_common_parse_key(json, srsa, keybuf, keylen);
    }

    return res;
}

int
ubiq_platform_common_fpe_parse_new_key(
    const cJSON * const json,
    const char * const srsa,
    void ** const keybuf, size_t * const keylen)
{
    int res = 0;

    res = ubiq_platform_common_parse_key(json, srsa, keybuf, keylen);
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
