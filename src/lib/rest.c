#include "ubiq/platform/internal/assert.h"
#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/support.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

int
ubiq_platform_snprintf_api_url(
    char * const buf, const size_t len,
    const char * const host, const char * const path)
{
    static const struct {
        const char * http;
        const char * https;
    } scheme = {
        .http = "http://",
        .https = "https://",
    };

    int res;

    if (strncmp(host, scheme.http, strlen(scheme.http)) == 0 ||
        strncmp(host, scheme.https, strlen(scheme.https)) == 0) {
        /* http or https already specified */
        res = snprintf(buf, len, "%s/%s", host, path);
    } else if (!strstr(host, "://")) {
        /* no scheme specified */
        res = snprintf(buf, len, "https://%s/%s", host, path);
    } else {
        /* unsupported scheme already specified */
        res = -EINVAL;
    }

    return res;
}

/*
 * convert a string to lower case
 *
 * characters are converted to lower case, beginning with the first
 * character in the string until either `len` characters (if len >= 0) have
 * been converted or until the first occurrence of `delim` in the string.
 *
 * to convert an entire string, use: string_tolower(str, -1, '\0')
 *
 * str is a pointer to the string to be converted
 * the number of characters to convert (or -1 to convert all)
 * a delimiter character at which to stop processing
 */
static
void
string_tolower(
    char * const str,
    const int len, const char delim)
{
    for (unsigned int i = 0;
         (len < 0 || i < len) && str[i] != delim;
         str[i] = tolower(str[i]), i++);
}

struct ubiq_url
{
    /*
     * A full URL looks like:
     * scheme://[user:pass@]host[:port]/path[?query][#frag]
     *
     * This structure supports:
     * scheme://host[:port]/[path][?query]
     *
     * see ubiq_url_parse()
     */
    char * scheme;
    char * hostname;
    char * port;
    char * path;
    char * query;
};

static
void
ubiq_url_init(
    struct ubiq_url * url)
{
    url->scheme = NULL;
    url->hostname = NULL;
    url->path = NULL;
    url->port = NULL;
    url->query = NULL;
}

static
void
ubiq_url_reset(
    struct ubiq_url * url)
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
static
int
ubiq_url_parse(
    struct ubiq_url * url, const char * str)
{
    char * host, * chr;
    int res;

    ubiq_url_init(url);

    errno = 0;
    res = sscanf(str, "%m[^:]://%m[^/]%m[^?]?%ms",
                 &url->scheme, &url->hostname, &url->path, &url->query);
    /*
     * sscanf returns the number of elements parsed/set/returned by
     * the call. if less than 3, then the call has failed to parse
     * a meaningful amount of data from the URL. free any allocated
     * data and reinitialize the url object.
     *
     * if 3 is returned, no query is present, which is ok.
     * if 4, then all parts are present.
     */
    if (res < 3) {
        switch (res) {
        case 2: free(url->hostname);
        case 1: free(url->scheme);
        default: break;
        }

        ubiq_url_init(url);

        return INT_MIN;
    }

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

    return 0;
}

struct ubiq_platform_rest_handle
{
    const char * papi, * sapi;

    struct ubiq_support_http_handle * hnd;

    /*
     * content received in an http response.
     * the buffer is malloc'd and must be free'd.
     */
    struct {
        void * buf;
        size_t len;
    } rsp;
};

int
ubiq_platform_rest_handle_create(
    const char * const papi, const char * const sapi,
    struct ubiq_platform_rest_handle ** h)
{
    const int papilen = strlen(papi) + 1;
    const int sapilen = strlen(sapi) + 1;

    int res;

    /*
     * space for the public and secret api keys is
     * allocated directly at the back of the handle
     */
    res = -ENOMEM;
    *h = calloc(1, sizeof(**h) + papilen + sapilen);
    if (*h) {
        /*
         * copy the api keys into the allocated space
         */

        (*h)->papi = (char *)((*h) + 1);
        strcpy((char *)(*h)->papi, papi);

        (*h)->sapi = (*h)->papi + papilen;
        strcpy((char *)(*h)->sapi, sapi);

        (*h)->hnd = ubiq_support_http_handle_create();
        if ((*h)->hnd) {
            res = 0;
        } else {
            free(*h);
        }
    }

    return res;
}

static
void
ubiq_platform_rest_handle_reset(
    struct ubiq_platform_rest_handle * h)
{
    ubiq_support_http_handle_reset(h->hnd);

    /* handle is either NULL or malloc'd. */
    free(h->rsp.buf);
    h->rsp.buf = NULL;
    h->rsp.len = 0;
}

void
ubiq_platform_rest_handle_destroy(
    struct ubiq_platform_rest_handle * h)
{
    ubiq_platform_rest_handle_reset(h);
    ubiq_support_http_handle_destroy(h->hnd);
    free(h);
}

http_response_code_t
ubiq_platform_rest_response_code(
    const struct ubiq_platform_rest_handle * const h)
{
    return ubiq_support_http_response_code(h->hnd);
}

const void *
ubiq_platform_rest_response_content(
    const struct ubiq_platform_rest_handle * const h,
    size_t * const len)
{
    if (len) {
        *len = h->rsp.len;
    }

    return h->rsp.buf;
}

const char *
ubiq_platform_rest_response_content_type(
    const struct ubiq_platform_rest_handle * const h)
{
    return ubiq_support_http_response_content_type(h->hnd);
}

/*
 * given a `key` representing the name of an http header and information
 * about the http request, create a string containing the content for
 * that http header.
 *
 * the created header content is returned in the `val` parameter.
 * the `len` parameter initially contains the number of bytes available
 *   in `val` and contains the size of the created content on return.
 */
static
int
ubiq_platform_rest_header_content(
    const char * const key,
    const http_request_method_t method, const struct ubiq_url * const url,
    const char * const content_type,
    const void * const content, const size_t length,
    char * const val, int * len)
{
    int err;

    err = -ENOENT;

    if (strcmp(key, "(created)") == 0) {
        /*
         * the (created) header is a faux header that is part of
         * the Signature header. it's associated value is the current
         * number of seconds since the UNIX epoch
         */
        const time_t now = time(NULL);
        *len = snprintf(val, *len, "%ju", (uintmax_t)now);
        err = 0;
    } else if (strcmp(key, "(request-target)") == 0) {
        /*
         * the (request-target) header is a faux header that is used
         * by the Signature header. it contains the http request method
         * (lowercased), and the path and query parts of the url
         */
        *len = snprintf(val, *len,
                        (url->query ? "%s %s?%s" : "%s %s"),
                        http_request_method_string(method),
                        url->path, url->query);
        string_tolower(val, *len, ' ');

        err = 0;
    } else if (strcmp(key, "Content-Length") == 0) {
        if (length != 0) {
            *len = snprintf(val, *len, "%zu", length);
        } else {
            *len = -1;
        }

        err = 0;
    } else if (strcmp(key, "Content-Type") == 0) {
        if (length != 0) {
            *len = snprintf(val, *len, "%s", content_type);
        } else {
            *len = -1;
        }

        err = 0;
    } else if (strcmp(key, "Date") == 0) {
        const time_t now = time(NULL);
        struct tm tm;

        gmtime_r(&now, &tm);
        *len = strftime(val, *len, "%a, %d %b %Y %H:%M:%S GMT", &tm);
        err = 0;
    } else if (strcmp(key, "Digest") == 0) {
        /* hard-coded to sha512 */
        struct ubiq_support_digest_context * ctx;
        void * digest;
        size_t digsiz;
        char * digenc;

        ubiq_support_digest_init("sha512", &ctx);
        if (length != 0) {
            ubiq_support_digest_update(ctx, content, length);
        }
        ubiq_support_digest_finalize(ctx, &digest, &digsiz);

        ubiq_support_base64_encode(&digenc, digest, digsiz);
        free(digest);

        *len = snprintf(val, *len, "%s", "SHA-512=");
        strcpy(val + *len, digenc);
        *len = strlen(val);
        free(digenc);

        err = 0;
    } else if (strcmp(key, "Host") == 0) {
        *len = snprintf(val, *len,
                        (url->port ? "%s:%s" : "%s"),
                        url->hostname, url->port);

        err = 0;
    }

    return err;
}

int
ubiq_platform_rest_request(
    struct ubiq_platform_rest_handle * h,
    const http_request_method_t method, const char * const urlstr,
    const char * const content_type,
    const void * const content, const size_t length)
{
    struct ubiq_url url;
    int res;

    /*
     * handle must have already been initialized.
     * reset it to release resources associated with a previous request.
     */
    ubiq_platform_rest_handle_reset(h);

    ubiq_url_init(&url);

    res = ubiq_url_parse(&url, urlstr);
    if (res == 0) {
        static const char * const key[] = {
            "(created)", "(request-target)",
            "Content-Length", "Content-Type",
            "Date", "Digest", "Host",
        };

        char sighdr[512];
        int sighdrlen;

        char hdrs[256];
        int hdrslen;

        struct ubiq_support_hmac_context * hctx;
        void * hdig;
        size_t hlen;

        char * enc;

        /*
         * the initial portion of the Signature header. the 'headers'
         * and 'signature' fields will be added to it later.
         */
        sighdrlen = snprintf(
            sighdr, sizeof(sighdr), "%s: %s=\"%s\", %s=\"%s\"",
            "Signature", "keyId", h->papi, "algorithm", "hmac-sha512");
        hdrslen = snprintf(hdrs, sizeof(hdrs), "headers=\"");

        /*
         * the following code, generates http headers necessary for
         * signing, signing them as it goes and adding the necessary
         * ones to a list of headers to be included in the request.
         *
         * headers are created and signed in the order specified by
         * the `key` array above. "Content-Length" and "Content-Type"
         * are ignored by the "header_content" function if length is 0
         */

        ubiq_support_hmac_init("sha512", h->sapi, strlen(h->sapi), &hctx);

        for (unsigned int i = 0;
             i < sizeof(key) / sizeof(*key) && res == 0;
             i++) {
            char val[440];
            int len = sizeof(val);

            /* get the content for the designated header */
            res = ubiq_platform_rest_header_content(
                key[i],
                method, &url, content_type, content, length,
                val, &len);

            if (res == 0 && len >= 0) {
                char hdr[512];
                int n;

                /*
                 * create a string containing the
                 * http header -> "key: value"
                 */
                n = snprintf(hdr, sizeof(hdr),
                             "%1$s: %2$.*3$s", key[i], val, (int)len);

                if (strcmp(key[i], "(created)") == 0) {
                    /*
                     * the (created) header is not an http header; it
                     * is a parameter added to the Signature http header
                     */
                    sighdrlen += snprintf(
                        sighdr + sighdrlen, sizeof(sighdr) - sighdrlen,
                        ", %1$s=%2$.*3$s", "created", val, (int)len);
                } else if (!(key[i][0] == '(' &&
                             key[i][strlen(key[i]) - 1] == ')') &&
                           strcmp(key[i], "Content-Type") != 0) {
                    /*
                     * all other headers not enclosed in parentheses
                     * are added to the list of headers to include
                     * in the http request
                     */
                    res = ubiq_support_http_add_header(h->hnd, hdr);
                }

                /*
                 * keep track of the list of headers included in
                 * signature in the order that they are signed.
                 * this list must be sent to the server so that it
                 * can recreate the signature.
                 */
                hdrslen += snprintf(
                    hdrs + hdrslen, sizeof(hdrs) - hdrslen,
                    "%s ", key[i]);

                /*
                 * add the header to the signature
                 */
                string_tolower(hdr, n, ':');
                n += snprintf(hdr + n, sizeof(hdr) - n,  "\n");
                ubiq_support_hmac_update(hctx, hdr, n);
            }
        }

        /*
         * add the 'headers' parameter, with the list of headers
         * that were signed, to the Signature header
         */
        hdrslen--;
        hdrs[hdrslen] = '\"';
        string_tolower(hdrs, hdrslen, '\0');
        sighdrlen += snprintf(
            sighdr + sighdrlen, sizeof(sighdr) - sighdrlen,
            ", %s", hdrs);

        /*
         * finalize the signature, converting it to base64 and
         * creating the 'signature' parameter for the Signature
         * header. then add the parameter to the header
         */

        ubiq_support_hmac_finalize(hctx, &hdig, &hlen);

        ubiq_support_base64_encode(&enc, hdig, hlen);
        free(hdig);

        sighdrlen += snprintf(
            sighdr + sighdrlen, sizeof(sighdr) - sighdrlen,
            ", signature=\"");
        strcpy(sighdr + sighdrlen, enc);
        sighdrlen = strlen(sighdr);
        sighdrlen += snprintf(
            sighdr + sighdrlen, sizeof(sighdr) - sighdrlen,
            "\"");

        free(enc);

        /*
         * add the Signature header to the list of headers
         * to send in the http request
         */
        res = ubiq_support_http_add_header(h->hnd, sighdr);
        if (res == 0) {
            res = ubiq_support_http_request(
                h->hnd,
                method, urlstr,
                content_type, content, length,
                &h->rsp.buf, &h->rsp.len);
        }

        ubiq_url_reset(&url);
    }

    return res;
}
