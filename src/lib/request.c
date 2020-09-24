#include "ubiq/platform/internal/assert.h"
#include "ubiq/platform/internal/request.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <sys/param.h>

const char * ubiq_platform_user_agent = NULL;

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
    const ssize_t len, const char delim)
{
    for (unsigned int i = 0;
         (len < 0 || i < len) && str[i] != delim;
         str[i] = tolower(str[i]), i++);
}

/*
 * returns a string representation of the http request method.
 * the returned string is uppercased as it would be in the request.
 */
const char *
http_request_method_string(
    const http_request_method_t method)
{
    const char * res;

    switch (method) {
    case HTTP_RM_CONNECT:   res = "CONNECT";    break;
    case HTTP_RM_DELETE:    res = "DELETE";     break;
    case HTTP_RM_GET:       res = "GET";        break;
    case HTTP_RM_HEAD:      res = "HEAD";       break;
    case HTTP_RM_PATCH:     res = "PATCH";      break;
    case HTTP_RM_POST:      res = "POST";       break;
    case HTTP_RM_PUT:       res = "PUT";        break;
    case HTTP_RM_OPTIONS:   res = "OPTIONS";    break;
    case HTTP_RM_TRACE:     res = "TRACE";      break;
    default:                res = "UNKNOWN";    break;
    }

    return res;
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

    CURL * ch;

    /* content to be sent in an http request */
    struct {
        const void * buf;
        size_t len, off;
    } req;

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

        /*
         * initialize the curl handle for http requests
         */

        (*h)->ch = curl_easy_init();
        if ((*h)->ch) {
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
    curl_easy_reset(h->ch);

    h->req.buf = NULL;
    h->req.len = h->req.off = 0;

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
    curl_easy_cleanup(h->ch);
    free(h);
}

http_response_code_t
ubiq_platform_rest_response_code(
    const struct ubiq_platform_rest_handle * const h)
{
    long st;
    curl_easy_getinfo(h->ch, CURLINFO_RESPONSE_CODE, &st);
    return st;
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
    char * type;
    curl_easy_getinfo(h->ch, CURLINFO_CONTENT_TYPE, &type);
    return type;
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
    char * const val, ssize_t * len)
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
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digsiz;
        EVP_MD_CTX * digctx;

        digctx = EVP_MD_CTX_create();
        EVP_DigestInit(digctx, EVP_sha512());
        if (length != 0) {
            EVP_DigestUpdate(digctx, content, length);
        }
        EVP_DigestFinal(digctx, digest, &digsiz);
        EVP_MD_CTX_destroy(digctx);

        *len = snprintf(val, *len, "%s", "SHA-512=");
        EVP_EncodeBlock(val + *len, digest, digsiz);
        *len = strlen(val);

        err = 0;
    } else if (strcmp(key, "Host") == 0) {
        *len = snprintf(val, *len,
                        (url->port ? "%s:%s" : "%s"),
                        url->hostname, url->port);

        err = 0;
    }

    return err;
}

/*
 * this function is a callback from the curl http request.
 * it supplies the payload/body to be uploaded as part of
 * the request.
 */
static
size_t
ubiq_platform_rest_upload(
    char * const buffer,
    const size_t size, const size_t nmemb,
    void * const priv)
{
    struct ubiq_platform_rest_handle * const h = priv;
    const size_t copy =
        MIN(size * nmemb, h->req.len - h->req.off);

    memcpy(buffer, (char *)h->req.buf + h->req.off, copy);
    h->req.off += copy;

    return copy;
}

/*
 * this function is a callback from the curl http request.
 * it copies data received from the server in the http response
 * to a buffer that it (re)allocates as data is received.
 */
static
size_t
ubiq_platform_rest_download(
    char * const buffer,
    const size_t size, const size_t nmemb,
    void * const priv)
{
    struct ubiq_platform_rest_handle * const h = priv;
    size_t copy;

    copy = size * nmemb;
    if (copy > 0) {
        const size_t len = h->rsp.len + copy;
        void * const p = realloc(h->rsp.buf, len);

        if (p) {
            memcpy((char *)p + h->rsp.len, buffer, copy);
            h->rsp.buf = p;
            h->rsp.len = len;
        } else {
            copy = 0;
        }
    }

    return copy;
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
        if (curl_easy_setopt(h->ch, CURLOPT_URL, urlstr) != CURLE_OK) {
            res = INT_MIN;
        }
    }

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

        HMAC_CTX * hctx;
        unsigned char hdig[EVP_MAX_MD_SIZE];
        unsigned int hlen;

        struct curl_slist * tlist, * slist;

        /*
         * the initial portion of the Signature header. the 'headers'
         * and 'signature' fields will be added to it later.
         */
        sighdrlen = snprintf(
            sighdr, sizeof(sighdr), "%s: %s=\"%s\", %s=\"%s\"",
            "Signature", "keyId", h->papi, "algorithm", "hmac-sha512");
        hdrslen = snprintf(hdrs, sizeof(hdrs), "headers=\"");

        /*
         * disable the expect header. otherwise curl will wait
         * for a 100 Continue response from the server (for up to
         * 1 second) before uploading any content.
         */
        slist = curl_slist_append(NULL, "Expect:");

        /*
         * the following code, generates http headers necessary for
         * signing, signing them as it goes and adding the necessary
         * ones to a list of headers to be included in the request.
         *
         * headers are created and signed in the order specified by
         * the `key` array above. "Content-Length" and "Content-Type"
         * are ignored by the "header_content" function if length is 0
         */

        hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, h->sapi, strlen(h->sapi), EVP_sha512(), NULL);

        for (unsigned int i = 0;
             i < sizeof(key) / sizeof(*key) && res == 0;
             i++) {
            char val[440];
            ssize_t len = sizeof(val);

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
                             key[i][strlen(key[i]) - 1] == ')')) {
                    /*
                     * all other headers not enclosed in parentheses
                     * are added to the list of headers to include
                     * in the http request
                     */
                    tlist = curl_slist_append(slist, hdr);

                    if (tlist) {
                        slist = tlist;
                    } else {
                        res = -ENOMEM;
                    }
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
                HMAC_Update(hctx, hdr, n);
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

        HMAC_Final(hctx, hdig, &hlen);
        HMAC_CTX_free(hctx);

        sighdrlen += snprintf(
            sighdr + sighdrlen, sizeof(sighdr) - sighdrlen,
            ", signature=\"");
        EVP_EncodeBlock(sighdr + sighdrlen, hdig, hlen);
        sighdrlen = strlen(sighdr);
        sighdrlen += snprintf(
            sighdr + sighdrlen, sizeof(sighdr) - sighdrlen,
            "\"");

        /*
         * add the Signature header to the list of headers
         * to send in the http request
         */

        tlist = curl_slist_append(slist, sighdr);
        if (tlist) {
            slist = tlist;
        } else {
            res = -ENOMEM;
        }

        if (res == 0) {
            CURLcode rc;

            curl_easy_setopt(
                h->ch, CURLOPT_USERAGENT, ubiq_platform_user_agent);

            /* add headers to the request */
            rc = curl_easy_setopt(h->ch, CURLOPT_HTTPHEADER, slist);
            if (rc == CURLE_OK) {
                if (length != 0) {
                    /*
                     * if content is supplied, then set up the
                     * request to read the content for upload
                     */
                    h->req.buf = content;
                    h->req.len = length;
                    h->req.off = 0;

                    curl_easy_setopt(
                        h->ch, CURLOPT_UPLOAD, 1L);
                    curl_easy_setopt(
                        h->ch, CURLOPT_READDATA, h);
                    curl_easy_setopt(
                        h->ch, CURLOPT_READFUNCTION,
                        &ubiq_platform_rest_upload);
                    curl_easy_setopt(
                        h->ch, CURLOPT_INFILESIZE, length);
                }

                /* set the request method: GET, POST, PUT, etc. */
                curl_easy_setopt(
                    h->ch, CURLOPT_CUSTOMREQUEST,
                    http_request_method_string(method));

                /* add callbacks for receiving the response payload */
                curl_easy_setopt(
                    h->ch, CURLOPT_WRITEDATA, h);
                curl_easy_setopt(
                    h->ch, CURLOPT_WRITEFUNCTION, &ubiq_platform_rest_download);

                /* send it! */
                rc = curl_easy_perform(h->ch);
            }

            res = (rc == CURLE_OK) ? 0 : INT_MIN;
        }

        curl_slist_free_all(slist);
        ubiq_url_reset(&url);
    }

    return res;
}

