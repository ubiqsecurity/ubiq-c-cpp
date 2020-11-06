#include <ubiq/platform/internal/support.h>
#include <ubiq/platform/internal/http.h>

#include <sys/param.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <curl/curl.h>

struct ubiq_support_http_handle
{
    CURL * ch;
    struct curl_slist * hlist;

    struct {
        const void * buf;
        size_t len, off;
    } req;

    struct {
        void * buf;
        size_t len;
    } rsp;
};

int ubiq_support_http_init(void)
{
    return (curl_global_init(CURL_GLOBAL_DEFAULT) == 0) ? 0 : INT_MIN;
}

void ubiq_support_http_exit(void)
{
    curl_global_cleanup();
}

struct ubiq_support_http_handle *
ubiq_support_http_handle_create(void)
{
    struct ubiq_support_http_handle * hnd;

    hnd = malloc(sizeof(*hnd));
    if (hnd) {
        hnd->ch = curl_easy_init();
        if (hnd->ch) {
            hnd->hlist = NULL;
        } else {
            free(hnd);
            hnd = NULL;
        }
    }

    return hnd;
}

void
ubiq_support_http_handle_reset(
    struct ubiq_support_http_handle * const hnd)
{
    curl_easy_reset(hnd->ch);
    if (hnd->hlist) {
        curl_slist_free_all(hnd->hlist);
        hnd->hlist = NULL;
    }
}

void
ubiq_support_http_handle_destroy(
    struct ubiq_support_http_handle * const hnd)
{
    curl_easy_cleanup(hnd->ch);
    if (hnd->hlist) {
        curl_slist_free_all(hnd->hlist);
    }
    free(hnd);
}

http_response_code_t
ubiq_support_http_response_code(
    const struct ubiq_support_http_handle * const hnd)
{
    long st;
    curl_easy_getinfo(hnd->ch, CURLINFO_RESPONSE_CODE, &st);
    return st;
}

const char *
ubiq_support_http_response_content_type(
    const struct ubiq_support_http_handle * const hnd)
{
    char * type;
    curl_easy_getinfo(hnd->ch, CURLINFO_CONTENT_TYPE, &type);
    return type;
}

int
ubiq_support_http_add_header(
    struct ubiq_support_http_handle * const hnd, const char * const s)
{
    struct curl_slist * slist;
    int err;

    err = -ENOMEM;
    slist = curl_slist_append(hnd->hlist, s);
    if (slist) {
        hnd->hlist = slist;
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
ubiq_support_http_upload(
    char * const buffer,
    const size_t size, const size_t nmemb,
    void * const priv)
{
    struct ubiq_support_http_handle * const h = priv;
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
ubiq_support_http_download(
    char * const buffer,
    const size_t size, const size_t nmemb,
    void * const priv)
{
    struct ubiq_support_http_handle * const h = priv;
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
ubiq_support_http_request(
    struct ubiq_support_http_handle * const hnd,
    const http_request_method_t method, const char * const urlstr,
    const char * const content_type,
    const void * const content, const size_t length,
    void ** const rspbuf, size_t * const rsplen)
{
    int res;

    res = INT_MIN;
    if (curl_easy_setopt(hnd->ch, CURLOPT_URL, urlstr) == CURLE_OK) {
        /*
         * disable the expect header. otherwise curl will wait
         * for a 100 Continue response from the server (for up to
         * 1 second) before uploading any content.
         */
        res = ubiq_support_http_add_header(hnd, "Expect:");
        if (res == 0) {
            CURLcode rc;

            curl_easy_setopt(
                hnd->ch, CURLOPT_USERAGENT, ubiq_support_user_agent);

            if (length != 0) {
                char cthdr[128];

                /*
                 * if content is supplied, then set up the
                 * request to read the content for upload
                 */

                hnd->req.buf = content;
                hnd->req.len = length;
                hnd->req.off = 0;

                curl_easy_setopt(
                    hnd->ch, CURLOPT_UPLOAD, 1L);
                curl_easy_setopt(
                    hnd->ch, CURLOPT_READDATA, hnd);
                curl_easy_setopt(
                    hnd->ch, CURLOPT_READFUNCTION,
                    &ubiq_support_http_upload);
                curl_easy_setopt(
                    hnd->ch, CURLOPT_INFILESIZE, length);

                snprintf(cthdr, sizeof(cthdr),
                         "Content-Type: %s", content_type);
                ubiq_support_http_add_header(hnd, cthdr);
            }

            /* add headers to the request */
            rc = curl_easy_setopt(hnd->ch, CURLOPT_HTTPHEADER, hnd->hlist);
            if (rc == CURLE_OK) {
                /* set the request method: GET, POST, PUT, etc. */
                curl_easy_setopt(
                    hnd->ch, CURLOPT_CUSTOMREQUEST,
                    http_request_method_string(method));

                /* add callbacks for receiving the response payload */
                curl_easy_setopt(
                    hnd->ch, CURLOPT_WRITEDATA, hnd);
                curl_easy_setopt(
                    hnd->ch, CURLOPT_WRITEFUNCTION,
                    &ubiq_support_http_download);

                hnd->rsp.buf = NULL;
                hnd->rsp.len = 0;

                /* send it! */
                rc = curl_easy_perform(hnd->ch);

                *rspbuf = hnd->rsp.buf;
                *rsplen = hnd->rsp.len;
            }

            res = (rc == CURLE_OK) ? 0 : INT_MIN;
        }
    }

    return res;
}
