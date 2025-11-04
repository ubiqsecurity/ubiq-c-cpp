#include <ubiq/platform/internal/support.h>
#include <ubiq/platform/internal/http.h>

#include <sys/param.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <curl/curl.h>

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;

#define UBIQ_CURL_CHECK(x,y) { CURLcode _rc; if ( (_rc = x) != CURLE_OK) {UBIQ_DEBUG(debug_flag, printf("%s rc(%d) %s \n",y, _rc, curl_easy_strerror(_rc)));}}


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
    const void * const content, const size_t length,
    void ** const rspbuf, size_t * const rsplen)
{
    int res;
    static const char * const csu = "ubiq_support_http_request";
    CURLcode rc;

    UBIQ_DEBUG(debug_flag, printf("ubiq_support_http_request: urlstr: '%s'\n", urlstr));
    UBIQ_DEBUG(debug_flag, printf("ubiq_support_http_request: content: '%s'\n", content));

    res = INT_MIN;
    if ((rc = curl_easy_setopt(hnd->ch, CURLOPT_URL, urlstr)) == CURLE_OK) {

        /*
         * disable the expect header. otherwise curl will wait
         * for a 100 Continue response from the server (for up to
         * 1 second) before uploading any content.
         */
        res = ubiq_support_http_add_header(hnd, "Expect:");
        if (res == 0) {
            CURLcode rc;

            UBIQ_CURL_CHECK(curl_easy_setopt(
                hnd->ch, CURLOPT_USERAGENT, ubiq_support_user_agent),"ubiq_support_http_request CURLOPT_USERAGENT");

            if (length != 0) {
                /*
                 * if content is supplied, then set up the
                 * request to read the content for upload
                 */

                hnd->req.buf = content;
                hnd->req.len = length;
                hnd->req.off = 0;


                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_UPLOAD, 1L),"ubiq_support_http_request CURLOPT_UPLOAD");
                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_READDATA, hnd),"ubiq_support_http_request CURLOPT_READDATA");
                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_READFUNCTION,
                    &ubiq_support_http_upload),"ubiq_support_http_request CURLOPT_READFUNCTION");
                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_INFILESIZE, length),"ubiq_support_http_request CURLOPT_INFILESIZE");
            }

            /* add headers to the request */
            UBIQ_CURL_CHECK(rc = curl_easy_setopt(hnd->ch, CURLOPT_HTTPHEADER, hnd->hlist),"ubiq_support_http_request CURLOPT_HTTPHEADER");
            if (rc == CURLE_OK) {
                /* set the request method: GET, POST, PUT, etc. */
                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_CUSTOMREQUEST,
                    http_request_method_string(method)),"ubiq_support_http_request CURLOPT_CUSTOMREQUEST");

                /* add callbacks for receiving the response payload */
                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_WRITEDATA, hnd),"ubiq_support_http_request CURLOPT_WRITEDATA");
                UBIQ_CURL_CHECK(curl_easy_setopt(
                    hnd->ch, CURLOPT_WRITEFUNCTION,
                    &ubiq_support_http_download),"ubiq_support_http_request CURLOPT_WRITEFUNCTION");

                hnd->rsp.buf = NULL;
                hnd->rsp.len = 0;

                UBIQ_CURL_CHECK(curl_easy_setopt(hnd->ch, CURLOPT_NOSIGNAL, 1L),"ubiq_support_http_request CURLOPT_NOSIGNAL");


                /* send it! */
                UBIQ_CURL_CHECK(rc = curl_easy_perform(hnd->ch),"ubiq_support_http_request curl_easy_perform");

                *rspbuf = hnd->rsp.buf;
                *rsplen = hnd->rsp.len;
            }

            res = (rc == CURLE_OK) ? 0 : INT_MIN;
        }
    }

    return res;
}

int
ubiq_support_uri_escape(struct ubiq_support_http_handle * const hnd,
  const char * const uri, char ** const encoded_uri)
{
  int ret = -ENOMEM;
  char * esc = NULL;
  char * url_escape = curl_easy_escape(hnd->ch, uri, strlen(uri));
  if (url_escape) {
    esc = strdup(url_escape);
    if (esc) {
      *encoded_uri = esc;
      ret = 0;
    }
    curl_free(url_escape);
  }
  return ret;
}
