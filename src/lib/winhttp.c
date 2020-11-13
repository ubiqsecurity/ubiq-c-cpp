#include <ubiq/platform/internal/support.h>
#include <ubiq/platform/internal/common.h>

#include <wtypes.h>
#include <winhttp.h>
#include <stdint.h>
#include <stdio.h>

/*
 * convert normal string to wide
 * returns 0 on success or a negative value, otherwise
 * the result is returned in wstr and is not modified
 * unless the function is successful
 */
static
int
string_widen(
    const char * const str, wchar_t ** const wstr)
{
    int err, n;

    /* call with NULL to determine the number of bytes needed */
    err = INT_MIN;
    n = MultiByteToWideChar(
        CP_ACP, MB_PRECOMPOSED, str, -1, NULL, 0);
    if (n > 0) {
        wchar_t * buf;

        /* allocate memory and do the conversion for real */
        err = -ENOMEM;
        buf = malloc(n * sizeof(*buf));
        if (buf) {
            if (MultiByteToWideChar(
                    CP_ACP, MB_PRECOMPOSED, str, -1, buf, n) == n) {
                *wstr = buf;
                err = 0;
            } else {
                free(buf);
                err = INT_MIN;
            }
        }
    }

    return err;
}

/*
 * convert wide string to narrow. this assumes all the
 * wide characters have a corresponding value in the narrowed
 * output. that should be true for use in this library
 * but probably not, more generally.
 *
 * function follows the same rules/conventions and procedure as
 * its widen counterpart
 */
static
int
wstring_narrow(
    const wchar_t * const wstr, char ** const str)
{
    int err, n;

    err = INT_MIN;
    n = WideCharToMultiByte(
        CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (n > 0) {
        char * buf;

        err = -ENOMEM;
        buf = malloc(n * sizeof(*buf));
        if (buf) {
            if (WideCharToMultiByte(
                    CP_ACP, 0, wstr, -1, buf, n, NULL, NULL) == n) {
                *str = buf;
                err = 0;
            } else {
                free(buf);
                err = INT_MIN;
            }
        }
    }

    return err;
}

/*
 * single session for the entire library. documentation states
 * that different sessions should be used for different users
 * so that cookies and the like are kept separate. this library
 * assumes a single user and uses a single session
 */
static HINTERNET winhttp_session = NULL;

int
ubiq_support_http_init(void)
{
    wchar_t * user_agent;
    int err;

    err = 0;

    /* widen the user agent string, if present */
    user_agent = NULL;
    if (ubiq_support_user_agent) {
        err = string_widen(ubiq_support_user_agent, &user_agent);
    }

    /*
     * since user agent was set to NULL prior to the widen call,
     * it's either NULL or a malloc'd value. Both values are legal
     * to pass to both WinHttpOpen() and free()
     */

    if (!err) {
        winhttp_session = WinHttpOpen(
            user_agent,
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!winhttp_session) {
            err = INT_MIN;
        }

        free(user_agent);
    }

    return err;
}

void
ubiq_support_http_exit(void)
{
    WinHttpCloseHandle(winhttp_session);
    winhttp_session = NULL;
}

struct ubiq_support_http_handle
{
    /*
     * headers require a request which require
     * a connection which isn't available until
     * a request is actually made, so headers
     * must be stored in the handle until that time.
     */
    struct {
        wchar_t ** vec;
        unsigned int num;
    } headers;

    /*
     * status is not available until after a successful
     * http request/response
     *
     * ctype is the content-type of the response. the value
     * is allocated on the heap and must be freed
     */
    http_response_code_t status;
    char * ctype;
};

struct ubiq_support_http_handle *
ubiq_support_http_handle_create(void)
{
    struct ubiq_support_http_handle * hnd;

    hnd = malloc(sizeof(*hnd));
    if (hnd) {
        hnd->headers.vec = NULL;
        hnd->headers.num = 0;

        /*
         * there is no "unknown" status code,
         * so it's just not initialized
         */
        hnd->ctype = NULL;
    }

    return hnd;
}

void
ubiq_support_http_handle_reset(
    struct ubiq_support_http_handle * const hnd)
{
    while (hnd->headers.num) {
        hnd->headers.num--;
        free(hnd->headers.vec[hnd->headers.num]);
    }

    free(hnd->headers.vec);
    hnd->headers.vec = NULL;

    free(hnd->ctype);
    hnd->ctype = NULL;
}

void
ubiq_support_http_handle_destroy(
    struct ubiq_support_http_handle * const hnd)
{
    ubiq_support_http_handle_reset(hnd);
    free(hnd);
}

http_response_code_t
ubiq_support_http_response_code(
    const struct ubiq_support_http_handle * const hnd)
{
    return hnd->status;
}

const char *
ubiq_support_http_response_content_type(
    const struct ubiq_support_http_handle * const hnd)
{
    return hnd->ctype;
}

int
ubiq_support_http_add_header(
    struct ubiq_support_http_handle *  const hnd, const char * const s)
{
    wchar_t ** vec;
    int err;

    /*
     * headers are stored as an array of pointers to strings.
     * first, resize the array; then, store the header in the
     * newly allocated space.
     */

    err = -ENOMEM;
    vec = realloc(hnd->headers.vec,
                  sizeof(*hnd->headers.vec) * (hnd->headers.num + 1));
    if (vec) {
        hnd->headers.vec = vec;

        /*
         * widen allocates the memory for the string. if it fails,
         * the array is left at the increased size, but the number of
         * elements is not increased.
         */
        hnd->headers.vec[hnd->headers.num] = NULL;
        string_widen(s, &hnd->headers.vec[hnd->headers.num]);
        if (hnd->headers.vec[hnd->headers.num]) {
            hnd->headers.num++;
            err = 0;
        }
    }

    return err;
}

/*
 * do the actual sending of the request and reception of the response.
 * the HINTERNET request handle must already be initialized prior
 * to calling this function. that means not only that it must be valid
 * but also that any headers or other setup necessary has already been
 * performed.
 */
static
int
ubiq_support_http_exchange(
    struct ubiq_support_http_handle * const hnd,
    const HINTERNET req,
    const void * const content, const size_t length,
    void ** const rspbuf, size_t * const rsplen)
{
    BOOL ret;
    int res;

    res = INT_MIN;

    /* send the request and wait for the (beginning of the) response */
    ret = WinHttpSendRequest(req,
                             WINHTTP_NO_ADDITIONAL_HEADERS, -1,
                             (void *)content, length, length,
                             0);
    if (ret) {
        ret = WinHttpReceiveResponse(req, NULL);
    }

    if (ret) {
        wchar_t ctype[128];
        DWORD val, vlen, off, got;
        void * buf;

        /* get the http response code */
        vlen = sizeof(val);
        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &val, &vlen,
            WINHTTP_NO_HEADER_INDEX);
        hnd->status = val;

        /* get the response content type */
        vlen = sizeof(ctype);
        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_CONTENT_TYPE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            ctype, &vlen,
            WINHTTP_NO_HEADER_INDEX);
        if (vlen) {
            wstring_narrow(ctype, &hnd->ctype);
        }

        /*
         * this code used to look for the content-length
         * header to determine how much data to read, but
         * the header is not always present
         */

        /*
         * depending on the size of the transfer and network
         * conditions, all of the response may not be available
         * at once. run a loop, waiting for data and reading it
         */

        res = 0;
        buf = NULL;
        off = 0;
        do {
            got = 0;

            /*
             * wait for data and determine how much is available.
             * `val` will be 0 when the end-of-file is reached and
             * the loop will terminate
             */
            ret = WinHttpQueryDataAvailable(req, &val);
            if (!ret) {
                res = INT_MIN;
            } else if (val > 0) {
                void * b;

                /* extend the response buffer and read the data */
                b = realloc(buf, off + val);
                if (b) {
                    buf = b;

                    ret = WinHttpReadData(
                        req,
                        (char *)buf + off, val,
                        &got);
                    if (ret) {
                        off += got;
                    } else {
                        res = INT_MIN;
                    }
                } else {
                    res = -ENOMEM;
                }
            }
        } while (res == 0 && val > 0);

        if (res == 0) {
            *rspbuf = buf;
            *rsplen = off;
        } else {
            free(buf);
        }
    }

    return res;
}

int
ubiq_support_http_request(
    struct ubiq_support_http_handle * const hnd,
    const http_request_method_t method, const char * const urlstr,
    const void * const content, const size_t length,
    void ** const rspbuf, size_t * const rsplen)
{
    struct ubiq_url url;
    int res;

    /*
     * winhttp (unlike curl) requires that the URL be
     * specified in its constituent pieces instead of
     * just a long string
     */

    res = ubiq_url_parse(&url, urlstr);
    if (res == 0) {
        HINTERNET con;
        uint16_t port;

        /*
         * note: wstr is repeatedly reused throughout the
         * code below to briefly store widened strings before
         * immediately freeing them again
         */
        wchar_t * wstr;

        port = INTERNET_DEFAULT_PORT;
        if (url.port) {
            port = atoi(url.port);
        }

        res = INT_MIN;
        string_widen(url.hostname, &wstr);
        con = WinHttpConnect(winhttp_session, wstr, port, 0);
        free(wstr);

        if (con) {
            wchar_t * verb;

            res = -ENOMEM;

            /* verb is GET, POST, PATCH, etc. */
            verb = NULL;
            string_widen(http_request_method_string(method), &verb);

            /*
             * if no query is present, just widen the url path.
             * if a query is present, concatenate the path and the
             * query and then widen.
             */
            wstr = NULL;
            if (!url.query) {
                string_widen(url.path, &wstr);
            } else {
                char * object;
                object = malloc(strlen(url.path) + 1 +
                                strlen(url.query) + 1);
                if (object) {
                    strcpy(object, url.path);
                    strcat(object, "?");
                    strcat(object, url.query);

                    string_widen(object, &wstr);
                    free(object);
                }
            }

            if (verb && wstr) {
                HINTERNET req;
                DWORD flags;

                /*
                 * if traveling through a proxy, don't get
                 * a cached version of a previous request
                 */
                flags = WINHTTP_FLAG_REFRESH;
                if (strcmp(url.scheme, "https") == 0) {
                    flags |= WINHTTP_FLAG_SECURE;
                }

                res = INT_MIN;
                req = WinHttpOpenRequest(
                    con,
                    verb,
                    wstr,
                    NULL /* http version */,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    flags);
                if (req) {
                    BOOL ret;

                    ret = TRUE;
                    for (unsigned int i = 0;
                         ret && i < hnd->headers.num;
                         i++) {
                        ret = WinHttpAddRequestHeaders(
                            req,
                            hnd->headers.vec[i], -1,
                            WINHTTP_ADDREQ_FLAG_ADD);
                    }

                    if (ret) {
                        res = ubiq_support_http_exchange(
                            hnd, req, content, length, rspbuf, rsplen);
                    }

                    WinHttpCloseHandle(req);
                }
            }

            /*
             * unconditionally call free as
             * freeing a NULL pointer is legal
             */
            free(wstr);
            free(verb);

            WinHttpCloseHandle(con);
        }

        ubiq_url_reset(&url);
    }

    return res;
}
