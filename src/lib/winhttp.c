#include <ubiq/platform/internal/support.h>
#include <ubiq/platform/internal/common.h>

#include <wtypes.h>
#include <winhttp.h>
#include <stdint.h>
#include <stdio.h>

static HINTERNET winhttp_session = NULL;

int
ubiq_support_http_init(void)
{
    winhttp_session = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    return winhttp_session ? 0 : INT_MIN;
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
     * must be stored until that time.
     */
    struct {
        wchar_t ** vec;
        unsigned int num;
    } headers;

    http_response_code_t status;
    char * ctype;
};

struct ubiq_support_http_handle *
ubiq_support_http_handle_create(void)
{
    struct ubiq_support_http_handle * hnd;
    int err;

    err = -ENOMEM;
    hnd = malloc(sizeof(*hnd));
    if (hnd) {
        hnd->headers.vec = NULL;
        hnd->headers.num = 0;
    }
    hnd->ctype = NULL;

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

static
int
string_widen(
    const char * const str, wchar_t ** const wstr)
{
    int err, n;

    err = INT_MIN;
    n = MultiByteToWideChar(
        CP_ACP, MB_PRECOMPOSED, str, -1, NULL, 0);
    if (n > 0) {
        wchar_t * buf;

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

int
ubiq_support_http_add_header(
    struct ubiq_support_http_handle *  const hnd, const char * const s)
{
    char ** vec;
    int err;

    err = -ENOMEM;
    vec = realloc(hnd->headers.vec,
                  sizeof(*hnd->headers.vec) * (hnd->headers.num + 1));
    if (vec) {
        hnd->headers.vec[hnd->headers.num] = NULL;
        string_widen(s, &hnd->headers.vec[hnd->headers.num]);
        if (hnd->headers.vec[hnd->headers.num]) {
            hnd->headers.num++;
            err = 0;
        }
    }

    return err;
}

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

    ret = WinHttpSendRequest(req,
                             WINHTTP_NO_ADDITIONAL_HEADERS, -1,
                             (void *)content, length, length,
                             0);
    if (ret) {
        ret = WinHttpReceiveResponse(req, NULL);
    }

    res = INT_MIN;
    if (ret) {
        wchar_t ctype[128];
        DWORD val, vlen;
        void * buf;

        vlen = sizeof(val);
        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &val, &vlen,
            WINHTTP_NO_HEADER_INDEX);
        hnd->status = val;

        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_CONTENT_TYPE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            ctype, &vlen,
            WINHTTP_NO_HEADER_INDEX);
        if (vlen) {
            wstring_narrow(ctype, &hnd->ctype);
        }

        vlen = sizeof(val);
        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &val, &vlen,
            WINHTTP_NO_HEADER_INDEX);

        res = 0;
        if (val > 0) {
            res = -ENOMEM;
            buf = malloc(val);
            if (buf) {
                DWORD off, got;

                off = 0;
                do {
                    ret = WinHttpReadData(
                        req,
                        (char *)buf + off, val - off,
                        &got);
                    off += got;
                } while (ret && got > 0);

                if (ret && got == 0) {
                    *rspbuf = buf;
                    *rsplen = val;
                    res = 0;
                } else {
                    free(buf);
                    res = INT_MIN;
                }
            }
        }
    }

    return res;
}

int
ubiq_support_http_request(
    struct ubiq_support_http_handle * const hnd,
    const http_request_method_t method, const char * const urlstr,
    const char * const content_type,
    const void * const content, const size_t length,
    void ** const rspbuf, size_t * const rsplen)
{
    struct ubiq_url url;
    int res;

    res = ubiq_url_parse(&url, urlstr);
    if (res == 0) {
        HINTERNET con;
        uint16_t port;
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
            char * object;

            res = -ENOMEM;
            if (url.query) {
                object = malloc(strlen(url.path) + 1 +
                                strlen(url.query) + 1);
                if (object) {
                    strcpy(object, url.path);
                    strcat(object, "?");
                    strcat(object, url.query);
                }
            } else {
                object = strdup(url.path);
            }

            if (object) {
                HINTERNET req;
                DWORD flags;
                wchar_t * verb;

                flags = WINHTTP_FLAG_REFRESH;
                if (strcmp(url.scheme, "https") == 0) {
                    flags |= WINHTTP_FLAG_SECURE;
                }

                res = INT_MIN;
                string_widen(http_request_method_string(method), &verb);
                string_widen(object, &wstr);
                free(object);
                req = WinHttpOpenRequest(
                    con,
                    verb,
                    wstr,
                    NULL /* http version */,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    flags);
                free(wstr);
                free(verb);
                if (req) {
                    if (content_type && length) {
                        char cthdr[128];

                        snprintf(cthdr, sizeof(cthdr),
                                 "Content-Type: %s", content_type);
                        ubiq_support_http_add_header(hnd, cthdr);
                    }

                    for (unsigned int i = 0; i < hnd->headers.num; i++) {
                        WinHttpAddRequestHeaders(
                            req,
                            hnd->headers.vec[i], -1,
                            WINHTTP_ADDREQ_FLAG_ADD);
                    }

                    res = ubiq_support_http_exchange(
                        hnd, req, content, length, rspbuf, rsplen);

                    WinHttpCloseHandle(req);
                }
            }

            WinHttpCloseHandle(con);
        }

        ubiq_url_reset(&url);
    }

    return res;
}
