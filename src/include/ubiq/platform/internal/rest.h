#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <stddef.h>

#include <ubiq/platform/internal/http.h>

__BEGIN_DECLS

int
ubiq_platform_snprintf_api_url(
    char * const buf, const size_t len,
    const char * const host, const char * const path);

struct ubiq_platform_rest_handle;

/*
 * create a http request/response handle for use with the ubiq platform
 *
 * caller supplies the public api key, secret api key, and a pointer
 * to a rest handle pointer. function initializes and returns a handle
 * via the pointer that can then be used to make requests to the
 * ubiq platform
 *
 * handle must be destroyed to release associated resources
 */
int
ubiq_platform_rest_handle_create(
    const char * const papi, const char * const sapi,
    struct ubiq_platform_rest_handle ** const h);
/*
 * dispose of a rest handle
 */
void
ubiq_platform_rest_handle_destroy(
    struct ubiq_platform_rest_handle * const h);

/*
 * make a request to the ubiq platform (using an already created handle)
 *
 * method specifies GET, POST, PUT, etc.
 * url specifies the full url to the REST endpoint, including any query
 *   url's of the form 'scheme://host[:port]/[path][?query]' are supported,
 *   e.g. inline use of username/password or url fragments are not supported
 * content_type is the mime type associated with the supplied content, if any,
 *  e.g. "text/plain" or "application/json". caller should set this parameter
 *  to NULL if it is not used.
 * content is any data to be sent to the server with the request.
 *   caller should set this parameter to NULL if there is no payload
 * length is the number of bytes pointed to by content. if there is no content,
 *   this value should be 0
 *
 * returns 0 on success or a negative value on failure. on success, the
 * response from the server can be retrieved via the
 * ubiq_platform_rest_response_* functions.
 */
int
ubiq_platform_rest_request(
    struct ubiq_platform_rest_handle * const h,
    const http_request_method_t method, const char * const url,
    const char * const content_type,
    const void * const content, const size_t length);

/*
 * after a successful request, this function can be used to
 * obtain the response code from the server.
 *
 * if there was no request or if the request itself failed, the
 * value returned by this function is undefined
 */
http_response_code_t
ubiq_platform_rest_response_code(
    const struct ubiq_platform_rest_handle * const h);
/*
 * obtain the content type of the response, if any
 *
 * if the content type was not present in the server's response,
 * this function will return NULL. if the request failed or there
 * was no request, the return value is undefined.
 *
 * the returned pointer is valid until the next request or until
 * the handle is destroyed
 */
const char *
ubiq_platform_rest_response_content_type(
    const struct ubiq_platform_rest_handle * const h);
/*
 * obtain the content/payload of the response, if any
 *
 * the length of the content is returned in the len parameter, if present.
 * len may be NULL to ignore the length.
 *
 * the returned pointer is valid until the next request or until
 * the handle is destroyed.
 */
const void *
ubiq_platform_rest_response_content(
    const struct ubiq_platform_rest_handle * const h,
    size_t * const len);

int
ubiq_platform_rest_uri_escape(
  const struct ubiq_platform_rest_handle * const h,
  const char * const uri, char ** const encoded_uri);


__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
