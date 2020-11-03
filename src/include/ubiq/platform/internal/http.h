/*
 * this file contains some generic http enumerations
 */

#pragma once

#include <ubiq/platform/compat/cdefs.h>

__BEGIN_DECLS

/*
 * the different types of http request methods
 */
typedef enum
{
    HTTP_RM_CONNECT,
    HTTP_RM_DELETE,
    HTTP_RM_GET,
    HTTP_RM_HEAD,
    HTTP_RM_PATCH,
    HTTP_RM_POST,
    HTTP_RM_PUT,
    HTTP_RM_OPTIONS,
    HTTP_RM_TRACE,
} http_request_method_t;

/*
 * http status codes (as found on wikipedia). these
 * are only the official codes listed there and do
 * not include unofficial codes that may be in use.
 */
typedef enum
{
    HTTP_RC_CONTINUE                    = 100,
    HTTP_RC_SWITCHING_PROTOCOLS         = 101,
    HTTP_RC_PROCESSING                  = 102,
    HTTP_RC_EARLY_HINTS                 = 103,

    HTTP_RC_OK                          = 200,
    HTTP_RC_CREATED                     = 201,
    HTTP_RC_ACCEPTED                    = 202,
    HTTP_RC_NA_INFORMATION              = 203,
    HTTP_RC_NO_CONTENT                  = 204,
    HTTP_RC_RESET_CONTENT               = 205,
    HTTP_RC_PARTIAL_CONTENT             = 206,
    HTTP_RC_MULTI_STATUS                = 207,
    HTTP_RC_ALREADY_REPORTED            = 208,
    HTTP_RC_IM_USED                     = 226,

    HTTP_RC_MULTIPLE_CHOICES            = 300,
    HTTP_RC_MOVED_PERMANENTLY           = 301,
    HTTP_RC_FOUND                       = 302,
    HTTP_RC_SEE_OTHER                   = 303,
    HTTP_RC_NOT_MODIFIED                = 304,
    HTTP_RC_USE_PROXY                   = 305,
    HTTP_RC_SWITCH_PROXY                = 306,
    HTTP_RC_TEMPORARY_REDIRECT          = 307,
    HTTP_RC_PERMANENT_REDIRECT          = 308,

    HTTP_RC_BAD_REQUEST                 = 400,
    HTTP_RC_UNAUTHORIZED                = 401,
    HTTP_RC_PAYMENT_REQUIRED            = 402,
    HTTP_RC_FORBIDDEN                   = 403,
    HTTP_RC_NOT_FOUND                   = 404,
    HTTP_RC_METHOD_NOT_ALLOWED          = 405,
    HTTP_RC_NOT_ACCEPTABLE              = 406,
    HTTP_RC_PROXY_AUTH_REQUIRED         = 407,
    HTTP_RC_REQUEST_TIMEOUT             = 408,
    HTTP_RC_CONFLICT                    = 409,
    HTTP_RC_GONE                        = 410,
    HTTP_RC_LENGTH_REQUIRED             = 411,
    HTTP_RC_PRECONDITION_FAILED         = 412,
    HTTP_RC_PAYLOAD_TOO_LARGE           = 413,
    HTTP_RC_URI_TOO_LONG                = 414,
    HTTP_RC_UNSUPPORTED_MEDIA_TYPE      = 415,
    HTTP_RC_RANGE_NOT_SATISFIABLE       = 416,
    HTTP_RC_EXPECTATION_FAILED          = 417,
    HTTP_RC_IM_A_TEAPOT                 = 418,
    HTTP_RC_MISDIRECTED_REQUEST         = 421,
    HTTP_RC_UNPROCESSABLE_ENTITY        = 422,
    HTTP_RC_LOCKED                      = 423,
    HTTP_RC_FAILED_DEPENDENCY           = 424,
    HTTP_RC_TOO_EARLY                   = 425,
    HTTP_RC_UPGRADE_REQUIRED            = 426,
    HTTP_RC_PRECONDITION_REQUIRED       = 428,
    HTTP_RC_TOO_MANY_REQUESTS           = 429,
    HTTP_RC_REQUEST_HEADER_TOO_LARGE    = 431,
    HTTP_RC_UNAVAILABLE_FOR_LEGAL       = 451,

    HTTP_RC_INTERNAL_SERVER_ERROR       = 500,
    HTTP_RC_NOT_IMPLEMENTED             = 501,
    HTTP_RC_BAD_GATEWAY                 = 502,
    HTTP_RC_SERVICE_UNAVAILABLE         = 503,
    HTTP_RC_GATEWAY_TIMEOUT             = 504,
    HTTP_RC_HTTP_VERSION_NOT_SUPPORTED  = 505,
    HTTP_RC_VARIANT_ALSO_NEGOTIATES     = 506,
    HTTP_RC_INSUFFICENT_STORAGE         = 507,
    HTTP_RC_LOOP_DETECTED               = 508,
    HTTP_RC_NOT_EXTENDED                = 510,
    HTTP_RC_NETWORK_AUTH_REQUIRED       = 511,
} http_response_code_t;

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
