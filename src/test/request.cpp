#include <gtest/gtest.h>

#include "ubiq/platform/internal/rest.h"

class request : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq_platform_rest_handle * _handle;

    void operator()(const http_request_method_t method);
};

void request::SetUp(void)
{
    ASSERT_EQ(0,
              ubiq_platform_rest_handle_create(
                  "", "",
                  &_handle));
}

void request::TearDown(void)
{
    ubiq_platform_rest_handle_destroy(_handle);
}

void
request::operator()(const http_request_method_t method)
{
    const std::string base("http://localhost:8080/");
    const std::string query("?a=b");

    const std::string content_type("text/plain");
    const std::string content("lorem ipsum");

    std::string path;
    http_response_code_t rc;

    switch (method) {
    case HTTP_RM_GET:
        path = "get";
        rc = HTTP_RC_NO_CONTENT;
        break;
    case HTTP_RM_PUT:
        path = "put";
        rc = HTTP_RC_LENGTH_REQUIRED;
        break;
    case HTTP_RM_POST:
        path = "post";
        rc = HTTP_RC_LENGTH_REQUIRED;
        break;
    default:
        rc = (http_response_code_t)0;
        break;
    }

    /*
     * request with no content. this will cause a 4xx response
     * for certain operations like put and post since those
     * require a payload with a length.
     */
    EXPECT_EQ(
        0,
        ubiq_platform_rest_request(
            _handle,
            method, (base + path).c_str(),
            NULL, NULL, 0));
    EXPECT_EQ(
        rc,
        ubiq_platform_rest_response_code(_handle));

    /*
     * request with a body and a query. this should succeed
     * for all methods
     */
    EXPECT_EQ(
        0,
        ubiq_platform_rest_request(
            _handle,
            method, (base + path + query).c_str(),
            content_type.c_str(), content.data(), content.size()));
    EXPECT_EQ(
        HTTP_RC_NO_CONTENT,
        ubiq_platform_rest_response_code(_handle));
}

TEST_F(request, DISABLED_get)
{
    (*this)(HTTP_RM_GET);
}

TEST_F(request, DISABLED_post)
{
    (*this)(HTTP_RM_POST);
}

TEST_F(request, DISABLED_put)
{
    (*this)(HTTP_RM_PUT);
}
