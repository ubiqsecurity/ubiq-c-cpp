#include <gtest/gtest.h>

#include "ubiq/platform.h"

class cpp_encrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::encryption _enc;
};

void cpp_encrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_encrypt::TearDown(void)
{
}

TEST_F(cpp_encrypt, none)
{
    ASSERT_NO_THROW(
        _enc = ubiq::platform::encryption(_creds, 1));
}

TEST_F(cpp_encrypt, simple)
{
    std::string pt("ABC");
    std::vector<std::uint8_t> v;

    ASSERT_NO_THROW(
        v = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));
}

TEST_F(cpp_encrypt, get_usage)
{
    std::string usage;
    std::string pt("ABC");
    _enc = ubiq::platform::encryption(_creds, 1);

    ASSERT_NO_THROW(
        usage = _enc.get_copy_of_usage());

    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::vector<uint8_t> pre = _enc.begin();
    std::vector<uint8_t> mid = _enc.update(pt.data(), pt.size());
    std::vector<uint8_t> post = _enc.end();

    usage = _enc.get_copy_of_usage();

    EXPECT_NE(usage.compare("{\"usage\":[]}"), 0);

}



TEST(c_encrypt, simple)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    void * ctbuf = NULL;
    size_t ctlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_encrypt(creds, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    ubiq_platform_credentials_destroy(creds);

    if (res == 0) {
        free(ctbuf);
    }
}

TEST(c_encrypt, add_user_defined_metadata)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_encryption * enc;
    char * buf = NULL;
    size_t len = 0;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_encryption_create(creds, 5, &enc);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_encryption_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);
    free(buf);

    // invalid
    res = ubiq_platform_encryption_add_user_defined_metadata(NULL, NULL);
    EXPECT_NE(res, 0);

    char toolong[1050];
    memset(toolong, 'a', sizeof(toolong));
    toolong[sizeof(toolong)] = '\0';
    res = ubiq_platform_encryption_add_user_defined_metadata(enc, toolong);
    EXPECT_NE(res, 0);

    res = ubiq_platform_encryption_add_user_defined_metadata(enc, "not json");
    EXPECT_NE(res, 0);

    res = ubiq_platform_encryption_add_user_defined_metadata(enc, "{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}");
    EXPECT_EQ(res, 0);

    // should still be the empty
    res = ubiq_platform_encryption_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0) << buf;
    free(buf);

    {
        // Ignore the actual CT - just want the billing records
        struct {
            void * buf;
            size_t len;
        } pre, upd, end;

        pre.buf = upd.buf = end.buf = NULL;

        res = ubiq_platform_encryption_begin(
            enc, &pre.buf, &pre.len);

        res = ubiq_platform_encryption_update(
            enc, pt, strlen(pt), &upd.buf, &upd.len);
        ASSERT_EQ(res, 0);

        res = ubiq_platform_encryption_end(
                enc, &end.buf, &end.len);
        ASSERT_EQ(res, 0);

        free(end.buf);
        free(upd.buf);
        free(pre.buf);
    }
    res = ubiq_platform_encryption_get_copy_of_usage(enc, &buf, &len);
    EXPECT_EQ(res, 0);
    EXPECT_NE(strcmp(buf, "{\"usage\":[]}"), 0);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_KEY"), nullptr) << buf ;
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_VALUE"), nullptr);
    EXPECT_NE(strstr(buf, "user_defined"), nullptr);
    // printf("%s\n", buf);
    free(buf);

    ubiq_platform_encryption_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
}

TEST_F(cpp_encrypt, add_user_defined_metadata)
{
    std::string usage;
    std::string pt("ABC");
    _enc = ubiq::platform::encryption(_creds, 1);

    usage = _enc.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    ASSERT_THROW(_enc.add_user_defined_metadata(""),std::system_error);
    ASSERT_THROW(_enc.add_user_defined_metadata("{"),std::system_error);
    ASSERT_NO_THROW(_enc.add_user_defined_metadata("{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}"));

    std::vector<uint8_t> pre = _enc.begin();
    std::vector<uint8_t> mid = _enc.update(pt.data(), pt.size());
    std::vector<uint8_t> post = _enc.end();

    usage = _enc.get_copy_of_usage();

    EXPECT_EQ(usage.find("{\"usage\":[]}"),  std::string::npos);
    EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_KEY"),  std::string::npos);
    EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_VALUE"),  std::string::npos);
    EXPECT_NE(usage.find("user_defined"),  std::string::npos);

}

TEST_F(cpp_encrypt, report_granularity)
{

    std::string usage;
    std::string pt("ABC");
    ubiq::platform::configuration cfg(91,92,93,94, "DAYS");
    _enc =  ubiq::platform::encryption(_creds, cfg, 1);

    usage = _enc.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::vector<uint8_t> pre = _enc.begin();
    std::vector<uint8_t> mid = _enc.update(pt.data(), pt.size());
    std::vector<uint8_t> post = _enc.end();

    usage = _enc.get_copy_of_usage();

    EXPECT_EQ(usage.find("{\"usage\":[]}"),  std::string::npos);
    EXPECT_NE(usage.find("00:00:00"),  std::string::npos) << usage;
}

