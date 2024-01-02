#include <gtest/gtest.h>

#include <cstring>

#include "ubiq/platform.h"

class cpp_decrypt : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    void encrypt_decrypt(const std::string &);

    ubiq::platform::credentials _creds;
    ubiq::platform::decryption _dec;
};

void cpp_decrypt::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
}

void cpp_decrypt::TearDown(void)
{
}

TEST_F(cpp_decrypt, none)
{
    ASSERT_NO_THROW(
        _dec = ubiq::platform::decryption(_creds));
}

void
cpp_decrypt::encrypt_decrypt(
    const std::string & pt)
{
    std::vector<std::uint8_t> ct, rec;

    /* encrypt the data */
    ASSERT_NO_THROW(
        ct = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));

    /* decrypt the data */
    ASSERT_NO_THROW(
        rec = ubiq::platform::decrypt(_creds, ct.data(), ct.size()));

    /* verify that the recovered data matches the plain text */
    ASSERT_EQ(pt.size(), rec.size());
    EXPECT_EQ(0, std::memcmp(pt.data(), rec.data(), pt.size()));

    /*
     * flip the last byte of the cipher text (should be part of the tag),
     * and verify that an exception is thrown.
     */
    ct[ct.size() - 1] = ~ct[ct.size() - 1];
    ASSERT_ANY_THROW(
        ubiq::platform::decrypt(_creds, ct.data(), ct.size()));
}

TEST_F(cpp_decrypt, simple)
{
    encrypt_decrypt(std::string("ABC"));
}

TEST_F(cpp_decrypt, aes_block_size)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOP"));
}

TEST_F(cpp_decrypt, aes_block_size_2xm1)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ01234"));
}

TEST_F(cpp_decrypt, aes_block_size_2x)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
}

TEST_F(cpp_decrypt, aes_block_size_2xp1)
{
    encrypt_decrypt(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"));
}

TEST(c_decrypt, simple)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    void * ctbuf, * ptbuf;
    size_t ctlen, ptlen;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_encrypt(
        creds, pt, strlen(pt), &ctbuf, &ctlen);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        res = ubiq_platform_decrypt(
            creds, ctbuf, ctlen, &ptbuf, &ptlen);

        free(ctbuf);

        EXPECT_EQ(res, 0);

        if (res == 0) {
            EXPECT_EQ(strlen(pt), ptlen);
            EXPECT_EQ(0, memcmp(pt, ptbuf, ptlen));

            free(ptbuf);
        }
    }

    ubiq_platform_credentials_destroy(creds);
}


TEST(c_decrypt, get_empty_usage)
{

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_decryption * dec;
    char * buf = NULL;
    size_t len = 0;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_decryption_create(creds, &dec);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_decryption_get_copy_of_usage(dec, &buf, &len);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);

    free(buf);

    ubiq_platform_decryption_destroy(dec);
    ubiq_platform_credentials_destroy(creds);
}

TEST(c_decrypt, get_non_empty_usage)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_encryption * enc;
    struct ubiq_platform_decryption * dec;
    void * ctbuf = NULL;
    void * ptbuf = NULL;
    size_t ctlen = 0;
    size_t ptlen = 0;
    char * buf = NULL;
    char * buf2 = NULL;
    size_t len = 0;
    int res;



    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    // Default configuration will need 5 events or 10 seconds before flushing so one encrypt / decrypt will 
    // be fine
    res = ubiq_platform_encryption_create(creds, 5, &enc);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_decryption_create(creds, &dec);
    EXPECT_EQ(res, 0);


    res = ubiq_platform_decryption_get_copy_of_usage(dec, &buf, &len);
    EXPECT_EQ(res, 0);
    res = ubiq_platform_encryption_get_copy_of_usage(enc, &buf2, &len);
    EXPECT_EQ(res, 0);

    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);
    EXPECT_EQ(strcmp(buf2, buf), 0);
    free(buf);
    free(buf2);

    {
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

        ctlen = pre.len + upd.len + end.len;
        ctbuf = malloc(ctlen);

        memcpy(ctbuf, pre.buf, pre.len);
        memcpy((char *)ctbuf + pre.len, upd.buf, upd.len);
        memcpy((char *)ctbuf + pre.len + upd.len, end.buf, end.len);

        free(end.buf);
        free(upd.buf);
        free(pre.buf);
    }

    EXPECT_EQ(res, 0);

    {
      struct {
        void * buf;
        size_t len;
      } pre, upd, end;

      pre.buf = upd.buf = end.buf = NULL;

      res = ubiq_platform_decryption_begin(
                  dec, &pre.buf, &pre.len);
      ASSERT_EQ(res, 0);

      res = ubiq_platform_decryption_update(
            dec, ctbuf, ctlen, &upd.buf, &upd.len);
      ASSERT_EQ(res, 0);

      res = ubiq_platform_decryption_end(
            dec, &end.buf, &end.len);
      ASSERT_EQ(res, 0);

      ptlen = pre.len + upd.len + end.len;
      ptbuf = malloc(ptlen);

      memcpy(ptbuf, pre.buf, pre.len);
      memcpy((char *)ptbuf + pre.len, upd.buf, upd.len);
      memcpy((char *)ptbuf + pre.len + upd.len, end.buf, end.len);

      free(end.buf);
      free(upd.buf);
      free(pre.buf);
    }

    res = ubiq_platform_decryption_get_copy_of_usage(dec, &buf, &len);
    res = ubiq_platform_encryption_get_copy_of_usage(enc, &buf2, &len);
    EXPECT_EQ(res, 0);

    EXPECT_NE(strcmp(buf, "{\"usage\":[]}"), 0);
    EXPECT_NE(strcmp(buf2, "{\"usage\":[]}"), 0);
    EXPECT_NE(strcmp(buf2, buf), 0);

    free(buf);
    free(buf2);
    free(ptbuf);
    free(ctbuf);

    ubiq_platform_decryption_destroy(dec);
    ubiq_platform_encryption_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
}

TEST_F(cpp_decrypt, get_usage)
{
    std::string usage;
    std::string pt("ABC");
    ubiq::platform::encryption _enc = ubiq::platform::encryption(_creds, 1);
    _dec = ubiq::platform::decryption(_creds);

    usage = _enc.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    usage = _dec.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::vector<uint8_t> pre = _enc.begin();
    std::vector<uint8_t> mid = _enc.update(pt.data(), pt.size());
    std::vector<uint8_t> post = _enc.end();

    usage = _enc.get_copy_of_usage();
    EXPECT_NE(usage.compare("{\"usage\":[]}"), 0);

    std::vector<uint8_t> ct(pre);
    ct.insert(ct.end(), mid.begin(), mid.end());
    ct.insert(ct.end(), post.begin(), post.end());

    pre = _dec.begin();
    mid = _dec.update(ct.data(), ct.size());
    post = _dec.end();

    usage = _dec.get_copy_of_usage();
    EXPECT_NE(usage.compare("{\"usage\":[]}"), 0);

}

TEST(c_decrypt, add_user_defined_metadata)
{
    static const char * const pt = "ABC";

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_decryption * dec;
    char * buf = NULL;
    size_t len = 0;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    ASSERT_EQ(res, 0);

    res = ubiq_platform_decryption_create(creds, &dec);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_decryption_get_copy_of_usage(dec, &buf, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);
    free(buf);

    // invalid
    res = ubiq_platform_decryption_add_user_defined_metadata(NULL, NULL);
    EXPECT_NE(res, 0);

    char toolong[1050];
    memset(toolong, 'a', sizeof(toolong));
    toolong[sizeof(toolong)] = '\0';
    res = ubiq_platform_decryption_add_user_defined_metadata(dec, toolong);
    EXPECT_NE(res, 0);

    res = ubiq_platform_decryption_add_user_defined_metadata(dec, "not json");
    EXPECT_NE(res, 0);

    res = ubiq_platform_decryption_add_user_defined_metadata(dec, "{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}");
    EXPECT_EQ(res, 0);

    // should still be the empty
    res = ubiq_platform_decryption_get_copy_of_usage(dec, &buf, &len);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(strcmp(buf, "{\"usage\":[]}"), 0);
    free(buf);

    {
        void * ctbuf = NULL;
        void * ptbuf = NULL;
        size_t ctlen = 0;
        size_t ptlen = 0;

        struct ubiq_platform_encryption * enc;
        res = ubiq_platform_encryption_create(creds, 5, &enc);
        EXPECT_EQ(res, 0);

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

        ctlen = pre.len + upd.len + end.len;
        ctbuf = malloc(ctlen);

        memcpy(ctbuf, pre.buf, pre.len);
        memcpy((char *)ctbuf + pre.len, upd.buf, upd.len);
        memcpy((char *)ctbuf + pre.len + upd.len, end.buf, end.len);

        free(end.buf);
        free(upd.buf);
        free(pre.buf);

        ubiq_platform_encryption_destroy(enc);

        pre.buf = upd.buf = end.buf = NULL;

        res = ubiq_platform_decryption_begin(
                    dec, &pre.buf, &pre.len);
        ASSERT_EQ(res, 0);

        res = ubiq_platform_decryption_update(
              dec, ctbuf, ctlen, &upd.buf, &upd.len);
        ASSERT_EQ(res, 0);

        res = ubiq_platform_decryption_end(
              dec, &end.buf, &end.len);
        ASSERT_EQ(res, 0);

        ptlen = pre.len + upd.len + end.len;
        ptbuf = malloc(ptlen + 1);
        ((char *)ptbuf)[ptlen] = '\0';

        memcpy(ptbuf, pre.buf, pre.len);
        memcpy((char *)ptbuf + pre.len, upd.buf, upd.len);
        memcpy((char *)ptbuf + pre.len + upd.len, end.buf, end.len);

        free(end.buf);
        free(upd.buf);
        free(pre.buf);

        EXPECT_EQ(strcmp((char *)ptbuf, pt), 0);
        free(ptbuf);
        free(ctbuf);
    }

    res = ubiq_platform_decryption_get_copy_of_usage(dec, &buf, &len);
    EXPECT_EQ(res, 0);
    EXPECT_NE(strcmp(buf, "{\"usage\":[]}"), 0);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_KEY"), nullptr);
    EXPECT_NE(strstr(buf, "UBIQ_SPECIAL_USER_DEFINED_VALUE"), nullptr);
    EXPECT_NE(strstr(buf, "user_defined"), nullptr);
    free(buf);
    ubiq_platform_decryption_destroy(dec);
    ubiq_platform_credentials_destroy(creds);
}

TEST_F(cpp_decrypt, add_user_defined_metadata)
{
    std::string usage;
    std::string pt("ABC");
    ubiq::platform::encryption _enc = ubiq::platform::encryption(_creds, 1);
    _dec = ubiq::platform::decryption(_creds);

    ASSERT_THROW(_dec.add_user_defined_metadata(""),std::system_error);
    ASSERT_THROW(_dec.add_user_defined_metadata("{"),std::system_error);
    ASSERT_NO_THROW(_dec.add_user_defined_metadata("{\"UBIQ_SPECIAL_USER_DEFINED_KEY\" : \"UBIQ_SPECIAL_USER_DEFINED_VALUE\"}"));

    usage = _dec.get_copy_of_usage();
    EXPECT_EQ(usage.compare("{\"usage\":[]}"), 0);

    std::vector<uint8_t> pre = _enc.begin();
    std::vector<uint8_t> mid = _enc.update(pt.data(), pt.size());
    std::vector<uint8_t> post = _enc.end();

    std::vector<uint8_t> ct(pre);
    ct.insert(ct.end(), mid.begin(), mid.end());
    ct.insert(ct.end(), post.begin(), post.end());

    pre = _dec.begin();
    mid = _dec.update(ct.data(), ct.size());
    post = _dec.end();

    usage = _dec.get_copy_of_usage();

    EXPECT_EQ(usage.find("{\"usage\":[]}"),  std::string::npos);
    EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_KEY"),  std::string::npos);
    EXPECT_NE(usage.find("UBIQ_SPECIAL_USER_DEFINED_VALUE"),  std::string::npos);
    EXPECT_NE(usage.find("user_defined"),  std::string::npos);

}


// TEST(c_billing, simple)
// {

//   int before;
//   struct fpe_billing_element * element;
//   struct fpe_billing_element * element2;
//   int after;


//   int res = billing_element_create(
//     &element,
//     "api key",
//     "dataset name",
//     "dataset group name",
//     123,
//     456789,
//     ENCRYPTION
//   );
  
//    res = billing_element_create(
//     &element2,
//     "api key",
//     "OTHER dataset name",
//     "OTHER dataset group name",
//     321,
//     987654,
//     ENCRYPTION
//   );
 
//   EXPECT_EQ(0, res);
//   before = res + 123;
//   after = res + 567;

//   billing_element_destroy(element);
// element = NULL;
//   res = billing_element_create(
//     &element,
//     "api key",
//     NULL,
//     "dataset group name",
//     123,
//     456789,
//     ENCRYPTION
//   );

//   EXPECT_EQ(0, res);
//  billing_element_destroy(element);

//   res = billing_element_create(
//     &element,
//     "api key",
//     "dataset name",
//     NULL,
//     123,
//     456789,
//     ENCRYPTION
//   );

//   EXPECT_EQ(0, res);
//  billing_element_destroy(element);
//  billing_element_destroy(element2);

//   std::cout << "before: " << before << "  after: " << after << std::endl;

// }
