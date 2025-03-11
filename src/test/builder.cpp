#include <gtest/gtest.h>

#include <cstring>

#include "ubiq/platform.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/sso.h"


#define GETENV(VAR, NAME)                       \
    do {                                        \
        VAR = getenv(NAME);                     \
        if (VAR) {                              \
            VAR = strdup(VAR);                  \
        }                                       \
    } while (0)

static
int create_credentials_api_from_env(
  struct ubiq_platform_credentials ** creds
)
{
  char * papi = NULL;
  char * sapi = NULL;
  char * srsa = NULL;
  char * host = NULL;

    GETENV(papi, "UBIQ_ACCESS_KEY_ID");
    GETENV(sapi, "UBIQ_SECRET_SIGNING_KEY");
    GETENV(srsa, "UBIQ_SECRET_CRYPTO_ACCESS_KEY");
    GETENV(host, "UBIQ_SERVER");

    int res = ubiq_platform_credentials_create_explicit(papi, sapi, srsa, host, creds);

    free(papi);
    free(sapi);
    free(srsa);
    free(host);

    return res;
}

static
ubiq::platform::credentials credentials_api_from_env()
{
  char * papi = NULL;
  char * sapi = NULL;
  char * srsa = NULL;
  char * host = NULL;

    GETENV(papi, "UBIQ_ACCESS_KEY_ID");
    GETENV(sapi, "UBIQ_SECRET_SIGNING_KEY");
    GETENV(srsa, "UBIQ_SECRET_CRYPTO_ACCESS_KEY");
    GETENV(host, "UBIQ_SERVER");

    ubiq::platform::credentials creds(papi, sapi, srsa, host);

    free(papi);
    free(sapi);
    free(srsa);
    free(host);

    return creds;
}

static
int create_credentials_idp_from_env(
  struct ubiq_platform_credentials ** creds
)
{
  char * username = NULL;
  char * password = NULL;
  char * host = NULL;

    GETENV(username, "UBIQ_UNITTEST_IDP_USERNAME");
    GETENV(password, "UBIQ_UNITTEST_IDP_PASSWORD");
    GETENV(host, "UBIQ_UNITTEST_IDP_SERVER");

    int res = ubiq_platform_credentials_create_explicit("", "", "", "", creds);
    res = ubiq_platform_credentials_set_idp(*creds, username, password, host);

    free(username);
    free(password);
    free(host);

    return res;
}

static
ubiq::platform::credentials credentials_idp_from_env()
{
  char * username = NULL;
  char * password = NULL;
  char * host = NULL;

    GETENV(username, "UBIQ_UNITTEST_IDP_USERNAME");
    GETENV(password, "UBIQ_UNITTEST_IDP_PASSWORD");
    GETENV(host, "UBIQ_UNITTEST_IDP_SERVER");

    ubiq::platform::credentials creds("papi", "sapi", "srsa", "host");

    creds.set_idp_parameters(username, password, host);

    free(username);
    free(password);
    free(host);

    return creds;
}

static
int create_config_from_env(
  struct ubiq_platform_configuration ** config
)
{
  char * client_secret = NULL;
  char * customer_id = NULL;
  char * tenant_id = NULL;
  char * token_endpoint_url = NULL;
  char * idp_type = NULL;

  GETENV(client_secret, "UBIQ_UNITTEST_IDP_CLIENT_SECRET");
  GETENV(customer_id, "UBIQ_UNITTEST_IDP_CUSTOMER_ID");
  GETENV(tenant_id, "UBIQ_UNITTEST_IDP_TENANT_ID");
  GETENV(token_endpoint_url, "UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL");
  GETENV(idp_type, "UBIQ_UNITTEST_IDP_TYPE");

  int res = ubiq_platform_configuration_create(config);

  if (!res) {
    if (idp_type) ubiq_platform_configuration_set_idp_type(*config, idp_type);
    if (customer_id) ubiq_platform_configuration_set_idp_customer_id(*config, customer_id);
    if (token_endpoint_url) ubiq_platform_configuration_set_idp_token_endpoint_url(*config, token_endpoint_url);
    if (tenant_id) ubiq_platform_configuration_set_idp_tenant_id(*config, tenant_id);
    if (client_secret) ubiq_platform_configuration_set_idp_client_secret(*config, client_secret);

    res = !(ubiq_platform_configuration_is_idp_set(*config) == 1);
  }
  free(client_secret);
  free(customer_id);
  free(tenant_id);
  free(token_endpoint_url);
  free(idp_type);

  return res;
}

static
ubiq::platform::configuration config_from_env()
{
  char * client_secret = NULL;
  char * customer_id = NULL;
  char * tenant_id = NULL;
  char * token_endpoint_url = NULL;
  char * idp_type = NULL;

  GETENV(client_secret, "UBIQ_UNITTEST_IDP_CLIENT_SECRET");
  GETENV(customer_id, "UBIQ_UNITTEST_IDP_CUSTOMER_ID");
  GETENV(tenant_id, "UBIQ_UNITTEST_IDP_TENANT_ID");
  GETENV(token_endpoint_url, "UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL");
  GETENV(idp_type, "UBIQ_UNITTEST_IDP_TYPE");

  ubiq::platform::configuration config;

  config.set_idp_parameters(idp_type, customer_id, token_endpoint_url, tenant_id, client_secret);

  free(client_secret);
  free(customer_id);
  free(tenant_id);
  free(token_endpoint_url);
  free(idp_type);

  return config;
}

TEST(c_builder, simple)
{
  struct ubiq_platform_builder * builder = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);
}

TEST(c_builder, build_structured_local)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_structured_enc_dec_obj * structured = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_build_structured(builder, &structured);
  EXPECT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);

  ubiq_platform_structured_enc_dec_destroy(structured);
}

TEST(c_builder, build_structured)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;
  struct ubiq_platform_structured_enc_dec_obj * structured = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = create_credentials_api_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_configuration_create(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_structured(builder, &structured);
  EXPECT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);

  ubiq_platform_structured_enc_dec_destroy(structured);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);
}


TEST(c_builder, build_unstructured_encrypt)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_encryption * encrypt = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = create_credentials_api_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_configuration_create(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_unstructured_encrypt(builder, &encrypt);
  EXPECT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);

  ubiq_platform_encryption_destroy(encrypt);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);

}

TEST(c_builder, build_unstructured_encrypt_local)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_encryption * encrypt = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_build_unstructured_encrypt(builder, &encrypt);
  EXPECT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);

  ubiq_platform_encryption_destroy(encrypt);

}


TEST(c_builder, build_unstructured_decrypt_local)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_decryption * decrypt = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_build_unstructured_decrypt(builder, &decrypt);
  EXPECT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);

  ubiq_platform_decryption_destroy(decrypt);

}

TEST(c_builder, build_unstructured_decrypt)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_decryption * decrypt = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;

  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = create_credentials_api_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_configuration_create(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_unstructured_decrypt(builder, &decrypt);
  EXPECT_EQ(res, 0);

  ubiq_platform_builder_destroy(builder);

  ubiq_platform_decryption_destroy(decrypt);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);

}


TEST(c_builder, build_unstructured_idp)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_encryption * encrypt = NULL;
  struct ubiq_platform_decryption * decrypt = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;
  
  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = create_credentials_idp_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = create_config_from_env(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_unstructured_decrypt(builder, &decrypt);
  EXPECT_EQ(res, 0);

  res = ubiq_platform_builder_build_unstructured_encrypt(builder, &encrypt);
  EXPECT_EQ(res, 0);

  ubiq_platform_encryption_destroy(encrypt);

  ubiq_platform_decryption_destroy(decrypt);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);

  ubiq_platform_builder_destroy(builder);

}


TEST(c_builder, build_unstructured_idp_wdata)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_encryption * encrypt = NULL;
  struct ubiq_platform_decryption * decrypt = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;
  
  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);
  res = create_credentials_idp_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = create_config_from_env(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_unstructured_decrypt(builder, &decrypt);
  EXPECT_EQ(res, 0);

  res = ubiq_platform_builder_build_unstructured_encrypt(builder, &encrypt);
  EXPECT_EQ(res, 0);

  static const char * const pt = "ABC";

  struct {
        void * buf;
        size_t len;
    } ct_pre, ct_upd, ct_end;

    ct_pre.buf = ct_upd.buf = ct_end.buf = NULL;

  if (res == 0) {
      res = ubiq_platform_encryption_begin(
          encrypt, &ct_pre.buf, &ct_pre.len);
  }

  if (res == 0) {
      res = ubiq_platform_encryption_update(
          encrypt, pt, strlen(pt), &ct_upd.buf, &ct_upd.len);
  }

  if (res == 0) {
      res = ubiq_platform_encryption_end(
          encrypt, &ct_end.buf, &ct_end.len);
  }

  char * ct_buf = (char *)calloc(ct_pre.len + ct_upd.len + ct_end.len + 1, sizeof(char));
  size_t pos = 0;
  if (ct_pre.len && ct_pre.buf) {
    memcpy(ct_buf + pos, ct_pre.buf, ct_pre.len);
    pos += ct_pre.len;
  }
  if (ct_upd.len && ct_upd.buf) {
    memcpy(ct_buf + pos, ct_upd.buf, ct_upd.len);
    pos += ct_upd.len;
  }
  if (ct_end.len && ct_end.buf) {
    memcpy(ct_buf + pos, ct_end.buf, ct_end.len);
    pos += ct_end.len;
  }

  free(ct_pre.buf);
  free(ct_upd.buf);
  free(ct_end.buf);

    struct {
        void * buf;
        size_t len;
    } pt_pre, pt_upd1, pt_end;

    pt_pre.buf = pt_upd1.buf = pt_end.buf = NULL;
    pt_pre.len = pt_upd1.len = pt_end.len = 0;


  ubiq_platform_decryption_begin(decrypt, &pt_pre.buf, &pt_pre.len);
  ubiq_platform_decryption_update(decrypt, ct_buf, pos, &pt_upd1.buf, &pt_upd1.len);
  ubiq_platform_decryption_end(decrypt, &pt_end.buf, &pt_end.len);

  char * str = (char *)calloc(pt_pre.len + pt_upd1.len + pt_end.len + 1, sizeof(char));
  pos = 0;
  if (pt_pre.len && pt_pre.buf) {
    memcpy(str + pos, pt_pre.buf, pt_pre.len);
    pos += pt_pre.len;
  }
  if (pt_upd1.len && pt_upd1.buf) {
    memcpy(str + pos, pt_upd1.buf, pt_upd1.len);
    pos += pt_upd1.len;
  }
  if (pt_end.len && pt_end.buf) {
    memcpy(str + pos, pt_end.buf, pt_end.len);
    pos += pt_end.len;
  }

  free(pt_pre.buf);
  free(pt_upd1.buf);
  free(pt_end.buf);

  EXPECT_EQ(strcmp(pt, str), 0);
  free(str);

  ubiq_platform_encryption_destroy(encrypt);

  ubiq_platform_decryption_destroy(decrypt);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);

  ubiq_platform_builder_destroy(builder);

  free(ct_buf);

}


TEST(c_builder, build_unstructured_wdata)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_encryption * encrypt = NULL;
  struct ubiq_platform_decryption * decrypt = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;
  
  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);
  res = create_credentials_api_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_configuration_create(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_unstructured_decrypt(builder, &decrypt);
  EXPECT_EQ(res, 0);

  res = ubiq_platform_builder_build_unstructured_encrypt(builder, &encrypt);
  EXPECT_EQ(res, 0);

  static const char * const pt = "ABC";

  struct {
        void * buf;
        size_t len;
    } ct_pre, ct_upd, ct_end;

    ct_pre.buf = ct_upd.buf = ct_end.buf = NULL;

  if (res == 0) {
      res = ubiq_platform_encryption_begin(
          encrypt, &ct_pre.buf, &ct_pre.len);
  }

  if (res == 0) {
      res = ubiq_platform_encryption_update(
          encrypt, pt, strlen(pt), &ct_upd.buf, &ct_upd.len);
  }

  if (res == 0) {
      res = ubiq_platform_encryption_end(
          encrypt, &ct_end.buf, &ct_end.len);
  }

  char * ct_buf = (char *)calloc(ct_pre.len + ct_upd.len + ct_end.len + 1, sizeof(char));
  size_t pos = 0;
  if (ct_pre.len && ct_pre.buf) {
    memcpy(ct_buf + pos, ct_pre.buf, ct_pre.len);
    pos += ct_pre.len;
  }
  if (ct_upd.len && ct_upd.buf) {
    memcpy(ct_buf + pos, ct_upd.buf, ct_upd.len);
    pos += ct_upd.len;
  }
  if (ct_end.len && ct_end.buf) {
    memcpy(ct_buf + pos, ct_end.buf, ct_end.len);
    pos += ct_end.len;
  }

  free(ct_pre.buf);
  free(ct_upd.buf);
  free(ct_end.buf);

  struct {
      void * buf;
      size_t len;
  } pt_pre, pt_upd1, pt_end;

  pt_pre.buf = pt_upd1.buf = pt_end.buf = NULL;
  pt_pre.len = pt_upd1.len = pt_end.len = 0;


  ubiq_platform_decryption_begin(decrypt, &pt_pre.buf, &pt_pre.len);
  ubiq_platform_decryption_update(decrypt, ct_buf, pos, &pt_upd1.buf, &pt_upd1.len);
  ubiq_platform_decryption_end(decrypt, &pt_end.buf, &pt_end.len);

  char * str = (char *)calloc(pt_pre.len + pt_upd1.len + pt_end.len + 1, sizeof(char));
  pos = 0;
  if (pt_pre.len && pt_pre.buf) {
    memcpy(str + pos, pt_pre.buf, pt_pre.len);
    pos += pt_pre.len;
  }
  if (pt_upd1.len && pt_upd1.buf) {
    memcpy(str + pos, pt_upd1.buf, pt_upd1.len);
    pos += pt_upd1.len;
  }
  if (pt_end.len && pt_end.buf) {
    memcpy(str + pos, pt_end.buf, pt_end.len);
    pos += pt_end.len;
  }

  free(pt_pre.buf);
  free(pt_upd1.buf);
  free(pt_end.buf);

  EXPECT_EQ(strcmp(pt, str), 0);
  free(str);

  ubiq_platform_encryption_destroy(encrypt);
  ubiq_platform_decryption_destroy(decrypt);
  ubiq_platform_credentials_destroy(creds);
  ubiq_platform_configuration_destroy(config);
  ubiq_platform_builder_destroy(builder);

  free(ct_buf);
}


TEST(c_builder, build_structured_idp)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_structured_enc_dec_obj * a = NULL;
  struct ubiq_platform_structured_enc_dec_obj * b = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;
  
  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = create_credentials_idp_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = create_config_from_env(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_structured(builder, &a);
  EXPECT_EQ(res, 0);

  res = ubiq_platform_builder_build_structured(builder, &b);
  EXPECT_EQ(res, 0);

  static const char * const pt = "123-45-6789";
  char * ct= NULL;
  size_t ct_len = 0;
  char * pt2 = NULL;
  size_t pt2_len = 0;
  
  res = ubiq_platform_structured_encrypt_data(a, "SSN", NULL, 0, pt, strlen(pt), &ct, &ct_len);
  EXPECT_EQ(res, 0);
  res = ubiq_platform_structured_decrypt_data(a, "SSN", NULL, 0, ct, strlen(ct), &pt2, &pt2_len);
  EXPECT_EQ(res, 0);

  EXPECT_EQ(strcmp(pt, pt2), 0);
  free(pt2);

  res = ubiq_platform_structured_encrypt_data(b, "SSN", NULL, 0, pt, strlen(pt), &pt2, &pt2_len);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(strcmp(ct, pt2), 0);
  
  free(ct);
  free(pt2);

  ubiq_platform_structured_enc_dec_destroy(a);
  ubiq_platform_structured_enc_dec_destroy(b);
  ubiq_platform_credentials_destroy(creds);
  ubiq_platform_configuration_destroy(config);
  ubiq_platform_builder_destroy(builder);
}



TEST(c_builder, build_structured_encrypt)
{
  struct ubiq_platform_builder * builder = NULL;
  struct ubiq_platform_structured_enc_dec_obj * a = NULL;
  struct ubiq_platform_structured_enc_dec_obj * b = NULL;
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;
  
  res = ubiq_platform_builder_create(&builder);
  ASSERT_EQ(res, 0);

  res = create_credentials_api_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_configuration_create(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_builder_set_credentials(builder, creds);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_set_configuration(builder, config);
  EXPECT_EQ(res, 0);  

  res = ubiq_platform_builder_build_structured(builder, &a);
  EXPECT_EQ(res, 0);

  res = ubiq_platform_builder_build_structured(builder, &b);
  EXPECT_EQ(res, 0);

  static const char * const pt = "123-45-6789";
  char * ct= NULL;
  size_t ct_len = 0;
  char * pt2 = NULL;
  size_t pt2_len = 0;
  

  res = ubiq_platform_structured_encrypt_data(a, "SSN", NULL, 0, pt, strlen(pt), &ct, &ct_len);
  EXPECT_EQ(res, 0);
  res = ubiq_platform_structured_decrypt_data(a, "SSN", NULL, 0, ct, strlen(ct), &pt2, &pt2_len);
  EXPECT_EQ(res, 0);

  EXPECT_EQ(strcmp(pt, pt2), 0);
  free(pt2);

  res = ubiq_platform_structured_encrypt_data(b, "SSN", NULL, 0, pt, strlen(pt), &pt2, &pt2_len);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(strcmp(ct, pt2), 0);
  
  free(ct);
  free(pt2);

  ubiq_platform_structured_enc_dec_destroy(a);

  ubiq_platform_structured_enc_dec_destroy(b);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);

  ubiq_platform_builder_destroy(builder);

}

TEST(c_sso, get_oauth_token)
{
  struct ubiq_platform_credentials * creds = NULL;
  struct ubiq_platform_configuration * config = NULL;

  int res = 0;
  
  res = create_credentials_idp_from_env(&creds);
  ASSERT_EQ(res, 0);

  res = create_config_from_env(&config);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_sso_login(creds, config);
  EXPECT_EQ(res, 0);

  ubiq_platform_credentials_destroy(creds);

  ubiq_platform_configuration_destroy(config);

}

TEST(cpp_builder, simple)
{
  ubiq::platform::builder builder;
}

TEST(cpp_builder, simple_unstructured_encryption)
{
  ubiq::platform::builder builder;

  ubiq::platform::encryption e = builder.buildUnstructuredEncryption();
}

TEST(cpp_builder, simple_unstructured_decryption)
{
  ubiq::platform::builder builder;

  ubiq::platform::decryption d = builder.buildUnstructuredDecryption();
}


TEST(cpp_builder, simple_structured)
{
  ubiq::platform::builder builder;

  ubiq::platform::structured::decryption d = builder.buildStructuredDecryption();
  ubiq::platform::structured::encryption e = builder.buildStructuredEncryption();
}


TEST(cpp_builder, unstructured_api)
{
  ubiq::platform::builder builder;
  ubiq::platform::credentials creds = credentials_api_from_env();

  ubiq::platform::encryption e = builder.with(creds).buildUnstructuredEncryption();
  ubiq::platform::decryption d = builder.with(creds).buildUnstructuredDecryption();

  std::string pt("ABC");
  std::vector<std::uint8_t> v1;
  std::vector<std::uint8_t> v2;
  std::vector<std::uint8_t> v3;

  ASSERT_NO_THROW(
      v1 = e.begin());
      
  ASSERT_NO_THROW(
      v2 = e.update(pt.data(), pt.size()));

  ASSERT_NO_THROW(
      v3 = e.end());

  std::vector<std::uint8_t> ct = v1;
  ct.insert(ct.end(), v2.begin(), v2.end());
  ct.insert(ct.end(), v3.begin(), v3.end());

  v1 = d.begin();
  v2 = d.update(ct.data(), ct.size());
  v3 = d.end();

  std::vector<std::uint8_t> pt2 = v1;
  pt2.insert(pt2.end(), v2.begin(), v2.end());
  pt2.insert(pt2.end(), v3.begin(), v3.end());

  EXPECT_EQ(pt.size(), pt2.size());
  EXPECT_EQ(memcmp(pt.data(), pt2.data(), pt2.size()), 0);

}

TEST(cpp_builder, unstructured_idp)
{
  ubiq::platform::builder builder;
  ubiq::platform::credentials creds = credentials_idp_from_env();
  ubiq::platform::configuration config = config_from_env();

  ubiq::platform::encryption e = builder.with(creds).with(config).buildUnstructuredEncryption();
  ubiq::platform::decryption d = builder.with(creds).with(config).buildUnstructuredDecryption();

  std::string pt("ABC");
  std::vector<std::uint8_t> v1;
  std::vector<std::uint8_t> v2;
  std::vector<std::uint8_t> v3;

  ASSERT_NO_THROW(
      v1 = e.begin());
      
  ASSERT_NO_THROW(
      v2 = e.update(pt.data(), pt.size()));

  ASSERT_NO_THROW(
      v3 = e.end());

  std::vector<std::uint8_t> ct = v1;
  ct.insert(ct.end(), v2.begin(), v2.end());
  ct.insert(ct.end(), v3.begin(), v3.end());

  v1 = d.begin();
  v2 = d.update(ct.data(), ct.size());
  v3 = d.end();

  std::vector<std::uint8_t> pt2 = v1;
  pt2.insert(pt2.end(), v2.begin(), v2.end());
  pt2.insert(pt2.end(), v3.begin(), v3.end());

  EXPECT_EQ(pt.size(), pt2.size());
  EXPECT_EQ(memcmp(pt.data(), pt2.data(), pt2.size()), 0);

}

TEST(cpp_builder, structured_api)
{
  ubiq::platform::builder builder;
  ubiq::platform::credentials creds = credentials_api_from_env();

  ubiq::platform::structured::encryption e = builder.with(creds).buildStructuredEncryption();
  ubiq::platform::structured::decryption d = builder.with(creds).buildStructuredDecryption();


  std::string pt("123-45-6789");

  std::string ct;
  
  std::string pt2;

  std::vector<std::uint8_t> v1;
  std::vector<std::uint8_t> v2;
  std::vector<std::uint8_t> v3;

  ASSERT_NO_THROW(
      ct = e.encrypt("SSN",pt));
  
      
  ASSERT_NO_THROW(
      pt2 = d.decrypt("SSN", ct));

  EXPECT_EQ(pt.size(), pt2.size());
  EXPECT_EQ(pt.compare(pt2.c_str()), 0);

}

TEST(cpp_builder, structured_idp)
{
  ubiq::platform::builder builder;
  ubiq::platform::credentials creds = credentials_idp_from_env();
  ubiq::platform::configuration config = config_from_env();

  ubiq::platform::structured::encryption e = builder.with(creds).with(config).buildStructuredEncryption();
  ubiq::platform::structured::decryption d = builder.with(creds).with(config).buildStructuredDecryption();


  std::string pt("123-45-6789");
  std::string ct;
  std::string pt2;

  ASSERT_NO_THROW(
      ct = e.encrypt("SSN",pt));
      
  ASSERT_NO_THROW(
      pt2 = d.decrypt("SSN", ct));

  EXPECT_EQ(pt.size(), pt2.size());
  EXPECT_EQ(pt.compare(pt2.c_str()), 0);

}

TEST(cpp_builder, structured_sleep_idp)
{
  ubiq::platform::builder builder;
  ubiq::platform::credentials creds = credentials_idp_from_env();
  ubiq::platform::configuration config = config_from_env();

  ubiq::platform::structured::encryption e = builder.with(creds).with(config).buildStructuredEncryption();

  std::string pt("123-45-6789");

  std::string ct;
  std::string ct2;


  ASSERT_NO_THROW(
      ct = e.encrypt("SSN",pt));
  
  sleep(1);    

  ASSERT_NO_THROW(
      ct2 = e.encrypt("SSN",pt));

  EXPECT_EQ(ct.compare(ct2.c_str()), 0);

}
