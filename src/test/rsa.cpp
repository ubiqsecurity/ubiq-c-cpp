#include <gtest/gtest.h>

#include "ubiq/platform/internal/rsa.h"

TEST(c_rsa, key_pair)
{
  char * prv_pem = NULL;
  char * pub_pem = NULL;

  int res = ubiq_platform_rsa_generate_key_pair(&prv_pem, &pub_pem);
  EXPECT_EQ(res, 0);
  ASSERT_TRUE(prv_pem != NULL);
  ASSERT_TRUE(pub_pem != NULL);

  EXPECT_TRUE(strstr(prv_pem, "RSA PRIVATE KEY") != NULL);
  EXPECT_TRUE(strstr(pub_pem, "PUBLIC KEY") != NULL);

  free(prv_pem);
  free(pub_pem);
}

TEST(c_rsa, csr)
{
  char * prv_pem = NULL;
  char * pub_pem = NULL;
  char * csr_pem = NULL;

  int res = ubiq_platform_rsa_generate_key_pair(&prv_pem, &pub_pem);
  EXPECT_EQ(res, 0);
  ASSERT_TRUE(prv_pem != NULL);
  ASSERT_TRUE(pub_pem != NULL);

  res = ubiq_platform_rsa_create_csr(prv_pem, &csr_pem);
  EXPECT_EQ(res, 0);
  ASSERT_TRUE(csr_pem != NULL);
  EXPECT_TRUE(strstr(csr_pem, "CERTIFICATE REQUEST") != NULL);

  free(prv_pem);
  free(pub_pem);
  free(csr_pem);
}

TEST(c_rsa, encrypt_pem)
{
  char * prv_pem = NULL;
  char * pub_pem = NULL;
  char * encrypted_pem = NULL;

  int res = ubiq_platform_rsa_generate_key_pair(&prv_pem, &pub_pem);
  EXPECT_EQ(res, 0);
  ASSERT_TRUE(prv_pem != NULL);
  ASSERT_TRUE(pub_pem != NULL);

  res = ubiq_platform_rsa_encrypt_private_pem(prv_pem, "sample passphrase", &encrypted_pem);
  EXPECT_EQ(res, 0);
  ASSERT_TRUE(encrypted_pem != NULL);
  EXPECT_TRUE(strstr(encrypted_pem, "ENCRYPTED PRIVATE KEY") != NULL);

  free(prv_pem);
  free(pub_pem);
  free(encrypted_pem);
}
