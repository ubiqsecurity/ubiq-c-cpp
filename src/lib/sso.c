#include "ubiq/platform.h"

#include "ubiq/platform/internal/rest.h"
#include "ubiq/platform/internal/assert.h"
#include "ubiq/platform/internal/common.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/rsa.h"
#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"

#include <openssl/pem.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cJSON/cJSON.h"


// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;

static int GetOAuthToken(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config,
  cJSON ** json_results);

static int getScimSso(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config,
  cJSON ** json_results);

static int parseSsoAndSetCreds(
  cJSON * json_results,
  struct ubiq_platform_credentials * const creds);

static int ubiq_platform_sso_get_scim(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config);

static int ubiq_platform_sso_get_oauth(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config);


int ubiq_platform_sso_renewIdpCert(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config)
{
  static const char * csu = "ubiq_platform_sso_renewIdpCert";
  int res = 0;
  UBIQ_DEBUG(debug_flag, printf("%s: exp(%llu) now(%llu) \n", csu, ubiq_platform_credentials_get_cert_expiration(creds), time(NULL)));
  if (ubiq_platform_credentials_is_idp(creds) &&
    ubiq_platform_credentials_get_cert_expiration(creds) < time(NULL)) {
    UBIQ_DEBUG(debug_flag, printf("%s: renew \n", csu));
    if ((res = ubiq_platform_sso_get_oauth(creds, config)) == 0) {
      res = ubiq_platform_sso_get_scim(creds, config);
    }
  }
  return res;
}

static int ubiq_platform_sso_get_oauth(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config)
{
  static const char * csu = "ubiq_platform_sso_get_oauth";

  int res = 0;
  if (!res) {
    cJSON * json_results = NULL;
    char * access_token = NULL;
    int value = 0;
    res = GetOAuthToken(creds, config, &json_results);
    // NOTE: cJSON_Print will cause memory leak in debug mode
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "GetOAuthToken", cJSON_Print(json_results)));
    if (!res && json_results != NULL) {
      cJSON * element = NULL;
      element = cJSON_GetObjectItem(json_results, "token_type");
      if (!cJSON_IsString(element) || (strcmp(cJSON_GetStringValue(element), "Bearer") != 0)) {
        res = -EINVAL;
      }
      UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "token_type", cJSON_GetStringValue(element)));
      element = cJSON_GetObjectItem(json_results, "access_token");
      if (!res && cJSON_IsString(element)) {
        access_token = strdup(cJSON_GetStringValue(element));
        UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "access_token", access_token));

      }
      element = cJSON_GetObjectItem(json_results, "expires_in");
      if (!res && (!cJSON_IsNumber(element) || ((value = cJSON_GetNumberValue(element)) == 0))) {
        res = -EINVAL;
      }
      UBIQ_DEBUG(debug_flag, printf("%s: %s %d \n", csu, "expires_in", value));
      if (!res) {
        res = ubiq_platform_credentials_set_access_token(creds, access_token, value);
      }
    }
    free(access_token);
    cJSON_Delete(json_results);

  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  return res;
}

static int ubiq_platform_sso_get_scim(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config)
{
  static const char * csu = "ubiq_platform_sso_get_scim";
  int res = 0;
  cJSON * json_results;
  if ((res = getScimSso(creds, config, &json_results)) == 0) {
    res = parseSsoAndSetCreds(json_results, creds);
  }

  cJSON_Delete(json_results);
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  return res;
}

int
ubiq_platform_sso_login(
  struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config)
{
  static const char * csu = "ubiq_platform_sso_login";
  
  int res = 0;

    UBIQ_DEBUG(debug_flag, printf("%s start: %d\n", csu, res));

  if (!ubiq_platform_configuration_is_idp_set(config)) {
    UBIQ_DEBUG(debug_flag, printf("%s ubiq_platform_configuration_is_idp_set: %d\n", csu, res));
    return -EINVAL;
  }

  u_int8_t srsa[33];
  char * srsa_b64 = NULL;
  char * encrypted_pem = NULL;
  res = ubiq_support_getrandom(srsa, sizeof(srsa));

  // Create the srsa 
  if (!res) {
    ubiq_support_base64_encode(&srsa_b64, srsa, sizeof(srsa));
    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_sso_login srsa(%s): %d\n", srsa_b64, res));
  }

  char * private_pem = NULL;
  char * public_pem = NULL;
  char * csr = NULL;

  // Create the rsa key pair

  if (!res) {
    res = ubiq_platform_rsa_generate_key_pair(&private_pem, &public_pem);
  }

  // Create the csr
  if (!res) {
    res = ubiq_platform_rsa_create_csr(private_pem, &csr);
  }

  if (!res) {
    res = ubiq_platform_rsa_encrypt_private_pem(private_pem, srsa_b64, &encrypted_pem);
  }

  // Call the sso login
  if (!res) {
    res = ubiq_platform_sso_get_oauth(creds, config);
  }

  // Set the credentials RSA / CSR values 
  if (!res) {
    res = ubiq_platform_credentials_set_rsa_keys(creds, srsa_b64, encrypted_pem, csr);
  }

  // Call the get token with expiration date
  if (!res) {
    res = ubiq_platform_sso_get_scim(creds, config);
  }

  free(encrypted_pem);
  free(csr);
  free(srsa_b64);
  free(private_pem);
  free(public_pem);
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  return res;
}


// Need to make sure to free strings;
static char * encode_str(
  const struct ubiq_platform_rest_handle * const h,
  char * str) {
  
}

static int GetOAuthToken(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config,
  cJSON ** json_results)
{
  static const char * csu = "GetOAuthToken";
  int res = 0;

  const char * const url = ubiq_platform_configuration_get_idp_token_endpoint_url(config);

  UBIQ_DEBUG(debug_flag, printf("%s: %s %s %d \n", csu, "ubiq_platform_configuration_get_idp_token_endpoint_url", url, res));

  struct ubiq_support_http_handle * hnd = ubiq_support_http_handle_create();

  char scope[1024];
  char tmp[5];
  char * post_fields = NULL;
  const char * cfgIdpType = ubiq_platform_configuration_get_idp_type(config);

  char * enc_tenant_id = NULL;
  char * enc_client_secret = NULL;
  char * enc_username = NULL;
  char * enc_password = NULL;
  char * enc_scope = NULL;

  // Cannot use encode on full string
  res = !res && ubiq_support_uri_escape(hnd, ubiq_platform_configuration_get_idp_tenant_id(config), &enc_tenant_id);
  UBIQ_DEBUG(debug_flag, printf("%s: %s %s %d \n", csu, "enc_tenant_id", enc_tenant_id, res));
  res = !res && ubiq_support_uri_escape(hnd, ubiq_platform_configuration_get_idp_client_secret(config), &enc_client_secret);
  UBIQ_DEBUG(debug_flag, printf("%s: %s %s %d \n", csu, "enc_client_secret", enc_client_secret, res));
  res = !res && ubiq_support_uri_escape(hnd, ubiq_platform_credentials_get_idp_username(creds), &enc_username);
  UBIQ_DEBUG(debug_flag, printf("%s: %s %s %d \n", csu, "enc_username", enc_username, res));
  res = !res && ubiq_support_uri_escape(hnd, ubiq_platform_credentials_get_idp_password(creds), &enc_password);
  UBIQ_DEBUG(debug_flag, printf("%s: %s %s %d \n", csu, "enc_password", enc_password, res));

  

  if (strcmp(cfgIdpType, "okta") == 0) {
            strcpy(scope, "openid offline_access okta.users.read okta.groups.read");
  } else if (strcmp(cfgIdpType, "entra") == 0) {
      snprintf(scope, sizeof(scope), "api://%s/.default", ubiq_platform_configuration_get_idp_tenant_id(config));
  }

  res = !res && ubiq_support_uri_escape(hnd, scope, &enc_scope);

  UBIQ_DEBUG(debug_flag, printf("%s: %s %s %d \n", csu, "enc_scope", enc_scope, res));

  
  // Figure out how long it needs to be, then allocate and perform copy
  size_t len = snprintf(tmp, sizeof(tmp), 
    "scope=%s&client_id=%s&client_secret=%s&username=%s&password=%s&grant_type=password",
    enc_scope,
    enc_tenant_id,
    enc_client_secret,
    enc_username,
    enc_password);

  UBIQ_DEBUG(debug_flag, printf("%s: %s %d \n", csu, "snprintf", len));

  
  post_fields = calloc(len + 2, sizeof(char));
  snprintf(post_fields, len + 1, 
    "scope=%s&client_id=%s&client_secret=%s&username=%s&password=%s&grant_type=password",
    enc_scope,
    enc_tenant_id,
    enc_client_secret,
    enc_username,
    enc_password);

  UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "snprintf", post_fields));


  res = ubiq_support_http_add_header(hnd, post_fields);

  free(enc_tenant_id);
  free(enc_client_secret);
  free(enc_username);
  free(enc_password);
  free(enc_scope);


  ubiq_support_http_add_header(hnd, "Accept: application/json");
  ubiq_support_http_add_header(hnd, "Cache-Control: no-cache");
  ubiq_support_http_add_header(hnd, "Content-Type: application/x-www-form-urlencoded");

  char * rspbuf = NULL;
  size_t rsplen = 0;
  res = ubiq_support_http_request(hnd, HTTP_RM_POST, url, post_fields, len,
      (void **)&rspbuf, &rsplen);

  UBIQ_DEBUG(debug_flag, printf("%s: res(%d) len(%d) '%s' \n", csu, res, rsplen, rspbuf));

  *json_results = cJSON_ParseWithLength(rspbuf, rsplen);

  ubiq_support_http_handle_destroy(hnd);

  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  free(post_fields);
  free(rspbuf);
  return res;

}

static int getScimSso(
  const struct ubiq_platform_credentials * const creds,
  const struct ubiq_platform_configuration * const config,
  cJSON ** json_results)
{
  static const char * csu = "getScimSso";
  int res = 0;

  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));


  struct ubiq_support_http_handle * hnd = ubiq_support_http_handle_create();

  const char * host = ubiq_platform_credentials_get_host(creds);
  const char * idp_customer_id = ubiq_platform_configuration_get_idp_customer_id(config);
  const char * api_path = "api/v3";

  char tmp[1];
  char * url = NULL;

  size_t len = snprintf(tmp, sizeof(tmp), "%s/%s/%s/scim/sso", host, idp_customer_id, api_path);

  url = calloc(len + 2, sizeof(char));
  snprintf(url, len + 1, "%s/%s/%s/scim/sso", host, idp_customer_id, api_path);

  UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "url", url));

  char * bearer = NULL;

  len = snprintf(tmp, sizeof(tmp), "Authorization: Bearer %s", ubiq_platform_credentials_get_access_token(creds));
  bearer = calloc(len + 2, sizeof(char));
  snprintf(bearer, len + 1, "Authorization: Bearer %s", ubiq_platform_credentials_get_access_token(creds));

  ubiq_support_http_add_header(hnd, bearer);
  ubiq_support_http_add_header(hnd, "Accept: application/json");
  ubiq_support_http_add_header(hnd, "Cache-Control: no-cache");
  ubiq_support_http_add_header(hnd, "Content-Type: application/json");

  cJSON * csr = cJSON_CreateObject();

  const char * t = ubiq_platform_credentials_get_csr(creds);
  UBIQ_DEBUG(debug_flag, printf("%s: %s\n %s \n", csu, "csr", t));
  cJSON_AddStringToObject(csr, "csr", t);
  char * str = cJSON_Print(csr);

  cJSON_Delete(csr);
  UBIQ_DEBUG(debug_flag, printf("%s: %s\n %s \n", csu, "str", str));


  char * rspbuf = NULL;
  size_t rsplen = 0;
  res = ubiq_support_http_request(hnd, HTTP_RM_POST, url, str, strlen(str),
      (void **)&rspbuf, &rsplen);

  *json_results = cJSON_ParseWithLength(rspbuf, rsplen);

  UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "rspbuf", rspbuf));

  free(rspbuf);
  free(str);

  ubiq_support_http_handle_destroy(hnd);

  free(url);
  free(bearer);
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));
  return res;
}

static int
parseSsoAndSetCreds(
  cJSON * json_results,
  struct ubiq_platform_credentials * const creds)
{
  static const char * csu = "parseSsoAndSetCreds";
  int res = 0;

  char * public_value = NULL;
  char * signing_value = NULL;
  char * api_cert = NULL;
  int enabled = 0;

  cJSON * element = NULL;

  element = cJSON_GetObjectItem(json_results, "public_value");
  if (!res && (!element || !cJSON_IsString(element))) {
    res = -EINVAL;
  } else {
    public_value = strdup(cJSON_GetStringValue(element));
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "public_value", public_value));
  }
  element = cJSON_GetObjectItem(json_results, "signing_value");
  if (!res && (!element || !cJSON_IsString(element))) {
    res = -EINVAL;
  } else {
    signing_value = strdup(cJSON_GetStringValue(element));
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "signing_value", signing_value));
  }
  element = cJSON_GetObjectItem(json_results, "api_cert");
  if (!res && (!element || !cJSON_IsString(element))) {
    res = -EINVAL;
  } else {
    api_cert = strdup(cJSON_GetStringValue(element));
    UBIQ_DEBUG(debug_flag, printf("%s: %s %s \n", csu, "api_cert", api_cert));
  }
  element = cJSON_GetObjectItem(json_results, "enabled");
  if (!res && (!element || !cJSON_IsBool(element))) {
    res = -EINVAL;
  } else {
    enabled = cJSON_IsTrue(element);
    UBIQ_DEBUG(debug_flag, printf("%s: %s %d \n", csu, "enabled", enabled));
  }

  if (!res && enabled && public_value && signing_value && api_cert) {
    ubiq_platform_credentials_set_papi(creds, public_value);
    ubiq_platform_credentials_set_sapi(creds, signing_value);
    ubiq_platform_credentials_set_rsa_cert(creds, api_cert);
  }

  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));
  free(public_value);
  free(signing_value);
  free(api_cert);
  return res;
}
