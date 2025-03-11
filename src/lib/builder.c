#include "ubiq/platform.h"

#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"
#include "ubiq/platform/internal/sso.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;

struct ubiq_platform_builder
{
    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * config;
    int creds_locally_managed;
    int config_locally_managed;
} ;

static void free_creds(struct ubiq_platform_builder * builder) {
  if (builder && builder->creds_locally_managed) {
    ubiq_platform_credentials_destroy(builder->creds);
    builder->creds_locally_managed = 0;
  }
}

static void free_config(struct ubiq_platform_builder * builder) {
  if (builder && builder->config_locally_managed) {
    ubiq_platform_configuration_destroy(builder->config);
    builder->config_locally_managed = 0;
  }
}


int
ubiq_platform_builder_create(
    struct ubiq_platform_builder ** const builder)
{
  int res;
  res = -ENOMEM;

  struct ubiq_platform_builder * c = NULL;

  c = calloc(1, sizeof(*c));
  if (c) {
    *builder = c;
    res = 0;
  }

  if (res != 0) {
    free(c);
    c = NULL;
  }
  return res;
}

void
ubiq_platform_builder_destroy(
    struct ubiq_platform_builder * const builder)
{
  free_creds(builder);
  free_config(builder);
  free(builder);
}

int
ubiq_platform_builder_set_credentials_file(
  struct ubiq_platform_builder * const builder,
  const char * filename,
  const char * profile
)
{
  int res = -EINVAL;
  if ((res = ubiq_platform_credentials_create_specific(filename, profile, &(builder->creds))) == 0) {
    builder->creds_locally_managed = 1;
  }
}

int
ubiq_platform_builder_set_credentials(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_credentials * const creds
)
{
  int res = -EINVAL;
  if (builder && creds) {
    free_creds(builder);
    builder->creds = creds;
    res = 0;
  }
  return res;
}

int
ubiq_platform_builder_set_configuration(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_configuration * const config
)
{
  int res = -EINVAL;
  if (builder && config) {
    free_config(builder);
    builder->config = config;
    res = 0;
  }
  return res;
}


static int check_credentials_and_config(
   struct ubiq_platform_builder * const builder
)
{
  static const char * csu = "check_credentials_and_config";
  int res = 0;
  if (!builder->creds) {
    if ((res = ubiq_platform_credentials_create(&(builder->creds))) == 0) {
      builder->creds_locally_managed = 1;
    }
  }
  if (!res && !builder->config) {
    if ((res = ubiq_platform_configuration_create(&(builder->config))) == 0) {
      builder->config_locally_managed = 1;
    }
  }

  if (!res && ubiq_platform_credentials_is_idp(builder->creds)) {
    // Don't login again if the access token is already set.
    if (ubiq_platform_credentials_get_access_token(builder->creds) == NULL) {
      if ((res = ubiq_platform_sso_login(builder->creds, builder->config)) != 0) {
        
      }
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  return res;
}

int
ubiq_platform_builder_build_structured(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_structured_enc_dec_obj ** structured
) 
{
  static const char * csu = "ubiq_platform_builder_build_structured";

  int res = -EINVAL;

  if (builder != NULL) {
    // Make sure credentials and config are loaded / set
    res = check_credentials_and_config(builder);
   
    if (!res) {
      res = ubiq_platform_structured_enc_dec_create_with_config(builder->creds,
        builder->config, 
        structured);
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  return res;
}

int
ubiq_platform_builder_build_unstructured_encrypt(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_encryption ** encrypt
)
{
  static const char * csu = "ubiq_platform_builder_build_unstructured_encrypt";

  int res = -EINVAL;

  if (builder != NULL) {
    // Make sure credentials and config are loaded / set
    res = check_credentials_and_config(builder);

    if (!res) {
      res = ubiq_platform_encryption_create_with_config(builder->creds,
        builder->config,
        1,
        encrypt);
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));

  return res;

}

int
ubiq_platform_builder_build_unstructured_decrypt(
  struct ubiq_platform_builder * const builder,
  struct ubiq_platform_decryption ** decrypt
)
{
  static const char * csu = "ubiq_platform_builder_build_unstructured_encrypt";
  int res = -EINVAL;

  if (builder != NULL) {
    // Make sure credentials and config are loaded / set
    res = check_credentials_and_config(builder);

    if (!res) {
      res = ubiq_platform_decryption_create_with_config(builder->creds,
        builder->config,
        decrypt);
    }
  }

  UBIQ_DEBUG(debug_flag, printf("%s: %d \n", csu, res));
  return res;

}