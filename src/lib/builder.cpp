#include "ubiq/platform.h"

#include "ubiq/platform/internal/credentials.h"
#include "ubiq/platform/internal/configuration.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <system_error>

// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;

using namespace ubiq::platform;

builder::builder(void) {
  struct ubiq_platform_builder * builder;
    int res;

    res = ubiq_platform_builder_create(&builder);
    if (res == 0) {
        _builder.reset(builder, &ubiq_platform_builder_destroy);
    }
}

builder & builder::with(const configuration & cfg) {
  ubiq_platform_builder_set_configuration(_builder.get(), (struct ubiq_platform_configuration * const)&(*cfg));
  return *this;
}

builder & builder::with(const credentials & creds) {
  ubiq_platform_builder_set_credentials(_builder.get(), (struct ubiq_platform_credentials * const)&(*creds));
  return *this;
}

encryption builder::buildUnstructuredEncryption(void)
{
  struct ubiq_platform_encryption * e = NULL;
  int res = ubiq_platform_builder_build_unstructured_encrypt(_builder.get(), &e);

   if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
  return encryption(e);
}

decryption builder::buildUnstructuredDecryption(void)
{
  struct ubiq_platform_decryption * d = NULL;
  int res = ubiq_platform_builder_build_unstructured_decrypt(_builder.get(), &d);

   if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
  return decryption(d);
}

structured::encryption builder::buildStructuredEncryption(void)
{
  struct ubiq_platform_structured_enc_dec_obj * e = NULL;
  int res = ubiq_platform_builder_build_structured(_builder.get(), &e);

   if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
  return structured::encryption(e);  
}

structured::decryption builder::buildStructuredDecryption(void)
{
  struct ubiq_platform_structured_enc_dec_obj * d = NULL;
  int res = ubiq_platform_builder_build_structured(_builder.get(), &d);

   if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
  return structured::decryption(d);    
}

const ::ubiq_platform_builder & builder::operator *(void) const
{
    return *_builder;
}

builder::operator bool(void) const
{
    return !!_builder.get();
}

