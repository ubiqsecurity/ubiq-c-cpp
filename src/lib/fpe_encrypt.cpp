#include "ubiq/platform.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform::fpe;



encryption::encryption(const credentials & creds)
{
    struct ubiq_platform_fpe_encryption * enc;
    int res;

    res = ubiq_platform_fpe_encryption_create(&*creds, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _enc.reset(enc, &ubiq_platform_fpe_encryption_destroy);
}

std::string
encryption::encrypt(
  const std::string & ffs_name,
  const std::string & pt
)
{
  return encrypt(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::string
encryption::encrypt(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const std::string & pt
)
{
  std::string ct;
  char * ctbuf;
  size_t ctlen;
  int res;

  res = ubiq_platform_fpe_encrypt_data(
    _enc.get(), ffs_name.data(),
    NULL, 0, //tweak.data(), tweak.size(),
    pt.data(), pt.length(),
    &ctbuf, &ctlen);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }

  ct = std::string(ctbuf, ctlen);
  std::free(ctbuf);
  return ct;
}


std::string
ubiq::platform::fpe_encrypt(
    const credentials & creds,
    const std::string & ffs_name,
    const std::string & pt)
{
    std::string v;
    char * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_fpe_encrypt(&*creds, ffs_name.data(),
    NULL, 0,
    pt.data(), pt.length(),
    &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    v = std::string(ctbuf, ctlen);
    // v.resize(ctlen);
    // std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}
