#include "ubiq/platform.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform::fpe;



decryption::decryption(const credentials & creds)
{
    struct ubiq_platform_fpe_enc_dec_obj * enc;
    int res;

    res = ubiq_platform_fpe_enc_dec_create(&*creds, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _dec.reset(enc, &ubiq_platform_fpe_enc_dec_destroy);
}

std::string
decryption::decrypt(
  const std::string & ffs_name,
  const std::string & pt
)
{
  return decrypt(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::string
decryption::decrypt(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const std::string & ct
)
{
  std::string pt;
  char * ptbuf;
  size_t ptlen;
  int res;

  res = ubiq_platform_fpe_decrypt_data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    ct.data(), ct.length(),
    &ptbuf, &ptlen);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }

  pt = std::string(ptbuf, ptlen);
  std::free(ptbuf);
  return pt;
}


std::string
ubiq::platform::fpe::decrypt(
    const credentials & creds,
    const std::string & ffs_name,
    const std::string & ct)
{
  return decrypt(creds, ffs_name, std::vector<std::uint8_t>(), ct);
}

std::string
ubiq::platform::fpe::decrypt(
    const credentials & creds,
    const std::string & ffs_name,
    const std::vector<std::uint8_t> & tweak,
    const std::string & ct)
{
    std::string pt;
    char * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_fpe_decrypt(&*creds, ffs_name.data(),
    tweak.data(), tweak.size(),
    ct.data(), ct.length(),
    &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    pt = std::string(ptbuf, ptlen);
    std::free(ptbuf);

    return pt;
}
