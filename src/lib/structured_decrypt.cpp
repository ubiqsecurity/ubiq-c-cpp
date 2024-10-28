#include "ubiq/platform.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform::structured;


decryption::decryption(const credentials & creds)
{
    struct ubiq_platform_structured_enc_dec_obj * enc(nullptr);
    int res;

    res = ubiq_platform_structured_enc_dec_create(&*creds, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), get_error(enc));
    }

    _dec.reset(enc, &ubiq_platform_structured_enc_dec_destroy);
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

  res = ubiq_platform_structured_decrypt_data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    ct.data(), ct.length(),
    &ptbuf, &ptlen);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

  pt = std::string(ptbuf, ptlen);
  std::free(ptbuf);
  return pt;
}

std::string
decryption:: get_copy_of_usage(void) {
  std::string s("");
  char * buf(nullptr);
  size_t len;
  int res(0);

  res = ubiq_platform_structured_enc_dec_get_copy_of_usage(_dec.get(), &buf, &len);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
  s.resize(len);
  std::memcpy((char *)s.data(), buf, len);
  std::free(buf);

  return s;
}

void
decryption::add_user_defined_metadata(const std::string & jsonString) {
  int res(0);

  res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(_dec.get(), jsonString.data());
  if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
}

