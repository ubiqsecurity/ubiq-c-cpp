#include "ubiq/platform.h"

#include <system_error>
#include <cstring>

#include "ubiq/platform/internal/parsing.h"

using namespace ubiq::platform::structured;

decryption::decryption(::ubiq_platform_structured_enc_dec_obj * d)
{
   _dec.reset(d, &ubiq_platform_structured_enc_dec_destroy);
}

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

decryption::decryption(
  const credentials & creds,
  const configuration & cfg)
{
    struct ubiq_platform_structured_enc_dec_obj * enc(nullptr);
    int res;

    res = ubiq_platform_structured_enc_dec_create_with_config(&*creds, &*cfg, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), get_error(enc));
    }

    _dec.reset(enc, &ubiq_platform_structured_enc_dec_destroy);
}

std::string
decryption::decrypt(
  const std::string & ffs_name,
  const std::string & ct
)
{
  return decrypt(ffs_name, std::vector<std::uint8_t>(), ct);
}

std::u32string
decryption::decrypt(
  const std::string & ffs_name,
  const std::u32string & ct
)
{
  return decrypt(ffs_name, std::vector<std::uint8_t>(), ct);
}


int32_t
decryption::decryptInt(
  const std::string & ffs_name,
  const int32_t & ct
)
{
  return decryptInt(ffs_name, std::vector<std::uint8_t>(), ct);
}

int64_t
decryption::decryptLong(
  const std::string & ffs_name,
  const int64_t & ct
)
{
  return decryptLong(ffs_name, std::vector<std::uint8_t>(), ct);
}

struct tm
decryption::decryptDate(
  const std::string & ffs_name,
  const struct tm & ct
)
{
  return decryptDate(ffs_name, std::vector<std::uint8_t>(), ct);
}

struct tm
decryption::decryptDateTime(
  const std::string & ffs_name,
  const struct tm & ct
)
{
  return decryptDateTime(ffs_name, std::vector<std::uint8_t>(), ct);
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
  char32_t * u32ptbuf = nullptr;
  char32_t * u32ct = nullptr;

  size_t ptlen;
  int res;

  res = convert_utf8_to_utf32((const uint8_t*)ct.c_str(), (uint32_t**)&u32ct);
  if (!res) {

    res = ubiq_platform_structured_decrypt_u32data(
      _dec.get(), ffs_name.data(),
      tweak.data(), tweak.size(),
      u32ct, u32_strlen((uint32_t*)u32ct),
      &u32ptbuf, &ptlen);
  }
  if (!res) {
    convert_utf32_to_utf8((uint32_t*)u32ptbuf, (uint8_t**)&ptbuf);
  }

  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

  pt = std::string(ptbuf, strlen(ptbuf));
  std::free(ptbuf);
  std::free(u32ptbuf);
  std::free(u32ct);
  return pt;
}

std::u32string
decryption::decrypt(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const std::u32string & ct
)
{
  std::u32string pt;
  char32_t * ptbuf;
  size_t ptlen;
  int res;

  res = ubiq_platform_structured_decrypt_u32data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    ct.data(), ct.length(),
    &ptbuf, &ptlen);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

  pt = std::u32string(ptbuf, ptlen);
  std::free(ptbuf);
  return pt;
}

int32_t
decryption::decryptInt(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const int32_t & ct
)
{
  int32_t pt;
  int res;

  res = ubiq_platform_structured_decrypt_int_data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    ct,
    &pt);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

  return pt;
}

int64_t
decryption::decryptLong(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const int64_t & ct
)
{
  int64_t pt;
  int res;

  res = ubiq_platform_structured_decrypt_long_data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    ct,
    &pt);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

  return pt;
}

struct tm
decryption::decryptDate(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const struct tm & ct
)
{
  struct tm pt;
  int res;

  res = ubiq_platform_structured_decrypt_date_data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    &ct,
    &pt);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

  return pt;
}

struct tm
decryption::decryptDateTime(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const struct tm & ct
)
{
  struct tm pt;
  int res;

  res = ubiq_platform_structured_decrypt_datetime_data(
    _dec.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    &ct,
    &pt);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_dec.get()));
  }

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

