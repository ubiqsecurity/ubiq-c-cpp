#include "ubiq/platform.h"

#include <system_error>
#include <cstring>
#include "ubiq/platform/internal/parsing.h"


using namespace ubiq::platform::structured;

encryption::encryption(::ubiq_platform_structured_enc_dec_obj * e)
{
   _enc.reset(e, &ubiq_platform_structured_enc_dec_destroy);
}


encryption::encryption(const credentials & creds,
  const configuration & cfg
) {
    struct ubiq_platform_structured_enc_dec_obj * enc(nullptr);
    int res;

    res = ubiq_platform_structured_enc_dec_create_with_config(&*creds, &(*cfg), &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), get_error(enc));
    }

    _enc.reset(enc, &ubiq_platform_structured_enc_dec_destroy);

}


encryption::encryption(const credentials & creds)
{
    struct ubiq_platform_structured_enc_dec_obj * enc(nullptr);

    int res;

    res = ubiq_platform_structured_enc_dec_create(&*creds, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), get_error(enc));
    }

    _enc.reset(enc, &ubiq_platform_structured_enc_dec_destroy);
}

std::string
encryption::encrypt(
  const std::string & ffs_name,
  const std::string & pt
)
{
  // printf("encryption::encrypt (no tweak) string dataset(%s) \n", ffs_name.c_str());
  return encrypt(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::u32string
encryption::encrypt(
  const std::string & ffs_name,
  const std::u32string & pt
)
{
  return encrypt(ffs_name, std::vector<std::uint8_t>(), pt);
}

int32_t
encryption::encryptInt(
  const std::string & ffs_name,
  const int32_t & pt
)
{
  return encryptInt(ffs_name, std::vector<std::uint8_t>(), pt);
}

int64_t
encryption::encryptLong(
  const std::string & ffs_name,
  const int64_t & pt
)
{
  return encryptLong(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::vector<std::string>
encryption::encrypt_for_search(
  const std::string & ffs_name,
  const std::string & pt
)
{
  return encrypt_for_search(ffs_name, std::vector<std::uint8_t>(), pt);
}


std::vector<std::string>
encryption::encrypt_for_search(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const std::string & pt
)
{
  std::vector<std::string> ct;
  int res;
  char ** ctbuf;
  size_t count;

  res = ubiq_platform_structured_encrypt_data_for_search(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    pt.data(), pt.length(),
    &ctbuf, &count);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct.reserve(count);
  // ct length is not reliable for all elements of ctbuf since the multibyte UTF8
  // may be different for each value.
  for (int i=0; i< count; i++) {
    ct.emplace(ct.end(), std::move(std::string(ctbuf[i])));
    std::free(ctbuf[i]);
  }
  std::free(ctbuf);
  return ct;
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
  char32_t * u32ctbuf = nullptr;
  char32_t * u32pt = nullptr;
  size_t ctlen;
  int res;

  // printf("encryption::encrypt (w/tweak) string dataset(%s) pt(%s)\n", ffs_name.c_str(), pt.c_str());

  res = convert_utf8_to_utf32((const uint8_t*)pt.c_str(), (uint32_t**)&u32pt);
  // printf("convert_utf8_to_utf32 res(%d) %S\n", res, u32pt);
  if (!res) {
    res = ubiq_platform_structured_encrypt_u32data(
      _enc.get(), ffs_name.data(),
      tweak.data(), tweak.size(),
      u32pt, u32_strlen((uint32_t*)u32pt),
      &u32ctbuf, &ctlen);
  }
  if (!res) {
    res = convert_utf32_to_utf8((uint32_t*)u32ctbuf, (uint8_t**)&ctbuf);
  }
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct = std::string(ctbuf, strlen(ctbuf));
  std::free(u32ctbuf);
  std::free(ctbuf);
  std::free(u32pt);
  return ct;
}

std::u32string
encryption::encrypt(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const std::u32string & pt
)
{
  std::u32string ct;
  char32_t * ctbuf;
  size_t ctlen;
  int res;

  res = ubiq_platform_structured_encrypt_u32data(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    pt.data(), pt.length(),
    &ctbuf, &ctlen);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct = std::u32string(ctbuf, ctlen);
  std::free(ctbuf);
  return ct;
}

int32_t
encryption::encryptInt(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const int32_t & pt
)
{
  int32_t ct;
  int res;

  res = ubiq_platform_structured_encrypt_int_data(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    pt,
    &ct);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  return ct;
}

std::vector<int32_t>
encryption::encryptInt_for_search(
  const std::string & ffs_name,
  const int32_t & pt
)
{
  return encryptInt_for_search(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::vector<int32_t>
encryption::encryptInt_for_search(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const int32_t & pt
)
{
  std::vector<int32_t> ct;
  int res;
  int32_t * ctbuf;
  size_t count;

  res = ubiq_platform_structured_encrypt_int_data_for_search(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    pt,
    &ctbuf, &count);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct.reserve(count);
  // ct length is not reliable for all elements of ctbuf since the multibyte UTF8
  // may be different for each value.
  for (int i=0; i< count; i++) {
    ct.push_back(ctbuf[i]);
  }
  std::free(ctbuf);
  return ct;
}

int64_t
encryption::encryptLong(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const int64_t & pt
)
{
  int64_t ct;
  int res;

  res = ubiq_platform_structured_encrypt_long_data(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    pt,
    &ct);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  return ct;
}

std::vector<int64_t>
encryption::encryptLong_for_search(
  const std::string & ffs_name,
  const int64_t & pt
)
{
  return encryptLong_for_search(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::vector<int64_t>
encryption::encryptLong_for_search(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const int64_t & pt
)
{
  std::vector<int64_t> ct;
  int res;
  int64_t * ctbuf;
  size_t count;

  res = ubiq_platform_structured_encrypt_long_data_for_search(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    pt,
    &ctbuf, &count);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct.reserve(count);
  // ct length is not reliable for all elements of ctbuf since the multibyte UTF8
  // may be different for each value.
  for (int i=0; i< count; i++) {
    ct.push_back(ctbuf[i]);
  }
  std::free(ctbuf);
  return ct;
}

struct tm 
encryption::encryptDate(
  const std::string & ffs_name,
  const struct tm & pt
)
{
  return encryptDate(ffs_name, std::vector<std::uint8_t>(), pt);
}

struct tm 
encryption::encryptDate(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const struct tm & pt
)
{
  struct tm ct;
  int res = 0;
  
  res = ubiq_platform_structured_encrypt_date_data(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    &pt,
    &ct);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  return ct;

}

std::vector<struct tm>
encryption::encryptDate_for_search(
  const std::string & ffs_name,
  const struct tm & pt
)
{
  return encryptDate_for_search(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::vector<struct tm>
encryption::encryptDate_for_search(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const struct tm & pt
)
{
  std::vector<struct tm> ct;
  int res;
  struct tm * ctbuf;
  size_t count;

  res = ubiq_platform_structured_encrypt_date_data_for_search(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    &pt,
    &ctbuf, &count);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct.reserve(count);
  // ct length is not reliable for all elements of ctbuf since the multibyte UTF8
  // may be different for each value.
  for (int i=0; i< count; i++) {
    ct.push_back(ctbuf[i]);
  }
  std::free(ctbuf);
  return ct;

}

struct tm 
encryption::encryptDateTime(
  const std::string & ffs_name,
  const struct tm & pt
)
{
  return encryptDateTime(ffs_name, std::vector<std::uint8_t>(), pt);
}

struct tm 
encryption::encryptDateTime(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const struct tm & pt
)
{
  struct tm ct;
  int res = 0;
  
  res = ubiq_platform_structured_encrypt_datetime_data(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    &pt,
    &ct);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  return ct;

}

std::vector<struct tm>
encryption::encryptDateTime_for_search(
  const std::string & ffs_name,
  const struct tm & pt
)
{
  return encryptDateTime_for_search(ffs_name, std::vector<std::uint8_t>(), pt);
}

std::vector<struct tm>
encryption::encryptDateTime_for_search(
  const std::string & ffs_name,
  const std::vector<std::uint8_t> & tweak,
  const struct tm & pt
)
{
  std::vector<struct tm> ct;
  int res;
  struct tm * ctbuf;
  size_t count;

  res = ubiq_platform_structured_encrypt_datetime_data_for_search(
    _enc.get(), ffs_name.data(),
    tweak.data(), tweak.size(),
    &pt,
    &ctbuf, &count);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category(), get_error(_enc.get()));
  }

  ct.reserve(count);
  // ct length is not reliable for all elements of ctbuf since the multibyte UTF8
  // may be different for each value.
  for (int i=0; i< count; i++) {
    ct.push_back(ctbuf[i]);
  }
  std::free(ctbuf);
  return ct;

}

std::string
ubiq::platform::structured::get_error(struct ubiq_platform_structured_enc_dec_obj * const enc)
{
  std::string ret("Unknown internal error");
  char * err_msg = NULL;
  int err_num;

  if (enc) {
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);

    if (err_num != 0 && err_msg != NULL) {
      ret = err_msg;
    }
    free(err_msg);
  }
  return ret;
}

std::string
encryption::get_copy_of_usage(void) {
  std::string s("");
  char * buf(nullptr);
  size_t len;
  int res(0);

  res = ubiq_platform_structured_enc_dec_get_copy_of_usage(_enc.get(), &buf, &len);
  if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
  s.resize(len);
  std::memcpy((char *)s.data(), buf, len);
  std::free(buf);

  return s;
}

void
encryption::add_user_defined_metadata(const std::string & jsonString) {
  int res(0);

  res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(_enc.get(), jsonString.data());
  if (res != 0) {
      throw std::system_error(-res, std::generic_category());
  }
}