#include "ubiq/platform/encrypt.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform;

encryption::encryption(::ubiq_platform_encryption * e)
{
   _enc.reset(e, &ubiq_platform_encryption_destroy);
}

encryption::encryption(const credentials & creds, const unsigned int uses)
{
    struct ubiq_platform_encryption * enc;
    int res;

    res = ubiq_platform_encryption_create(&*creds, uses, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_create");
    }

    _enc.reset(enc, &ubiq_platform_encryption_destroy);
}

encryption::encryption(const credentials & creds, const configuration & cfg, unsigned int uses)
{
    struct ubiq_platform_encryption * enc;
    int res;

    res = ubiq_platform_encryption_create_with_config(&*creds, &*cfg, uses, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_create_with_config");
    }

    _enc.reset(enc, &ubiq_platform_encryption_destroy);
}
std::vector<std::uint8_t>
encryption::begin(void)
{

  _session = encryption_session(*this); //.reset(encryption_session(*this),  &ubiq_platform_encryption_destroy_session);
  return begin(_session);
}

std::vector<std::uint8_t>
encryption::begin(encryption_session & session)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encryption_beginTS(_enc.get(), session._session.get(), &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_beginTS");
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}
std::vector<std::uint8_t>
encryption::update(const void * ptbuf, std::size_t ptlen)
{
  return update(_session, ptbuf, ptlen);
}

std::vector<std::uint8_t>
encryption::update(encryption_session & session, const void * ptbuf, std::size_t ptlen)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encryption_updateTS(
        _enc.get(),session._session.get(), ptbuf, ptlen, &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_updateTS");
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}

std::vector<std::uint8_t>
encryption::end(void)
{
  return end(_session);
}

std::vector<std::uint8_t>
encryption::end(encryption_session & session)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encryption_endTS(_enc.get(), session._session.get(), &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_endTS");
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}

std::vector<std::uint8_t>
ubiq::platform::encrypt(
    const credentials & creds, const void * ptbuf, std::size_t ptlen)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encrypt(&*creds, ptbuf, ptlen, &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encrypt");
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}

std::string
encryption::get_copy_of_usage(void)
{
    std::string v("");
    char * ctbuf(nullptr);
    size_t ctlen(0);
    int res(0);

    res = ubiq_platform_encryption_get_copy_of_usage(_enc.get(), &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_get_copy_of_usage");
    }

    v.resize(ctlen);
    std::memcpy((char *)v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}

void
encryption::add_user_defined_metadata(const std::string & jsonString)
{
    int res = ubiq_platform_encryption_add_user_defined_metadata(_enc.get(), 
    jsonString.data());
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_encryption_add_user_defined_metadata");
    }
}

