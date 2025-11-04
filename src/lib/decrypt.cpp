#include "ubiq/platform/decrypt.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform;

decryption::decryption(::ubiq_platform_decryption * d)
{
   _dec.reset(d, &ubiq_platform_decryption_destroy);
}

decryption::decryption(const credentials & creds)
{
    struct ubiq_platform_decryption * dec;
    int res;

    res = ubiq_platform_decryption_create(&*creds, &dec);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decryption_create");
    }

    _dec.reset(dec, &ubiq_platform_decryption_destroy);
}

decryption::decryption(const credentials & creds, const configuration & cfg)
{
    struct ubiq_platform_decryption * dec;
    int res;

    res = ubiq_platform_decryption_create_with_config(&*creds, &*cfg, &dec);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decryption_create_with_config");
    }

    _dec.reset(dec, &ubiq_platform_decryption_destroy);
}


std::vector<std::uint8_t>
decryption::begin(void)
{
  _session = decryption_session(*this);
  return begin(_session);
}

std::vector<std::uint8_t>
decryption::begin(decryption_session &session)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decryption_beginTS(_dec.get(), session._session.get(), &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decryption_beginTS");
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}

std::vector<std::uint8_t>
decryption::update(const void * ctbuf, std::size_t ctlen)
{
  return update(_session, ctbuf, ctlen);
}

std::vector<std::uint8_t>
decryption::update(decryption_session &session, const void * ctbuf, std::size_t ctlen)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decryption_updateTS(
        _dec.get(), session._session.get(), ctbuf, ctlen, &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decryption_updateTS");
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}

std::vector<std::uint8_t>
decryption::end(void)
{
  return end(_session);
}

std::vector<std::uint8_t>
decryption::end(decryption_session &session)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decryption_endTS(_dec.get(), session._session.get(), &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decryption_endTS");
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}

std::vector<std::uint8_t>
ubiq::platform::decrypt(const credentials & creds,
                       const void * ctbuf, std::size_t ctlen)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decrypt(&*creds, ctbuf, ctlen, &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decrypt");
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}


std::string
decryption::get_copy_of_usage(void)
{
    std::string v("");
    char * buf(nullptr);
    size_t len(0);
    int res(0);

    res = ubiq_platform_decryption_get_copy_of_usage(_dec.get(), &buf, &len);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during ubiq_platform_decryption_get_copy_of_usage");
    }

    v.resize(len);
    std::memcpy((char *)v.data(), buf, len);
    std::free(buf);

    return v;
}

void
decryption::add_user_defined_metadata(const std::string & jsonString)
{
    int res = ubiq_platform_decryption_add_user_defined_metadata(_dec.get(), 
    jsonString.data());
    if (res != 0) {
        throw std::system_error(-res, std::generic_category(), "during add_user_defined_metadata");
    }
}
