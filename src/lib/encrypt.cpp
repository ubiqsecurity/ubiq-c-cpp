#include "ubiq/platform/encrypt.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform;

encryption::encryption(const credentials & creds, const unsigned int uses)
{
    struct ubiq_platform_encryption * enc;
    int res;

    res = ubiq_platform_encryption_create(&*creds, uses, &enc);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _enc.reset(enc, &ubiq_platform_encryption_destroy);
}

std::vector<std::uint8_t>
encryption::begin(void)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encryption_begin(_enc.get(), &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}

std::vector<std::uint8_t>
encryption::update(const void * ptbuf, std::size_t ptlen)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encryption_update(
        _enc.get(), ptbuf, ptlen, &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}

std::vector<std::uint8_t>
encryption::end(void)
{
    std::vector<std::uint8_t> v;
    void * ctbuf;
    size_t ctlen;
    int res;

    res = ubiq_platform_encryption_end(_enc.get(), &ctbuf, &ctlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
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
        throw std::system_error(-res, std::generic_category());
    }

    v.resize(ctlen);
    std::memcpy(v.data(), ctbuf, ctlen);
    std::free(ctbuf);

    return v;
}
