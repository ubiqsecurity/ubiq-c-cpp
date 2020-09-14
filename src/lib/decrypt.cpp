#include "ubiq/platform/decrypt.h"

#include <system_error>
#include <cstring>

using namespace ubiq::platform;

decryption::decryption(const credentials & creds)
{
    struct ubiq_platform_decryption * dec;
    int res;

    res = ubiq_platform_decryption_create(&*creds, &dec);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _dec.reset(dec, &ubiq_platform_decryption_destroy);
}

std::vector<std::uint8_t>
decryption::begin(void)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decryption_begin(_dec.get(), &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}

std::vector<std::uint8_t>
decryption::update(const void * ctbuf, std::size_t ctlen)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decryption_update(
        _dec.get(), ctbuf, ctlen, &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}

std::vector<std::uint8_t>
decryption::end(void)
{
    std::vector<std::uint8_t> v;
    void * ptbuf;
    size_t ptlen;
    int res;

    res = ubiq_platform_decryption_end(_dec.get(), &ptbuf, &ptlen);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
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
        throw std::system_error(-res, std::generic_category());
    }

    v.resize(ptlen);
    std::memcpy(v.data(), ptbuf, ptlen);
    std::free(ptbuf);

    return v;
}
