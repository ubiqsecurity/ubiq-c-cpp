#include "ubiq/platform/credentials.h"

#include <system_error>

using namespace ubiq::platform;

credentials::credentials(void)
{
    struct ubiq_platform_credentials * creds;
    int res;

    res = ubiq_platform_credentials_create(&creds);
    if (res == 0) {
        _cred.reset(creds, &ubiq_platform_credentials_destroy);
    }
}

credentials::credentials(
    const std::string & path, const std::string & profile)
{
    struct ubiq_platform_credentials * creds;
    int res;

    res = ubiq_platform_credentials_create_specific(
        path.empty() ? nullptr : path.c_str(),
        profile.empty() ? nullptr : profile.c_str(),
        &creds);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _cred.reset(creds, &ubiq_platform_credentials_destroy);
}

credentials::credentials(
    const std::string & papi, const std::string & sapi,
    const std::string & srsa,
    const std::string & host)
{
    struct ubiq_platform_credentials * creds;
    int res;

    res = ubiq_platform_credentials_create_explicit(
        papi.c_str(), sapi.c_str(),
        srsa.c_str(),
        host.empty() ? nullptr : host.c_str(),
        &creds);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _cred.reset(creds, &ubiq_platform_credentials_destroy);
}

const ::ubiq_platform_credentials & credentials::operator *(void) const
{
    return *_cred;
}

credentials::operator bool(void) const
{
    return !!_cred.get();
}
