#include "ubiq/platform/configuration.h"

#include <system_error>

using namespace ubiq::platform;

configuration::configuration(void)
{
    struct ubiq_platform_configuration * creds;
    int res;

    res = ubiq_platform_configuration_create(&creds);
    if (res == 0) {
        _config.reset(creds, &ubiq_platform_configuration_destroy);
    }
}

configuration::configuration(
    const std::string & path)
{
    struct ubiq_platform_configuration * creds;
    int res;

    res = ubiq_platform_configuration_load_configuration(
        path.empty() ? nullptr : path.c_str(),
        &creds);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _config.reset(creds, &ubiq_platform_configuration_destroy);
}

configuration::configuration(
  const int event_reporting_wake_interval,
  const int event_reporting_minimum_count,
  const int event_reporting_flush_interval,
  const int event_reporting_trap_exceptions,
  const std::string & event_reporting_timestamp_granularity)
{
    struct ubiq_platform_configuration * creds;
    int res;

    res = ubiq_platform_configuration_create_explicit(
        event_reporting_wake_interval,
        event_reporting_minimum_count,
        event_reporting_flush_interval,
        event_reporting_trap_exceptions,
        event_reporting_timestamp_granularity.data(),
        &creds);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _config.reset(creds, &ubiq_platform_configuration_destroy);
}

configuration::configuration(
              const int event_reporting_wake_interval,
              const int event_reporting_minimum_count,
              const int event_reporting_flush_interval,
              const int event_reporting_trap_exceptions,
              const std::string & event_reporting_timestamp_granularity,
              const int key_caching_encrypt_keys,
              const int key_caching_structured_keys,
              const int key_caching_unstructured_keys,
              const int key_caching_ttl_seconds)
{
    struct ubiq_platform_configuration * creds;
    int res;

    res = ubiq_platform_configuration_create_explicit2(
        event_reporting_wake_interval,
        event_reporting_minimum_count,
        event_reporting_flush_interval,
        event_reporting_trap_exceptions,
        event_reporting_timestamp_granularity.data(),
        key_caching_encrypt_keys,
        key_caching_structured_keys,
        key_caching_unstructured_keys,
        key_caching_ttl_seconds,
        &creds);
    if (res != 0) {
        throw std::system_error(-res, std::generic_category());
    }

    _config.reset(creds, &ubiq_platform_configuration_destroy);
}              

const ::ubiq_platform_configuration & configuration::operator *(void) const
{
    return *_config;
}

configuration::operator bool(void) const
{
    return !!_config.get();
}
