#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS


typedef enum reporting_granularity {
  NANOS = 0,
  MILLIS,
  SECONDS,
  MINUTES,
  HOURS,
  HALF_DAYS,
  DAYS
} reporting_granularity_t; 

const int
ubiq_platform_configuration_get_event_reporting_wake_interval(
    const struct ubiq_platform_configuration * const config);
const int
ubiq_platform_configuration_get_event_reporting_min_count(
    const struct ubiq_platform_configuration * const config);
const int
ubiq_platform_configuration_get_event_reporting_flush_interval(
    const struct ubiq_platform_configuration * const config);
const int 
ubiq_platform_configuration_get_event_reporting_trap_exceptions(
    const struct ubiq_platform_configuration * const config);
const reporting_granularity_t
ubiq_platform_configuration_get_event_reporting_timestamp_granularity(
    const struct ubiq_platform_configuration * const config);

const int
ubiq_platform_configuration_get_key_caching_encrypt(
    const struct ubiq_platform_configuration * const config);
const int
ubiq_platform_configuration_get_key_caching_structured_keys(
    const struct ubiq_platform_configuration * const config);
const int
ubiq_platform_configuration_get_key_caching_unstructured_keys(
    const struct ubiq_platform_configuration * const config);
const int
ubiq_platform_configuration_get_key_caching_ttl_seconds(
    const struct ubiq_platform_configuration * const config);


__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
