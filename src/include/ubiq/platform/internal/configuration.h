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

const char *
ubiq_platform_configuration_get_idp_type(
    const struct ubiq_platform_configuration * const config);
const char *
ubiq_platform_configuration_get_idp_customer_id(
    const struct ubiq_platform_configuration * const config);
const char *
ubiq_platform_configuration_get_idp_token_endpoint_url(
    const struct ubiq_platform_configuration * const config);
const char *
ubiq_platform_configuration_get_idp_tenant_id(
    const struct ubiq_platform_configuration * const config);
const char *
ubiq_platform_configuration_get_idp_client_secret(
    const struct ubiq_platform_configuration * const config);

void
ubiq_platform_configuration_set_idp_type(
    struct ubiq_platform_configuration * const config,
    const char * idp_type);
void
ubiq_platform_configuration_set_idp_customer_id(
    struct ubiq_platform_configuration * const config,
    const char * idp_customer_id);
void
ubiq_platform_configuration_set_idp_token_endpoint_url(
    struct ubiq_platform_configuration * const config,
    const char * idp_token_endpoint_url);
void
ubiq_platform_configuration_set_idp_tenant_id(
    struct ubiq_platform_configuration * const config,
    const char * idp_tenant_id);
void
ubiq_platform_configuration_set_idp_client_secret(
    struct ubiq_platform_configuration * const config,
    const char * idp_client_secret);

int
ubiq_platform_configuration_is_idp_set(
    const struct ubiq_platform_configuration * const config);

// Deep copy
int ubiq_platform_configuration_clone(
  const struct ubiq_platform_configuration * const src,
  struct ubiq_platform_configuration ** const dest);

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
