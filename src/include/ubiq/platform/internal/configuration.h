#pragma once

#include <ubiq/platform/compat/cdefs.h>
#include <ubiq/platform/configuration.h>

__BEGIN_DECLS

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

__END_DECLS

/*
 * local variables:
 * mode: c++
 * end:
 */
