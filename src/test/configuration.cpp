#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "ubiq/platform.h"
#include "ubiq/platform/internal/configuration.h"

TEST(c_configuration, automatic)
{
    struct ubiq_platform_configuration * cfg;
    int res;

    res = ubiq_platform_configuration_create(&cfg);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        ubiq_platform_configuration_destroy(cfg);
    }
}


TEST(c_configuration, explicit)
{
    struct ubiq_platform_configuration * cfg;
    int res;

    res = ubiq_platform_configuration_create_explicit(91,92,93,94, "DAYS", &cfg);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 91);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 92);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 93);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 94);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg), DAYS);

        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_structured_keys(cfg), 1);
        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg), 1);
        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg), 1800);
        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_encrypt(cfg), 0);

        ubiq_platform_configuration_destroy(cfg);
    }
}

TEST(c_configuration, explicit2)
{
    struct ubiq_platform_configuration * cfg;
    int res;

    res = ubiq_platform_configuration_create_explicit2(91,92,93,94, "DAYS", 1, 0, 0, 90, &cfg);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 91);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 92);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 93);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 94);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg), DAYS);

        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_structured_keys(cfg), 0);
        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg), 0);
        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg), 90);
        ASSERT_EQ(ubiq_platform_configuration_get_key_caching_encrypt(cfg), 1);

        ubiq_platform_configuration_destroy(cfg);
    }
}

TEST(c_configuration, diff)
{
    struct ubiq_platform_configuration * cfg_default;
    struct ubiq_platform_configuration * cfg;
    int res;

    res = ubiq_platform_configuration_create_explicit2(91,92,93,94, "DAYS", 1, 0, 0, 180, &cfg);
    EXPECT_EQ(res, 0);
    res = ubiq_platform_configuration_create(&cfg_default);
    EXPECT_EQ(res, 0);


    if (res == 0) {
        ASSERT_NE(cfg, nullptr);
        ASSERT_NE(cfg_default, nullptr);

        ASSERT_NE(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 
          ubiq_platform_configuration_get_event_reporting_wake_interval(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_event_reporting_min_count(cfg),
          ubiq_platform_configuration_get_event_reporting_min_count(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 
          ubiq_platform_configuration_get_event_reporting_flush_interval(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg),
          ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg),
          ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_key_caching_encrypt(cfg),
          ubiq_platform_configuration_get_key_caching_encrypt(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_key_caching_structured_keys(cfg),
          ubiq_platform_configuration_get_key_caching_structured_keys(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg),
          ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg_default));
        ASSERT_NE(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg),
          ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg_default));

        ubiq_platform_configuration_destroy(cfg);
        ubiq_platform_configuration_destroy(cfg_default);
    }
}

TEST(c_configuration, load)
{
    struct ubiq_platform_configuration * cfg;
    int res;

    res = ubiq_platform_configuration_load_configuration(nullptr, &cfg);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 1);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 5);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 10);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 0);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg), NANOS);

        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_structured_keys(cfg), 1);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg), 1);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg), 1800);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_encrypt(cfg), 0);

        ubiq_platform_configuration_destroy(cfg);
    }
}

char *
write_temp_file(
  const std::string & er,
  const std::string & wake_interval_name,
  int a, int b, int c, int d, const std::string &timestamp_granularity,
  const std::string & kc,
  const std::string & encrypt_name,
  const std::string & encrypt, const std::string & structured, const std::string & unstructured, int ttl_seconds) {


    char s[50];

    char * y = tmpnam_r(s);

    std::ofstream file1(s);
    file1 << "{ \"" << er << "\" : {" <<
      "\"" << wake_interval_name << "\" : " << a << ","  << 
      "\"" << "timestamp_granularity" << "\" : \"" << timestamp_granularity <<"\","  << 
      "\"" << "minimum_count" << "\" : " << b <<","  << 
      "\"" << "flush_interval" << "\" : " << c <<","  << 
      "\"" << "trap_exceptions" << "\" : " << ((d == 0) ? "false" : "true") << "}," <<
      "\"" << kc << "\" : {" << 
      "\"" << encrypt_name << "\" : " << encrypt <<","  << 
      "\"structured\" : " << structured <<","  << 
      "\"unstructured\" : " << unstructured <<","  << 
      "\"ttl_seconds\" : " << ttl_seconds <<
      "}" <<
      "}";

    file1.close();

    return strdup(s);

    // std:
}


TEST(c_configuration, tmpFile) {
    struct ubiq_platform_configuration * cfg = NULL;
    int res = 1;

    char * filename = write_temp_file("event_reporting","wake_interval",1,2,3,4, "SECONDS",
    "key_caching",
    "encrypt", "true", "false", "false", 270);

    res = ubiq_platform_configuration_load_configuration(filename, &cfg);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 1);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 2);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 3);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 1);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg), SECONDS);

        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_structured_keys(cfg), 0);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg), 0);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg), 270);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_encrypt(cfg), 1);

        ubiq_platform_configuration_destroy(cfg);
    }

    free(filename);

}

TEST(c_configuration, tmpFileIncomplete) {
    struct ubiq_platform_configuration * cfg = NULL;
    struct ubiq_platform_configuration * cfg_default = NULL;
    int res = 1;

    char * filename = write_temp_file("event_reporting","wake_interval_bad",1,2,3,0, "MINUTES",
    "key_caching",
    "encrypt_bad", "true", "false", "false", 270);

    res = ubiq_platform_configuration_load_configuration(filename, &cfg);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_configuration_create(&cfg_default);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        EXPECT_NE(cfg, nullptr);
        EXPECT_NE(cfg_default, nullptr);

        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 
          ubiq_platform_configuration_get_event_reporting_wake_interval(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 2);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 3);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 0);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg), MINUTES);

        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_structured_keys(cfg), 0);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg), 0);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg), 270);
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_encrypt(cfg), 
        ubiq_platform_configuration_get_key_caching_encrypt(cfg_default));

        ubiq_platform_configuration_destroy(cfg);
        ubiq_platform_configuration_destroy(cfg_default);
    }

    free(filename);

}

TEST(c_configuration, tmpFileIncomplete2) {
    struct ubiq_platform_configuration * cfg = NULL;
    struct ubiq_platform_configuration * cfg_default = NULL;
    int res = 1;

    char * filename = write_temp_file("event_reporting2","wake_interval_bad",1,2,3,0, "DAYS",
    "key_caching_bad",
    "encrypt", "true", "false", "false", 270);

    res = ubiq_platform_configuration_load_configuration(filename, &cfg);
    EXPECT_EQ(res, 0);

    res = ubiq_platform_configuration_create(&cfg_default);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        EXPECT_NE(cfg, nullptr);
        EXPECT_NE(cfg_default, nullptr);

        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 
          ubiq_platform_configuration_get_event_reporting_wake_interval(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg),
          ubiq_platform_configuration_get_event_reporting_min_count(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 
          ubiq_platform_configuration_get_event_reporting_flush_interval(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg),
          ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg),
          ubiq_platform_configuration_get_event_reporting_timestamp_granularity(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_encrypt(cfg),
          ubiq_platform_configuration_get_key_caching_encrypt(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_structured_keys(cfg),
          ubiq_platform_configuration_get_key_caching_structured_keys(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg),
          ubiq_platform_configuration_get_key_caching_unstructured_keys(cfg_default));
        EXPECT_EQ(ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg),
          ubiq_platform_configuration_get_key_caching_ttl_seconds(cfg_default));

        ubiq_platform_configuration_destroy(cfg);
        ubiq_platform_configuration_destroy(cfg_default);
    }

    free(filename);

}
