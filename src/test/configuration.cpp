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

    res = ubiq_platform_configuration_create_explicit(91,92,93,94, &cfg);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 91);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 92);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 93);
        ASSERT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 94);

        ubiq_platform_configuration_destroy(cfg);
    }
}

TEST(c_configuration, diff)
{
    struct ubiq_platform_configuration * cfg_default;
    struct ubiq_platform_configuration * cfg;
    int res;

    res = ubiq_platform_configuration_create_explicit(91,92,93,94, &cfg);
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

        ubiq_platform_configuration_destroy(cfg);
    }
}

char *
write_temp_file(
  const std::string & er,
  const std::string & wake_interval_name,
  int a, int b, int c, int d) {


    char s[50];

    char * y = tmpnam_r(s);

    std::ofstream file1(s);
    file1 << "{ \"" << er << "\" : {" <<
      "\"" << wake_interval_name << "\" : " << a << ","  << 
      "\"" << "minimum_count" << "\" : " << b <<","  << 
      "\"" << "flush_interval" << "\" : " << c <<","  << 
      "\"" << "trap_exceptions" << "\" : " << ((d == 0) ? "false" : "true") << "}}";

    file1.close();

    return strdup(s);

    // std:
}


TEST(c_configuration, tmpFile) {
    struct ubiq_platform_configuration * cfg = NULL;
    int res = 1;

    char * filename = write_temp_file("event_reporting","wake_interval",1,2,3,4);

    res = ubiq_platform_configuration_load_configuration(filename, &cfg);
    EXPECT_EQ(res, 0);

    if (res == 0) {
        ASSERT_NE(cfg, nullptr);

        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_wake_interval(cfg), 1);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_min_count(cfg), 2);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_flush_interval(cfg), 3);
        EXPECT_EQ(ubiq_platform_configuration_get_event_reporting_trap_exceptions(cfg), 1);

        ubiq_platform_configuration_destroy(cfg);



    }

    free(filename);

}

TEST(c_configuration, tmpFileIncomplete) {
    struct ubiq_platform_configuration * cfg = NULL;
    struct ubiq_platform_configuration * cfg_default = NULL;
    int res = 1;

    char * filename = write_temp_file("event_reporting","wake_interval_bad",1,2,3,0);

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

        ubiq_platform_configuration_destroy(cfg);
        ubiq_platform_configuration_destroy(cfg_default);
    }

    free(filename);

}

TEST(c_configuration, tmpFileIncomplete2) {
    struct ubiq_platform_configuration * cfg = NULL;
    struct ubiq_platform_configuration * cfg_default = NULL;
    int res = 1;

    char * filename = write_temp_file("event_reporting2","wake_interval_bad",1,2,3,0);

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

        ubiq_platform_configuration_destroy(cfg);
        ubiq_platform_configuration_destroy(cfg_default);
    }

    free(filename);

}
