#include <gtest/gtest.h>

#include "ubiq/platform.h"

#include "ubiq/platform/internal/parsing.h"


class cpp_parsing : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
};

void cpp_parsing::SetUp(void)
{
}

void cpp_parsing::TearDown(void)
{
}

TEST_F(cpp_parsing, none)
{

}

TEST_F(cpp_parsing, simple)
{

}

TEST(c_parsing, simple)
{
    static const char * const pt = "123-45-6789";
    static const char * const input_character_set = "0123456789";
    static const char * const passthrough_character_set = "-";
    char empty_formatted_output[12];
//     = "AAAAAAAAAAA";
    char trimmed_output [15];

    memset(empty_formatted_output, 'A', sizeof(empty_formatted_output));
    empty_formatted_output[strlen(pt)] = '\0';
    memset(trimmed_output, 'B', sizeof(trimmed_output));
    trimmed_output[strlen(pt)] = '\0';

    int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
    trimmed_output, empty_formatted_output);

    std::cout << "trimmed_output '" << (char *)(&trimmed_output[0]) << "'" << std::endl;
    std::cout << "empty_formatted_output '" << (char *)(&empty_formatted_output[0]) << "'" << std::endl;

    ASSERT_EQ(x, 0);
    ASSERT_STREQ(trimmed_output, "123456789");
    ASSERT_STREQ(empty_formatted_output, "AAA-AA-AAAA");
}

TEST(c_parsing, no_passthrough)
{
    static const char * const pt = "123-45-6789";
    static const char * const input_character_set = "0123456789-";
    static const char * const passthrough_character_set = NULL;
    char empty_formatted_output[12];
//     = "AAAAAAAAAAA";
    char trimmed_output [15];

    memset(empty_formatted_output, 'A', sizeof(empty_formatted_output));
    empty_formatted_output[strlen(pt)] = '\0';
    memset(trimmed_output, 'B', sizeof(trimmed_output));
    trimmed_output[strlen(pt)] = '\0';

    int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
    trimmed_output, empty_formatted_output);

    std::cout << "trimmed_output '" << (char *)(&trimmed_output[0]) << "'" << std::endl;
    std::cout << "empty_formatted_output '" << (char *)(&empty_formatted_output[0]) << "'" << std::endl;

    ASSERT_EQ(x, 0);
    ASSERT_STREQ(trimmed_output, pt);
//    ASSERT_STREQ(empty_formatted_output, "AAA-AA-AAAA");
}

TEST(c_parsing, invalid_data)
{
    static const char * const pt = "123-45-6789";
    static const char * const input_character_set = "0123456789";
    static const char * const passthrough_character_set = NULL;
    char empty_formatted_output[12];
    char trimmed_output [15];

    memset(empty_formatted_output, 'A', sizeof(empty_formatted_output));
    empty_formatted_output[strlen(pt)] = '\0';
    memset(trimmed_output, 'B', sizeof(trimmed_output));
    trimmed_output[strlen(pt)] = '\0';

    int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
    trimmed_output, empty_formatted_output);

    std::cout << "trimmed_output '" << (char *)(&trimmed_output[0]) << "'" << std::endl;
    std::cout << "empty_formatted_output '" << (char *)(&empty_formatted_output[0]) << "'" << std::endl;

    ASSERT_EQ(x, -EINVAL);
}

TEST(c_parsing, auto)
{
  char pt[50];
  char input_character_set [50];
  char passthrough_character_set[50];
  char res_trimmed [50];
  char res_formatted [50];

  memset(pt, '\0', sizeof(pt));
  memset(passthrough_character_set, '\0', sizeof(passthrough_character_set));
  memset(input_character_set, '\0', sizeof(input_character_set));

  memset(res_trimmed, '\0', sizeof(res_trimmed));
  memset(res_formatted, 'A', sizeof(res_formatted));
//  res_trimmed[sizeof(pt) - 1] = '\0';
  res_formatted[sizeof(pt) - 1] = '\0';

  char * i = &input_character_set[0];
  char * p = &passthrough_character_set[0];
  char * t = &res_trimmed[0];

  for (int j = 0; j < sizeof(pt) - 1; j++) {
    pt[j] = (rand() % 255) + 1;
    printf("char %c", pt[j]);
    // Duplicate character ?
    if (!strchr(input_character_set, pt[j]) && !strchr(passthrough_character_set, pt[j])) {
      if ((rand() % 4) != 0) {
        printf(" (input)");
        *i++ = pt[j];
      } else {
        printf(" (passthrough)");
        *p++ = pt[j];
      }
    }
    printf("\n");
    if (strchr(input_character_set, pt[j])) {
      *t++ = pt[j];
    } else {
      res_formatted[j] = pt[j];
    }
  }
  pt[sizeof(pt)] = '\n';
  printf("res_trimmed '%s'\n", res_trimmed);
  printf("res_formatted '%s'\n", res_formatted);

  char empty_formatted_output[50];
  char trimmed_output [50];

  memset(empty_formatted_output, 'A', sizeof(empty_formatted_output));
  empty_formatted_output[strlen(pt)] = '\0';
  memset(trimmed_output, 'B', sizeof(trimmed_output));
  trimmed_output[strlen(pt)] = '\0';


  int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
  trimmed_output, empty_formatted_output);

  std::cout << "trimmed_output '" << (char *)(&trimmed_output[0]) << "'" << std::endl;
  std::cout << "empty_formatted_output '" << (char *)(&empty_formatted_output[0]) << "'" << std::endl;

  ASSERT_EQ(x, 0);
  ASSERT_STREQ(trimmed_output, res_trimmed);
  ASSERT_STREQ(empty_formatted_output, res_formatted);

}
