#include <gtest/gtest.h>
#include <unistr.h>


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

void verify_string( const uint32_t * const s1,  const uint32_t * const s2) {
  const uint32_t * p1 = s1;
  const uint32_t * p2 = s2;

//  printf("test\n");

  while (*p1 && *p2) {
    printf("p1 (%d)  p2(%d)\n", *p1, *p2);
    ASSERT_EQ(*p1++, *p2++);
  }
  ASSERT_EQ(*p1, *p2);

}

void init_u32(uint32_t * str, ucs4_t c, size_t len) {
//  memset(trimmed_output, 0, sizeof(trimmed_output));
  u32_set(str, 0, len);
  u32_set(str, c, len -1);
//  str[len] = 0;
}

TEST(c_parsing, simple)
{
     const uint32_t * const pt = (const uint32_t * const )U"123-45-6789";
     const uint32_t * const input_character_set = (const uint32_t * const ) U"0123456789";
     const uint32_t * const passthrough_character_set = (const uint32_t * const )L"-";
    uint32_t empty_formatted_output[12];
    uint32_t trimmed_output [15];

    init_u32(empty_formatted_output, U'A', sizeof(empty_formatted_output) / sizeof(uint32_t));
    init_u32(trimmed_output, U'B', sizeof(trimmed_output) / sizeof(uint32_t));

    int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
     trimmed_output, empty_formatted_output);

    ASSERT_EQ(x, 0);
    ASSERT_EQ(u32_strcmp(trimmed_output, (uint32_t *) U"123456789"),0);
    ASSERT_EQ(u32_strcmp(empty_formatted_output, (uint32_t *) U"AAA-AA-AAAA"),0);
    // verify_string(trimmed_output, (uint32_t *) L"123456789");
    // verify_string(empty_formatted_output, (uint32_t *) L"AAA-AA-AAAA");
}


TEST(c_parsing, no_passthrough)
{
    static const uint32_t * const pt = (const uint32_t * const )U"123-45-6789";
    static const uint32_t * const input_character_set = (const uint32_t * const )U"0123456789-";
    static const uint32_t * const passthrough_character_set = NULL;
    uint32_t empty_formatted_output[12];
    uint32_t trimmed_output [15];

    init_u32(empty_formatted_output, U'A', sizeof(empty_formatted_output) / sizeof(uint32_t));

    init_u32(trimmed_output, U'B', sizeof(trimmed_output) / sizeof(uint32_t));
    int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
      trimmed_output, empty_formatted_output);

    ASSERT_EQ(x, 0);
    ASSERT_EQ(u32_strcmp(trimmed_output, pt),0);
}

TEST(c_parsing, invalid_data)
{
    static const uint32_t * const pt = (const uint32_t * const )U"123-45-6789";
    static const uint32_t * const input_character_set = (const uint32_t * const )U"0123456789";
    static const uint32_t * const passthrough_character_set = NULL;
    uint32_t empty_formatted_output[12];
    uint32_t trimmed_output [15];

    init_u32(empty_formatted_output, U'A', sizeof(empty_formatted_output) / sizeof(uint32_t));
    init_u32(trimmed_output, U'B', sizeof(trimmed_output) / sizeof(uint32_t));

    int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
      trimmed_output, empty_formatted_output);

    ASSERT_EQ(x, -EINVAL);
}

// Creates a string and randomly creates input / passthrough characters and then determines what the
// output should look like, and then calls
TEST(c_parsing, auto)
{
  uint32_t pt[50];
  uint32_t input_character_set [50];
  uint32_t passthrough_character_set[50];
  uint32_t res_trimmed [50];
  uint32_t res_formatted [50];

  memset(pt, 0, sizeof(pt));
  memset(passthrough_character_set, 0, sizeof(passthrough_character_set));
  memset(input_character_set, 0, sizeof(input_character_set));

  memset(res_trimmed, 0, sizeof(res_trimmed));
  init_u32(res_formatted, U'A', sizeof(res_formatted) / sizeof(uint32_t));
//  res_formatted[(pt) - 1] = '\0';

  uint32_t * i = &input_character_set[0];
  uint32_t * p = &passthrough_character_set[0];
  uint32_t * t = &res_trimmed[0];
  srand(time(NULL));
  for (int j = 0; j < (sizeof(pt) / sizeof(uint32_t))- 1; j++) {
    pt[j] = (rand() % 255) + 1;
    // Duplicate character ?
    if (!u32_strchr(input_character_set, pt[j]) && !u32_strchr(passthrough_character_set, pt[j])) {
      if ((rand() % 4) != 0) {
        *i++ = pt[j];
      } else {
        *p++ = pt[j];
      }
    }
    if (u32_strchr(input_character_set, pt[j])) {
      *t++ = pt[j];
    } else {
      res_formatted[j] = pt[j];
    }
  }
  pt[sizeof(pt) / sizeof(uint32_t)] = '\n';

  uint32_t empty_formatted_output[50];
  uint32_t trimmed_output [50];

  // memset(empty_formatted_output, 'A', sizeof(empty_formatted_output));
  // empty_formatted_output[strlen(pt)] = '\0';
  init_u32(empty_formatted_output, U'A', sizeof(empty_formatted_output) / sizeof(uint32_t));
  empty_formatted_output[u32_strlen(pt)] = 0;

  init_u32(trimmed_output, U'B', sizeof(trimmed_output) / sizeof(uint32_t));
  trimmed_output[u32_strlen(pt)] = 0;

  int x = ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set,
  trimmed_output, empty_formatted_output);

  ASSERT_EQ(x, 0);
  ASSERT_EQ(u32_strcmp(trimmed_output, res_trimmed),0);
  ASSERT_EQ(u32_strcmp(empty_formatted_output, res_formatted),0);

}
