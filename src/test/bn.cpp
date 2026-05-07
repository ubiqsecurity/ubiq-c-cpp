#include <gtest/gtest.h>
#include <ubiq/platform/internal/bn.h>
#include <ubiq/platform/internal/parsing.h>

#include <unistr.h>

TEST(bn, set_str)
{
    char n5[] = "00011010";

    uint8_t * numb;
    size_t numc;
    bigint_t n;

    bigint_init(&n);

    bigint_set_str(&n, n5, 5);
    EXPECT_EQ(bigint_cmp_si(&n, 755), 0);

    bigint_deinit(&n);
}

static void _copy(uint32_t * u32_dest, const char * const src) {
  for (int i = 0; i < strlen(src); i++) {
    u32_dest[i] = (uint8_t)src[i];
  }
}

static
void __u32_radix_test(const char * const input, const char * const ialpha,
                  const char * const oalpha, const char * const expect)
{
    bigint_t n;
    int r1, r2;
    size_t len;

    std::vector<uint32_t> output;

    uint32_t * u32_input = NULL;//u8_to_u32((uint8_t *)input, strlen(input) + 1, NULL, &len);
    uint32_t * u32_ialpha = NULL;//u8_to_u32((uint8_t *)ialpha, strlen(ialpha) + 1, NULL, &len);
    uint32_t * u32_oalpha = NULL;//u8_to_u32((uint8_t *)oalpha, strlen(oalpha) + 1, NULL, &len);
    uint32_t * u32_expect = NULL;//u8_to_u32((uint8_t *)expect, strlen(expect) + 1, NULL, &len);

    convert_utf8_to_utf32((uint8_t *)input, &u32_input);
    convert_utf8_to_utf32((uint8_t *)ialpha, &u32_ialpha);
    convert_utf8_to_utf32((uint8_t *)oalpha, &u32_oalpha);
    convert_utf8_to_utf32((uint8_t *)expect, &u32_expect);


    /* @n will be the numerical value of @inp */
    bigint_init(&n);

    r1 = __u32_bigint_set_str(&n, u32_input, u32_ialpha);
    ASSERT_EQ(r1, 0);

    output.resize(50);

    r2 = __u32_bigint_get_str(output.data(), output.size(), u32_oalpha, &n);
    EXPECT_EQ(r2, 0);
    EXPECT_EQ(u32_strlen(output.data()), u32_strlen(u32_expect));
    for (int i=0; i < u32_strlen(output.data()); i++) {
      EXPECT_EQ(output[i], u32_expect[i]);
    }

    free(u32_input);
    free(u32_ialpha);
    free(u32_oalpha);
    free(u32_expect);

    bigint_deinit(&n);
}

static
void __radix_test(const char * const input, const char * const ialpha,
                  const char * const oalpha, const char * const expect)
{
    bigint_t n;
    int r1, r2;

    std::vector<char> output;
    output.resize(50);

    /* @n will be the numerical value of @inp */
    bigint_init(&n);

    // std::cerr << " input(" << input << ")   expect(" << expect << ")"<< std::endl;
    // std::cerr << " ialpha(" << ialpha << ")   oalpha(" << oalpha << ")"<< std::endl;
    r1 = __bigint_set_str(&n, input, ialpha);
    ASSERT_EQ(r1, 0);


    r2 = __bigint_get_str(output.data(), output.size(), oalpha, &n);
    EXPECT_EQ(r2, 0) ;
    EXPECT_EQ(strcmp(output.data(), expect), 0) << " output(" << output.data() << ")   expect(" << expect << ")"<< std::endl;


    bigint_deinit(&n);
}


static
void radix_test(const char * const input, const char * const ialpha,
                const char * const oalpha, const char * const expect)
{
    /* convert from one radix to another */
    __radix_test(input, ialpha, oalpha, expect);
    /* test that the conversion can be successfully reversed */
    __radix_test(expect, oalpha, ialpha, input);


    /* convert from one radix to another */
    __u32_radix_test(input, ialpha, oalpha, expect);
    /* test that the conversion can be successfully reversed */
    __u32_radix_test(expect, oalpha, ialpha, input);
}

TEST(radix, dec2hex)
{
    radix_test("100", "0123456789", "0123456789ABCDEF", "64");
}

TEST(radix, oct2hex)
{
    radix_test("100", "01234567", "0123456789ABCDEF", "40");
}

TEST(radix, dec2dec)
{
    radix_test("@$#", "!@#$%^&*()", "0123456789", "132");
}

TEST(radix, oct2dec)
{
    radix_test("@$#", "!@#$%^&*", "0123456789", "90");
}

TEST(radix, invalid_dest_buffer)
{
    bigint_t n;
    int r1(0);
    int r2(0);
    const char data []= "123456789";
    const char input_radix [] = "0123456789";
    const char output_radix [] = "0123456789ABC";
    std::vector<char> output;


    bigint_init(&n);

    r1 = __bigint_set_str(&n, data, input_radix);
    ASSERT_EQ(r1, 0);

    output.resize(50);

    // Make sure dest buffer is TOO small
    r2 = __bigint_get_str(output.data(), 1, output_radix, &n);
    EXPECT_EQ(r2, -ENOMEM);

    bigint_deinit(&n);
}

TEST(radix, invalid_characters_buffer)
{
    bigint_t n;
    int r1(0);
    const char data []= "123456789";
    const char input_radix [] = "ABCDEFG";
    bigint_init(&n);

    r1 = __bigint_set_str(&n, data, input_radix);
    ASSERT_EQ(r1, -EINVAL);

  
    bigint_deinit(&n);
}

// Use arbitrary radix 62 and test conversions back and forth
TEST(radix, radix62)
{
    char data [5] = "\0\0\0\0";
    char input_radix[63];
    const char output_radix [] = "0123456879";

    memset(input_radix,0, sizeof(input_radix));

    // Arbitrary input string
    for (int i = 0;i < 62; i++) {
        input_radix[i] = '0' + i;
    }

    data[0] = input_radix[1];
    radix_test(data, input_radix, output_radix, "1");

    data[0] = input_radix[61];
    radix_test(data, input_radix, output_radix, "61");

}

// Use arbitrary radix > 62 and test conversions back and forth
TEST(radix, radix63)
{
    char data [5] = "\0\0\0\0";
    char input_radix[65];

    const char output_radix [] = "0123456879";

    memset(input_radix,0, sizeof(input_radix));

    for (int i = 0;i < 63; i++) {
        input_radix[i] = '0' + i;
    }

    data[0] = input_radix[1];
    radix_test(data, input_radix, output_radix, "1");

    data[0] = input_radix[62];
    radix_test(data, input_radix, output_radix, "62");

}

TEST(chars, mapset)
{
    int r1;

    char src[]      = "BCDEFGHIJ";
    char expected[] = "123456789";

    const char input_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char output_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char * dst1;
    char * dst2;

    dst1 = strdup(src);
    r1 = map_characters(dst1,src,input_set, output_set);
    ASSERT_EQ(r1, 0);
    EXPECT_EQ(strcmp(dst1, expected),0) << " dst1 = '" << dst1 << "'";

    dst2 = strdup(dst1);
    r1 = map_characters(dst2, dst1, output_set, input_set);
    ASSERT_EQ(r1, 0);
    EXPECT_EQ(strcmp(dst2, src),0);

    free(dst1);
    free(dst2);

}

TEST(chars, mapset_2)
{
    unsigned long long r1 = 0;

    char src[]      = "JIHGFEDCBABCDEFGHIJ";
    char expected[] = "9876543210123456789";

    const char input_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char output_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char * dst1;
    char * dst2;

    dst1 = strdup(src);

    r1 = map_characters(dst1,src,input_set, output_set);
    ASSERT_EQ(r1, 0);
    EXPECT_EQ(strcmp(dst1, expected),0) << " dst1 = '" << dst1 << "'";

    dst2 = strdup(dst1);
    r1 = map_characters(dst2, dst1, output_set, input_set);
    ASSERT_EQ(r1, 0);
    EXPECT_EQ(strcmp(dst2, src),0);

    free(dst1);
    free(dst2);

}



TEST(chars, non_std)
{
    unsigned long long r1 = 0;

    char src[] = "!@#$%^&*()";
    char expected[] = "02468ACEGI";

    const char input_set[] =  "!a@b#c$d%e^f&g*h(i)";
    const char output_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char * dst1;
    char * dst2;

    dst1 = strdup(src);
    ASSERT_EQ(map_characters(dst1,src,input_set, output_set), 0);

    EXPECT_EQ(strcmp(dst1, expected),0) << " dst1 = '" << dst1 << "'";

    dst2 = strdup(dst1);
    r1 = map_characters(dst2, dst1, output_set, input_set);
    ASSERT_EQ(r1, 0);
    EXPECT_EQ(strcmp(dst2, src),0);

    free(dst1);
    free(dst2);


}

TEST(chars, mapset_invalid)
{
    unsigned long long r1 = 0;

    char src[]      = "JIHGFEDCBABCDEFGHIJ";
    char expected[] = "9876543210123456789";

    const char input_set[] = "BCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char output_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char * dst1;

    dst1 = strdup(src);

    r1 = map_characters(dst1,src,input_set, output_set);
    EXPECT_NE(r1, 0);

    free(dst1);

}
 
TEST(chars, mapset_63)
{
    unsigned long long r1 = 0;

    char src[]      = "09";
    char expected[] = "\x01\x0a";

    const char input_set[] = "0123456789";
    const char * output_set = get_standard_bignum_radix(63);

    char * dst1;

    dst1 = strdup(src);

    r1 = map_characters(dst1,src,input_set, output_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(expected, dst1), 0);

    free(dst1);

}

TEST(chars, u32_mapset_63)
{
    setlocale(LC_ALL, "C.UTF-8");
    unsigned long long r1 = 0;

    char src[]      = "09";
    char expected[] = "\x01\x0a";

    const uint32_t * input_set = (uint32_t * )L"0123456789";
    const char * output_set = get_standard_bignum_radix(63);

    char * dst1;

    dst1 = strdup(src);

    r1 = map_characters_from_u32(dst1, (uint8_t *) src,input_set, output_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(expected, dst1), 0);

    free(dst1);

}

TEST(chars, u32_mapset_63_custom)
{
    setlocale(LC_ALL, "C.UTF-8");
    unsigned long long r1 = 0;

    char src[]      = "09";
    char expected[] = "\x0a\x09";

    const uint32_t * input_set = (uint32_t * )L"1234567890";
    const char * const output_set =   get_standard_bignum_radix(72);
      // "\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" 
      //                              "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
      //                              "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
      //                              "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
      //                              "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
      //                              "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
      //                              "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
      //                              "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
      //                              "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
      //                              "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
      //                              "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
      //                              "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
      //                              "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
      //                              "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
      //                              "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
      //                              "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

    char * dst1;
    uint8_t * dst2;

    dst1 = strdup(src);
    dst2 = (uint8_t*) calloc(sizeof(src) + 1, sizeof(uint8_t));

    r1 = map_characters_from_u32(dst1, (uint8_t *) src,input_set, output_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(expected, dst1), 0);

    r1 = map_characters_to_u32(dst2, dst1, output_set, input_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(src, (char *)dst2), 0);

    free(dst1);
    free(dst2);

}


TEST(chars, u32_to_mapset_63)
{
    setlocale(LC_ALL, "C.UTF-8");
    unsigned long long r1 = 0;

    char src[]      = "09";
    char expected[] = "\x01\x0a";

    const uint32_t * input_set = (uint32_t * )L"0123456789";
    const char * output_set = get_standard_bignum_radix(63);

    char * dst1;
    uint8_t * dst2;

    dst1 = strdup(src);
    dst2 = (uint8_t*) calloc(sizeof(src) + 1, sizeof(uint8_t));

    r1 = map_characters_from_u32(dst1, (uint8_t *) src,input_set, output_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(expected, dst1), 0);

    r1 = map_characters_to_u32(dst2, dst1, output_set, input_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(src, (char *)dst2), 0);

    free(dst1);
    free(dst2);

}

TEST(chars, mapset_255)
{
    setlocale(LC_ALL, "C.UTF-8");
    unsigned long long r1 = 0;

    char src[]      = "0Az<";
    char expected[] = "\x01\x0b\x3e\x57";

    const char * input_set = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()~`{}|[]:;,./?><";
    const char * output_set = get_standard_bignum_radix(255);
    uint32_t * u32_input_set = NULL;//(uint32_t *)calloc(strlen(input_set) + 1, sizeof(uint32_t));
    // size_t len = strlen(input_set) + 1;
    // u32_input_set = u8_to_u32((const uint8_t*)input_set, strlen(input_set), u32_input_set, &len);
    convert_utf8_to_utf32((uint8_t *)input_set, &u32_input_set);
    // printf("len(%d)\n",len);

    char * dst1;
    char * dst2;

    dst1 = strdup(src);
    dst2 = (char *) calloc(strlen(src) + 1, sizeof(char));

    r1 = map_characters(dst1, src, input_set, output_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(expected, dst1), 0);

    // Reverse it
    r1 = map_characters(dst2, dst1, output_set, input_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(src, dst2), 0);


    r1 = map_characters_from_u32(dst1, (uint8_t*)src, u32_input_set, output_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(expected, dst1), 0);

    r1 = map_characters_to_u32((uint8_t*)dst2, dst1, output_set, u32_input_set);
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(strcmp(dst2, src), 0);

    free(dst1);
    free(dst2);
    free(u32_input_set);
}


TEST(radix, t1)
{
    unsigned long long r1 = 0;

    char src[]      = "1234567890ABCDEFabcdef";
    const char i_radix[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const char o_radix[] = "0123456789";
    char expect[] = "45117932320280791338835719979215890389";

    std::vector<char> data(50);
  
   radix_test(src, i_radix, o_radix, expect);
}

TEST(radix, t2)
{
    unsigned long long r1 = 0;

    char src[]      = "3456789AB2CDEFGHcdefgh";
    const char i_radix[] = "23456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01";
    const char o_radix[] = "0123456789";
    char expect[] = "45117932320280791338835719979215890389";

    std::vector<char> data(50);
  
   radix_test(src, i_radix, o_radix, expect);
}

TEST(radix, t3)
{
    unsigned long long r1 = 0;

    char src[]      = "6KNFyZss7SBQ7w7udUwsv8";
    const char i_radix[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const char o_radix[] = "23456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01";
    char expect[] = "8MPH0buu9UDS9y9wfWyuxA";

    std::vector<char> data(50);
  
   radix_test(src, i_radix, o_radix, expect);
}


TEST(radix, t4)
{
    unsigned long long r1 = 0;
    char src[]      = "9G0L29YNJ6";
    const char i_radix[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char o_radix[] = "!\"#$%'()*+,./0123456789:<=>?ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_`abcdefghijklmnopqrstuvwxyz{}~";

    char expect[] = "=J*K42c(";

    std::vector<char> data(50);
  
   radix_test(src, i_radix, o_radix, expect);

   radix_test(expect, o_radix, i_radix, src);

}

TEST(radix, u32)
{
    unsigned long long r1 = 0;
    char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"0123456789";

    const wchar_t expect[] = L"1234567890";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), data.size(),  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, 0);

    EXPECT_EQ(memcmp(expect, data.data(), sizeof(expect)), 0);
    bigint_deinit(&n);

}

TEST(radix, u32_b)
{
    unsigned long long r1 = 0;
    char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"0123456789";

    const wchar_t expect[] = L"1234567890";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), data.size(),  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, 0);

    EXPECT_EQ(memcmp(expect, data.data(), sizeof(expect)), 0);
    bigint_deinit(&n);

}

TEST(radix, u32_c)
{
    unsigned long long r1 = 0;
     char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"ÊËÌÍÎÏðñòó";

    const wchar_t expect[] = L"ËÌÍÎÏðñòóÊ";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), data.size(),  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, 0);

    EXPECT_EQ(memcmp(expect, data.data(), sizeof(expect)), 0);
    bigint_deinit(&n);

}

TEST(radix, u32_d)
{
    unsigned long long r1 = 0;
    char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"ĵĶķĸĹϺϻϼϽϾ";

    const wchar_t expect[] = L"ĶķĸĹϺϻϼϽϾĵ";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), data.size(),  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, 0);

    EXPECT_EQ(memcmp(expect, data.data(), sizeof(expect)), 0);
    bigint_deinit(&n);

}

TEST(radix, u32_e)
{
    unsigned long long r1 = 0;
    char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"ĵĶķĸĹϺϻϼϽϾ";

    const wchar_t expect[] = L"ĶķĸĹϺϻϼϽϾĵ";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), data.size(),  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, 0);

    EXPECT_EQ(memcmp(expect, data.data(), sizeof(expect)), 0);
    bigint_deinit(&n);

}

TEST(radix, u32_f)
{
    unsigned long long r1 = 0;
    char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"ĵĶķĸĹϺϻϼϽϾ";

    const wchar_t expect[] = L"ĶķĸĹϺϻϼϽϾĵ";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), 2,  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, -ENOMEM);
    bigint_deinit(&n);

}

TEST(radix, u32_g)
{
    unsigned long long r1 = 0;
    char src[]      = "1234567890";
    const char i_radix[] = "0123456789";
    const wchar_t o_radix[] = L"012345678Ͼ";

    const wchar_t expect[] = L"12345678Ͼ0";

    std::vector<wchar_t> data(50);
  
    bigint_t n;

    bigint_init(&n);

    r1 = __bigint_set_str(&n, src, i_radix);
    EXPECT_EQ(r1, 0);

    r1 = __u32_bigint_get_str((uint32_t *)data.data(), data.size(),  (uint32_t *)o_radix, &n);
    EXPECT_EQ(r1, 0);

    EXPECT_EQ(memcmp(expect, data.data(), sizeof(expect)), 0);
    bigint_deinit(&n);

}

TEST(radix, quick_test)
{
    bigint_t n;
    int r1(0);
    const char data []= "1234";
    const char input_radix [] = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    bigint_init(&n);

    r1 = __bigint_set_str(&n, data, input_radix);
    ASSERT_EQ(r1, 0);

    // gmp_printf("%Zd\n", n);
  
    bigint_deinit(&n);
}

TEST(radix, u32_hex)
{
  uint32_t * str = (uint32_t*)L"10";
  uint32_t * input_radix = (uint32_t*)L"0123456789";
  uint32_t * output_radix = (uint32_t*)L"0123456789ABCDEF";
  uint32_t * expect = (uint32_t*)L"0A";

  uint32_t * out = (uint32_t*)calloc(10, sizeof(uint32_t));

  int res = ubiq_platform_u32_str_convert_u32_radix(str, input_radix, output_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(expect, out), 0);

  res = ubiq_platform_u32_str_convert_u32_radix(expect, output_radix, input_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(str, out), 0);

  free(out);

}

TEST(radix, u32_custom_hex)
{
  uint32_t * str = (uint32_t*)L"10";
  uint32_t * input_radix = (uint32_t*)L"2345678901";
  uint32_t * output_radix = (uint32_t*)L"23456789ABCDEF01";
  uint32_t * expect = (uint32_t*)L"84";

  uint32_t * out = (uint32_t*)calloc(10, sizeof(uint32_t));
  int res = ubiq_platform_u32_str_convert_u32_radix(str, input_radix, output_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(expect, out), 0);

  res = ubiq_platform_u32_str_convert_u32_radix(expect, output_radix, input_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(str, out), 0);

  free(out);

}

TEST(radix, u32_custom_utf_hex)
{
  uint32_t * str = (uint32_t*)L"Ķĵ";
  uint32_t * input_radix = (uint32_t*)L"ĵĶķĸĹϺϻϼϽϾ";
  uint32_t * output_radix = (uint32_t*)L"0123456789ABCDEF";
  uint32_t * expect = (uint32_t*)L"0A";

  uint32_t * out = (uint32_t*)calloc(10, sizeof(uint32_t));
  int res = ubiq_platform_u32_str_convert_u32_radix(str, input_radix, output_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(expect, out), 0);

  res = ubiq_platform_u32_str_convert_u32_radix(expect, output_radix, input_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(str, out), 0);

  free(out);

}

TEST(radix, u32_custom_utf_hex_2)
{
  uint32_t * str = (uint32_t*)L"Ķĵ";
  uint32_t * input_radix = (uint32_t*)L"ķĸĹϺϻϼϽϾĵĶ";
  uint32_t * output_radix = (uint32_t*)L"23456789ABCDEF01";
  uint32_t * expect = (uint32_t*)L"84";

  uint32_t * out = (uint32_t*)calloc(10, sizeof(uint32_t));
  int res = ubiq_platform_u32_str_convert_u32_radix(str, input_radix, output_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(expect, out), 0);

  res = ubiq_platform_u32_str_convert_u32_radix(expect, output_radix, input_radix, 0, 1, out);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(u32_strcmp(str, out), 0);

  free(out);

}