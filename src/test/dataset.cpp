#include <gtest/gtest.h>
#include <ubiq/platform/internal/dataset.h>
#include <unistr.h>

static int create_dataset(
  std::string & passthrough_rules,
  cJSON ** const json) {
  int res = -EINVAL;
  std::string s;

  s = "{\"name\": \"DATE\"," \
  "\"data_type\": \"date\"," \
  "\"data_type_config\": {" \
    "\"epoch\": \"0001-01-01T00:00:00Z\"," \
    "\"max_input_date_value\": \"2738-11-28T00:00:00Z\"," \
    "\"min_input_date_value\": \"0001-01-01T00:00:00Z\"" \
  "}," \
  "\"salt\": \"52aqrIi96OOCBcLZNmtjhh4sBmG1jgeplMnpk7N9Lu0=\"," \
  "\"min_input_length\": 6," \
  "\"max_input_length\": 6," \
  "\"input_pad_character\": null," \
  "\"input_encoding\": null," \
  "\"tweak_source\": \"constant\"," \
  "\"encryption_algorithm\": \"FF1\"," \
  "\"passthrough\": \"\"," \
  "\"input_character_set\": \"0123456789\"," \
  "\"output_character_set\": \"0123456789AB\"," \
  "\"msb_encoding_bits\": 3," \
  "\"tweak_min_len\": 6," \
  "\"tweak_max_len\": 32," \
  "\"tweak\": \"fTrI5TNimEOjxuk1mbMrwXOXu2DZ4KQIcczjy73dtCM=\"," \
  "\"fpe_definable_type\": \"EfpeDefinition\"," + passthrough_rules + \
  "\"permissions\": {" \
    "\"decrypt\": true," \
    "\"encrypt\": true}" \
  "}";
 
  cJSON *j = cJSON_ParseWithLength(s.data(), s.length());
  if (j != NULL && !cJSON_IsNull(j)) {
    res = 0;
    *json = j;
  } else {
    cJSON_Delete(j);
  }
  return res;   
}

TEST(dataset, parse)
{
  std::string rules = "\"passthrough_rules\": [{\"type\":\"passthrough\", \"priority\":1,\"value\":\"-\"}],";

  cJSON * dataset_json = NULL;//cJSON_CreateObject();
  ubiq_platform_dataset_t * dataset = NULL;
  int res = 0;

  res = create_dataset(rules, &dataset_json);
  ASSERT_EQ(res, 0);

  // char* x = cJSON_Print(dataset_json);
  // printf("%s\n", x);
  // free(x);

  res = ubiq_platform_dataset_create(dataset_json, &dataset);
  ASSERT_EQ(res, 0);

  cJSON_Delete(dataset_json);
  ubiq_platform_dataset_destroy(dataset);

}


TEST(dataset, rules)
{
  std::string rules = 
   "\"passthrough_rules\": [" \
   " {\"type\": \"prefix\", \"value\": 3, \"priority\": 11}," \
   " {\"type\": \"suffix\", \"value\": 4, \"priority\": 3}," \
   " {\"type\": \"passthrough\", \"value\": \"-\", \"priority\": 2}],";

  cJSON * dataset_json = NULL;//cJSON_CreateObject();
  ubiq_platform_dataset_t * dataset = NULL;
  int res = 0;

  res = create_dataset(rules, &dataset_json);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_dataset_create(dataset_json, &dataset);
  ASSERT_EQ(res, 0);

  size_t priorities[5];
  res = ubiq_platform_dataset_get_passthrough_rule_priorities(dataset, priorities, 5);
  ASSERT_EQ(res, 0);

  EXPECT_EQ(priorities[0], UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PASSTHROUGH);
  EXPECT_EQ(priorities[1], UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_SUFFIX);
  EXPECT_EQ(priorities[2], UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PREFIX);

  cJSON_Delete(dataset_json);
  ubiq_platform_dataset_destroy(dataset);

}

TEST(dataset, rules_2)
{
  std::string rules = 
   "\"passthrough_rules\": [" \
   " {\"type\": \"prefix\", \"value\": 3, \"priority\": 11}," \
   " {\"type\": \"suffix\", \"value\": 4, \"priority\": 3}],";

  cJSON * dataset_json = NULL;//cJSON_CreateObject();
  ubiq_platform_dataset_t * dataset = NULL;
  int res = 0;

  res = create_dataset(rules, &dataset_json);
  ASSERT_EQ(res, 0);

  res = ubiq_platform_dataset_create(dataset_json, &dataset);
  ASSERT_EQ(res, 0);

  size_t priorities[5];
  res = ubiq_platform_dataset_get_passthrough_rule_priorities(dataset, priorities, 5);
  ASSERT_EQ(res, 0);

  EXPECT_EQ(priorities[0], UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_SUFFIX);
  EXPECT_EQ(priorities[1], UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PREFIX);
  EXPECT_EQ(priorities[2], UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_NONE);

  cJSON_Delete(dataset_json);
  ubiq_platform_dataset_destroy(dataset);

}
