#include "ubiq/platform.h"


#include "ubiq/platform/internal/encryption_pipeline.h"
#include "ubiq/platform/internal/structured_pipeline.h"
#include "ubiq/platform/internal/encode_input_operation.h"
#include "ubiq/platform/internal/convert_radix_operation.h"
#include "ubiq/platform/internal/encrypt_operation.h"
#include "ubiq/platform/internal/pad_input_operation.h"
#include "ubiq/platform/internal/trim_passthrough_characters_operation.h"
#include "ubiq/platform/internal/expand_passthrough_characters_operation.h"
#include "ubiq/platform/internal/trim_passthrough_prefix_operation.h"
#include "ubiq/platform/internal/expand_passthrough_prefix_operation.h"
#include "ubiq/platform/internal/trim_passthrough_suffix_operation.h"
#include "ubiq/platform/internal/expand_passthrough_suffix_operation.h"
#include "ubiq/platform/internal/encode_key_number_operation.h"

#include "ubiq/platform/internal/dataset.h"
#include "ubiq/platform/internal/parsing.h"
#include "ubiq/platform/internal/support.h"
#include <stdlib.h>
#include <string.h>
#include <unistr.h>
#include <stdio.h>


/**************************************************************************************
 *
 * Defines
 *
**************************************************************************************/
// #define UBIQ_DEBUG_ON // UNCOMMENT to Enable UBIQ_DEBUG macro


#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 1;


/**************************************************************************************
 *
 * Constants
 *
**************************************************************************************/

/**************************************************************************************
 *
 * Structures
 *
************************************** ************************************************/

struct ubiq_platform_encryption_pipeline {
  ubiq_platform_structured_pipeline_t * structured_pipeline;
};



/**************************************************************************************
 *
 * Static functions body
 *
**************************************************************************************/

static int add_base_operations(ubiq_platform_structured_pipeline_t * const pipeline);

static int add_passthrough_rules(
  ubiq_platform_dataset_t const * const dataset,
  ubiq_platform_structured_pipeline_t * const pipeline
);



static int add_base_operations(ubiq_platform_structured_pipeline_t * const pipeline)
{
  int res = 0;

  if (!res) {res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
    ubiq_platform_encode_input_operation_create(), -1);}

  if (!res) {res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
    ubiq_platform_pad_input_operation_create(), -1);}

  if (!res) {res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
    ubiq_platform_encrypt_operation_create(), -1);}

  if (!res) {res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
    ubiq_platform_convert_radix_operation_create(), -1);}

  if (!res) {res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
    ubiq_platform_encode_key_number_operation_create(), -1);}
    
  return res;
}

static int add_passthrough_rules(
  ubiq_platform_dataset_t const * const dataset,
  ubiq_platform_structured_pipeline_t * const pipeline)
{
  int res = -EINVAL;

  size_t rule_priorities[UBIQ_PASSTHROUGH_RULES_COUNT];

  UBIQ_DEBUG(debug_flag, printf("sizeof(rule_priorities): %d\n", UBIQ_PASSTHROUGH_RULES_COUNT));
  res = ubiq_platform_dataset_get_passthrough_rule_priorities(dataset, rule_priorities, UBIQ_PASSTHROUGH_RULES_COUNT);
  UBIQ_DEBUG(debug_flag, printf("ubiq_platform_dataset_get_passthrough_rule_priorities res(%d)\n", res));

  int rulecount = 0;
  // Rules are returned in order sorted by priority.  Want to run through this in decending order of priority
  for (int i = UBIQ_PASSTHROUGH_RULES_COUNT - 1; !res && i >= 0; i--) {
    UBIQ_DEBUG(debug_flag, ("i(%d) rule_priorities(%d)\n", i, rule_priorities[i]));
    switch (rule_priorities[i]) {
      case UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PASSTHROUGH:
        rulecount++;
        res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
          ubiq_platform_trim_passthrough_characters_operation_create(), 0);
        if (!res) {
          res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
              ubiq_platform_expand_passthrough_characters_operation_create(), -1);}
        break;

      case UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_PREFIX:
        rulecount++;
        res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
          ubiq_platform_trim_passthrough_prefix_operation_create(), 0);
        if (!res) {
          res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
              ubiq_platform_expand_passthrough_prefix_operation_create(), -1);}
        break;

      case UBIQ_DATASET_PASSTHROUGH_RULE_TYPE_SUFFIX:
        rulecount++;
        res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
          ubiq_platform_trim_passthrough_suffix_operation_create(), 0);
        if (!res) {
          res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
              ubiq_platform_expand_passthrough_suffix_operation_create(), -1);}
        break;

      // ignore other rule types
      default:
        break;
    } // switch
  } // for

  // If there aren't any passthrough rules but there are passthrough characters from
  // an old dataset, need to add passthrough handing
  char32_t const * const passthrough_chars = ubiq_platform_dataset_get_passthrough_characters(dataset);
  if ((!res) && (rulecount == 0) && (NULL != passthrough_chars && U'\0' != passthrough_chars[0])) {
    res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
      ubiq_platform_trim_passthrough_characters_operation_create(), 0);
    if (!res) {
      res = ubiq_platform_structured_pipeline_add_operation(pipeline, 
          ubiq_platform_expand_passthrough_characters_operation_create(), -1);}
  }

  return res;
}

int ubiq_platform_encryption_pipeline_invoke(
  ubiq_platform_encryption_pipeline_t * const pipeline,
  ubiq_platform_operation_context_t * const context) 
{
  int res = -EINVAL;

  if (context) {
    res = ubiq_platform_structured_pipeline_invoke(pipeline->structured_pipeline, context);
  } //ctx
  return res;
}

ubiq_platform_encryption_pipeline_t * const ubiq_platform_encryption_pipeline_create(
   ubiq_platform_dataset_t const * const dataset)
{
  int res = -ENOMEM;
  ubiq_platform_encryption_pipeline_t * p = calloc(1, sizeof(ubiq_platform_encryption_pipeline_t));
    UBIQ_DEBUG(debug_flag, printf("calloc \n"));
  if (p != NULL) {
    res = ubiq_platform_structured_pipeline_create(10, &p->structured_pipeline);
    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_structured_pipeline_create res(%d) \n", res));
    if (!res) {
      res = add_base_operations(p->structured_pipeline);
      UBIQ_DEBUG(debug_flag, printf("add_base_operations res(%d) \n", res));
    }
    
    if (!res) {
      res = add_passthrough_rules(dataset, p->structured_pipeline);
      UBIQ_DEBUG(debug_flag, printf("add_passthrough_rules res(%d) \n", res));
    }
  }
  if (res) {
    UBIQ_DEBUG(debug_flag, printf("!res(%d) \n", res));
    ubiq_platform_encryption_pipeline_delete(p);
    p = NULL;
  }
  UBIQ_DEBUG(debug_flag, printf("res(%d) p(%P) \n", res, p));
  return p;
}

void ubiq_platform_encryption_pipeline_delete(ubiq_platform_encryption_pipeline_t * const op) {
  ubiq_platform_structured_pipeline_destroy(op->structured_pipeline);
  free(op);
}

