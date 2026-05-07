#include "ubiq/platform.h"

#include <stdio.h>

#include "ubiq/platform/internal/structured_pipeline.h"
#include "ubiq/platform/internal/support.h"
#include "ubiq/platform/internal/operation.h"
#include <stdlib.h>
#include <string.h>
#include <unistr.h>


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

static int debug_flag = 0;


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

struct ubiq_platform_structured_pipeline {
  ubiq_platform_operation_t ** operations;
  size_t allocated; // Number of elements created
  size_t next_available; // 0 means empty
};


/**************************************************************************************
 *
 * Static functions body
 *
**************************************************************************************/



int ubiq_platform_structured_pipeline_create(size_t const initial_capacity, ubiq_platform_structured_pipeline_t ** const pipeline) 
{
  int res = -ENOMEM;
  static const char * const csu = "ubiq_platform_structured_pipeline_create";

  UBIQ_DEBUG(debug_flag, printf("%s started\n", csu));
  ubiq_platform_structured_pipeline_t * p = NULL;

  if ((p = calloc(1, sizeof(*p))) != NULL) {
    if ((p->operations = (ubiq_platform_operation_t **)reallocarray(NULL, initial_capacity, sizeof(ubiq_platform_operation_t*))) != NULL) {
      p->allocated = initial_capacity;
      p->next_available = 0;
      *pipeline = p;
      res = 0;
    } else {
      free(p);
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s end res(%d)\n", csu, res));
  return res;
}

void ubiq_platform_structured_pipeline_destroy(ubiq_platform_structured_pipeline_t * const pipeline) 
{
  static const char * const csu = "ubiq_platform_structured_pipeline_destroy";
  UBIQ_DEBUG(debug_flag, printf("%s started\n", csu));
  // ubiq_platform_operation_t * ptr = pipeline->operations[0];
  for (int i = 0; i < pipeline->next_available; i++) {
    UBIQ_DEBUG(debug_flag, printf("i: %d\n", i));
    UBIQ_DEBUG(debug_flag, printf("destroy :%d\n", pipeline->operations[i]->getType()));
    pipeline->operations[i]->destroy(pipeline->operations[i]->ctx);
    // ptr++;
  }
  free(pipeline->operations);
  free(pipeline);
  UBIQ_DEBUG(debug_flag, printf("%s end \n", csu));
}

int ubiq_platform_structured_pipeline_add_operation(
  ubiq_platform_structured_pipeline_t * const pipeline, 
  ubiq_platform_operation_t * const operation,
  size_t const position) // 0 means beginning, MAX_INT or -1 means end;
{
  static const char * const csu = "ubiq_platform_structured_pipeline_add_operation";
  UBIQ_DEBUG(debug_flag, printf("%s started\n", csu));
  int res = -ENOMEM;
  if (pipeline->next_available >= pipeline->allocated) {
    UBIQ_DEBUG(debug_flag, printf("Allocating addition space (%d)\n", pipeline->next_available));
    pipeline->allocated += 10;
    if ((pipeline->operations = realloc((pipeline->operations), pipeline->allocated * sizeof(ubiq_platform_operation_t))) != NULL) {
      res = 0;
    }
  } else {
    res = 0;
  }
  if (!res) {
    if (position == 0) {
      for (int i = pipeline->next_available; i > 0; i--) {
        pipeline->operations[i] = pipeline->operations[i - 1];
      }
      pipeline->next_available++;
      (pipeline->operations[0]) = operation;
    } else {
      UBIQ_DEBUG(debug_flag, printf("Adding at end : next_available(%d)\n", pipeline->next_available));
      (pipeline->operations[pipeline->next_available++]) = operation;
    }
  }
  UBIQ_DEBUG(debug_flag, printf("%s end res(%d)\n", csu, res));
  return res;
}

int ubiq_platform_structured_pipeline_invoke(
  ubiq_platform_structured_pipeline_t * const pipeline, 
  ubiq_platform_operation_context_t * const context)
{
  static int debug_flag = 1;
  static const char * const csu = "ubiq_platform_structured_pipeline_invoke";
  UBIQ_DEBUG(debug_flag, printf("%s started loop(%d)\n", csu, pipeline->next_available));
  int res = 0;
  for (int i = 0; !res && i < pipeline->next_available; i++) {
    char32_t * tmp = NULL;
    UBIQ_DEBUG(debug_flag, printf("%s pipeline->operations[i]->getType(%d) current(%S)\n", csu, pipeline->operations[i]->getType(), ubiq_platform_operation_context_get_current_value(context)));

    res = pipeline->operations[i]->invoke(context, &tmp);
    UBIQ_DEBUG(debug_flag, printf("%s pipeline->operations[i]->getType(%d) tmp(%S) res(%d)\n", csu, pipeline->operations[i]->getType(), tmp, res));
    if (!res) {
      res = ubiq_platform_operation_context_set_current_value(context, tmp);
    }
    free(tmp);
  }
  UBIQ_DEBUG(debug_flag, printf("%s end res(%d)\n", csu, res));
  return res;
}