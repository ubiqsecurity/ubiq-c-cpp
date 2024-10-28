/*
 * Caching of FFS information based on FFS name.  Including pAPI in the
 * cache_ht since in theory, this could used to go to different accounts
 * which could have same FFS name but for different Ubiq accounts, and therefore
 * different data.
 *
 * Since the universe of FFS values will be small, but the linux hash table is an
 * immutable size, going to use a simple b-tree
*/

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "ubiq/platform/internal/hashtable.h"

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


struct ubiq_platform_cache {
  ubiq_platform_hashtable * root;
  time_t ttl_seconds;
  // TODO - Add something to prevent aged elements from being removed - such as billing elements.  Not critical since should flush every 10 seconds or so so ageing out shouldn't happen
};

// The element records the expiration time.
// If it is expired, the find will remove the element automatically

struct cache_element {
  time_t expires_after;
  char * key;
  void (*free_ptr)(void *);
  void * data;
};

static
int
get_time(struct timespec * ck_mon) {
  int res = 0;
  struct timespec tp;
  if (0 == (res = clock_gettime(CLOCK_MONOTONIC, &tp))) {
    *ck_mon = tp;
  } else {
    res = -errno;
  }
  return res;
}

static
void
destroy_element(
void * element)
{
  struct cache_element* e = (struct cache_element*)element;
  free(e->key);
  if (e->free_ptr && e->data) {
    (*e->free_ptr)(e->data);
  }
  free(e);
}

static
int
create_element(
  struct cache_element ** const element,
  const char * const key,
  const time_t duration,
  void * data,
  void (*free_ptr)(void *))
{
  struct cache_element * e;
  struct timespec ts;
  int res = -ENOMEM;

  if (duration < 0) {
    res = -EINVAL;
  } else if (0 == (res = get_time(&ts))) {
    e = calloc(1, sizeof(* e));
    if (e != NULL) {
      e->key = strdup(key);
      e->data = data;
      e->free_ptr = free_ptr;
      // current time + duration in seconds
      if (duration == 0) {
        // Meant to expire immediately so add it as expired.
        e->expires_after = ts.tv_sec - 1;
      } else {
        e->expires_after = ts.tv_sec + duration;
        
      }

      if (e->key != NULL) {
        *element = e;
      } else {
        res = -ENOMEM;
        destroy_element(e);
      }
    }
  }
  return res;
}

const void *
ubiq_platform_cache_find_element(
  struct ubiq_platform_cache * const  ubiq_cache,
  const char * const key
)
{
  int debug_flag = 1;
  const char * csu = "ubiq_platform_cache_find_element";
  const char * ret = NULL;
  struct timespec ts;
  int res = 0;
  // Find requires an element but will not insert if
  // it does not exist, so make ffs empty string

  // tfind does insert into tree, so can simple use stack
  // for find_element

  if (ubiq_cache == NULL || ubiq_cache->root == NULL) {
    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_cache_find_element   ubiq_cache or ubiq_cache->root is NULL\n"));
  }

  void * find_node = ubiq_platform_ht_get(ubiq_cache->root, key);

  if (find_node != NULL) {
    struct cache_element * const rec = (struct cache_element * ) find_node;
    // If expired after is BEFORE current time, then delete it.
    res = get_time(&ts);
    if (res != 0 || rec->expires_after < ts.tv_sec)
    {
      UBIQ_DEBUG(debug_flag, printf("res(%d)  expired(%d)\n", res,rec->expires_after < ts.tv_sec));
      find_node = ubiq_platform_ht_remove((((struct ubiq_platform_cache const *)ubiq_cache)->root), key);
      destroy_element(find_node);
    } else {
      ret = rec->data;
    }
  }
  return ret;
}

int
ubiq_platform_cache_add_element(
  struct ubiq_platform_cache * ubiq_cache,
  const char * const key,
  void * data,
  void (*free_ptr)(void *)
)
{
  const char * csu = "ubiq_platform_cache_add_element";

  // add needs to be careful if the record already exists or not.  If
  // it already exists, the new record might not match the find record
  // in which case, need to destroy the find item.

  int res = 0;

  struct cache_element * existing_element = NULL;
  struct cache_element * inserted_element = NULL;

  // Attempt to find the element. If it already exists, don't add
  // Use the cache find since that will remove an element if the time has expired.

  // If it doesn't exist, then insert.  Else return 

  existing_element = (struct cache_element *)ubiq_platform_cache_find_element(ubiq_cache, key);
  UBIQ_DEBUG(debug_flag, printf("%s existing_element (%s) : %d\n", csu, key, (existing_element != NULL)));
  if (existing_element == NULL) {
     if (0 == (res = create_element(&inserted_element, key, ubiq_cache->ttl_seconds, data, free_ptr))) {
      // Did a check above so put should return 0 since record should not exist
      res = ubiq_platform_ht_put(ubiq_cache->root, key, inserted_element, (void **)&existing_element);
      if (existing_element != NULL) {
        destroy_element(existing_element);
        res = -EINVAL;
      }
    }
  } else {
      UBIQ_DEBUG(debug_flag, printf("Data payload already exists\n"));
    // Data payload is NOT added since record already exists so free data
    if (free_ptr) {
      UBIQ_DEBUG(debug_flag, printf("Freeing data : %d\n", free_ptr != NULL));
      (free_ptr)(data);
    }
  }
  return res;
}


int
ubiq_platform_cache_create(
  unsigned int capacity,
  const time_t ttl_seconds,
  struct ubiq_platform_cache ** const ubiq_cache)
{
  struct ubiq_platform_cache * tmp_cache;
  int res = -ENOMEM;
  *ubiq_cache = NULL;

  if (ttl_seconds < 0) {
    
    return -EINVAL;
  }
  
  tmp_cache = calloc(1, sizeof(* tmp_cache));
  if (tmp_cache != NULL) {
    ubiq_platform_ht_create(capacity, &tmp_cache->root);
    tmp_cache->ttl_seconds = ttl_seconds;
    *ubiq_cache = tmp_cache;

    res = 0;
  }

  return res;
}

void
ubiq_platform_cache_destroy(
  struct ubiq_platform_cache * const ubiq_cache)
{
  // Walk the list and destroy each node
  if (ubiq_cache) {
    ubiq_platform_ht_destroy(((struct ubiq_platform_cache *)ubiq_cache)->root, destroy_element);
    // tdestroy(((struct ubiq_platform_cache *)ubiq_cache)->root, destroy_element);
  }
  free(ubiq_cache );

}


int
ubiq_platform_cache_get_element_count(
  struct ubiq_platform_cache * ubiq_cache,
  unsigned int * count
)
{
  int res = -EINVAL;
  if (ubiq_cache != NULL && count != NULL) {
    *count = ubiq_platform_ht_element_count(ubiq_cache->root);
    res = 0;
  }

  return res;
}

typedef struct callback_data {
    void (* action) (const void *__nodep, void *__closure);
    void * data;
  } callback_data_t;


void
cache_ht_walk_r_action(const void *nodep, void *__closure)
{
  int debug_flag = 0;
  static const char * const csu = "cache_ht_walk_r_action";

  struct cache_element * e = NULL;

  e = *(struct cache_element **) nodep;

  UBIQ_DEBUG(debug_flag, printf("%s key (%s): \n", csu, e->key));

  struct callback_data * cb;
  cb = (struct callback_data *)__closure;

  UBIQ_DEBUG(debug_flag, printf("%s \n \tcb.action(%p)  cb.data(%p) \n",csu, cb->action, cb->data));


  (cb->action)(&e->data, cb->data);


  UBIQ_DEBUG(debug_flag, printf("%s \n \t END \n",csu));
}


void
ubiq_platform_cache_walk_r(
  struct ubiq_platform_cache * ubiq_cache,
  void (* action) (const void *__nodep, void *__closure) ,
  void *__closure)
{
  int debug_flag = 0;
  static const char * const csu = "ubiq_platform_cache_walk_r";


  UBIQ_DEBUG(debug_flag, printf("%s started(%p %p %p)\n", csu, ubiq_cache, action, __closure));

  struct callback_data  * cb = malloc(sizeof(*cb));

  if (cb == NULL) {
    UBIQ_DEBUG(debug_flag, printf("ubiq_platform_cache_walk_r cb is NULL:\n"));
  }

  UBIQ_DEBUG(debug_flag, printf("%s cb (%p)\n", csu, cb));

  cb->action = action;
  cb->data = __closure;

  ubiq_platform_ht_walk_r(ubiq_cache->root, cache_ht_walk_r_action, cb);

  free(cb);
}
