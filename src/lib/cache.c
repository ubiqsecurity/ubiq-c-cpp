/*
 * Caching of FFS information based on FFS name.  Including pAPI in the
 * cache since in theory, this could used to go to different accounts
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
#include <search.h>


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

// Defined in CMAKE if glibc < 2.30
#ifdef SUPPRESS_TWALK_R
void
twalk_r (const void *vroot, void (*action) (const void *, VISIT, void *),
	   void *closure) {
}

#endif


struct ubiq_platform_cache {
  void * root;
  unsigned int count;
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
element_compare(const void *l, const void *r)
{
  const struct cache_element *el = l;
  const struct cache_element *er = r;
  return strcmp(el->key, er->key);
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
      e->expires_after = ts.tv_sec + duration;

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

const char *
ubiq_platform_cache_find_element(
  struct ubiq_platform_cache * const  ubiq_cache,
  char * const key
)
{
  const char * csu = "find_element";
  const char * ret = NULL;
  struct timespec ts;
  int res = 0;
  // Find requires an element but will not insert if
  // it does not exist, so make ffs empty string

  // tfind does insert into tree, so can simple use stack
  // for find_element

  void * root = NULL;
  struct cache_element find_element;
  find_element.key = key;
  void * data = NULL;
  void * const find_node = tfind(&find_element, &(((struct ubiq_platform_cache const *)ubiq_cache)->root), element_compare);
  if (find_node != NULL) {

    /*
    * tfind returns the pointer tothe node in the tre *Basically a point to a point to the data item.
    * cast as a double pointer and then deference to get the actual data.
    */

    struct cache_element * const rec = *(struct cache_element ** ) find_node;
    // If expired after is BEFORE current time, then delete it.
    res = get_time(&ts);
    if (res != 0 || rec->expires_after < ts.tv_sec)
    {
      tdelete(&find_element, &(((struct ubiq_platform_cache *)ubiq_cache)->root), element_compare);
      destroy_element(rec);
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
  const time_t duration,
  void * data,
  void (*free_ptr)(void *)
)
{
  const char * csu = "ubiq_platform_cache_add_element";
  int debug_flag = 0;

  // add needs to be careful if the record already exists or not.  If
  // it already exists, the new record might not match the find record
  // in which case, need to destroy the find item.

  int res = 0;

  struct cache_element * find_element = NULL;
  struct cache_element * inserted_element = NULL;

  res = create_element(&find_element, key, duration, data, free_ptr);
  UBIQ_DEBUG(debug_flag, printf("%s \n \tcreate_element res(%d) \n",csu, res));
  if (!res) {
    inserted_element = tsearch(find_element,&((struct ubiq_platform_cache *)ubiq_cache)->root, element_compare);
    if (inserted_element == NULL) {
      res = -ENOMEM;
      UBIQ_DEBUG(debug_flag, printf("%s \n \ttsearch res(%d) \n",csu, res));
    } else {
      ((struct ubiq_platform_cache *)ubiq_cache)->count++;
      /*  We must know if the allocated pointed
          to space was saved in the tree or not. */
      struct cache_element *re = 0;
      re = *(struct cache_element **)inserted_element;
      if (re != find_element) {
      UBIQ_DEBUG(debug_flag, printf("Record already exists %s \n",csu));
        // Record already existed.
        struct timespec ts;
        res = get_time(&ts);
        // Check expiration date and delete OLD, then add new if necessary
        // Otherwise delete the find element since it was not ADDED

        if (res != 0 || re->expires_after < ts.tv_sec)
        {

          struct cache_element tmp;
          tmp.expires_after = find_element->expires_after;
          tmp.key = find_element->key;
          tmp.data = find_element->data;
          tmp.free_ptr = find_element->free_ptr;

          find_element->expires_after = re->expires_after;
          find_element->key = re->key;
          find_element->data = re->data;
          find_element->free_ptr = tmp.free_ptr;

          re->expires_after = tmp.expires_after;
          re->key = tmp.key;
          re->data = tmp.data;
          re->free_ptr = tmp.free_ptr;

        }
        destroy_element(find_element);

      }
    }
  }
  return res;
}


int
ubiq_platform_cache_create(
  struct ubiq_platform_cache ** const ubiq_cache)
{
  struct ubiq_platform_cache * tmp_cache;
  int res = -ENOMEM;
  tmp_cache = calloc(1, sizeof(* tmp_cache));
  if (tmp_cache != NULL) {
    tmp_cache->root = NULL;
    tmp_cache->count = 0; 
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
    tdestroy(((struct ubiq_platform_cache *)ubiq_cache)->root, destroy_element);
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
    *count = ubiq_cache->count;
    res = 0;
  }

  return res;
}

typedef struct callback_data {
    void (* action) (const void *__nodep, VISIT __value, void *__closure);
    void * data;
  } callback_data_t;


void
walk_r_action(const void *nodep, VISIT which, void *__closure)
{
  int debug_flag = 0;
  static const char * const csu = "walk_r_action";

  // UBIQ_DEBUG(debug_flag, printf("%s \n \t%p  %d \n",csu, ubiq_cache->root, ubiq_cache->count));

  struct cache_element * e = NULL;

  e = *(struct cache_element **) nodep;

  UBIQ_DEBUG(debug_flag, printf("%s key (%s): \n", csu, e->key));
  // printf("%s data (%s): \n", csu, e->data);

  struct callback_data * cb;
  cb = (struct callback_data *)__closure;

  UBIQ_DEBUG(debug_flag, printf("%s \n \tcb.action(%p)  cb.data(%p) \n",csu, cb->action, cb->data));


  (cb->action)(&e->data, which, cb->data);


  UBIQ_DEBUG(debug_flag, printf("%s \n \t END \n",csu));
}


void
ubiq_platform_cache_walk_r(
  struct ubiq_platform_cache * ubiq_cache,
  void (* action) (const void *__nodep, VISIT __value,
			       void *__closure) ,
  void *__closure)
{
  int debug_flag = 0;
  static const char * const csu = "ubiq_platform_cache_walk_r";

  callback_data_t * cb;

  cb = malloc(sizeof(struct callback_data));

  cb->action = action;
  cb->data = __closure;

  UBIQ_DEBUG(debug_flag, printf("%s \n \tcb.action(%p)  cb.data(%p) \n",csu, cb->action, cb->data));


  UBIQ_DEBUG(debug_flag, printf("%s \n \taction(%p)  data(%p) \n",csu, action, __closure));


  UBIQ_DEBUG(debug_flag, printf("%s \n \t%p  %p \n",csu, ubiq_cache->root, ubiq_cache->count));


  if (ubiq_cache != NULL) {
    twalk_r(ubiq_cache->root, walk_r_action, cb);
  }
  UBIQ_DEBUG(debug_flag, printf("%s \n \t END \n",csu));
  free(cb);
}
