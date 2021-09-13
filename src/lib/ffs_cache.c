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

#include <search.h>

struct ffs_cache {
  void * root;
};

struct ffs_element {
  char * key;
  void (*free_ptr)(void *);
  void * ffs;
};

static
void
destroy_element(
  void * element)
  {
    struct ffs_element* e = (struct ffs_element*)element;
    free(e->key);
    if (e->free_ptr && e->ffs) {
      (*e->free_ptr)(e->ffs);
    }
    free(e);
}

static
int
element_compare(const void *l, const void *r)
{
  printf("in compare\n");
    const struct ffs_element *el = l;
    const struct ffs_element *er = r;
    return strcmp(el->key, er->key);
}


static
int
create_element(
  struct ffs_element ** const element,
  const char * const key,
  void * ffs,
  void (*free_ptr)(void *))
{
  struct ffs_element * e;
  int res = -ENOMEM;

  printf ("sizeof(*ffs_element) %d\n", sizeof(* e));
  e = calloc(1, sizeof(* e));
  if (e != NULL) {
    e->key = strdup(key);
    e->ffs = ffs; //strdup(ffs);
    e->free_ptr = free_ptr;

    printf ("e %p\n", (void *) e);
    printf ("e->key %p\n", (void *) e->key);
    printf ("e->ffs %p\n", e->ffs);

    if (e->key != NULL) {
      *element = e;
      res = 0;
    } else {
      destroy_element(e);
    }
  }
  return res;
}

const char *
find_element(
  void * const  f,
  const char * const key
)
{
  const char * csu = "find_element";
  const char * ret = NULL;
  int res = 0;
  // Find requires an element but will not insert if
  // it does not exist, so make ffs empty string

  // printf("BEFORE &(((struct ffs_cache const *)f)->root %p\n", (((struct ffs_cache const *)f)->root));
  // printf ("f %p\n", (void *)f);
  // printf ("root %p\n", ((struct ffs_cache const *)f)->root);

  // void ** r = NULL;

  // r = &((struct ffs_cache const *)f)->root;
  // printf ("%s r %p\n", csu, r);

  void * root = NULL;
  struct ffs_element * find_element = NULL;
  void * data = NULL;
  res = create_element(&find_element, key, data, &free);
  if (!res) {
    printf("BEFORE\n");
    void * const find_node = tfind(find_element, &(((struct ffs_cache const *)f)->root), element_compare);
    printf("rec '%p'\n", (void *)find_node);
    if (find_node != NULL) {

      /*
      * tfind returns the pointer tothe node in the tre *Basically a point to a point to the data item.
      * cast as a double pointer and then deference to get the actual data.
      */

      struct ffs_element * const rec = *(struct ffs_element ** ) find_node;
      printf("rec '%p'\n", (void *)rec);
      ret = rec->ffs;
      printf("%s rec->key '%p'\n", csu, (void *)rec->key);
      printf("%s rec->ffs '%p'\n", csu, rec->ffs);
    }
  }
  destroy_element(find_element);
  printf("%s AFTER &(((struct ffs_cache const *)f)->root %p\n", csu, (((struct ffs_cache const *)f)->root));
  return ret;
}

int
add_element(
  void * f,
  const char * const key,
  void * ffs,
  void (*free_ptr)(void *)
)
{
  const char * csu = "add_element";

  // add needs to be careful if the record already exists or not.  If
  // it already exists, the new record might not match the find record
  // in which case, need to destroy the find item.

  int res = 0;

  struct ffs_element * find_element = NULL;
  struct ffs_element * inserted_element = NULL;

  res = create_element(&find_element, key, ffs, free_ptr);
  if (!res) {
    printf("%s find_element '%p'\n", csu, (void *)find_element);
    printf("%s find_element->key '%p'\n", csu, (void *)find_element->key);
    printf("%s find_element->ffs '%p'\n", csu, find_element->ffs);
    inserted_element = tsearch(find_element,&((struct ffs_cache *)f)->root, element_compare);
    if (inserted_element == NULL) {
      res = -ENOMEM;
    } else {
      /*  We must know if the allocated pointed
          to space was saved in the tree or not. */
       struct ffs_element *re = 0;
       re = *(struct ffs_element **)inserted_element;
      if (re != find_element) {
        printf("Add Existing element\n");
        // Record already existed.
        destroy_element(find_element);
      } else {
        printf("%s re '%p'\n", csu, (void *)re);
        printf("%s re->key '%p'\n", csu, (void *)re->key);
        printf("%s re->ffs '%p'\n", csu, re->ffs);
        printf("%s inserted_element '%p'\n", csu, (void *)inserted_element);
        printf("%s inserted_element->key '%p'\n", csu, (void *)inserted_element->key);
        printf("%s inserted_element->ffs '%p'\n", csu, inserted_element->ffs);
        printf("Added new element\n");
      }
    }
  }
  return res;
}


int
create_ffs_cache(void ** const ffs_cache) {
  struct ffs_cache * f;
  int res = -ENOMEM;
  printf ("sizeof(* f) %d\n", sizeof(* f));
  f = calloc(1, sizeof(* f));
  if (f != NULL) {
    f->root = NULL;
    *ffs_cache = f;

    res = 0;
  }
  printf ("f %p\n", (void *)f);
  printf ("root %p\n", f->root);

  return res;
}

void
destroy_ffs_cache(void * const ffs_cache) {
  // Walk the list and destroy each node
  tdestroy(((struct ffs_cache *)ffs_cache)->root, destroy_element);
  free(ffs_cache );

}
