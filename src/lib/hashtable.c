
/*
 * Adapted from https://gist.github.com/phsym/4605704 (Pierre-Henri Symoneaux)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
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
**************************************************************************************/

typedef struct hash_elem_t ubiq_platform_hash_elem;

//Hashtable element structure
struct hash_elem_t {
	ubiq_platform_hash_elem* next; // Next element in case of a collision
	void* data;	// Pointer to the stored element
	char key[]; 	// Key of the stored element
};

//Hashtabe structure
struct hashtable_t {
	unsigned int capacity;	// Hashtable capacity (in terms of hashed keys)
	unsigned int e_num;	// Number of element currently stored in the hashtable
	ubiq_platform_hash_elem** table;	// The table containaing elements
} ;

//Structure used for iterations
struct hash_elem_it_t {
	ubiq_platform_hashtable* ht; 	// The hashtable on which we iterate
	unsigned int index;	// Current index in the table
	ubiq_platform_hash_elem* elem; 	// Curent element in the list
} ;

unsigned int ubiq_platform_ht_element_count(const ubiq_platform_hashtable * const hasht) {

   return hasht->e_num;
}

/* 	
  Internal funcion to calculate hash for keys.
	It's based on the DJB algorithm from Daniel J. Bernstein.
	The key must be ended by '\0' character.
*/
static unsigned int ht_calc_hash(const char * const key)
{
	unsigned int hash = 5381;
	int c;
  char * ptr = (char *)key;
	while ((c = (int)*ptr++)) {
		hash = ((hash << 5) + hash) + c;
  }

	return hash;
}

/*
   Create a hashtable with capacity 'capacity'
	 and return a pointer to it
*/
int ubiq_platform_ht_create(unsigned int capacity, ubiq_platform_hashtable** hasht)
{
  int ret = 0;
  ubiq_platform_hashtable * h = NULL;


	h = malloc(sizeof(*h));
	if(!h) {
		return -ENOMEM;
  }
  
	if((h->table = calloc(capacity, sizeof(ubiq_platform_hash_elem*))) == NULL)
	{
		free(h->table);
    free(h);
		return -ENOMEM;;
	}

	h->capacity = capacity;
	h->e_num = 0;
  *hasht = h;
	return 0;
}

/* 	Store data in the hashtable. If data with the same key are already stored,
	they are overwritten, and return by the function. Else it return NULL.
	Return HT_ERROR if there are memory alloc error*/
int ubiq_platform_ht_put(ubiq_platform_hashtable* hasht, const char* const key, void* data, void ** existing_data)
{
	if(data == NULL) {
		return -EINVAL;
  }
	unsigned int h = ht_calc_hash(key) % hasht->capacity;
	ubiq_platform_hash_elem* e = hasht->table[h];

	while(e != NULL)
	{
		if(!strcmp(e->key, key))
		{
			*existing_data = e->data;
			e->data = data;
      
			return 0;
		}
		e = e->next;
	}

	// Getting here means the key doesn't already exist

	if((e = malloc(sizeof(ubiq_platform_hash_elem)+strlen(key)+1)) == NULL) {
		return -ENOMEM;
  }
	strcpy(e->key, key);
	e->data = data;

	// Add the element at the beginning of the linked list
	e->next = hasht->table[h];
	hasht->table[h] = e;
	hasht->e_num ++;

	*existing_data = NULL;
  return 0;
}

/* Retrieve data from the hashtable */
void* ubiq_platform_ht_get(const ubiq_platform_hashtable * const hasht, const char * const key)
{
	unsigned int h = ht_calc_hash(key) % hasht->capacity;
	ubiq_platform_hash_elem* e = hasht->table[h];
	while(e != NULL)
	{
		if(!strcmp(e->key, key))
			return e->data;
		e = e->next;
	}
	return NULL;
}

/* 	Remove data from the hashtable. Return the data removed from the table
	so that we can free memory if needed */
void* ubiq_platform_ht_remove(ubiq_platform_hashtable * const hasht, const char* const key)
{
	unsigned int h = ht_calc_hash(key) % hasht->capacity;
	ubiq_platform_hash_elem* e = hasht->table[h];
	ubiq_platform_hash_elem* prev = NULL;
	while(e != NULL)
	{
		if(!strcmp(e->key, key))
		{
			void* ret = e->data;
			if(prev != NULL)
				prev->next = e->next;
			else
				hasht->table[h] = e->next;
			free(e);
			e = NULL;
			hasht->e_num --;
			return ret;
		}
		prev = e;
		e = e->next;
	}
	return NULL;
}

/* List keys. k should have length equals or greater than the number of keys */
int ubiq_platform_ht_list_keys(const ubiq_platform_hashtable * const hasht, char** k, size_t len)
{
	if(len < hasht->e_num) {
		return -EINVAL;
  }
	int ki = 0; //Index to the current string in **k
	int i = hasht->capacity;
	while(--i >= 0)
	{
		ubiq_platform_hash_elem* e = hasht->table[i];
		while(e)
		{
			k[ki++] = e->key;
			e = e->next;
		}
	}
  return 0;
}

/* 	List values. v should have length equals or greater 
	than the number of stored elements */
int ubiq_platform_ht_list_values(const ubiq_platform_hashtable * const hasht, void** v, size_t len)
{
	if(len < hasht->e_num){
		return -EINVAL;
  }

	int vi = 0; //Index to the current string in **v
	int i = hasht->capacity;
	while(--i >= 0)
	{
		ubiq_platform_hash_elem* e = hasht->table[i];
		while(e)
		{
			v[vi++] = e->data;
			e = e->next;
		}
	}
  return 0;
}

/* Iterate through table's elements. */
ubiq_platform_hash_elem* ubiq_platform_ht_iterate(ubiq_platform_hash_elem_itr* iterator)
{
	while(iterator->elem == NULL)
	{
		if(iterator->index < iterator->ht->capacity - 1)
		{
			iterator->index++;
			iterator->elem = iterator->ht->table[iterator->index];
		}
		else
			return NULL;
	}
	ubiq_platform_hash_elem* e = iterator->elem;
	if(e)
		iterator->elem = e->next;
	return e;
}

/* Iterate through keys. */
const char* const ubiq_platform_ht_iterate_keys(ubiq_platform_hash_elem_itr * const iterator)
{
	ubiq_platform_hash_elem* e = ubiq_platform_ht_iterate(iterator);
	return (e == NULL ? NULL : e->key);
}

/* Iterate through values. */
void* ubiq_platform_ht_iterate_values(ubiq_platform_hash_elem_itr * const iterator)
{
	ubiq_platform_hash_elem* e = ubiq_platform_ht_iterate(iterator);
	return (e == NULL ? NULL : e->data);
}

/* 	Removes all elements stored in the hashtable.
	if free_data, all stored datas are also freed.*/
int ubiq_platform_ht_clear(ubiq_platform_hashtable * const hasht, void (*free_node)(void *nodep))
{
	ubiq_platform_hash_elem_itr *it = NULL;
	ubiq_platform_ht_create_iterator(hasht, &it);
	const char* k = ubiq_platform_ht_iterate_keys(it);
	while(k != NULL)
	{
    // freenode could be null if no memory management needed
    if (free_node) {
		  (free_node)(ubiq_platform_ht_remove(hasht, k));
    } else {
      ubiq_platform_ht_remove(hasht, k);
    }
		k = ubiq_platform_ht_iterate_keys(it);
	}
	ubiq_platform_ht_destroy_iterator(it);
  return 0;
}

/* 	Destroy the hash table, and free memory.
	Data still stored are freed*/
void ubiq_platform_ht_destroy(ubiq_platform_hashtable* hasht, void (*free_node)(void *nodep))
{
	ubiq_platform_ht_clear(hasht, free_node); // Delete and free all.
	free(hasht->table);
	free(hasht);
}


const char * ubiq_platform_ht_element_key(ubiq_platform_hash_elem * element) {
   return element->key;
}
const void * ubiq_platform_ht_element_data(ubiq_platform_hash_elem * element) {
   return element->data;
}



int ubiq_platform_ht_create_iterator(ubiq_platform_hashtable* ht, ubiq_platform_hash_elem_itr ** itr) {
   ubiq_platform_hash_elem_itr * it;
   it = calloc(1, sizeof(*it));
   if (it == NULL) {
    return -ENOMEM;
   }
   it->ht = ht;
   it->index = 0;
   it->elem = ht->table[0];
   
   *itr = it;
   return 0;
}

void ubiq_platform_ht_destroy_iterator(ubiq_platform_hash_elem_itr * itr) {

   free(itr);
   itr = NULL;
}


void ubiq_platform_ht_walk_r(
  const ubiq_platform_hashtable * const hasht,
  void (* action) (const void *__nodep, void *__closure) ,
  void *__closure) 
{

 static const char * const csu = "ubiq_platform_ht_walk_r";

  UBIQ_DEBUG(debug_flag, printf("%s __closure(%p)\n", csu, __closure));
	int i = hasht->capacity;
	while(--i >= 0)
	{
		ubiq_platform_hash_elem* e = hasht->table[i];
		while(e)
		{
			(action)(&e->data, __closure);
			e = e->next;
		}
	}
}
   


