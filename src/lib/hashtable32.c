
/*
 * Adapted from https://gist.github.com/phsym/4605704 (Pierre-Henri Symoneaux)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "ubiq/platform/internal/hashtable32.h"

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

typedef struct hash32_elem_t ubiq_platform_hash32_elem;

//Hashtable element structure
struct hash32_elem_t {
	ubiq_platform_hash32_elem* next; // Next element in case of a collision
	void* data;	// Pointer to the stored element
	char32_t key[]; 	// Key of the stored element
};

//Hashtabe structure
struct hashtable32_t {
	unsigned int capacity;	// Hashtable capacity (in terms of hashed keys)
	unsigned int e_num;	// Number of element currently stored in the hashtable
	ubiq_platform_hash32_elem** table;	// The table containaing elements
} ;

//Structure used for iterations
struct hash32_elem_it_t {
	ubiq_platform_hashtable32* ht; 	// The hashtable on which we iterate
	unsigned int index;	// Current index in the table
	ubiq_platform_hash32_elem* elem; 	// Curent element in the list
} ;

unsigned int ubiq_platform_ht32_element_count(const ubiq_platform_hashtable32 * const hasht) {

   return hasht->e_num;
}

/* 	
  Internal funcion to calculate hash for keys.
	It's based on the DJB algorithm from Daniel J. Bernstein.
	The key must be ended by '\0' character.
*/
static unsigned long ht_calc_hash32(const char32_t * const key)
{
	unsigned long hash = 5381;
	unsigned long c;
  char32_t * ptr = (char32_t *)key;
	while ((c = (unsigned long)*ptr++)) {
		hash = ((hash << 5) + hash) + c;
  }

	return hash;
}

/*
   Create a hashtable with capacity 'capacity'
	 and return a pointer to it
*/
int ubiq_platform_ht32_create(unsigned int capacity, ubiq_platform_hashtable32** hasht)
{
  int ret = 0;
  ubiq_platform_hashtable32 * h = NULL;


	h = malloc(sizeof(*h));
	if(!h) {
		return -ENOMEM;
  }
  
	if((h->table = calloc(capacity, sizeof(ubiq_platform_hash32_elem*))) == NULL)
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
int ubiq_platform_ht32_put(ubiq_platform_hashtable32* hasht, const char32_t* const key, void* data, void ** existing_data)
{
	if(data == NULL) {
		return -EINVAL;
  }
	unsigned long h = ht_calc_hash32(key) % hasht->capacity;
	ubiq_platform_hash32_elem* e = hasht->table[h];

	while(e != NULL)
	{
		if(!u32_strcmp((const uint32_t *)e->key, (const uint32_t *)key))
		{
			*existing_data = e->data;
			e->data = data;
      
			return 0;
		}
		e = e->next;
	}

	// Getting here means the key doesn't already exist

	if((e = malloc(sizeof(ubiq_platform_hash32_elem)+(u32_strlen((const uint32_t *)key)+1) * sizeof(char32_t))) == NULL) {
		return -ENOMEM;
  }
	u32_strcpy((uint32_t * const)e->key, (const uint32_t *)key);
	e->data = data;

	// Add the element at the beginning of the linked list
	e->next = hasht->table[h];
	hasht->table[h] = e;
	hasht->e_num ++;

	*existing_data = NULL;
  return 0;
}

/* Retrieve data from the hashtable */
void* ubiq_platform_ht32_get(const ubiq_platform_hashtable32 * const hasht, const char32_t * const key)
{
	unsigned long h = ht_calc_hash32(key) % hasht->capacity;
	ubiq_platform_hash32_elem* e = hasht->table[h];
	while(e != NULL)
	{
		if(!u32_strcmp((const uint32_t *)e->key, (const uint32_t *)key))
			return e->data;
		e = e->next;
	}
	return NULL;
}

/* 	Remove data from the hashtable. Return the data removed from the table
	so that we can free memory if needed */
void* ubiq_platform_ht32_remove(ubiq_platform_hashtable32 * const hasht, const char32_t* const key)
{
	unsigned long h = ht_calc_hash32(key) % hasht->capacity;
	ubiq_platform_hash32_elem* e = hasht->table[h];
	ubiq_platform_hash32_elem* prev = NULL;
	while(e != NULL)
	{
		if(!u32_strcmp((const uint32_t *)e->key, (const uint32_t *)key))
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
int ubiq_platform_ht32_list_keys(const ubiq_platform_hashtable32 * const hasht, char32_t** k, size_t len)
{
	if(len < hasht->e_num) {
		return -EINVAL;
  }
	int ki = 0; //Index to the current string in **k
	int i = hasht->capacity;
	while(--i >= 0)
	{
		ubiq_platform_hash32_elem* e = hasht->table[i];
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
int ubiq_platform_ht32_list_values(const ubiq_platform_hashtable32 * const hasht, void** v, size_t len)
{
	if(len < hasht->e_num){
		return -EINVAL;
  }

	int vi = 0; //Index to the current string in **v
	int i = hasht->capacity;
	while(--i >= 0)
	{
		ubiq_platform_hash32_elem* e = hasht->table[i];
		while(e)
		{
			v[vi++] = e->data;
			e = e->next;
		}
	}
  return 0;
}

/* Iterate through table's elements. */
ubiq_platform_hash32_elem* ubiq_platform_ht32_iterate(ubiq_platform_hash32_elem_itr* iterator)
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
	ubiq_platform_hash32_elem* e = iterator->elem;
	if(e)
		iterator->elem = e->next;
	return e;
}

/* Iterate through keys. */
const char32_t* const ubiq_platform_ht32_iterate_keys(ubiq_platform_hash32_elem_itr * const iterator)
{
	ubiq_platform_hash32_elem* e = ubiq_platform_ht32_iterate(iterator);
	return (e == NULL ? NULL : e->key);
}

/* Iterate through values. */
void* ubiq_platform_ht32_iterate_values(ubiq_platform_hash32_elem_itr * const iterator)
{
	ubiq_platform_hash32_elem* e = ubiq_platform_ht32_iterate(iterator);
	return (e == NULL ? NULL : e->data);
}

/* 	Removes all elements stored in the hashtable.
	if free_data, all stored datas are also freed.*/
int ubiq_platform_ht32_clear(ubiq_platform_hashtable32 * const hasht, void (*free_node)(void *nodep))
{
	ubiq_platform_hash32_elem_itr *it = NULL;
	ubiq_platform_ht32_create_iterator(hasht, &it);
	const char32_t* k = ubiq_platform_ht32_iterate_keys(it);
	while(k != NULL)
	{
    // freenode could be null if no memory management needed
    if (free_node) {
		  (free_node)(ubiq_platform_ht32_remove(hasht, k));
    } else {
      ubiq_platform_ht32_remove(hasht, k);
    }
		k = ubiq_platform_ht32_iterate_keys(it);
	}
	ubiq_platform_ht32_destroy_iterator(it);
  return 0;
}

/* 	Destroy the hash table, and free memory.
	Data still stored are freed*/
void ubiq_platform_ht32_destroy(ubiq_platform_hashtable32* hasht, void (*free_node)(void *nodep))
{
	ubiq_platform_ht32_clear(hasht, free_node); // Delete and free all.
	free(hasht->table);
	free(hasht);
}


const char32_t * ubiq_platform_ht32_element_key(ubiq_platform_hash32_elem * element) {
   return element->key;
}
const void * ubiq_platform_ht32_element_data(ubiq_platform_hash32_elem * element) {
   return element->data;
}



int ubiq_platform_ht32_create_iterator(ubiq_platform_hashtable32* ht, ubiq_platform_hash32_elem_itr ** itr) {
   ubiq_platform_hash32_elem_itr * it;
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

void ubiq_platform_ht32_destroy_iterator(ubiq_platform_hash32_elem_itr * itr) {

   free(itr);
   itr = NULL;
}


void ubiq_platform_ht32_walk_r(
  const ubiq_platform_hashtable32 * const hasht,
  void (* action) (const void *__nodep, void *__closure) ,
  void *__closure) 
{

 static const char * const csu = "ubiq_platform_ht32_walk_r";

  UBIQ_DEBUG(debug_flag, printf("%s __closure(%p)\n", csu, __closure));
	int i = hasht->capacity;
	while(--i >= 0)
	{
		ubiq_platform_hash32_elem* e = hasht->table[i];
		while(e)
		{
			(action)(&e->data, __closure);
			e = e->next;
		}
	}
}
   


