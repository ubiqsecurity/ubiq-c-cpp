#pragma once

#include <ubiq/platform/compat/cdefs.h>


__BEGIN_DECLS

#ifdef NODEF
//struct hash_elem_t;
// typedef struct hash_elem_t ubiq_platform_hash_elem;
#endif

//Hashtabe structure
typedef struct hashtable_t ubiq_platform_hashtable;

//Structure used for iterations
typedef struct hash_elem_it_t ubiq_platform_hash_elem_itr;


/**
 * @brief Creae a hash table.  Capacity is storage allocated for the hash table.  
 * The capacity cannot be changed but the number of elements stored can be larger than the capacity value, 
 * It just leads to a potentially higher number of key collisions and performance issues.
 * 
 * @param capacity 
 * @return ubiq_platform_hashtable* 
 */
 int ubiq_platform_ht_create(unsigned int capacity, ubiq_platform_hashtable** hasht);

/**
 * @brief Insert data into the hash table
 * 
 * @param hasht - handle of table
 * @param key - character string for the key.  Key will be copied 
 * @param data - Data to be inserted
 * @return void* - NULL if data was inserted.  If data already existed for this key, the 
 * original data will be returned and the supplied data will be stored.  Caller is responsible for
 * freeing original data if it existed.
 */
int ubiq_platform_ht_put(ubiq_platform_hashtable* hasht, const char*const key, void* data, void ** existing_data);

/**
 * @brief Get a handle to the data stored.  This is actual handle to the data and should not be 
 * freed by the caller.
 * 
 * @param hasht 
 * @param key 
 * @return void* 
 */
void* ubiq_platform_ht_get(const ubiq_platform_hashtable * const hasht, const char * const key);

/**
 * @brief Remove an element from the table.  Returns a pointer to the data which may require freeing by the caller.  Returns NULL if 
 * data doesn't exist
 * 
 * @param hasht 
 * @param key 
 * @return void* 
 */
void* ubiq_platform_ht_remove(ubiq_platform_hashtable * const hasht, const char * const key);

/**
 * @brief Return a list of the keys for the table.  k needs to be pre-allocated to len.  Will fail if 
 * len is less than the number of elements stored in the table.  Do not alter key values
 * 
 * @param hasht 
 * @param k 
 * @param len 
 */
int ubiq_platform_ht_list_keys(const ubiq_platform_hashtable * const hasht, char** k, size_t len);

/**
 * @brief Return a list of the data values stored.  Will fail if 
 * len is less than the number of elements stored in the table.  Caller can modify data values
 * 
 * @param hasht 
 * @param v 
 * @param len 
 */

int ubiq_platform_ht_list_values(const ubiq_platform_hashtable * const hasht, void** v, size_t len);

/**
 * @brief Iterate over elements in the hash table
 * 
 * @param iterator 
 * @return hash_elem_t* 
 */
// ubiq_platform_hash_elem * ubiq_platform_ht_iterate(ubiq_platform_hash_elem_itr* iterator);

/**
 * @brief Iterate over key values
 * 
 * @param iterator 
 * @return char* 
 */
const char* const ubiq_platform_ht_iterate_keys(ubiq_platform_hash_elem_itr * const iterator);

/**
 * @brief Iterate over values stored in the table
 * 
 * @param iterator 
 * @return void* 
 */
void* ubiq_platform_ht_iterate_values(ubiq_platform_hash_elem_itr * const iterator);

/**
 * @brief Remove all elements from the table. Need to supply
 * a function to free the data associated with each node.
 * 
 * @param hasht 
 * @param free_node 
 */
int ubiq_platform_ht_clear(ubiq_platform_hashtable * const hasht, void (*free_node)(void *nodep));

/**
 * @brief Destroy the hash table.  Need to supply
 * a function to free the data associated with each node.
 * 
 * @param hasht 
 * @param free_node 
 */
void ubiq_platform_ht_destroy(ubiq_platform_hashtable* hasht, void (*free_node)(void *nodep));


void ubiq_platform_ht_walk_r(
  const ubiq_platform_hashtable * const hasht,
  void (* action) (const void *__nodep, void *__closure) ,
  void *__closure);

#ifdef NODEF
/**
 * @brief Get the key associated with an element.  Do not alter the value
 * 
 * @return const char* 
 */
// const char * ubiq_platform_ht_element_key(ubiq_platform_hash_elem *);

/**
 * @brief Get the data associated with an element
 * 
 * @return const void* 
 */
// const void * ubiq_platform_ht_element_data(ubiq_platform_hash_elem *);
#endif

/**
 * @brief Get the number of elements stored in the hash table
 * 
 * @param hasht 
 * @return unsigned int 
 */
unsigned int ubiq_platform_ht_element_count(const ubiq_platform_hashtable * const hasht);

/**
 * @brief Create a hash table iteratore
 * 
 * @param ht 
 * @param itr 
 * @return int 
 */
int ubiq_platform_ht_create_iterator(ubiq_platform_hashtable* ht, ubiq_platform_hash_elem_itr ** itr);

/**
 * @brief Destroy the hash table iterator
 * 
 * @param itr 
 */
void ubiq_platform_ht_destroy_iterator(ubiq_platform_hash_elem_itr * itr);


__END_DECLS
