#include <gtest/gtest.h>

#include <cstring>

#include "ubiq/platform.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ubiq/platform.h>


#define UBIQ_UNITTEST_TS_NUM_THREADS "UBIQ_UNITTEST_TS_NUM_THREADS"
#define UBIQ_UNITTEST_TS_ITERATIONS "UBIQ_UNITTEST_TS_ITERATIONS"

#define GETENV(VAR, NAME)                       \
    do {                                        \
        VAR = getenv(NAME);                     \
        if (VAR) {                              \
            VAR = strdup(VAR);                  \
        }                                       \
    } while (0)

static
void
get_int_env_option(long & var, const char * const env_name) {

  if (var == 0) {
      char * data = NULL;
      GETENV(data,env_name);

      if (data) {
        std::stringstream ss;
        ss << data;
        ss >> var;
        free(data);
      }
  }
}


const int dataset_count = 3;
const char * const datasets[] = {"ALPHANUM_SSN", "SSN", "BIRTH_DATE"};


// Thread function
void* thread_function(void* arg) {
  const char * csu = "thread_function";
    // printf("%s: A\n", csu);
    struct ubiq_platform_structured_enc_dec_obj *enc = (struct ubiq_platform_structured_enc_dec_obj *) arg;
    int res = 0;
    char pt[36+1];
    char * ctbuf = NULL;
    size_t ctlen = 0;

    char * decbuf = NULL;
    size_t declen = 0;
    long long num1 = 0;

    int iterations = 300;
    long tmp = 0;
    get_int_env_option(tmp, UBIQ_UNITTEST_TS_ITERATIONS);
    if (tmp > 0) {
      iterations = tmp;
    }
    printf("%s \t %s : %d\n",csu, UBIQ_UNITTEST_TS_ITERATIONS, iterations);

    for (int i = 0; i < iterations; i++) {
      
      // Large number printed as hex to be encrypted and decrypted
      num1 = ((rand() & 0xFFFFFFFFFFFF) | 0x1000000000000);
      snprintf(pt, 36, "%lld", num1);
      int dataset_idx = rand() % dataset_count;

      res = ubiq_platform_structured_encrypt_data(enc,
        datasets[dataset_idx], NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
      if (res) {
        printf("%s: encrypt dataset(%s) pt(%s) \t res(%d)\n", csu, datasets[dataset_idx], pt, res);
      }

      res = ubiq_platform_structured_decrypt_data(enc,
        datasets[dataset_idx], NULL, 0, ctbuf, strlen(ctbuf), &decbuf, &declen);
      if (res) {
        printf("%s: decrypt dataset(%s) pt(%s) ct(%s) \t res(%d)\n", csu, datasets[dataset_idx], pt, ctbuf, res);
      }

      EXPECT_TRUE(strcmp(pt, decbuf) == 0);
      free(ctbuf);
      free(decbuf);
    }
    
    return NULL;
}

TEST(c_structured, multithread)
{
    const char * csu = "c_structured.multithread";

    int res = 0;;
    // Initialize common object
    struct ubiq_platform_structured_enc_dec_obj *enc = NULL;

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * cfg;
    
    // res = ubiq_platform_init();

    res = ubiq_platform_credentials_create(&creds);
    res = ubiq_platform_configuration_create(&cfg);

    res = ubiq_platform_structured_enc_dec_create_with_config(creds, cfg, &enc);

    {
      char  pt[36+1];
      char * ctbuf = NULL;
      size_t ctlen = 0;

      char * decbuf = NULL;
      size_t declen = 0;

      srand(time(NULL));
      long long num1 = ((rand() & 0xFFFFFFFFFFFF) | 0x1000000000000);

      snprintf(pt, 36, "%lld", num1);
      for (int i = 0; i < dataset_count; i++) {
        res = ubiq_platform_structured_encrypt_data(enc,
          datasets[i], NULL, 0, pt, strlen(pt), &ctbuf, &ctlen);
        if (res) {
          printf("%s: encrypt dataset(%s) pt(%s) \t res(%d)\n", csu, datasets[i], pt, res);
        }
        EXPECT_TRUE(res == 0);

        // printf("%s: C\n", csu);
        res = ubiq_platform_structured_decrypt_data(enc,
          datasets[i], NULL, 0, ctbuf, strlen(ctbuf), &decbuf, &declen);
        if (res) {
          printf("%s: decrypt dataset(%s) pt(%s) ct(%s) \t res(%d)\n", csu, datasets[i], pt, ctbuf, res);
        }
        EXPECT_TRUE(res == 0);

        EXPECT_TRUE(strcmp(pt, decbuf) == 0);

        free(ctbuf);
        free(decbuf);
      }
    
    }

    // Create threads

    int num_threads = 10;
    long tmp = 0;
    get_int_env_option(tmp, UBIQ_UNITTEST_TS_NUM_THREADS);
    if (tmp > 0) {
      num_threads = tmp;
    }
    printf("%s \t %s : %d\n",csu, UBIQ_UNITTEST_TS_NUM_THREADS, num_threads);

    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, thread_function, enc) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for threads to finish
    for (int i = 0; i < num_threads; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("pthread_join");
            exit(EXIT_FAILURE);
        }
    }

    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_configuration_destroy(cfg);
    ubiq_platform_credentials_destroy(creds);
    // ubiq_platform_exit();

}

