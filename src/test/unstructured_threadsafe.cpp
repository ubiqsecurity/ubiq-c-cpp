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


// #define UBIQ_DEBUG_ON
#ifdef UBIQ_DEBUG_ON
#define UBIQ_DEBUG(x,y) {x && y;}
#else
#define UBIQ_DEBUG(x,y)
#endif

static int debug_flag = 0;

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

typedef struct thread_args
{
  int threadNumber;
  struct ubiq_platform_encryption * encCtx;
  struct ubiq_platform_decryption * decCtx;
  struct ubiq_platform_credentials * creds;
  struct ubiq_platform_configuration * cfg;

} thread_args_t;

typedef struct thread_args_cpp
{
  int threadNumber;
  struct ubiq::platform::encryption * encCtx;
  struct ubiq::platform::decryption * decCtx;
  struct  ubiq::platform::credentials * creds;
  struct  ubiq::platform::configuration * cfg;

} thread_args_cpp_t;

const int len = 128;

typedef struct buf {
    void * buf;
    size_t len;
} buf_t;


int decrypt(
  struct ubiq_platform_decryption * ctx,
  void * ctBuf,
  size_t ctlen,
  void ** ptbuf,
  size_t * ptlen) {
  const char * csu = "decrypt";
  buf_t pre, upd, end;

  struct ubiq_platform_decryption_session * session;

  int res = ubiq_platform_decryption_init_session(ctx, &session);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_decryption_init_session", res));

  res = ubiq_platform_decryption_beginTS(ctx, session, &pre.buf, &pre.len);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_decryption_begin", res));

  res = ubiq_platform_decryption_updateTS(ctx, session, ctBuf, ctlen, &upd.buf, &upd.len);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_encryption_update", res));

  res = ubiq_platform_decryption_endTS(ctx, session, &end.buf, &end.len);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_decryption_end", res));

  *ptlen = pre.len + upd.len + end.len;
  uint8_t * buf = (uint8_t *)calloc(*ptlen + 1, sizeof(uint8_t));

  memcpy(buf, pre.buf, pre.len);
  memcpy(buf + pre.len, upd.buf, upd.len);
  memcpy(buf + pre.len + upd.len, end.buf, end.len);
  *ptbuf = buf;

  free(end.buf);
  free(upd.buf);
  free(pre.buf);
  ubiq_platform_decryption_destroy_session(session);

  return res;
}


int encrypt(
  struct ubiq_platform_encryption * ctx,
  void * ptbuf,
  size_t ptlen,
  void ** ctbuf,
  size_t * ctlen) {
  const char * csu = "encrypt";
  buf_t pre, upd, end;

  struct ubiq_platform_encryption_session * session;

  int res = ubiq_platform_encryption_init_session(ctx, &session);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_encryption_init_session", res));


  res = ubiq_platform_encryption_beginTS(ctx, session, &pre.buf, &pre.len);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_encryption_begin", res));

  res = ubiq_platform_encryption_updateTS(
      ctx, session, ptbuf, ptlen, &upd.buf, &upd.len);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_encryption_update", res));

  res = ubiq_platform_encryption_endTS(
    ctx, session, &end.buf, &end.len);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t res(%d)\n", csu, "ubiq_platform_encryption_end", res));

  *ctlen = pre.len + upd.len + end.len;
  uint8_t *  buf = (uint8_t *)calloc(*ctlen + 1, sizeof(uint8_t));

  memcpy(buf, pre.buf, pre.len);
  memcpy(buf + pre.len, upd.buf, upd.len);
  memcpy(buf + pre.len + upd.len, end.buf, end.len);
  *ctbuf = buf;

  free(end.buf);
  free(upd.buf);
  free(pre.buf);
  ubiq_platform_encryption_destroy_session(session);

  return res;
}


// Thread function
void* unstructured_thread_function(void* arg) {
  const char * csu = "unstructured_thread_function";
    // printf("%s: A\n", csu);
    thread_args_t *thread_params = (thread_args_t *) arg;
    int res = 0;
    char pt[len+1];
    buf_t ctBuf;
    buf_t decBuf;

    u_int64_t num1 = 0;
    int iterations = 300;
    long tmp = 0;
    get_int_env_option(tmp, UBIQ_UNITTEST_TS_ITERATIONS);
    if (tmp > 0) {
      iterations = tmp;
    }
    printf("%s \t %s : %d\n",csu, UBIQ_UNITTEST_TS_ITERATIONS, iterations);
    
    for (int i = 0; i < iterations; i++) {
      
      // Large number printed as hex to be encrypted and decrypted
      num1 = ((rand() * 0xFFFFFFFFFFFF) | 0x1000000000000);
      snprintf(pt, len, "%llX", num1);

      res = encrypt(thread_params->encCtx, pt, strlen(pt), &ctBuf.buf, &ctBuf.len);
      EXPECT_TRUE(res == 0);
      res = decrypt(thread_params->decCtx, ctBuf.buf, ctBuf.len, &decBuf.buf, &decBuf.len);
      EXPECT_TRUE(res == 0);

      EXPECT_TRUE(strcmp(pt, (char *)decBuf.buf) == 0);

      free(ctBuf.buf);
      free(decBuf.buf);
    }
    
    return NULL;
}

// Thread function - 
// Will sporadically get a new encryption key but the 
// decryption objects are still shared and therefore have to make rest calls
// to get the decryption key.
void* unstructured_thread_function_combo(void* arg) {
  const char * csu = "unstructured_thread_function_combo";
    // printf("%s: A\n", csu);
    thread_args_t *thread_params = (thread_args_t *) arg;
    int threadNum = thread_params->threadNumber;
    int res = 0;
    char pt[len+1];
    buf_t ctBuf;
    buf_t decBuf;
    ctBuf.buf = NULL;
    decBuf.buf = NULL;

    int new_key_factor = ((rand() % 250) + 50); // Between 50 and 300
    printf("%s: %d new_key_factor(%d) params(%p) %d\n", csu, threadNum, new_key_factor, thread_params, res);

    u_int64_t num1 = 0;
    int iterations = 300;
    long tmp = 0;
    get_int_env_option(tmp, UBIQ_UNITTEST_TS_ITERATIONS);
    if (tmp > 0) {
      iterations = tmp;
    }
    printf("%s \t %s : %d\n",csu, UBIQ_UNITTEST_TS_ITERATIONS, iterations);

    for (int i = 0; i < iterations; i++) {
      
    //   // Large number printed as hex to be encrypted and decrypted
      num1 = ((rand() * 0xFFFFFFFFFFFF) | 0x1000000000000);
      snprintf(pt, len, "%llX", num1);

    //   // Can be rate limited with too many fresh keys so only get a new key a little 
    //   // less frequently
      if (i % new_key_factor == 0) {
        usleep(150000 * threadNum);
        int max_retry = 10;
        res = ubiq_platform_encrypt(thread_params->creds,pt, strlen(pt), &ctBuf.buf, &ctBuf.len);
        int failed_count = 0;
        while (res != 0 && failed_count < max_retry) {
          free(&ctBuf.buf);
          usleep(250000 * threadNum);
          res = ubiq_platform_encrypt(thread_params->creds,pt, strlen(pt), &ctBuf.buf, &ctBuf.len);
          failed_count++;
        }
      } else {
        res = encrypt(thread_params->encCtx, pt, strlen(pt), &ctBuf.buf, &ctBuf.len);
        if (res) {
          printf("%s: %d encrypt loop(%d) %d\n", csu, threadNum, i, res);
        }
      }
      EXPECT_TRUE(res == 0) << "Thread " << threadNum << " failed" << std::endl;
      res = decrypt(thread_params->decCtx, ctBuf.buf, ctBuf.len, &decBuf.buf, &decBuf.len);
    //   EXPECT_TRUE(res == 0);
      if (res) {
        printf("%s: %d decrypt loop(%d) %d\n", csu, threadNum, i, res);
      }

    //   EXPECT_TRUE(strcmp(pt, (char *)decBuf.buf) == 0);

      free(ctBuf.buf);
      ctBuf.buf = NULL;
      free(decBuf.buf);
      if (i % 100 == 0) {
        printf("%s: thread(%d) loop(%d) res(%d)\n", csu, threadNum, i, res);
      }
    }
    
    return NULL;
}

TEST(c_unstructured, multithread)
{
    const char * csu = "c_structured.multithread";

    int res = 0;;
    // Initialize common object

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * cfg;
    struct ubiq_platform_encryption * encCtx;
    struct ubiq_platform_decryption * decCtx;

    // res = ubiq_platform_init();

    res = ubiq_platform_credentials_create(&creds);

    res = ubiq_platform_configuration_create(&cfg);
    
    res = ubiq_platform_encryption_create_with_config(creds, cfg, 1, &encCtx);

    res = ubiq_platform_decryption_create_with_config(creds, cfg, &decCtx);


    {
      buf_t ct;
      buf_t pt;

      encrypt(encCtx, (void *)"1234", 4, &ct.buf, &ct.len);
      decrypt(decCtx, ct.buf, ct.len, &pt.buf, &pt.len);
      EXPECT_TRUE(strcmp("1234", (char *)pt.buf) == 0);
      free(ct.buf);
      free(pt.buf);
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
    thread_args_t * thread_params[num_threads];

    for (int i = 0; i < num_threads; i++) {
      thread_params[i] = (thread_args_t*)calloc(sizeof(thread_args_t), 1);

      thread_params[i]->encCtx = encCtx;
      thread_params[i]->decCtx = decCtx;
      thread_params[i]->creds = creds;
      thread_params[i]->cfg = cfg;
      thread_params[i]->threadNumber = i;

        if (pthread_create(&threads[i], NULL, unstructured_thread_function, thread_params[i]) != 0) {
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
        free(thread_params[i]);
    }

    ubiq_platform_encryption_destroy(encCtx);
    ubiq_platform_decryption_destroy(decCtx);
    ubiq_platform_configuration_destroy(cfg);
    ubiq_platform_credentials_destroy(creds);
    // ubiq_platform_exit();

}

TEST(c_unstructured, multithreadCombo)
{
    const char * csu = "c_structured.multithread";

    int res = 0;;
    // Initialize common object

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_configuration * cfg;
    struct ubiq_platform_encryption * encCtx;
    struct ubiq_platform_decryption * decCtx;

    // res = ubiq_platform_init();

    res = ubiq_platform_credentials_create(&creds);

    res = ubiq_platform_configuration_create(&cfg);
    
    res = ubiq_platform_encryption_create_with_config(creds, cfg, 1, &encCtx);

    res = ubiq_platform_decryption_create_with_config(creds, cfg, &decCtx);


    {
      buf_t ct;
      buf_t pt;

      encrypt(encCtx, (void *)"1234", 4, &ct.buf, &ct.len);
      decrypt(decCtx, ct.buf, ct.len, &pt.buf, &pt.len);
      EXPECT_TRUE(strcmp("1234", (char *)pt.buf) == 0);
      free(ct.buf);
      free(pt.buf);
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
    thread_args_t * thread_params[num_threads];
    for (int i = 0; i < num_threads; i++) {
      thread_params[i] = (thread_args_t*)calloc(sizeof(thread_args_t), 1);

      thread_params[i]->encCtx = encCtx;
      thread_params[i]->decCtx = decCtx;
      thread_params[i]->creds = creds;
      thread_params[i]->cfg = cfg;
      thread_params[i]->threadNumber = i;
        if (pthread_create(&threads[i], NULL, unstructured_thread_function_combo, thread_params[i]) != 0) {
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
        free(thread_params[i]);
    }

    ubiq_platform_encryption_destroy(encCtx);
    ubiq_platform_decryption_destroy(decCtx);
    ubiq_platform_configuration_destroy(cfg);
    ubiq_platform_credentials_destroy(creds);
    // ubiq_platform_exit();

}


std::vector<std::uint8_t> encrypt_cpp(
  ubiq::platform::encryption & enc,
  void * ptbuf,
  size_t ptlen) {
  const char * csu = "encrypt_cpp";
  std::vector<std::uint8_t> beg, upd, end;

  ubiq::platform::encryption_session session(enc);

  beg = enc.begin(session);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t length(%d)\n", csu, "begin", beg.size()));

  upd = enc.update(session, ptbuf, ptlen);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t length(%d)\n", csu, "update", upd.size()));

  end = enc.end(session);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t length(%d)\n", csu, "end", end.size()));

 std::vector<std::uint8_t> merged;

  merged.reserve(beg.size() + upd.size() + end.size() + 1);

  merged.insert(merged.end(), beg.begin(), beg.end());
  merged.insert(merged.end(), upd.begin(), upd.end());
  merged.insert(merged.end(), end.begin(), end.end());

  return merged;
}

std::vector<std::uint8_t> decrypt_cpp(
  ubiq::platform::decryption & dec,
  void * ctBuf,
  size_t ctlen) {

  const char * csu = "decrypt_cpp";
  std::vector<std::uint8_t> beg, upd, end;

  UBIQ_DEBUG(debug_flag, printf("%s: \t before session\n", csu ));
  ubiq::platform::decryption_session session(dec);
  UBIQ_DEBUG(debug_flag, printf("%s: \t after session\n", csu));


  beg = dec.begin(session);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t length(%d)\n", csu, "begin", beg.size()));

  upd = dec.update(session, ctBuf, ctlen);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t length(%d)\n", csu, "update", upd.size()));

  end = dec.end(session);
  UBIQ_DEBUG(debug_flag, printf("%s: %s \t length(%d)\n", csu, "end", end.size()));

 std::vector<std::uint8_t> merged;

  merged.reserve(beg.size() + upd.size() + end.size() + 1);

  merged.insert(merged.end(), beg.begin(), beg.end());
  merged.insert(merged.end(), upd.begin(), upd.end());
  merged.insert(merged.end(), end.begin(), end.end());

  return merged;
}



// Thread function - 
// Will sporadically get a new encryption key but the 
// decryption objects are still shared and therefore have to make rest calls
// to get the decryption key.
void* unstructured_thread_function_cpp_combo(void* arg) {
  const char * csu = "unstructured_thread_function_cpp_combo";
    // printf("%s: A\n", csu);
    thread_args_cpp_t *thread_params = (thread_args_cpp_t *) arg;
    int threadNum = thread_params->threadNumber;
    int res = 0;
    char pt[len+1];
    std::vector<std::uint8_t> ctBuf;
    std::vector<std::uint8_t> decBuf;

    int new_key_factor = ((rand() % 100) + 5); // Between 5 and 105
    printf("%s: %d new_key_factor(%d) %d\n", csu, threadNum, new_key_factor, res);

    u_int64_t num1 = 0;
    int iterations = 300;
    long tmp = 0;
    get_int_env_option(tmp, UBIQ_UNITTEST_TS_ITERATIONS);
    if (tmp > 0) {
      iterations = tmp;
    }
    printf("%s \t %s : %d\n",csu, UBIQ_UNITTEST_TS_ITERATIONS, iterations);

    for (int i = 0; i < iterations; i++) {
      
      // Large number printed as hex to be encrypted and decrypted
      num1 = ((rand() * 0xFFFFFFFFFFFF) | 0x1000000000000);
      snprintf(pt, len, "%llX", num1);

      // Can be rate limited with too many fresh keys so only get a new key a little 
      // less frequently
      if (i % new_key_factor == 0) {
        int max_retry = 10;
        usleep(150000 * threadNum);
        for (int failed_count = 0; failed_count < max_retry; failed_count++) {
          try {
            ctBuf = ubiq::platform::encrypt(*thread_params->creds, pt, strlen(pt));
            // No exception so break out of loop
            break;
          } catch (std::exception e) {
            printf("ubiq::platform::encrypt thread(%d) failed (%d) times.  Exception caught: %s.  Sleep %.2f seconds and re-try\n", threadNum, failed_count, e.what(), 0.25 * threadNum);
            if (failed_count < max_retry) {
              usleep(250000 * threadNum);
            } else {
              throw;
            }
          }
        }
      } else {
        ctBuf = encrypt_cpp(std::ref(*(thread_params->encCtx)), pt, strlen(pt));
      }
      EXPECT_TRUE(ctBuf.size() != 0);
      decBuf = decrypt_cpp(std::ref(*(thread_params->decCtx)), ctBuf.data(), ctBuf.size());
      // printf("%s: thread(%d) pt(%s) \n", csu, threadNum, decBuf.data());

      EXPECT_TRUE(strncmp(pt, (char *)decBuf.data(), strlen(pt)) == 0);

      if (i % 100 == 0) {
        printf("%s: thread(%d) loop(%d) res(%d)\n", csu, threadNum, i, res);
      }
    }
    
    return NULL;
}

class cpp_encrypt_threadsafe : public ::testing::Test
{
public:
    void SetUp(void);
    void TearDown(void);

protected:
    ubiq::platform::credentials _creds;
    ubiq::platform::configuration _cfg;
};

void cpp_encrypt_threadsafe::SetUp(void)
{
    ASSERT_TRUE((bool)_creds);
    ASSERT_TRUE((bool)_cfg);
}

void cpp_encrypt_threadsafe::TearDown(void)
{
}

TEST_F(cpp_encrypt_threadsafe, simple)
{
    std::string pt("ABC");
    std::vector<std::uint8_t> v;
    std::vector<std::uint8_t> v2;

    ASSERT_NO_THROW(
        v = ubiq::platform::encrypt(_creds, pt.data(), pt.size()));
    ASSERT_NO_THROW(
        v2 = ubiq::platform::decrypt(_creds, v.data(), v.size()));
    ASSERT_TRUE(memcmp(pt.data(), v2.data(), v2.size()) == 0);
}


TEST_F(cpp_encrypt_threadsafe, combo)
{
  const char * csu = "cpp_encrypt_threadsafe.combo";
    ubiq::platform::encryption enc(_creds, _cfg, 1);
    ubiq::platform::decryption dec(_creds, _cfg);
    
    {
      std::vector<std::uint8_t> ct;
      std::vector<std::uint8_t> pt;

      ct =  encrypt_cpp(enc, (void *)"1234", 4);
      printf("encrypt length(%d)\n", ct.size());
      pt =  decrypt_cpp(dec, ct.data(), ct.size());
      printf("decrypt length(%d)\n", pt.size());
    }

    int num_threads = 10;

    long tmp = 0;
    get_int_env_option(tmp, UBIQ_UNITTEST_TS_NUM_THREADS);
    if (tmp > 0) {
      num_threads = tmp;
    }
    printf("%s \t %s : %d\n",csu, UBIQ_UNITTEST_TS_NUM_THREADS, num_threads);

    pthread_t threads[num_threads];
    thread_args_cpp * thread_params[num_threads];

    for (int i = 0; i < num_threads; i++) {
      thread_params[i] = new thread_args_cpp();

      thread_params[i]->encCtx = &enc;
      thread_params[i]->decCtx = &dec;
      thread_params[i]->creds = &_creds;
      thread_params[i]->cfg = &_cfg;
      thread_params[i]->threadNumber = i;
        if (pthread_create(&threads[i], NULL, unstructured_thread_function_cpp_combo, thread_params[i]) != 0) {
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
        delete(thread_params[i]);
    }

}
