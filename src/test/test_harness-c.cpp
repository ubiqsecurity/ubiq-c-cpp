/*
* Test harness that uses C APIs but CPP because of convenience 
* and timing numbers.
*/
#include "test_harness_helper.h"

#include <ubiq/platform.h>
#include <ubiq/platform/internal/structured_private.h>
#include <ubiq/platform/internal/parsing.h>

#include <iostream>
#include <map>
#include <chrono>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>


class PerfCounts {
  public:
  long encrypt_duration;
  long decrypt_duration;
  long recordCount;

  PerfCounts() :encrypt_duration(0L), decrypt_duration(0L), recordCount(0L) {
  }
};

class Results {
  public:
  std::string out;
  long duration;

  Results() : out(""), duration(0L) {

  }
};


Results encrypt(ubiq_platform_structured_enc_dec_obj * const enc,
  Data_rec & dr, ubiq_platform_dataset_t const * const dataset) 
{
  Results results;
  int res;
  char const * const dataset_type = ubiq_platform_dataset_get_data_type(dataset);

  if (strcmp("integer", dataset_type) == 0) {
    ubiq_platform_data_type_config_t const * const cfg = ubiq_platform_dataset_get_data_type_config(dataset);
    if (32 == ubiq_platform_data_type_config_get_size(cfg)) {
      int32_t pt = std::stoi(dr.plain_text);
      int32_t ct = 0;
      auto start = std::chrono::steady_clock::now();
      res = ubiq_platform_structured_encrypt_int_data(enc, dr.dataset_name.c_str(), NULL, 0, pt, &ct);
      auto end = std::chrono::steady_clock::now();
      
      results.out = std::to_string(ct);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    } else {
      int64_t pt = std::stoll(dr.plain_text);
      auto start = std::chrono::steady_clock::now();

      int64_t ct = 0;
      res = ubiq_platform_structured_encrypt_long_data(enc, dr.dataset_name.c_str(), NULL, 0, pt, &ct);
      auto end = std::chrono::steady_clock::now();
      results.out = std::to_string(ct);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    }

  } else if (strcmp("date", dataset_type) == 0) {

    struct tm ct;
    struct tm pt;
    ubiq_platform_parse_iso8601(dr.plain_text.c_str(), &pt);
    auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_encrypt_date_data(enc, dr.dataset_name.c_str(), NULL, 0, &pt, &ct);
      
    auto end = std::chrono::steady_clock::now();

    char buffer[25];

    size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%MZ", &ct);

    results.out = buffer;
    results.duration = std::chrono::duration<double, std::nano>(end - start).count();



  } else if (strcmp("datetime", dataset_type) == 0) {
    struct tm ct;
    struct tm pt;
    ubiq_platform_parse_iso8601(dr.plain_text.c_str(), &pt);
    auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_encrypt_datetime_data(enc, dr.dataset_name.c_str(), NULL, 0, &pt, &ct);
    auto end = std::chrono::steady_clock::now();

    char buffer[25];

    size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct);

    results.out = buffer;
    results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    
  } else {
      auto start = std::chrono::steady_clock::now();
        static const size_t buflen = 2048;
        char ct_buf[buflen];

        size_t len = buflen;
        res = ubiq_platform_structured_encrypt_data_prealloc(enc, dr.dataset_name.c_str(), NULL, 0, 
          dr.plain_text.c_str(), dr.plain_text.length(),
          ct_buf, &len);
      auto end = std::chrono::steady_clock::now();
      results.out = ct_buf;
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
  }

  return results;
}


Results decrypt(ubiq_platform_structured_enc_dec_obj * const enc,
  Data_rec & dr, ubiq_platform_dataset_t const * const dataset) 
{
  Results results;
  int res;
  char const * const dataset_type = ubiq_platform_dataset_get_data_type(dataset);

  if (strcmp("integer", dataset_type) == 0) {
    ubiq_platform_data_type_config_t const * const cfg = ubiq_platform_dataset_get_data_type_config(dataset);
    if (32 == ubiq_platform_data_type_config_get_size(cfg)) {
      int32_t ct = std::stoi(dr.cipher_text);
      int32_t pt = 0;
      auto start = std::chrono::steady_clock::now();
      res = ubiq_platform_structured_decrypt_int_data(enc, dr.dataset_name.c_str(), NULL, 0, ct, &pt);
      auto end = std::chrono::steady_clock::now();
      
      results.out = std::to_string(pt);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    } else {
      int64_t ct = std::stoll(dr.cipher_text);
      auto start = std::chrono::steady_clock::now();
      // std::cout << "PT64: " << pt << std::endl;

      int64_t pt = 0;
      res = ubiq_platform_structured_decrypt_long_data(enc, dr.dataset_name.c_str(), NULL, 0, ct, &pt);
      auto end = std::chrono::steady_clock::now();
      // std::cout << "  CT64: " << ct << std::endl;
      results.out = std::to_string(pt);
      // results.out = dr.cipher_text;
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    }

  } else if (strcmp("date", dataset_type) == 0) {

    struct tm ct;
    struct tm pt;
    ubiq_platform_parse_iso8601(dr.cipher_text.c_str(), &ct);
    auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_decrypt_date_data(enc, dr.dataset_name.c_str(), NULL, 0, &ct, &pt);
      
    auto end = std::chrono::steady_clock::now();

    char buffer[25];

    size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%MZ", &pt);

    results.out = buffer;
    results.duration = std::chrono::duration<double, std::nano>(end - start).count();



  } else if (strcmp("datetime", dataset_type) == 0) {
    struct tm ct;
    struct tm pt;
    ubiq_platform_parse_iso8601(dr.cipher_text.c_str(), &ct);
    auto start = std::chrono::steady_clock::now();
    res = ubiq_platform_structured_decrypt_datetime_data(enc, dr.dataset_name.c_str(), NULL, 0, &ct, &pt);
    auto end = std::chrono::steady_clock::now();

    char buffer[25];

    size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &pt);

    results.out = buffer;
    results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    
  } else {
      auto start = std::chrono::steady_clock::now();
        static const size_t buflen = 2048;
        char pt_buf[buflen];

        size_t len = buflen;
        res = ubiq_platform_structured_decrypt_data_prealloc(enc, dr.dataset_name.c_str(), NULL, 0, 
          dr.cipher_text.c_str(), dr.cipher_text.length(),
          pt_buf, &len);
      auto end = std::chrono::steady_clock::now();
      results.out = pt_buf;
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
  }

  return results;
}

int main(const int argc, char * const argv[])
{
    Options options;
    std::list<Data_rec> data;
    std::map<std::string, PerfCounts> perf_values;

    std::list<Data_rec> errors;
    int exit_value = EXIT_SUCCESS;

    static const size_t buflen = 2048;
    static const size_t search_keys_max = 128;
    char pt_buf[buflen];
    char ct_buf[buflen];
    size_t len = 0;
    size_t len2 = 0;
    char search_buf[128][buflen];

    struct ubiq_platform_credentials * creds;
    struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
    int res = 0;

    try {
      /* library must be initialized */
      ubiq_platform_init();      

      /*
       * the ubiq_getopt function will parse the command line for arguments
       * specific to the sample application and return the found options
       * in the variables below.
       */

      ubiq_getopt(argc, argv,
                        options);

      if (options.credentials.length() == 0) {
          res = ubiq_platform_credentials_create(&creds);
      } else {
          res = ubiq_platform_credentials_create_specific(
          options.credentials.c_str(), options.profile.c_str(), &creds);
      }

      if (!creds || res) {
          std::cerr << "unable to load credentials: return code(" << res << ")" << std::endl;
          std::exit(EXIT_FAILURE);
      }

      res = ubiq_platform_structured_enc_dec_create(creds, &enc);

      std::list<std::string> files = std::list<std::string>();

      struct stat s;
      int t = stat(options.infile.c_str(), &s);

      if (t == 0 && s.st_mode & S_IFREG) {
        files.push_back(options.infile);
      } else if (t == 0 && s.st_mode & S_IFDIR) {
        DIR *d;
        struct dirent *dir;
        d = opendir(options.infile.c_str());
        
        if (d) {
            while ((dir = readdir(d)) != NULL)
            {
                //Condition to check regular file.
                if(dir->d_type==DT_REG){
                  std::string path = options.infile;
                  path += "/" + std::string(dir->d_name);
                  files.push_back(path);
                }
            }
            closedir(d);
        }
      }


      long recordCount = 0;
      for (auto const & file : files) {
        std::list<Data_rec> data;

        ubiq_load_datafile(file, data);

        recordCount += data.size();

        for (std::list<Data_rec>::iterator dit=data.begin(); dit != data.end(); ++dit) {
          auto itr = perf_values.find(dit->dataset_name);
          ubiq_platform_dataset_t const * const dataset = ubiq_platform_structured_get_dataset(enc, dit->dataset_name.c_str());
          if (itr == perf_values.end()) {
            try {
              encrypt(enc, *dit, dataset);
            } catch (const std::exception& e) {
              exit_value = EXIT_FAILURE;
              std::cerr << "Error: " << e.what() << std::endl;
              std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
            }
            try {
              decrypt(enc, *dit, dataset);
            } catch (const std::exception& e) {
              exit_value = EXIT_FAILURE;
              std::cerr << "Error: " << e.what() << std::endl;
              std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
            }
            perf_values[dit->dataset_name] = PerfCounts();
            itr = perf_values.find(dit->dataset_name);
          }

          
          try {
            Results ct = encrypt(enc, *dit, dataset);
            Results pt = decrypt(enc, *dit, dataset);

            if (ct.out != dit->cipher_text || pt.out != dit->plain_text) {
              errors.push_back(*dit);
            }

            itr->second.encrypt_duration += ct.duration;
            itr->second.decrypt_duration += pt.duration;
            itr->second.recordCount ++;

          } catch (const std::exception& e) {
            errors.push_back(*dit);
          }
        }
      }

      if (errors.size() == 0) {
          long encryptTotal = 0;
          long decryptTotal = 0;

          std::cout << "All data validated" << std::endl;
          std::cout << "Encrypt records count: " << recordCount << ".  Times in (microseconds)" << std::endl;

          for (auto itr = perf_values.begin(); itr != perf_values.end(); ++itr) {
            std::cout << "\tDataset: " << itr->first << ", record count: " << itr->second.recordCount << ", Average: " << itr->second.encrypt_duration / 1000 / itr->second.recordCount << ", Total: " << itr->second.encrypt_duration / 1000 << std::endl;
            encryptTotal += itr->second.encrypt_duration;
          }
            encryptTotal /= 1000;
          std::cout << "\t  Total: Average: " << encryptTotal / recordCount << ", Total: " << encryptTotal << std::endl;

          std::cout << "\ndecrypt records count: " << recordCount << ".  Times in (microseconds)" << std::endl;
          for (auto itr = perf_values.begin(); itr != perf_values.end(); ++itr) {
            std::cout << "\tDataset: " << itr->first << ", record count: " << itr->second.recordCount << ", Average: " << itr->second.decrypt_duration / 1000 / itr->second.recordCount << ", Total: " << itr->second.decrypt_duration / 1000 << std::endl;
            decryptTotal += itr->second.decrypt_duration;
          }
          decryptTotal /= 1000;
          std::cout << "\t  Total: Average: " << decryptTotal / recordCount << ", Total: " << decryptTotal << std::endl;

          if (options.max_avg_encrypt > 0) {
            if (options.max_avg_encrypt <= encryptTotal / recordCount) {
              std::cerr << "FAILED: Exceeded maximum allowed average encrypt threshold of " << options.max_avg_encrypt << " microseconds" << std::endl;
              exit_value = EXIT_FAILURE;
            } else {
              std::cout << "PASSED: Maximum allowed average encrypt threshold of " << options.max_avg_encrypt << " microseconds" << std::endl;
            }
          } else {
            std::cout << "NOTE: No maximum allowed average encrypt threshold supplied" << std::endl;
          }

          if (options.max_avg_decrypt > 0) {
            if (options.max_avg_decrypt <= decryptTotal / recordCount) {
              std::cerr << "FAILED: Exceeded maximum allowed average decrypt threshold of " << options.max_avg_decrypt << " microseconds" << std::endl;
              exit_value = EXIT_FAILURE;
            } else {
              std::cout << "PASSED: Maximum allowed average decrypt threshold of " << options.max_avg_decrypt << " microseconds" << std::endl;
            }
          } else {
            std::cout << "NOTE: No maximum allowed average decrypt threshold supplied" << std::endl;
          }

          if (options.max_total_encrypt > 0) {
            if (options.max_total_encrypt <= encryptTotal) {
              std::cerr << "FAILED: Exceeded maximum allowed total encrypt threshold of " << options.max_total_encrypt << " microseconds" << std::endl;
              exit_value = EXIT_FAILURE;
            } else {
              std::cout << "PASSED: Maximum allowed total encrypt threshold of " << options.max_total_encrypt << " microseconds" << std::endl;
            }
          } else {
            std::cout << "NOTE: No maximum allowed total encrypt threshold supplied" << std::endl;
          }

          if (options.max_total_decrypt > 0) {
            if (options.max_total_decrypt <= decryptTotal) {
              std::cerr << "FAILED: Exceeded maximum allowed total decrypt threshold of " << options.max_total_decrypt << " microseconds" << std::endl;
              exit_value = EXIT_FAILURE;
            } else {
              std::cout << "PASSED: Maximum allowed total decrypt threshold of " << options.max_total_decrypt << " microseconds" << std::endl;
            }
          } else {
            std::cout << "NOTE: No maximum allowed total decrypt threshold supplied" << std::endl;
          }

      } else {
        exit_value = EXIT_FAILURE;
        std::cerr << "ERROR: Encrypt / Decrypt operation failed to validate for " << errors.size() << " records" << std::endl;
        if (!options.print_errors) {
          std::cerr << "       use -p option to print information about records" << std::endl;
        } else {
          for (std::list<Data_rec>::iterator dit=errors.begin(); dit != errors.end(); ++dit)
          std::cerr << "  dataset: '" << dit->dataset_name << "'  plaintext: '" << dit->plain_text << "'" << std::endl;
        }
      }


    }
    catch (const std::exception& e) {
      std::cerr << "Error: " << e.what() << std::endl;
      exit_value = EXIT_FAILURE;
    }
    /* The library needs to clean up after itself */
    ubiq_platform_structured_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_exit();

    exit(exit_value);
}
