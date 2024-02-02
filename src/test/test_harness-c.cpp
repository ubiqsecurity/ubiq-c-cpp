/*
* Test harness that uses C APIs but CPP because of convenience 
* and timing numbers.
*/
#include "test_harness_helper.h"

#include <ubiq/platform.h>

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
    struct ubiq_platform_fpe_enc_dec_obj *enc = NULL;
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

      res = ubiq_platform_fpe_enc_dec_create(creds, &enc);

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
          if (itr == perf_values.end()) {
            try {
              len = buflen;
              res = ubiq_platform_fpe_encrypt_data_prealloc(enc, dit->dataset_name.c_str(), NULL, 0, 
                dit->plain_text.c_str(), dit->plain_text.length(),
                ct_buf, &len);
              
              // printf("Encrypt Init:\n\tpt(%s)\n\tct(%s)\n\t len(%d) res(%d)\n", dit->plain_text.c_str(), ct_buf, len, res);
            } catch (const std::exception& e) {
              exit_value = EXIT_FAILURE;
              std::cerr << "Error: " << e.what() << std::endl;
              std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
            }
            try {
              len = buflen;
              res = ubiq_platform_fpe_decrypt_data_prealloc(enc, dit->dataset_name.c_str(), NULL, 0, 
                dit->cipher_text.c_str(), dit->cipher_text.length(),
                pt_buf, &len);

              // printf("Decrypt Init:\n\tct(%s)\n\tpt(%s)\n\t len(%d) res(%d)\n", dit->cipher_text.c_str(), pt_buf, len, res);

            } catch (const std::exception& e) {
              exit_value = EXIT_FAILURE;
              std::cerr << "Error: " << e.what() << std::endl;
              std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
            }
            perf_values[dit->dataset_name] = PerfCounts();
            itr = perf_values.find(dit->dataset_name);
          }

          
          try {
            len = buflen;
            len2 = buflen;

            auto start = std::chrono::steady_clock::now();

            res = ubiq_platform_fpe_encrypt_data_prealloc(enc, dit->dataset_name.c_str(), NULL, 0, 
                dit->plain_text.c_str(), dit->cipher_text.length(),
                ct_buf, &len);

            auto encrypt = std::chrono::steady_clock::now();

            res = ubiq_platform_fpe_decrypt_data_prealloc(enc, dit->dataset_name.c_str(), NULL, 0, 
              dit->cipher_text.c_str(), dit->cipher_text.length(),
              pt_buf, &len2);

            auto decrypt = std::chrono::steady_clock::now();

              // printf("Encrypt :\n\tct(%s)\n\tlen(%d) res(%d)\n", ct_buf, len, res);
              // printf("Decrypt :\n\tpt(%s)\n\tlen(%d) res(%d)\n", pt_buf, len2, res);

            if (strcmp(ct_buf, dit->cipher_text.c_str()) || strcmp(pt_buf, dit->plain_text.c_str())) {
              errors.push_back(*dit);
            }

            itr->second.encrypt_duration += std::chrono::duration<double, std::nano>(encrypt - start).count();
            itr->second.decrypt_duration += std::chrono::duration<double, std::nano>(decrypt - encrypt).count();
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
    ubiq_platform_fpe_enc_dec_destroy(enc);
    ubiq_platform_credentials_destroy(creds);
    ubiq_platform_exit();

    exit(exit_value);
}
