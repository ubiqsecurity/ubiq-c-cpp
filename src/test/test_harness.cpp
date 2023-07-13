#include "test_harness_helper.h"

#include <ubiq/platform.h>

#include <iostream>
#include <map>
#include <chrono>




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
    ubiq::platform::credentials creds;
    std::list<Data_rec> data;
    std::map<std::string, PerfCounts> perf_values;

    std::list<Data_rec> errors;
    int exit_value = EXIT_SUCCESS;


    try {
      /* library must be initialized */
      ubiq::platform::init();

      /*
       * the ubiq_getopt function will parse the command line for arguments
       * specific to the sample application and return the found options
       * in the variables below.
       */

      ubiq_getopt(argc, argv,
                        options);

      if (options.credentials.length() == 0) {
        creds = ubiq::platform::credentials();
      } else {
        creds = ubiq::platform::credentials(
            options.credentials,
            options.profile);
      }
      if (!creds) {
          std::cerr << "unable to load credentials" << std::endl;
          std::exit(EXIT_FAILURE);
      }

      ubiq_load_datafile(options.infile, data);

      ubiq::platform::fpe::decryption dec(creds);
      ubiq::platform::fpe::encryption enc(creds);

      for (std::list<Data_rec>::iterator dit=data.begin(); dit != data.end(); ++dit) {
        auto itr = perf_values.find(dit->dataset_name);
        if (itr == perf_values.end()) {
          try {
            std::string ct = enc.encrypt(dit->dataset_name, dit->plain_text);
          } catch (const std::exception& e) {
            exit_value = EXIT_FAILURE;
            std::cerr << "Error: " << e.what() << std::endl;
            std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
          }
          try {
            std::string pt = dec.decrypt(dit->dataset_name, dit->cipher_text);
          } catch (const std::exception& e) {
            exit_value = EXIT_FAILURE;
            std::cerr << "Error: " << e.what() << std::endl;
            std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
          }
          perf_values[dit->dataset_name] = PerfCounts();
          itr = perf_values.find(dit->dataset_name);
        }

        try {
          auto start = std::chrono::steady_clock::now();

          std::string ct = enc.encrypt(dit->dataset_name, dit->plain_text);
          auto encrypt = std::chrono::steady_clock::now();

          std::string pt = dec.decrypt(dit->dataset_name, dit->cipher_text);
          auto decrypt = std::chrono::steady_clock::now();

          if (ct != dit->cipher_text || pt != dit->plain_text) {
            errors.push_back(*dit);
          }

          itr->second.encrypt_duration += std::chrono::duration<double, std::nano>(encrypt - start).count();
          itr->second.decrypt_duration += std::chrono::duration<double, std::nano>(decrypt - encrypt).count();
          itr->second.recordCount ++;
        } catch (const std::exception& e) {
          errors.push_back(*dit);
        }
      }


      if (errors.size() == 0) {
          long encryptTotal = 0;
          long decryptTotal = 0;

          std::cout << "All data validated" << std::endl;
          std::cout << "Encrypt records count: " << data.size() << ".  Times in (microseconds)" << std::endl;

          for (auto itr = perf_values.begin(); itr != perf_values.end(); ++itr) {
            std::cout << "\tDataset: " << itr->first << ", record count: " << itr->second.recordCount << ", Average: " << itr->second.encrypt_duration / 1000 / itr->second.recordCount << ", Total: " << itr->second.encrypt_duration / 1000 << std::endl;
            encryptTotal += itr->second.encrypt_duration;
          }
            encryptTotal /= 1000;
          std::cout << "\t  Total: Average: " << encryptTotal / data.size() << ", Total: " << encryptTotal << std::endl;

          std::cout << "\ndecrypt records count: " << data.size() << ".  Times in (microseconds)" << std::endl;
          for (auto itr = perf_values.begin(); itr != perf_values.end(); ++itr) {
            std::cout << "\tDataset: " << itr->first << ", record count: " << itr->second.recordCount << ", Average: " << itr->second.decrypt_duration / 1000 / itr->second.recordCount << ", Total: " << itr->second.decrypt_duration / 1000 << std::endl;
            decryptTotal += itr->second.decrypt_duration;
          }
          decryptTotal /= 1000;
          std::cout << "\t  Total: Average: " << decryptTotal / data.size() << ", Total: " << decryptTotal << std::endl;

          if (options.max_avg_encrypt > 0) {
            if (options.max_avg_encrypt <= encryptTotal / data.size()) {
              std::cerr << "FAILED: Exceeded maximum allowed average encrypt threshold of " << options.max_avg_encrypt << " microseconds" << std::endl;
              exit_value = EXIT_FAILURE;
            } else {
              std::cout << "PASSED: Maximum allowed average encrypt threshold of " << options.max_avg_encrypt << " microseconds" << std::endl;
            }
          } else {
            std::cout << "NOTE: No maximum allowed average encrypt threshold supplied" << std::endl;
          }

          if (options.max_avg_decrypt > 0) {
            if (options.max_avg_decrypt <= decryptTotal / data.size()) {
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
    ubiq::platform::exit();

    exit(exit_value);
}
