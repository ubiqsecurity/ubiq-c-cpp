#include "test_harness_helper.h"

#include <ubiq/platform.h>
#include <ubiq/platform/internal/structured_private.h>
#include <ubiq/platform/internal/parsing.h>

#include <iostream>
#include <map>
#include <chrono>
#include <sys/stat.h>
#include <dirent.h>
#include <cstring>

class Results {
  public:
  std::string out;
  long duration;

  Results() : out(""), duration(0L) {

  }
};


class PerfCounts {
  public:
  long encrypt_duration;
  long decrypt_duration;
  long recordCount;

  PerfCounts() :encrypt_duration(0L), decrypt_duration(0L), recordCount(0L) {
  }
};

Results encrypt(ubiq::platform::structured::encryption & enc, Data_rec & dr, ubiq_platform_dataset_t const * const dataset) {
  Results results;
  char const * const dataset_type = ubiq_platform_dataset_get_data_type(dataset);

  if (strcmp("integer", dataset_type) == 0) {
    ubiq_platform_data_type_config_t const * const cfg = ubiq_platform_dataset_get_data_type_config(dataset);
    if (32 == ubiq_platform_data_type_config_get_size(cfg)) {
      int32_t pt = std::stoi(dr.plain_text);
      auto start = std::chrono::steady_clock::now();

      int32_t ct = enc.encryptInt(dr.dataset_name, pt);
      auto end = std::chrono::steady_clock::now();
      results.out = std::to_string(ct);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    } else {
      int64_t pt = std::stoll(dr.plain_text);
      auto start = std::chrono::steady_clock::now();

      int64_t ct = enc.encryptLong(dr.dataset_name, pt);
      auto end = std::chrono::steady_clock::now();
      results.out = std::to_string(ct);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    }

  } else if (strcmp("date", dataset_type) == 0) {

    struct tm ct;
    struct tm pt;
    ubiq_platform_parse_iso8601(dr.plain_text.c_str(), &pt);
    auto start = std::chrono::steady_clock::now();
    ct = enc.encryptDate(dr.dataset_name, pt);
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
    ct = enc.encryptDateTime(dr.dataset_name, pt);
    auto end = std::chrono::steady_clock::now();

    char buffer[25];

    size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct);

    results.out = buffer;
    results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    
  } else {
      auto start = std::chrono::steady_clock::now();
      std::string ct = enc.encrypt(dr.dataset_name, dr.plain_text);
      auto end = std::chrono::steady_clock::now();
      results.out = ct;
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();

  }


  return results;

}

Results decrypt(ubiq::platform::structured::decryption & dec, Data_rec & dr, ubiq_platform_dataset_t const * const dataset) {
  Results results;
  char const * const dataset_type = ubiq_platform_dataset_get_data_type(dataset);

  if (strcmp("integer", dataset_type) == 0) {
    ubiq_platform_data_type_config_t const * const cfg = ubiq_platform_dataset_get_data_type_config(dataset);
    if (32 == ubiq_platform_data_type_config_get_size(cfg)) {
      int32_t ct = std::stoi(dr.cipher_text);
      auto start = std::chrono::steady_clock::now();

      int32_t pt = dec.decryptInt(dr.dataset_name, ct);
      auto end = std::chrono::steady_clock::now();
      results.out = std::to_string(pt);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    } else {
      int64_t ct = std::stoll(dr.cipher_text);
      auto start = std::chrono::steady_clock::now();

      int64_t pt = dec.decryptLong(dr.dataset_name, ct);
      auto end = std::chrono::steady_clock::now();
      results.out = std::to_string(pt);
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    }

  } else if (strcmp("date", dataset_type) == 0) {
    struct tm ct;
    struct tm pt;
    ubiq_platform_parse_iso8601(dr.cipher_text.c_str(), &ct);
    auto start = std::chrono::steady_clock::now();
    pt = dec.decryptDate(dr.dataset_name, ct);
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
    pt = dec.decryptDateTime(dr.dataset_name, ct);
    auto end = std::chrono::steady_clock::now();

    char buffer[25];

    size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &pt);

    results.out = buffer;
    results.duration = std::chrono::duration<double, std::nano>(end - start).count();
    
  } else {
      auto start = std::chrono::steady_clock::now();
      std::string pt = dec.decrypt(dr.dataset_name, dr.cipher_text);
      auto end = std::chrono::steady_clock::now();
      results.out = pt;
      results.duration = std::chrono::duration<double, std::nano>(end - start).count();

  }


  return results;
}

void find_files_recursive(const std::string &dir_path, std::list<std::string> &files) {
    DIR *d;
    struct dirent *dir;
    struct stat s;

    d = opendir(dir_path.c_str());
    if (!d) return;

    while ((dir = readdir(d)) != NULL) {
        // Skip "." and ".." to avoid infinite loops
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
            continue;

        std::string full_path = dir_path + "/" + std::string(dir->d_name);

        if (dir->d_type == DT_REG) {
            // Regular file — add to list
            files.push_back(full_path);
        } else if (dir->d_type == DT_DIR) {
            // Subdirectory — recurse into it
            find_files_recursive(full_path, files);
        } else if (dir->d_type == DT_UNKNOWN) {
            // Some filesystems (e.g. ext2) don't support d_type,
            // so fall back to stat()
            if (stat(full_path.c_str(), &s) == 0) {
                if (s.st_mode & S_IFREG)
                    files.push_back(full_path);
                else if (s.st_mode & S_IFDIR)
                    find_files_recursive(full_path, files);
            }
        }
    }
    closedir(d);
}


int main(const int argc, char * const argv[])
{
    Options options;
    ubiq::platform::credentials creds;
    std::map<std::string, PerfCounts> perf_values;

    std::list<Data_rec> errors;
    int exit_value = EXIT_SUCCESS;

    ubiq_platform_credentials * c_creds = NULL;
    ubiq_platform_structured_enc_dec_obj * c_enc = NULL;

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

      ubiq::platform::structured::decryption dec(creds);
      ubiq::platform::structured::encryption enc(creds);

      int res = ubiq_platform_credentials_create(&c_creds);
      if (!res) { res = ubiq_platform_structured_enc_dec_create(c_creds, &c_enc); }

      // Test to see if the infile is a directory or file.  If it is a directory, then perform a dirlist of everything in the directory and loop
      // over each file

      std::list<std::string> files = std::list<std::string>();

      struct stat s;
      int t = stat(options.infile.c_str(), &s);

      if (t == 0 && s.st_mode & S_IFREG) {
          files.push_back(options.infile);
      } else if (t == 0 && s.st_mode & S_IFDIR) {
          find_files_recursive(options.infile, files);
      }

      long recordCount = 0;
      for (auto const & file : files) {
        std::list<Data_rec> data;
        ubiq_load_datafile(file, data);

        recordCount += data.size();
        for (std::list<Data_rec>::iterator dit=data.begin(); dit != data.end(); ++dit) {
          auto itr = perf_values.find(dit->dataset_name);
          if (itr == perf_values.end()) {
              ubiq_platform_dataset_t const * const dataset = ubiq_platform_structured_get_dataset(c_enc, dit->dataset_name.c_str());
            try {
              encrypt(enc, *dit, dataset);
            } catch (const std::exception& e) {
              exit_value = EXIT_FAILURE;
              std::cerr << "Error: " << e.what() << std::endl;
              std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
            }
            try {
              decrypt(dec, *dit, dataset);
            } catch (const std::exception& e) {
              exit_value = EXIT_FAILURE;
              std::cerr << "Error: " << e.what() << std::endl;
              std::cerr << "     dataset: '" << dit->dataset_name << "'  plaintext: '"<< dit->plain_text << "'" << std::endl;
            }
            perf_values[dit->dataset_name] = PerfCounts();
            itr = perf_values.find(dit->dataset_name);
          }

          try {
            // auto start = std::chrono::steady_clock::now();
            ubiq_platform_dataset_t const * const dataset = ubiq_platform_structured_get_dataset(c_enc, dit->dataset_name.c_str());

            Results ct = encrypt(enc, *dit, dataset);
            Results pt = decrypt(dec, *dit, dataset);

            if (ct.out != dit->cipher_text || pt.out != dit->plain_text) {
              errors.push_back(*dit);
            }

            itr->second.encrypt_duration += ct.duration;
            itr->second.decrypt_duration += pt.duration;
            itr->second.recordCount ++;
          } catch (const std::exception& e) {
            printf("In Catch %s", e.what());
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
    ubiq::platform::exit();

    exit(exit_value);
}
