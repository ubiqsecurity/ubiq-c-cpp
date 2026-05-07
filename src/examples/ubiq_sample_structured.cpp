#include "common.h"
#include <ubiq/platform.h>

#include <iostream>


static
int
encryptForSearch(
  ubiq::platform::structured::encryption & enc,
  const char * const dataset_name, 
  const char * const p, 
  const ubiq_dataset_type_t dataset_type)
{
  int res = 0;

  switch (dataset_type) {
    case UBIQ_DATASET_TYPE_INTEGER32:
    {
        int32_t pt = std::stoi(p);
        std::vector<int32_t> ct = enc.encryptInt_for_search(dataset_name, pt);
        std::cout << "EncryptForSearch results:" << std::endl;
        for (int32_t c : ct) {
          std::cout << "\t" << c << std::endl;
        }
    }
    break;
    case UBIQ_DATASET_TYPE_INTEGER64:
    {
        int64_t pt = std::stoi(p);
        std::vector<int64_t> ct = enc.encryptLong_for_search(dataset_name, pt);
        std::cout << "EncryptForSearch results:" << std::endl;
        for (int64_t c : ct) {
          std::cout << "\t" << c << std::endl;
        }
      }
    break;
    case UBIQ_DATASET_TYPE_DATE:
    {
        struct tm pt;
        parse_iso8601(p, &pt);
        std::vector<struct tm> ct = enc.encryptDate_for_search(dataset_name, pt);
        std::cout << "EncryptForSearch results:" << std::endl;
        for (struct tm c : ct) {
          char buffer[30];
          size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &c);

          std::cout << "\t" << buffer << std::endl;
        }
      }
    break;
    case UBIQ_DATASET_TYPE_DATETIME:
    {
        struct tm pt;
        parse_iso8601(p, &pt);
        std::vector<struct tm> ct = enc.encryptDate_for_search(dataset_name, pt);
        std::cout << "EncryptForSearch results:" << std::endl;
        for (struct tm c : ct) {
          char buffer[30];
          size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &c);

          std::cout << "\t" << buffer << std::endl;
        }
      }
    break;
    default:
    {
      std::vector<std::string> ct = enc.encrypt_for_search(dataset_name, p);
      std::cout << "EncryptForSearch results:" << std::endl;
      for (std::string c : ct) {
        std::cout << "\t" << c << std::endl;
      }
    }
    break;
  }
  return res;
}

static
int
encrypt(
  ubiq::platform::structured::encryption & enc,
  const char * const dataset_name, 
  const char * const p, 
  const ubiq_dataset_type_t dataset_type)
{
  int res = 0;

  switch (dataset_type) {
    case UBIQ_DATASET_TYPE_INTEGER32:
    {
        int32_t pt = std::stoi(p);
        int32_t ct = enc.encryptInt(dataset_name, pt);
        printf("Structured Encryption Data Results => '%d'\n", ct);
    }
    break;
    case UBIQ_DATASET_TYPE_INTEGER64:
    {
        int64_t pt = std::stoll(p);
        int64_t ct = enc.encryptLong(dataset_name, pt);
        printf("Structured Encryption Data Results => '%ld'\n", ct);
      }
    break;
    case UBIQ_DATASET_TYPE_DATE:
    {
        struct tm ct;
        struct tm pt;
        parse_iso8601(p, &pt);
        ct = enc.encryptDate(dataset_name, pt);

        char buffer[30];
        size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%MZ", &ct);
        printf("Structured Encryption Data Results => '%s'\n", buffer);
      }
    break;
    case UBIQ_DATASET_TYPE_DATETIME:
    {
        struct tm ct;
        struct tm pt;
        parse_iso8601(p, &pt);
        ct = enc.encryptDateTime(dataset_name, pt);

        char buffer[30];
        size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &ct);
        printf("Structured Encryption Data Results => '%s'\n", buffer);
      }
    break;
    default:
    {
      std::string ct;
      ct = enc.encrypt(dataset_name, p);

      std::cout << "Structured Encryption Data Results => '" << ct << "'" << std::endl;
    }
    break;
  }
  return res;
}

static
void
ubiq_structured_encrypt(
  const ubiq::platform::credentials & creds,
  const ubiq::platform::configuration & cfg,
  const char * const dataset_name,
  const char * const pt,
  const int encryptForSearchFlag,
  const ubiq_dataset_type_t dataset_type)
{

  ubiq::platform::structured::encryption enc(creds, cfg);

  if (encryptForSearchFlag) {
    encryptForSearch(enc, dataset_name, pt, dataset_type);
  } else {
    encrypt(enc, dataset_name, pt, dataset_type);;
  }

}

static
void
ubiq_structured_decrypt(
  const ubiq::platform::credentials & creds,
  const ubiq::platform::configuration & cfg,
  const char * const dataset_name,
  const char * const c,
  const ubiq_dataset_type_t dataset_type)
{
  std::string pt;
  ubiq::platform::structured::decryption dec(creds, cfg);
    switch (dataset_type) {
    case UBIQ_DATASET_TYPE_INTEGER32:
    {
      int32_t ct = std::stoi(c);
      int32_t pt = dec.decryptInt(dataset_name, ct);

      printf("Structured Decryption Data Results => '%d'\n", pt);
    }
    break;
    case UBIQ_DATASET_TYPE_INTEGER64:
    {
      int64_t ct = std::stoll(c);
      int64_t pt = dec.decryptLong(dataset_name, ct);

      printf("Structured Decryption Data Results => '%d'\n", pt);
    }
    break;
    case UBIQ_DATASET_TYPE_DATE:
    {
      struct tm ct;
      struct tm pt;
      parse_iso8601(c, &ct);
      pt = dec.decryptDate(dataset_name, ct);
      char buffer[30];
      size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &pt);

      printf("Structured Decryption Data Results => '%s'\n", buffer);
    }
    break;
    case UBIQ_DATASET_TYPE_DATETIME:
    {
      struct tm ct;
      struct tm pt;
      parse_iso8601(c, &ct);
      pt = dec.decryptDateTime(dataset_name, ct);
      char buffer[30];
      size_t len = strftime(buffer, sizeof(buffer), "%04Y-%m-%dT%H:%M:%SZ", &pt);

      printf("Structured Decryption Data Results => '%s'\n", buffer);
    }
    break;
    default:
    {
      std::string pt;
      pt = dec.decrypt(dataset_name, c);

      printf("Structured Decryption Data Results => '%.*s'\n", pt.c_str());
    }
    break;
  }
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    const char * inputstring, * dataset_name, * credfile, * profile, *cfgfile = NULL;
    int encryptForSearch;
    ubiq_dataset_type_t dataset_type;

    ubiq::platform::credentials creds;
    ubiq::platform::configuration cfg;

    try {
      /* library must be initialized */
      ubiq::platform::init();

      /*
       * the getopt function will parse the command line for arguments
       * specific to the sample application and return the found options
       * in the variables below.
       *
       * `mode`, `method`, `dataset_name`, and `inputstring`
       * are required and will be set to the options found on the command
       * line.
       *
       * `credfile` and `profile` are not required arguments and may be
       * NULL upon return from the call.
       */
      ubiq_structured_getopt(argc, argv,
                        &mode, 
                        &dataset_name, &inputstring,
                        &credfile, &profile, &cfgfile, &encryptForSearch,
                        &dataset_type);

      /*
       * When `creds` was declared above, it loaded the default
       * credentials found in ~/.ubiq/credentials or it failed to load
       * those credentials and the object is in an invalid state.
       *
       * If `credfile` or `profile` was specified, reload the credentials
       * using those parameters. Note that the constructor takes
       * std::string's as arguments, which cannot be initialized from
       * NULL pointers.
       */
      if (credfile || profile) {
         creds = ubiq::platform::credentials(
             std::string(credfile ? credfile : ""),
             std::string(profile ? profile : ""));
      }

      if (encryptForSearch && mode != UBIQ_SAMPLE_MODE_ENCRYPT) {
        std::cerr << "EncryptForSearch is only compatible when encrypting data" << std::endl;
        std::exit(EXIT_FAILURE);
      }

      if (!creds) {
          std::cerr << "unable to load credentials" << std::endl;
          std::exit(EXIT_FAILURE);
      }

      if (cfgfile) {
        cfg = ubiq::platform::configuration(cfgfile);
      }

      if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
          ubiq_structured_encrypt(creds, cfg, dataset_name, inputstring, encryptForSearch, dataset_type);
      } else {
          ubiq_structured_decrypt(creds, cfg, dataset_name, inputstring, dataset_type);
      }
    }
    catch (const std::exception& e) {
      std::cerr << "Error: " << e.what() << std::endl;
    }
    /* The library needs to clean up after itself */
    ubiq::platform::exit();

    return 0;
}
