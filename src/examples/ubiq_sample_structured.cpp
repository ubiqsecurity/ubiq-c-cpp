#include "common.h"
#include <ubiq/platform.h>

#include <iostream>


static
void
ubiq_structured_encrypt(
  const ubiq::platform::credentials & creds,
  const ubiq::platform::configuration & cfg,
  const char * const dataset_name,
  const char * const pt)
{
  std::string ct;

  ubiq::platform::structured::encryption enc(creds, cfg);

  ct = enc.encrypt(dataset_name, pt);

  std::cout << "Structured Encryption Data Results => '" << ct << "'" << std::endl;

}

static
void
ubiq_structured_decrypt(
  const ubiq::platform::credentials & creds,
  const ubiq::platform::configuration & cfg,
  const char * const dataset_name,
  const char * const ct)
{
  std::string pt;
  ubiq::platform::structured::decryption dec(creds, cfg);
  pt = dec.decrypt(dataset_name, ct);

  std::cout << "Structured Decryption Data Results => '" << pt << "'" << std::endl;
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_mode_t mode;
    const char * inputstring, * dataset_name, * credfile, * profile, *cfgfile = NULL;

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
                        &credfile, &profile, &cfgfile);

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

      if (!creds) {
          std::cerr << "unable to load credentials" << std::endl;
          std::exit(EXIT_FAILURE);
      }

      if (cfgfile) {
        cfg = ubiq::platform::configuration(cfgfile);
      }

      if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
          ubiq_structured_encrypt(creds, cfg, dataset_name, inputstring);
      } else {
          ubiq_structured_decrypt(creds, cfg, dataset_name, inputstring);
      }
    }
    catch (const std::exception& e) {
      std::cerr << "Error: " << e.what() << std::endl;
    }
    /* The library needs to clean up after itself */
    ubiq::platform::exit();

    return 0;
}
