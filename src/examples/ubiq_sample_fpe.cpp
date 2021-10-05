#include "common.h"
#include <ubiq/platform.h>

#include <iostream>


static
void
ubiq_fpe_simple_encrypt(
  const ubiq::platform::credentials & creds,
  const char * const ffs_name,
  const char * const pt)
{
  std::string ct;
  ct = ubiq::platform::fpe::encrypt(creds, ffs_name, pt);

  std::cout << "FPE Encrypted Data Results => '" << ct << "'" << std::endl;
}

static
void
ubiq_fpe_simple_decrypt(
  const ubiq::platform::credentials & creds,
  const char * const ffs_name,
  const char * const ct)
{
  std::string pt;
  pt = ubiq::platform::fpe::decrypt(creds, ffs_name, ct);

  std::cout << "FPE Decrypt Data Results => '" << pt << "'" << std::endl;

}

static
void
ubiq_fpe_bulk_encrypt(
  const ubiq::platform::credentials & creds,
  const char * const ffs_name,
  const char * const pt)
{
  std::string ct;

  ubiq::platform::fpe::encryption enc(creds);

  ct = enc.encrypt(ffs_name, pt);

  std::cout << "FPE Encrypted Data Results => '" << ct << "'" << std::endl;

}

static
void
ubiq_fpe_bulk_decrypt(
  const ubiq::platform::credentials & creds,
  const char * const ffs_name,
  const char * const ct)
{
  std::string pt;
  ubiq::platform::fpe::decryption dec(creds);
  pt = dec.decrypt(ffs_name, ct);

  std::cout << "FPE Decrypt Data Results => '" << pt << "'" << std::endl;
}

int main(const int argc, char * const argv[])
{
    ubiq_sample_method_t method;
    ubiq_sample_mode_t mode;
    const char * inputstring, * ffsname, * credfile, * profile;

    ubiq::platform::credentials creds;

    /* library must be initialized */
    ubiq::platform::init();

    /*
     * the getopt function will parse the command line for arguments
     * specific to the sample application and return the found options
     * in the variables below.
     *
     * `mode`, `method`, `ffnsname`, and `inputstring`
     * are required and will be set to the options found on the command
     * line.
     *
     * `credfile` and `profile` are not required arguments and may be
     * NULL upon return from the call.
     */
    ubiq_fpe_getopt(argc, argv,
                      &mode, &method,
                      &ffsname, &inputstring,
                      &credfile, &profile);

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

    if ( method == UBIQ_SAMPLE_METHOD_SIMPLE) {
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            ubiq_fpe_simple_encrypt(creds, ffsname, inputstring);
        } else /* decrypt */ {
            ubiq_fpe_simple_decrypt(creds, ffsname, inputstring);
        }
    } else /* bulk */{
        if (mode == UBIQ_SAMPLE_MODE_ENCRYPT) {
            ubiq_fpe_bulk_encrypt(creds, ffsname, inputstring);
        } else {
            ubiq_fpe_bulk_decrypt(creds, ffsname, inputstring);
        }
    }

    /* The library needs to clean up after itself */
    ubiq::platform::exit();

    return 0;
}
