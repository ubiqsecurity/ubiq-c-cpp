# Ubiq Security C/C++ Libraries


The Ubiq Security C and C++ libraries provide convenient interaction with the
Ubiq Security Platform API from applications written in the C and C++ languages.
They include a pre-defined set of functions and classes that will provide
simple interfaces to encrypt and decrypt data


## Documentation

See the [C/C++ API docs](https://dev.ubiqsecurity.com/docs/api) and
[below](#usage) for examples.

Individual interfaces are documented in greater detail in:
* [platform.h](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/blob/master/src/include/ubiq/platform.h)
* [credentials.h](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/blob/master/src/include/ubiq/platform/credentials.h)
* [configuration.h](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/blob/master/src/include/ubiq/platform/configuration.h)
* [encrypt.h](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/blob/master/src/include/ubiq/platform/encrypt.h)
* [decrypt.h](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/blob/master/src/include/ubiq/platform/decrypt.h)

## Installation

#### Using the package manager:

Packages are available for systems that can use `.deb` and `.rpm` files. In that case,
you don't need this source code unless you want to modify the libraries. If you
just want to use the libraries, install the pre-built packages available from
[Releases](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/releases):

```sh
# For debian based systems
# installs the runtime libraries, needed for running existing clients
$ sudo apt install ./libubiqclient_<version>_<arch>.deb
# installs the development headers, needed for building or modifying clients
$ sudo apt install ./libubiqclient-dev_<version>_<arch>.deb
```
```sh
# For rpm based systems
# installs the runtime libraries, needed for running existing clients
$ sudo yum install ./libubiqclient-<version>_<arch>.rpm
# installs the development headers, needed for building or modifying clients
$ sudo yum install ./libubiqclient-dev-<version>_<arch>.rpm
```


When building clients with `gcc`, use `-lubiqclient` to link against the C
library and `-lubiqclient++` to link against the C++ library.

#### Building from source:

Clone this repository, initialize the submodules, and build the client. The
commands are the same on both Windows and Unix-like systems:
```console
$ git clone https://gitlab.com/ubiqsecurity/ubiq-c-cpp.git
$ cd ubiq-c-cpp
$ git submodule update --init --recursive
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
```

The package manager can be used to install the built packages using the
commands described above.

### Requirements

[CMake 3.10+](https://cmake.org/files/) is required for building on both
Windows and Unix-like systems.

On Windows, the library has been tested to build with the
[Visual Studio 2017 CE](https://visualstudio.microsoft.com/downloads/)
compiler.

On Unix-like systems, the following libraries and development headers are
required:
-   cURL 7.68+
-   OpenSSL 1.1+
-   GMP 10

```sh
# On Debian-like systems, those packages can be installed with the following
# commands:
# for runtime libraries needed to use the library
$ sudo apt install cmake libcurl4 libssl1.1 libgmp10
# for development headers needed to build the library
$ sudo apt install libcurl4 openssl-dev libssl-dev libgmp-dev
```
```sh
# On Fedora-like systems, those packages can be installed with the following
# commands:
# for runtime libraries needed to use the library
$ sudo yum install cmake curl openssl-libs gmp
# for development headers needed to build the library
$ sudo yum install openssl-devel libcurl-devel gmp-devel gmp-c++
```

## Usage

### Initialization

Before the library can be used, it must be initialized

```c
#include <ubiq/platform.h>
```
```c
/* C
 *
 * Returns an `int` equal to 0 if the library is successfully
 * initialized and a negative value, otherwise.
 */
ubiq_platform_init();
```
```c++
/* C++
 *
 * Returns `void`, but throws an exception if the library
 * is not successfully initialized.
 */
ubiq::platform::init();
```

Conversely, the library should be shutdown/de-initialized when it is no
longer needed:
```c
/* C */
ubiq_platform_exit();
```
```c++
/* C++ */
ubiq::platform::exit();
```

### Credentials

The library needs to be configured with your account credentials which are
available in your [Ubiq Dashboard][dashboard] [credentials][credentials]. The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).  A configuration can also be supplied to control specific behavior of the library.  The configuration file can be loaded from an explicit file or read from the default location [~/.ubiq/configuration].  See [below](#configuration-file) for a sample configuration file and content description.


#### Read credentials from a specific file and use a specific profile
```c
/* C */
struct ubiq_platform_credentials * credentials;

ubiq_platform_credentials_create_specific(
    "/path/to/credentials", "profile-name", &credentials);
```
```c++
/* C++ */
ubiq::platform::credentials credentials(
    "/path/to/credentials", "profile-name");
```

#### Read configuration from a specific file
```c
/* C */
struct ubiq_platform_configuration * configuration;

ubiq_platform_configuration_load_configuration(
    "/path/to/configuration", &configuration);
```
```c++
/* C++ */
ubiq::platform::configuration configuration(
    "/path/to/configuration");
```



#### Read credentials from ~/.ubiq/credentials and use the default profile
```c
/* C */
struct ubiq_platform_credentials * credentials;

ubiq_platform_credentials_create(&credentials);
```
```c++
/* C++ */
ubiq::platform::credentials credentials;
```

#### Read configuration from ~/.ubiq/configuration
```c
/* C */
struct ubiq_platform_configuration * configuration;

ubiq_platform_configuration_create(&configuration);
```
```c++
/* C++ */
ubiq::platform::configuration configuration;
```


#### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```c
/* C */
struct ubiq_platform_credentials * credentials;

ubiq_platform_credentials_create(&credentials);
```
```c++
/* C++ */
ubiq::platform::credentials credentials;
```


#### Explicitly set the credentials
```c
/* C */
struct ubiq_platform_credentials * credentials;

ubiq_platform_credentials_create_explicit(
    "..." /* access key id */,
    "..." /* secret signing key */,
    "..." /* secret crypto access key */,
    "..." /* Ubiq API server, may be NULL */,
    &credentials);
```
```c++
/* C++ */
ubiq::platform::credentials credentials(
    "..." /* access key id */,
    "..." /* secret signing key */,
    "..." /* secret crypto access key */,
    "..." /* Ubiq API server, may be unspecified */);
```

#### Explicitly set the configuration
```c
/* C */
struct ubiq_platform_configuration * configuration;

ubiq_platform_configuration_create_explicit2(
    <int>, // event_reporting_wake_interval
    <int>, // event_reporting_minimum_count
    <int>, // event_reporting_flush_interval
    <int>, // event_reporting_trap_exceptions
    "..." //  event_reporting_timestamp_granularity
    <int>, // key_caching_encrypt_keys - 0 leave decrypted, 1 keep encrypted
    <int>, // key_caching_structured_keys - 0 don't cache, 1 cache structured keys
    <int>, // key_caching_unstructured_keys - 0 don't cache, 1 cache unstructured keys
    <int>, // key_caching_ttl_seconds
    &configuration);
```
```c++
/* C++ */
ubiq::platform::configuration configuration(
    <int>, // event_reporting_wake_interval
    <int>, // event_reporting_minimum_count
    <int>, // event_reporting_flush_interval
    <int>, // event_reporting_trap_exceptions
    "..." //  event_reporting_timestamp_granularity
    <int>, // key_caching_encrypt_keys - 0 leave decrypted, 1 keep encrypted
    <int>, // key_caching_structured_keys - 0 don't cache, 1 cache structured keys
    <int>, // key_caching_unstructured_keys - 0 don't cache, 1 cache unstructured keys
    <int>, // key_caching_ttl_seconds);
```


### Handling exceptions

#### C

Unsuccessful functions return non-zero values. In general, these values are
negative error numbers which indicate the nature of the error/failure. More
common errors include:

* `-EACCES`
    Access is denied, usually due to invalid credentials, but this can also
    be caused by failure to decrypt keys from the server
* `-EAGAIN`:
    The library has not been initialized
* `-EBADMSG`:
    The server rejected a message from the client or vice versa. This is
    usually an incompatibility between the client and server, but can also
    be caused by the clock being set incorrectly on the client side,
    causing authentication to fail. This error can also be caused by an
    invalid or unsupported data format during decryption
* `-ECONNABORTED`:
    An error occurred on the server side
* `-EINPROGRESS`:
    A chunking encryption or decryption has already been started when one of
    the encryption or decryption begin() functions is called
* `-EINVAL`:
    A function was called with an invalid value/parameter
* `-ENODATA`:
    During encryption, no random data was available. During decryption, not
    enough data was supplied to completed the decryption
* `-ENOENT`:
    The specified or default credentials could not be found or were incomplete
* `-ENOMEM`:
    The system was unable to allocate memory from the heap
* `-ENOSPC`, formerly `-EDQUOT`:
    The encryption key has already been used the maximum number of times
* `-EPROTO`:
    A response from the server was not understood. This is a problem with the
    library and should be reported.
* `-ESRCH`, formerly `-EBADFD`:
    The functions associated with a chunking encryption or decryption have
    been called in an incorrect order
* `-EALREADY`:
    The library init() function or exit() functions have been called in the
    wrong order.  The ubiq_platform_init() or ubiq::platform::init() should be 
    called before any other functions and ubiq_platform_exit() or ubiq::platform::exit()
    should be called when the library resources should be released.

Errors returned from external libraries are converted to `INT_MIN` where the
failure is not specific or can't be converted to an error number. While it is
possible that the error indicates a runtime issue, most likely it is a misuse
of that external library by the Ubiq client and should be reported.

#### C++

Unsuccessful requests raise exceptions. In general, exceptions are of the type
`std::system_error` and in the category `std::generic_category`. These
exceptions carry error codes corresponding to error numbers. The error
conditions associated with those numbers are described [above](#c).

### Unstructured encryption and decryption

#### Simple interfaces to encrypt of a single block of data

Pass credentials and data into the encryption function. The encrypted data
will be returned.


```c
/* C */
#include <ubiq/platform.h>

struct ubiq_platform_credentials * creds = NULL;
void * ptbuf = NULL, * ctbuf = NULL;
size_t ptlen = 0, ctlen = 0;

/* initialize ptbuf and ptlen */
...

ubiq_platform_credentials_create(&creds);
ubiq_platform_encrypt(creds, ptbuf, ptlen, &ctbuf, &ctlen);
free(ctbuf);
ubiq_platform_credentials_destroy(creds);
```
```c++
/* C++ */
#include <ubiq/platform.h>

ubiq::platform::credentials creds;
std::vector<std::uint8_t> ctbuf;
void * ptbuf;
size_t ptlen;

/* initialize ptbuf and ptlen */
...

ctbuf = ubiq::platform::encrypt(creds, ptbuf, ptlen);
```

#### Simple interface to decrypt a single block of data

Pass credentials and encrypted data into the decryption function. The
plaintext data will be returned.

```c
/* C */
#include <ubiq/platform.h>

struct ubiq_platform_credentials * creds = NULL;
void * ptbuf = NULL, * ctbuf = NULL;
size_t ptlen = 0, ctlen = 0;

/* initialize ctbuf and ctlen */
...

ubiq_platform_credentials_create(&creds);
ubiq_platform_decrypt(creds, ctbuf, ctlen, &ptbuf, &ptlen);
free(ptbuf);
ubiq_platform_credentials_destroy(creds);
```
```c++
/* C++ */
#include <ubiq/platform.h>

ubiq::platform::credentials creds;
std::vector<std::uint8_t> ptbuf;
void * ctbuf;
size_t ctlen;

/* initialize ctbuf and ctlen */
...

ptbuf = ubiq::platform::decrypt(creds, ctbuf, ctlen);
```

### Chunking encryption and decryption

#### Unstructured encryption of a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
- Call the encryption instance end method


```c
/* C */
#include <ubiq/platform.h>

/* Process 1 MiB of plaintext data at a time */
#define BLOCK_SIZE  (1024 * 1024)

struct ubiq_platform_credentials * credentials = NULL;
struct ubiq_platform_encryption * enc = NULL;
void * ctbuf = NULL, * buf = NULL;
size_t ctlen = 0, len = 0;

ubiq_platform_credentials_create(&credentials);
ubiq_platform_encryption_create(credentials, 1, &enc);

ubiq_platform_encryption_begin(enc, &buf, &len);
ctbuf = realloc(ctbuf, ctlen + len);
memcpy(ctbuf + ctlen, buf, len);
ctlen += len;
free(buf);

while (!feof(infp)) {
    char ptbuf[BLOCK_SIZE];
    size_t ptsize;

    ptsize = fread(ptbuf, 1, BLOCK_SIZE, infp);
    ubiq_platform_encryption_update(enc, ptbuf, ptsize, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);
}

ubiq_platform_encryption_end(enc, &buf, &len);
ctbuf = realloc(ctbuf, ctlen + len);
memcpy(ctbuf + ctlen, buf, len);
ctlen += len;
free(buf);

ubiq_platform_encryption_destroy(enc);
ubiq_platform_credentials_destroy(credentials);
```
```c++
/* C++ */
#include <ubiq/platform.h>

/* Process 1 MiB of plaintext data at a time */
#define BLOCK_SIZE  (1024 * 1024)

ubiq::platform::credentials credentials;
ubiq::platform::encryption enc(credentials, 1);
std::vector<std::uint8_t> ctbuf, buf;

ctbuf = enc.begin();

while (!infile.eof()) {
    std::vector<char> ptbuf(BLOCK_SIZE);

    infile.read(ptbuf.data(), ptbuf.size());
    ptbuf.resize(infile.gcount());
    buf = enc.update(ptbuf.data(), ptbuf.size());
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());
}

buf = enc.end();
ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());
```

#### Encrypt several objects using the same data encryption key (fewer calls to the server)

In this example, the same data encryption key is used to encrypt several different plain text objects, object1 .. objectn.  In each case, a different initialization vector, IV, is automatically used but the ubiq platform is not called to obtain a new data encryption key, resulting in better throughput.  For data security reasons, you should limit n to be less than 2^32 (4,294,967,296) for each unique data encryption key.

1. Create an encryption object using the credentials.
2. Repeat following three steps as many times as appropriate
*  Call the encryption instance begin method
*  Call the encryption instance update method repeatedly until a single object's data is processed
*  Call the encryption instance end method
3. Call the encryption instance close method


```c
/* C */
#include <ubiq/platform.h>

/* Process 1 MiB of plaintext data at a time */
#define BLOCK_SIZE  (1024 * 1024)

struct ubiq_platform_credentials * credentials = NULL;
struct ubiq_platform_encryption * enc = NULL;
void * ctbuf = NULL, * buf = NULL;
size_t ctlen = 0, len = 0;

    int res = ubiq_platform_init();

    ubiq_platform_credentials_create(&credentials);
    ubiq_platform_encryption_create(credentials, 1, &enc);

    ...

    // Process Object 1
    ubiq_platform_encryption_begin(enc, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);

    char ptbuf[BLOCK_SIZE];
    size_t ptsize;

    // Fill ptbuf with some data to encrypt.  Repeat next few lines as needed
    ubiq_platform_encryption_update(enc, ptbuf, ptsize, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);

    ubiq_platform_encryption_end(enc, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);
    // Do something with the encrypted data ctbuf

    // Reset the output cipher text
    free(ctbuf);
    ctbuf = NULL;
    ctlen = 0;

    // Process Object 2 
    ubiq_platform_encryption_begin(enc, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);

    // Fill ptbuf with some data to encrypt.  Repeat next few lines as needed
    ubiq_platform_encryption_update(enc, ptbuf, ptsize, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);

    ... 
    // Reset the output cipher text
    free(ctbuf);
    ctbuf = NULL;
    ctlen = 0;

    // Process Object n 
    ubiq_platform_encryption_begin(enc, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);

    // Fill ptbuf with some data to encrypt.  Repeat next few lines as needed
    ubiq_platform_encryption_update(enc, ptbuf, ptsize, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);

    ubiq_platform_encryption_end(enc, &buf, &len);
    ctbuf = realloc(ctbuf, ctlen + len);
    memcpy(ctbuf + ctlen, buf, len);
    ctlen += len;
    free(buf);
    // Do something with the encrypted data ctbuf

    ...

    ubiq_platform_encryption_destroy(enc);
    ubiq_platform_credentials_destroy(credentials);
    ubiq_platform_exit();
```
```c++
/* C++ */
#include <ubiq/platform.h>

/* Process 1 MiB of plaintext data at a time */
#define BLOCK_SIZE  (1024 * 1024)

ubiq::platform::init();
ubiq::platform::credentials credentials;
ubiq::platform::encryption enc(credentials, 1);
std::vector<std::uint8_t> ctbuf, buf;
    std::vector<char> ptbuf(BLOCK_SIZE);

    // process object 1
    ctbuf = enc.begin();

    // Populate ptbuf with data to encrypt.  Repeat as needed for all data chunks
    buf = enc.update(ptbuf.data(), ptbuf.size());
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());

    buf = enc.end();
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());
    // Do something with the encrypted data ctbuf

    // Process Object 2
    ctbuf = enc.begin();

    // Populate ptbuf with data to encrypt.  Repeat as needed for all data chunks
    buf = enc.update(ptbuf.data(), ptbuf.size());
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());

    buf = enc.end();
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());
    // Do something with the encrypted data ctbuf

    ...
    // Process Object n
    ctbuf = enc.begin();

    // Populate ptbuf with data to encrypt.  Repeat as needed for all data chunks
    buf = enc.update(ptbuf.data(), ptbuf.size());
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());

    buf = enc.end();
    ctbuf.insert(ctbuf.end(), buf.begin(), buf.end());
    // Do something with the encrypted data ctbuf

ubiq::platform::exit();
```



#### Unstructured decryption of a large data element where data is loaded in chunks
- Create an instance of the decryption object using the credentials.
- Call the decryption instance begin method
- Call the decryption instance update method repeatedly until all the data is processed
- Call the decryption instance end method


```c
/* C */
#include <ubiq/platform.h>

/* Process 1 MiB of plaintext data at a time */
#define BLOCK_SIZE  (1024 * 1024)

struct ubiq_platform_credentials * credentials = NULL;
struct ubiq_platform_decryption * dec = NULL;
void * ptbuf = NULL, * buf = NULL;
size_t ptlen = 0, len = 0;

ubiq_platform_credentials_create(&credentials);
ubiq_platform_decryption_create(credentials, &dec);

ubiq_platform_decryption_begin(dec, &buf, &len);
ptbuf = realloc(ptbuf, ptlen + len);
memcpy(ptbuf + ptlen, buf, len);
ptlen += len;
free(buf);

while (!feof(infp)) {
    char ctbuf[BLOCK_SIZE];
    size_t ctsize;

    ctsize = fread(ctbuf, 1, BLOCK_SIZE, infp);
    ubiq_platform_decryption_update(dec, ctbuf, ctsize, &buf, &len);
    ptbuf = realloc(ptbuf, ptlen + len);
    memcpy(ptbuf + ptlen, buf, len);
    ptlen += len;
    free(buf);
}

ubiq_platform_decryption_end(dec, &buf, &len);
ptbuf = realloc(ptbuf, ptlen + len);
memcpy(ptbuf + ptlen, buf, len);
ptlen += len;
free(buf);

ubiq_platform_decryption_destroy(dec);
ubiq_platform_credentials_destroy(credentials);
```
```c++
/* C++ */
#include <ubiq/platform.h>

/* Process 1 MiB of plaintext data at a time */
#define BLOCK_SIZE  (1024 * 1024)

ubiq::platform::credentials credentials;
ubiq::platform::decryption dec(credentials);
std::vector<std::uint8_t> ptbuf, buf;

ptbuf = dec.begin();

while (!infile.eof()) {
    std::vector<char> ctbuf(BLOCK_SIZE);

    infile.read(ctbuf.data(), ctbuf.size());
    ctbuf.resize(infile.gcount());
    buf = dec.update(ctbuf.data(), ctbuf.size());
    ptbuf.insert(ptbuf.end(), buf.begin(), buf.end());
}

buf = dec.end();
ptbuf.insert(ptbuf.end(), buf.begin(), buf.end());
```

## Ubiq Structured Encryption

## Requirements

-   Please follow the same requirements as described above for the unstructured functionality.
-   Library packages, include files and initialization are the same as above for unstructured functionality.
-   When building clients with `gcc`, use `-lubiqclient` to link against the C
library and `-lubiqclient++` to link against the C++ library.

## Usage

You will need to obtain account credentials in the same way as described above for conventional encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to use a structured dataset.
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).


### Encrypt a social security text field
Create an structured_enc_dec object with credentials and then allow repeated calls to encrypt / decrypt
data using a Field Format Specification and the data.  Cipher text will be returned.

```c
/* C */
#include <ubiq/platform.h>

struct ubiq_platform_credentials * creds = NULL;
struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
const char * const DATASET_NAME = "SSN";
// Loop through a bunch of plaintext values
char * ptbuf[] = {"123-45-6789", "987-65-4321","111-22-3333","444-55-6666",NULL};
char * ctbuf = NULL;
size_t ctlen = 0;
...
int res = ubiq_platform_init();

if (!res) {res = ubiq_platform_credentials_create(&creds); }
if (!res) {res = ubiq_platform_structured_enc_dec_create(creds, &enc); }

// Loop through all the PT values and encrypt each one
char ** p = ptbuf;
while ((!res) && *p) {
  res = ubiq_platform_structured_encrypt_data(enc,
     DATASET_NAME, NULL, 0, *p, strlen(*p), &ctbuf, &ctlen);
  // Check for error message and print error information
  if (res) {
    char * err_msg = NULL;
    int err_num;
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error (%d) Encountered.  What '%s'\n", err_num, err_msg);
    free(err_msg);
  }
  ...
  free(ctbuf);
  p++;
}

...
ubiq_platform_structured_enc_dec_destroy(enc);
ubiq_platform_credentials_destroy(creds);

ubiq_platform_exit();

```
```c
/* C - Using preallocated buffer for the cipher text */
#include <ubiq/platform.h>

struct ubiq_platform_credentials * creds = NULL;
struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
const char * const DATASET_NAME = "SSN";
// Loop through a bunch of plaintext values
char * ptbuf[] = {"123-45-6789", "987-65-4321","111-22-3333","444-55-6666",NULL};
// ctbuf has to be larger enough to hold the cipher text of longest string PLUS the NULL terminator
char ctbuf[1024]; 
size_t len = sizeof(ctbuf);
.....
int res = ubiq_platform_init();

if (!res) {res = ubiq_platform_credentials_create(&creds); }
if (!res) {res = ubiq_platform_structured_enc_dec_create(creds, &enc); }

// Loop through all the PT values and encrypt each one
char ** p = ptbuf;
while ((!res) && *p) {
  // Reset the variable for the max size of the available buffer each time through loop
  size_t ctlen = len;
  res = ubiq_platform_structured_encrypt_data_prealloc(enc,
     DATASET_NAME, NULL, 0, *p, strlen(*p), ctbuf, &ctlen);
  // Check for error message and print error information
  if (res) {
    char * err_msg = NULL;
    int err_num;
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error (%d) Encountered.  What '%s'\n", err_num, err_msg);
    free(err_msg);
  }
  ....
  p++;
}

...
ubiq_platform_structured_enc_dec_destroy(enc);
ubiq_platform_credentials_destroy(creds);

ubiq_platform_exit();

```
```c++
/* C++ */
#include <ubiq/platform.h>

std::string dataset_name("ALPHANUM_SSN");
std::vector<std::string> pt = {"123-45-6789", "987-65-4321","123-45-6789","123-45-6789","123-45-6789"};
std::string ct;

try {
   ubiq::platform::credentials creds;
   ubiq::platform::init();
   ubiq::platform::structured::encryption enc(creds);

   // loop through a vector of plain text elements to encrypt
   for(auto itr : pt) {
     ct = enc.encrypt(dataset_name, itr);
     ...
   }
}
catch (const std::exception& e) {
  std::cerr << "Error: " << e.what() << std::endl;
}

ubiq::platform::exit();
```


### Decrypt a social security text field
Create an structured_enc_dec object with Pass credentials and then allow repeated calls to encrypt / decrypt
data using a Field Format Specification and the data.  Depending upon the call, either cipher text or
plain text will be returned.

```c
/* C */
#include <ubiq/platform.h>

struct ubiq_platform_credentials * creds = NULL;
struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
const char * const DATASET_NAME = "SSN";
char * ctbuf[] = {"7\"c-`P-fGj?", "7$S-27-9D4A",NULL};
char * ptbuf = NULL;
size_t ptlen = 0;
...
int res = ubiq_platform_init();

if (!res) {res = ubiq_platform_credentials_create(&creds); }
if (!res) {res = ubiq_platform_structured_enc_dec_create(creds, &enc); }

// Loop through all the CT values and decrypt each one
char ** c = ctbuf;
while ((!res) && *c) {
  res = ubiq_platform_structured_decrypt_data(enc,
    DATASET_NAME, NULL, 0, *c, strlen(*c), &ptbuf, &ptlen);
  if (res) {
    char * err_msg = NULL;
    int err_num;
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error (%d) Encountered.  What '%s'\n", err_num, err_msg);
    free(err_msg);
  }
  ...
  free(ptbuf);
  c++;
}

...
ubiq_platform_structured_enc_dec_destroy(enc);
ubiq_platform_credentials_destroy(creds);

ubiq_platform_exit();

```
```c
/* C - Using preallocated buffer for the cipher text */
#include <ubiq/platform.h>

struct ubiq_platform_credentials * creds = NULL;
struct ubiq_platform_structured_enc_dec_obj *enc = NULL;
const char * const DATASET_NAME = "ALPHANUM_SSN";
char * ctbuf[] = {"7\"c-`P-fGj?", "7$S-27-9D4A",NULL};
// Has to be larger enough to hold the cipher text of longest string PLUS the NULL terminator
char ptbuf[1024]; 
size_t len = sizeof(ptbuf);
...
int res = ubiq_platform_init();

if (!res) {res = ubiq_platform_credentials_create(&creds); }
if (!res) {res = ubiq_platform_structured_enc_dec_create(creds, &enc); }

// Loop through all the CT values and decrypt each one
char ** c = ctbuf;
while ((!res) && *c) {
  // Reset the variable for the max size of the available buffer each time through loop
  size_t ptlen = len;
  res = ubiq_platform_structured_decrypt_data_prealloc(enc,
    DATASET_NAME, NULL, 0, *c, strlen(*c), ptbuf, &ptlen);
  if (res) {
    char * err_msg = NULL;
    int err_num;
    ubiq_platform_structured_get_last_error(enc, &err_num, &err_msg);
    printf("Error (%d) Encountered.  What '%s'\n", err_num, err_msg);
    free(err_msg);
  }
  ...
  c++;
}

...
ubiq_platform_structured_enc_dec_destroy(enc);
ubiq_platform_credentials_destroy(creds);

ubiq_platform_exit();

```
```c++
/* C++ */
#include <ubiq/platform.h>

std::string dataset_name("ALPHANUM_SSN");
std::vector<std::string> ct = {"7\"c-`P-fGj?", "7$S-27-9D4A"};
std::string pt;

try {
   ubiq::platform::credentials creds;
   ubiq::platform::init();
   ubiq::platform::structured::decryption dec(creds);

   // loop through a vector of plain text elements to encrypt
   for(auto itr : ct) {
     pt = dec.decrypt(dataset_name, itr);
     ...
   }  
}
catch (const std::exception& e) {
  std::cerr << "Error: " << e.what() << std::endl;
}
ubiq::platform::exit();
```

### Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The *<b>_add_user_defined_metadata</b> function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the <b>{</b> and <b>}</b> symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.  If immediate changes to the values are required, it would be safer to create a new encrypt / decrypt object and call the appropriate *<b>_add_user_defined_metadata</b> function with the new values.

Examples are shown below.
```c
...
  int res = ubiq_platform_init();
  ...
  res = ubiq_platform_encryption_create(creds, 5, &enc);
  res = ubiq_platform_encryption_add_user_defined_metadata(enc, "{\"some_key\" : \"some_value\" }");
  ...
  // Unstructured Encrypt operations
```
```c
...
  int res = ubiq_platform_init();
  ...
  res = ubiq_platform_structured_enc_dec_create(creds, &enc);
  res = ubiq_platform_structured_enc_dec_add_user_defined_metadata(enc, "{\"some_meaningful_flag\" : true }");
  ...
  // Structured Encrypt and Decrypt operations
```
### Encrypt For Search

The same plaintext data will result in different cipher text when encrypted using different data keys.  The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys.  This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```c
/* C - Encrypting a SSN value using all previously used data keys */

    const char * const DATASET_NAME = "SSN";
    char * ptbuf = "123-45-6789";
    char ** ct_arr(NULL);
    size_t ctcount(0);

    int res = ubiq_platform_init();

    if (!res) {res = ubiq_platform_credentials_create(&creds); }
    if (!res) {res = ubiq_platform_structured_enc_dec_create(creds, &enc); }

    ubiq_platform_structured_encrypt_data_for_search(enc, DATASET_NAME, NULL, 0, ptbuf, strlen(ptbuf), &ct_arr, &ctcount);
    ...

    for (int i = 0; i < ctcount; i++) {
      free(ct_arr[i]);
    }
    free(ct_arr);

    ubiq_platform_exit();
```
```c++
/* C++ - Encrypting a SSN value using all previously used data keys */

    std::string dataset_name("SSN");
    std::string pt("123-45-6789");
    std::vector<std::string> ct_arr;
    ubiq::platform::credentials creds;

    ubiq::platform::init();

    enc = ubiq::platform::structured::encryption(creds);
    ct_arr = enc.encrypt_for_search(dataset_name, pt);
    ...

    ubiq::platform::exit();
```

### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  

#### Event Reporting
The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events.  Valid values are
  - "NANOS"  
    // DEFAULT: values are reported down to the nanosecond resolution when possible
  - "MILLIS"  
  // values are reported to the millisecond
  - "SECONDS"  
  // values are reported to the second
  - "MINUTES"  
  // values are reported to minute
  - "HOURS"  
  // values are reported to hour
  - "HALF_DAYS"  
  // values are reported to half day
  - "DAYS"  
  // values are reported to the day

#### Key Caching
The <b>key_caching</b> section contains values to control how and when keys are cached.

- <b>ttl_seconds</b> indicates how many seconds a cache element should remain before it must be re-retrieved. (default: 1800)
- <b>structured</b> indicates whether keys will be cached when doing structured encryption and decryption. (default: true)
- <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
- <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)

```json
{
  "event_reporting": {
    "wake_interval": 1,
    "minimum_count": 2,
    "flush_interval": 2,
    "trap_exceptions": false,
    "timestamp_granularity" : "NANOS"
  },
  "key_caching" : {
     "structured" : true,
     "unstructured" : true,
     "encrypted" : false,
     "ttl_seconds" : 1800
  }
}
```

[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
