# Ubiq Security C/C++ Libraries


The Ubiq Security C and C++ libraries provide convenient interaction with the
Ubiq Security Platform API from applications written in the C and C++ languages.
They include a pre-defined set of functions and classes that will provide
simple interfaces to encrypt and decrypt data

## Documentation

See the [C/C++ API docs](https://dev.ubiqsecurity.com/docs/api) and
[below](#usage) for examples.

Individual interfaces are documented in greater detail in:
* [platform.h](src/include/ubiq/platform.h)
* [credentials.h](src/include/ubiq/platform/credentials.h)
* [encrypt.h](src/include/ubiq/platform/encrypt.h)
* [decrypt.h](src/include/ubiq/platform/decrypt.h)

## Installation

#### Using the package manager:

Packages are available for systems that can use `.deb` files. In that case,
you don't need this source code unless you want to modify the libraries. If you
just want to use the libraries, install the pre-built packages available from
[Releases](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/releases):

```console
# installs the runtime libraries, needed for running existing clients
$ sudo apt install ./libubiqclient_<version>_<arch>.deb
# installs the development headers, needed for building or modifying clients
$ sudo apt install ./libubiqclient-dev_<version>_<arch>.deb
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

On Unix-like systems, the following libraries and the development headers are
required:
-   cURL 7.68+
-   OpenSSL 1.1+

On Debian-like systems, those packages can be installed with the following
commands:
```sh
# for runtime libraries needed to use the library
$ sudo apt install cmake libcurl4 libssl1.1
# for development headers needed to build the library
$ sudo apt install libcurl4-openssl-dev libssl-dev
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
available in your [Ubiq Dashboard][dashboard] [credentials][credentials]. The
credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).

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
    usually an incompatibility betweer the client and server, but can also
    be caused by the clock being set incorrectly on the client side,
    causing authentication to fail. This error can also be caused by an
    invalid or unsupported data format during decryption
* `-ECONNABORTED`:
    An error occurred on the server side
* `-EINPROGRESS`:
    A piecewise encryption or decryption has already been started when one of
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
    The functions associated with a piecewise encryption or decryption have
    been called in an incorrect order

Errors returned from external libraries are converted to `INT_MIN` where the
failure is not specific or can't be converted to an error number. While it is
possible that the error indicates a runtime issue, most likely it is a misuse
of that external library by the Ubiq client and should be reported.

#### C++

Unsuccessful requests raise exceptions. In general, exceptions are of the type
`std::system_error` and in the category `std::generic_category`. These
exceptions carry error codes corresponding to error numbers. The error
conditions associated with those numbers are described [above](#c).

### Simple encryption and decryption

#### Encrypt a single block of data

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

#### Decrypt a single block of data

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

### Piecewise encryption and decryption

#### Encrypt a large data element where data is loaded in chunks

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


#### Decrypt a large data element where data is loaded in chunks

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

[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[windows-sdk]:https://developer.microsoft.com/en-us/windows/downloads/sdk-archive/
