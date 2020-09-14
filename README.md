# Ubiq Security C/C++ Libraries


The Ubiq Security C and C++ libraries provide convenient interaction with the
Ubiq Security Platform API from applications written in the C and C++ languages.
They include a pre-defined set of functions and classes that will provide
simple interfaces to encrypt and decrypt data

## Documentation

See the [C/C++ API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

#### Using the package manager:

You don't need this source code unless you want to modify the libraries. If you
just want to use the libraries, install the pre-built packages:

```sh
# installs the runtime libraries, needed for running existing clients
$ sudo apt install ./libubiqclient_<version>_<arch>.deb
# installs the development headers, needed for building or modifying clients
$ sudo apt install ./libubiqclient-dev_<version>_<arch>.deb
```

When building clients, use `-lubiqclient` to link against the C library and
`-lubiqclient++` to link against the C++ library.

#### Building from source:

From within the cloned git repository directory, Install from source with:

```
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build . --target package
```

The package manager can be used to install the built packages using the
commands described above.

### Requirements

-   [CMake 3.10+](https://cmake.org/files/)
-   cURL 7.68+
-   OpenSSL 1.1+

```sh
# for runtime libraries needed to use the library
$ sudo apt install cmake libcurl4 libssl1.1
# for development headers needed to build the library
$ sudo apt install libcurl4-openssl-dev libssl-dev
```

## Usage

The library needs to be configured with your account credentials which are
available in your [Ubiq Dashboard][dashboard] [credentials][credentials]. The
credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).

```c
#include <ubiq/platform.h>
```

### Read credentials from a specific file and use a specific profile
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


### Read credentials from ~/.ubiq/credentials and use the default profile
```c
/* C */
struct ubiq_platform_credentials * credentials;

ubiq_platform_credentials_create(&credentials);
```
```c++
/* C++ */
ubiq::platform::credentials credentials;
```


### Use the following environment variables to set the credential values
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


### Explicitly set the credentials
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

Unsuccessful requests return non-zero values. In general, these values are
negative error numbers which indicate the nature of the error/failure. However,
specific interfaces may return other values which are documented in the
interface headers.

#### C++

Unsuccessful requests raise exceptions. In general, exceptions are of the type
`std::system_error` and in the category `std::generic_category`. These
exceptions carry error codes corresponding to error numbers.


### Encrypt a simple block of data

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

### Decrypt a simple block of data

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


### Encrypt a large data element where data is loaded in chunks

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


### Decrypt a large data element where data is loaded in chunks

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
