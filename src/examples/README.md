# Ubiq Security Sample Application using C/C++ Library

This sample application will demonstrate how to encrypt and decrypt data using
the different APIs.

### Documentation

See the [C/C++ API docs](https://dev.ubiqsecurity.com/docs/api).

## Dockerized samples

Pre-built versions of the samples can be run in a docker container as described
[here](Docker.md).

## Installation

Install or build the software as described [here](/README.md#installation).

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq
dashboard

<pre>
[default]
ACCESS_KEY_ID = ...  
SECRET_SIGNING_KEY = ...  
SECRET_CRYPTO_ACCESS_KEY = ...  
</pre>

## Build the examples

If you installed the libraries and development headers via the `.deb`
packages, then you can build the examples directly from the installation
(note that these commands will only work on a Linux system where the
package files have been installed):

```console
$ mkdir ~/ubiq_sample
$ cd ~/ubiq_sample
$ cmake /usr/share/doc/libubiqclient-dev/examples
$ cmake --build . --target all
```

If you built the software yourself, the examples are built automatically as
part of a complete build.

- On Windows, the DLL files can be found in `build\src\Debug` or
`build\src\Release`, depending on your CMake configuration. The sample
executables can be found in `build\src\examples\Debug` or
`build\src\examples\Release`, again depending on your CMake configuration.

- On Unix-like systems, the libraries and executables are produced in
`build/src` and `build/src/examples`, respectively.

To run the examples below, copy the libraries/DLL's and executables into the
`src/examples` directory (where the example source code is located).

## View Program Options

From within the directory where your executables are located, you can
execute/test the following commands. On Linux, you may need to set the
`LD_LIBRARY_PATH` environment variable to include the directory where your
libraries are located in order for the executables to work properly. On
Windows, you may need to create the `C:\Temp` directory.

The examples below show both Unix and Windows syntax:

```console
$ ./ubiq_sample-c -h
```
```console
> .\ubiq_sample-c.exe -h
```
<pre>
Encrypt or decrypt files using the Ubiq service

  -h                       Show this help message and exit
  -V                       Show program's version number and exit
  -e                       Encrypt the contents of the input file and write
                             the results to the output file
  -d                       Decrypt the contents of the input file and write
                             the results to the output file
  -s                       Use the simple encryption / decryption interfaces
  -p                       Use the piecewise encryption / decryption interfaces
  -i INFILE                Set input file name
  -o OUTFILE               Set output file name
  -c CREDENTIALS           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE               Identify the profile within the credentials file
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to encrypt the README file

```console
$ ./ubiq_sample-c -i README.md -o /tmp/readme.enc -e -s -c credentials
```
```console
> .\ubiq_sample-c.exe -i README.md -o C:\Temp\readme.enc -e -s -c credentials
```

#### Demonstrate using the simple (-s / --simple) API interface to decrypt the README file

```console
$ ./ubiq_sample-c -i /tmp/readme.enc -o /tmp/README.out -d -s -c credentials
```
```console
> .\ubiq_sample-c.exe -i C:\Temp\readme.enc -o C:\Temp\README.out -d -s -c credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to encrypt the README file

```console
$ ./ubiq_sample-c -i README.md -o /tmp/readme.enc -e -p -c credentials
```
```console
> .\ubiq_sample-c.exe -i README.md -o C:\Temp\readme.enc -e -p -c credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the README file

```console
$ ./ubiq_sample-c -i /tmp/readme.enc -o /tmp/README.out -d -p -c credentials
```
```console
> .\ubiq_sample-c.exe -i C:\Temp\readme.enc -o C:\Temp\README.out -d -p -c credentials
```

##### _All of the above commands can be used with the C++ example by subsituting `ubiq_sample-c` with `ubiq_sample-c++`_



## Documentation for ubiq_sample_fpe.c and ubiq_sample_fpe.cpp
This library also incorporates Ubiq Format Preserving Encryption (eFPE).  eFPE allows encrypting so that the output cipher text is in the same format as the original plaintext. This includes preserving special characters and control over what characters are permitted in the cipher text. For example, consider encrypting a social security number '123-45-6789'. The cipher text will maintain the dashes and look something like: 'W$+-qF-oMMV'.


See the [C API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build the examples

If you installed the libraries and development headers via the `.deb` or `.rpm`
packages, then you can build the examples directly from the installation
(note that these commands will only work on a Linux system where the
package files have been installed):

```console
$ mkdir ~/ubiq_sample
$ cd ~/ubiq_sample
$ cmake /usr/share/doc/libubiqclient-dev/examples
$ cmake --build . --target all
```

## View Program Options

```console
$ ./ubiq_sample_fpe-c -h

$ ./ubiq_sample_fpe-c++ -h
```

```console
Encrypt or decrypt data using the Ubiq eFPE service

  -h                       Show this help message and exit
  -V                       Show program's version number and exit
  -e INPUT                 Encrypt the supplied input string
                             escape or use quotes if input string
                             contains special characters
  -d INPUT                 Decrypt the supplied input string
                             escape or use quotes if input string
                             contains special characters
  -s                       Use the simple eFPE encryption / decryption interfaces
  -b                       Use the bulk eFPE encryption / decryption interfaces
  -n FFS                   Use the supplied Field Format Specification
  -c CREDENTIALS           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE               Identify the profile within the credentials file
```



#### Demonstrate encrypting a social security number and returning a cipher text

```console
$ ./ubiq_sample_fpe-c -e '123-45-6789' -n ALPHANUM_SSN -s
```

#### Demonstrate decrypting a social security number and returning the plain text

```console
$ ./ubiq_sample_fpe-c -d 'W#]-iV-`,"j' -n ALPHANUM_SSN -s
```
