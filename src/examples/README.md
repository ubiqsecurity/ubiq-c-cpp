# Ubiq Security Sample Application using C/C++ Library

This sample application will demonstrate how to encrypt and decrypt data using the different APIs.

### Documentation

See the [C/C++ API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Make sure to first install the ubiq-security library and development headers from [Releases](https://gitlab.com/ubiqsecurity/ubiq-c-cpp/-/releases)

```sh
$ sudo apt install ./libubiqclient_<version>_<arch>.deb
$ sudo apt install ./libubiqclient-dev_<version>_<arch>.deb
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

<pre>
[default]
ACCESS_KEY_ID = ...  
SECRET_SIGNING_KEY = ...  
SECRET_CRYPTO_ACCESS_KEY = ...  
</pre>

## Build the examples

Create a local directory and compile the example application

```sh
$ mkdir ~/ubiq_sample
$ cd ~/ubiq_sample
$ cmake /usr/share/doc/libubiqclient-dev/examples
$ cmake --build . --target all
```

## View Program Options

From within the examples directory

```sh
$ ./ubiq_sample-c -h
```
<pre>
Encrypt or decrypt files using the Ubiq service

  -h, --help               Show this help message and exit
  -V, --version            Show program's version number and exit
  -e, --encrypt            Encrypt the contents of the input file and write
                             the results to the output file
  -d, --decrypt            Decrypt the contents of the input file and write
                             the results to the output file
  -s, --simple             Use the simple encryption / decryption interfaces
  -p, --pieceswise         Use the piecewise encryption / decryption interfaces
  -i INFILE, --in INFILE   Set input file name
  -o OUTFILE, --out OUTFILE
                           Set output file name
  -c CREDENTIALS, --creds CREDENTIALS
                           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE, --profile PROFILE
                           Identify the profile within the credentials file
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ ./ubiq_sample-c -i /usr/share/doc/libubiqclient-dev/examples/README.md -o /tmp/readme.enc -e -s -c ./credentials 
```

#### Demonstrate using the simple (-s / --simple) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ ./ubiq_sample-c -i /tmp/readme.enc -o /tmp/README.out -d -s -c ./credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ ./ubiq_sample-c -i /usr/share/doc/libubiqclient-dev/examples/README.md -o /tmp/readme.enc -e -p -c ./credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ ./ubiq_sample-c -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials
```

##### _All of the above commands can be used with the C++ example by subsituting `ubiq_sample-c` with `ubiq_sample-c++`_
