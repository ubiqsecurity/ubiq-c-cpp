# Changelog

## 2.2.2.0 - 2025-01-22
* Added support for IDP integration using Okta and Entra
* Added builder design pattern for creating both
  encryption and decryption objects for either structured or unstructured data elements

## 2.2.1.0 - 2024-10-02
* Key caching improvement for unstructured decryption
* Key caching options got structured encryption / decryption
* Deprecated simple interfaces for structured encryption
* Updated exception handling and updated README documentation
* Updated README code samples

## 2.2.0.0 - 2024-04-17
* Added support for partial encryption datasets which allow data to be left in the clear after encryption.

## 2.1.2.0 - 2024-02-13
* Bugfix for usage tracking

## 2.1.1.0 - 2024-02-01
* Incorporated files from ubiq-fpe-c repo directly into this repo
* Removed ff3-1 related files

## 2.1.0.0 - 2024-01-04
* Added functions to support user defined metadata in the billing events
* Added support for different granular levels of timestamps when reporting usage

## 2.0.5.0 - 2023-09-17
* fix typo in README
* Changed google test submodule version to support debian 12 (bookworm)

## 2.0.4.0 - 2023-07-25
* Added APIs to support pre-allocated output buffers

## 2.0.3.0 - 2023-06-29
* Data caching optimization

## 2.0.2.0 - 2023-06-14
* Optimizations for Encrypt For Search algorithms

## 2.0.1.0 - 2023-05-17
* Standardize unit tests across different languages
* Fix memory leak

## 2.0.0.0 - 2023-04-19
* FPE and usage reporting optimizations

## 0.4.5.0 - 2022-06-23
* Improved FPE Algorithm

## 0.4.4.0 - 2022-05-03
* Add encrypt_for_search capabilities

## 0.4.3.0 - 2022-02-23
* Add full support for UTF-8 strings for (e)FPE

## 0.4.2.0 - 2021-10-12
* Improve error handling / reporting

## 0.4.1.0 - 2021-10-05
* Changed reference to the ubiq-fpe-c submodule

## 0.4.0.0 - 2021-10-05
* Added support for Format Preserving Encryption, FPE

## 0.3.0.0 - 2021-01-18
* Fix bug causing wrong credentials to be loaded when no profile is specified
* Modify default credentials constructor to allow environment to override,
  existing code did not operate as documented
* Remove requirement for specific "test" credentials in unit tests
* Add CI pipelines to build and test library
* Add build and deployment of Docker container containing sample applications

## 0.2.0.0 - 2020-11-13
* Add support for Windows clients

## 0.1.1.2 - 2020-10-28
* Change to MIT license

## 0.1.1.1 - 2020-10-19
* Add infrastructure to build packages in Docker container
* Create credentials file in the example build directory

## 0.1.1.0 - 2020-09-24
* Made error values more consistent across the library
* Added documentation of library initialization and error values
* Simplified examples

## 0.1.0.0 - 2020-09-24
* Added AAD information to ciphers for encrypt and decrypt

## 0.0.2.0 - 2020-09-16
* Fix key length header during decryption

## 0.0.1.1 - 2020-09-14
* Bug fix related to optimizer

## 0.0.1.0 - 2020-09-14
* Initial Version
