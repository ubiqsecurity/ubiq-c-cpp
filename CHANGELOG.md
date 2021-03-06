# Changelog

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
