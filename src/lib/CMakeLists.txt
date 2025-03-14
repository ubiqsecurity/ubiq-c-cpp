
set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/inih/ini.c
  PROPERTIES
  COMPILE_DEFINITIONS INI_ALLOW_MULTILINE=0)


set_property(
  SOURCE init.c
  APPEND
  PROPERTY COMPILE_DEFINITIONS
  UBIQ_PLATFORM_USER_AGENT=\"ubiq-c/${PROJECT_VERSION}\"
  UBIQ_VERSION=\"${PROJECT_VERSION}\"
  UBIQ_PRODUCT=\"ubiq-c\")

add_library(
  c_objects

  OBJECT

  algorithm.c
  bn.c
  billing.c
  builder.c
  cache.c
  common.c
  credentials.c
  configuration.c
  decrypt.c
  encrypt.c
  ff1.c
  ffx.c
  deprecated_fpe.c
  structured.c
  hashtable.c
  init.c
  parsing.c
  rest.c
  rsa.c
  sso.c
  support.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/cJSON/cJSON.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/inih/ini.c)

if(WIN32)
  # silence warnings about "more secure"
  # alternative functions on windows
  #
  # silence warnings about ISO conformant names
  target_compile_definitions(
    c_objects
    PRIVATE
    DLL_EXPORT
    _CRT_SECURE_NO_WARNINGS
    strdup=_strdup
    strcasecmp=_stricmp)
  target_sources(
    c_objects

    PRIVATE

    wincrypt.c
    winhttp.c)
else()
  target_sources(
    c_objects

    PRIVATE

    curl.c
    openssl.c)

  target_compile_options(
    c_objects
    PUBLIC
    -O2)
   
endif()

target_include_directories(
  c_objects
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext)
set_target_properties(
  c_objects
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON)

  set_property(
    SOURCE init.cpp
    APPEND
    PROPERTY COMPILE_DEFINITIONS
    UBIQ_PLATFORM_USER_AGENT=\"ubiq-c++/${PROJECT_VERSION}\"
    UBIQ_VERSION=\"${PROJECT_VERSION}\"
    UBIQ_PRODUCT=\"ubiq-c++\")




add_library(
  cxx_objects

  OBJECT

  builder.cpp
  credentials.cpp
  configuration.cpp
  decrypt.cpp
  encrypt.cpp
  deprecated_encrypt.cpp
  deprecated_decrypt.cpp
  structured_encrypt.cpp
  structured_decrypt.cpp
  init.cpp)
if(WIN32)
  target_compile_definitions(
    cxx_objects
    PRIVATE
    DLL_EXPORT)
else()
  target_compile_options(
    cxx_objects
    PUBLIC
    -O2)
    
endif()
target_include_directories(
  cxx_objects
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set_target_properties(
  cxx_objects
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON)
