
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
  convert_radix_operation.c
  credentials.c
  configuration.c
  dataset.c
  dataset_cache.c
  decrypt.c
  decrypt_operation.c
  decryption_pipeline.c
  decode_input_operation.c
  decode_key_number_operation.c
  encode_input_operation.c
  encode_key_number_operation.c
  encrypt.c
  encrypt_operation.c
  encryption_pipeline.c
  expand_passthrough_characters_operation.c
  expand_passthrough_prefix_operation.c
  expand_passthrough_suffix_operation.c
  ff1.c
  ff1_cache.c
  ffx.c
  deprecated_fpe.c
  structured_new.c
  hashtable.c
  hashtable32.c
  init.c
  operation_context.c
  pad_input_operation.c
  parsing.c
  rest.c
  rsa.c
  sso.c
  structured_key_cache.c
  structured_pipeline.c
  support.c
  trim_passthrough_characters_operation.c
  trim_passthrough_prefix_operation.c
  trim_passthrough_suffix_operation.c
  unpad_input_operation.c
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
    -O0
    -g)
   
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
  encrypt_session.cpp
  decrypt_session.cpp
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
    -O0
    -g)
    
endif()
target_include_directories(
  cxx_objects
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext
  ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set_target_properties(
  cxx_objects
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON)
