set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/inih/ini.c
  PROPERTIES
  COMPILE_DEFINITIONS INI_ALLOW_MULTILINE=0)

set_source_files_properties(
  init.c
  PROPERTIES
  COMPILE_DEFINITIONS
  UBIQ_PLATFORM_USER_AGENT=\"ubiq-c/${PROJECT_VERSION}\")

add_library(
  c_objects

  OBJECT

  algorithm.c
  common.c
  credentials.c
  decrypt.c
  encrypt.c
  init.c
  parsing.c
  rest.c
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

set_source_files_properties(
  init.cpp
  PROPERTIES
  COMPILE_DEFINITIONS
  UBIQ_PLATFORM_USER_AGENT=\"ubiq-c++/${PROJECT_VERSION}\")

add_library(
  cxx_objects

  OBJECT

  credentials.cpp
  decrypt.cpp
  encrypt.cpp
  init.cpp)
if(WIN32)
  target_compile_definitions(
    cxx_objects
    PRIVATE
    DLL_EXPORT)
endif()
target_include_directories(
  cxx_objects
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set_target_properties(
  cxx_objects
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON)
