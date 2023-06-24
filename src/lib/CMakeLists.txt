MACRO (CHECK_GLIBC_VERSION)
    EXECUTE_PROCESS (
        COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.so.6
	OUTPUT_VARIABLE GLIBC
	OUTPUT_STRIP_TRAILING_WHITESPACE)

    GET_FILENAME_COMPONENT (GLIBC ${GLIBC} REALPATH)
    GET_FILENAME_COMPONENT (GLIBC_VERSION ${GLIBC} NAME)
    STRING (REPLACE "libc-" "" GLIBC_VERSION ${GLIBC_VERSION})
    STRING (REPLACE ".so" "" GLIBC_VERSION ${GLIBC_VERSION})
    IF (NOT GLIBC_VERSION MATCHES "^[0-9.]+$")
        MESSAGE (FATAL_ERROR "Unknown glibc version: ${GLIBC_VERSION}")
    ENDIF (NOT GLIBC_VERSION MATCHES "^[0-9.]+$")
ENDMACRO (CHECK_GLIBC_VERSION)

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
  billing.c
  cache.c
  common.c
  credentials.c
  configuration.c
  decrypt.c
  encrypt.c
  fpe.c
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

  target_compile_options(
    c_objects
    PUBLIC
    -O2)
   
endif()

target_include_directories(
  c_objects
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/ubiq-fpe-c/src/include
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

# If the glib version is less than 2.30, then TWALK_R does not exist
# so we need to suppress TWALK_R by a NOP function
CHECK_GLIBC_VERSION()

string(REGEX MATCH "^[0-9].[012][0-9]*$" SUPPRESS_TWALK_R ${GLIBC_VERSION})

IF (SUPPRESS_TWALK_R)
  set_property(
    SOURCE cache.c
    APPEND
    PROPERTY COMPILE_DEFINITIONS
    SUPPRESS_TWALK_R=\"${SUPPRESS_TWALK_R}\")
ENDIF()



add_library(
  cxx_objects

  OBJECT

  credentials.cpp
  configuration.cpp
  decrypt.cpp
  encrypt.cpp
  fpe_encrypt.cpp
  fpe_decrypt.cpp
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
