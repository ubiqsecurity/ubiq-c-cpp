cmake_minimum_required(VERSION 3.10)

project(
  ubiq_sample
  VERSION 0.2.0.0
  LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/common.c
  PROPERTIES
  COMPILE_FLAGS -DUBIQ_SAMPLE_VERSION=\\\"${PROJECT_VERSION}\\\")

add_library(
  ubiq_sample-common
  OBJECT
  common.c)
target_compile_definitions(
  ubiq_sample-common
  PRIVATE
  _CRT_SECURE_NO_WARNINGS)

add_executable(
  ubiq_sample-c

  ubiq_sample.c
  $<TARGET_OBJECTS:ubiq_sample-common>
)
target_compile_definitions(
  ubiq_sample-c
  PRIVATE
  _CRT_SECURE_NO_WARNINGS)

target_link_libraries(
  ubiq_sample-c
  ubiqclient)

add_executable(
  ubiq_sample-c++

  ubiq_sample.cpp
  $<TARGET_OBJECTS:ubiq_sample-common>
)
target_compile_definitions(
  ubiq_sample-c++
  PRIVATE
  _CRT_SECURE_NO_WARNINGS)
target_link_libraries(
  ubiq_sample-c++
  ubiqclient++)


add_executable(
  ubiq_sample_fpe-c

  ubiq_sample_fpe.c
  $<TARGET_OBJECTS:ubiq_sample-common>
)
target_compile_definitions(
  ubiq_sample_fpe-c
  PRIVATE
  _CRT_SECURE_NO_WARNINGS)

target_link_libraries(
  ubiq_sample_fpe-c
  ubiqclient)

add_executable(
  ubiq_sample_fpe-c++

  ubiq_sample_fpe.cpp
  $<TARGET_OBJECTS:ubiq_sample-common>
)
target_compile_definitions(
  ubiq_sample_fpe-c++
  PRIVATE
  _CRT_SECURE_NO_WARNINGS)
target_link_directories(
  ubiq_sample_fpe-c++
  PUBLIC ${CMAKE_BINARY_DIR}/fpe/src)
target_link_libraries(
  ubiq_sample_fpe-c++
  ubiqclient++ )


# Copy the Credentials file from the source directory to the
# target directory if necessary. Do not copy the file if the
# file has been updated by the user.
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/credentials credentials COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/README.md README.md COPYONLY)
