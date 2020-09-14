set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/src/ext/inih/ini.c
  PROPERTIES
  COMPILE_FLAGS -DINI_ALLOW_MULTILINE=0)

set_source_files_properties(
  init.c
  PROPERTIES
  COMPILE_FLAGS -DUBIQ_PLATFORM_USER_AGENT=\\\"ubiq-c/${PROJECT_VERSION}\\\")

add_library(
  c_objects

  OBJECT

  algorithm.c
  credentials.c
  decrypt.c
  encrypt.c
  init.c
  request.c
  ${CMAKE_SOURCE_DIR}/src/ext/cJSON/cJSON.c
  ${CMAKE_SOURCE_DIR}/src/ext/inih/ini.c)
target_include_directories(
  c_objects
  PRIVATE
  ${CMAKE_SOURCE_DIR}/src/include
  ${CMAKE_SOURCE_DIR}/src/ext)
set_target_properties(
  c_objects
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON)

set_source_files_properties(
  init.cpp
  PROPERTIES
  COMPILE_FLAGS -DUBIQ_PLATFORM_USER_AGENT=\\\"ubiq-c++/${PROJECT_VERSION}\\\")

add_library(
  cxx_objects

  OBJECT

  credentials.cpp
  decrypt.cpp
  encrypt.cpp
  init.cpp)
target_include_directories(
  cxx_objects
  PRIVATE
  ${CMAKE_SOURCE_DIR}/src/include)
set_target_properties(
  cxx_objects
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON)
