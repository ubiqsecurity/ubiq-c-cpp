cmake_minimum_required(VERSION 3.10)
project(
  libubiqclient
  VERSION 0.3.0.0
  LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

set(UBIQ_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(src)
