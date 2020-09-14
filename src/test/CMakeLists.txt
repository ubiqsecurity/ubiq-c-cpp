set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
add_subdirectory(googletest)

add_executable(
  unittests

  credentials.cpp
  decrypt.cpp
  encrypt.cpp
  global.cpp
  request.cpp)
target_link_libraries(
  unittests
  ubiqclient++ gtest_main)

add_custom_target(
  run_tests
  COMMAND unittests
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
