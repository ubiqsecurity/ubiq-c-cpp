set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(googletest)

add_executable(
  unittests

  bn.cpp
  cache.cpp
  credentials.cpp
  configuration.cpp
  decrypt.cpp
  encrypt.cpp
  ff1.cpp
  ff3_1.cpp
  ffx.cpp
  fpedecrypt.cpp
  fpeencrypt.cpp
  fpeencrypt_new.cpp
  global.cpp
  hashtable.cpp
  parsing.cpp
  request.cpp)
# link against the static libraries which avoids
# having to export certain internal interfaces
# on windows to make them available for testing

add_executable(
  test_performance
  
  test_harness_helper.cpp
  test_harness.cpp)

add_executable(
  test_performance_c
  
  test_harness_helper.cpp
  test_harness-c.cpp)
  
target_link_libraries(
  unittests
  ubiqclient++-static gtest gtest_main)

target_include_directories(
  test_performance
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext)

target_link_libraries(
  test_performance
  ubiqclient++-static pthread)

target_include_directories(
  test_performance_c
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext)

target_link_libraries(
  test_performance_c
  ubiqclient++-static pthread)

  
if(WIN32)
  target_compile_definitions(
    unittests
    PRIVATE
    STATIC_IMPORT)
  target_link_libraries(
    unittests
    ws2_32 userenv winhttp bcrypt crypt32)
else()
  target_link_libraries(
    unittests
    curl crypto gmp)

  target_link_libraries(
    test_performance
    curl crypto gmp)

  target_link_libraries(
    test_performance_c
    curl crypto gmp)
  
endif()

target_link_libraries(
    unittests
    unistring)

target_link_libraries(
    test_performance
    unistring)

target_link_libraries(
  test_performance_c
  unistring)
  
add_custom_target(
  run_tests
  COMMAND unittests
  COMMAND test_performance_c
  COMMAND test_performance
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DATA/1m.json 1m.json COPYONLY)
