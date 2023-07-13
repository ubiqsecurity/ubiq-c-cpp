set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(googletest)

add_executable(
  unittests

  cache.cpp
  credentials.cpp
  configuration.cpp
  decrypt.cpp
  encrypt.cpp
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

target_link_directories(
   unittests
   PUBLIC ${CMAKE_BINARY_DIR}/fpe/src)
target_link_libraries(
  unittests
  ubiqclient++-static gtest gtest_main ubiqfpe.a)

target_include_directories(
  test_performance
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/ubiq-fpe-c/src/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext)

target_link_directories(
   test_performance
   PUBLIC ${CMAKE_BINARY_DIR}/fpe/src)
target_link_libraries(
  test_performance
  ubiqclient++-static pthread ubiqfpe.a)

  
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
endif()

target_link_libraries(
    unittests
    unistring)

target_link_libraries(
    test_performance
    unistring)


add_custom_target(
  run_tests
  COMMAND unittests
  COMMAND test_performance
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DATA/1m.json 1m.json COPYONLY)
