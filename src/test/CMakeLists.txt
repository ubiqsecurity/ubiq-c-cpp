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
  parsing.cpp
  request.cpp)
# link against the static libraries which avoids
# having to export certain internal interfaces
# on windows to make them available for testing

target_link_directories(
   unittests
   PUBLIC ${CMAKE_BINARY_DIR}/fpe/src)
target_link_libraries(
  unittests
  ubiqclient++-static gtest gtest_main ubiqfpe.a)
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
endif()

target_link_libraries(
    unittests
    unistring)

add_custom_target(
  run_tests
  COMMAND unittests
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
