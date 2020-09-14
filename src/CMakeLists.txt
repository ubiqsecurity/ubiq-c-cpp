include(GNUInstallDirs)

function(strip_target TARGET)
  set(CMAKE_STRIP_COMMAND /usr/bin/strip)

  if(CMAKE_BUILD_TYPE STREQUAL Release OR
      CMAKE_BUILD_TYPE STREQUAL MinSizeRel)
    add_custom_command(
      TARGET ${TARGET} POST_BUILD
      COMMAND ${CMAKE_STRIP_COMMAND} $<TARGET_FILE:${TARGET}>)
  endif()
endfunction(strip_target)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ubiq
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE
                   GROUP_READ
                   WORLD_READ
  DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                        GROUP_READ GROUP_EXECUTE
                        WORLD_READ WORLD_EXECUTE
  COMPONENT development
  PATTERN "internal" EXCLUDE)

# c static library
add_library(
  ubiqclient-static
  STATIC
  $<TARGET_OBJECTS:c_objects>)
set_target_properties(
  ubiqclient-static
  PROPERTIES
  OUTPUT_NAME ubiqclient)
target_include_directories(
  ubiqclient-static
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
strip_target(ubiqclient-static)
install(
  TARGETS ubiqclient-static
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE
              GROUP_READ
              WORLD_READ
  COMPONENT runtime)

# c shared library
add_library(
  ubiqclient
  SHARED
  $<TARGET_OBJECTS:c_objects>)
set_target_properties(
  ubiqclient
  PROPERTIES
  VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
target_include_directories(
  ubiqclient
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(
  ubiqclient
  curl crypto)
strip_target(ubiqclient)
install(
  TARGETS ubiqclient
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
              GROUP_READ GROUP_EXECUTE
              WORLD_READ WORLD_EXECUTE
  COMPONENT runtime)

# c++ static library
add_library(
  ubiqclient++-static
  STATIC
  $<TARGET_OBJECTS:c_objects>
  $<TARGET_OBJECTS:cxx_objects>)
set_target_properties(
  ubiqclient++-static
  PROPERTIES
  OUTPUT_NAME ubiqclient++)
target_include_directories(
  ubiqclient++-static
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
strip_target(ubiqclient++-static)
install(
  TARGETS ubiqclient++-static
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE
              GROUP_READ
              WORLD_READ
  COMPONENT runtime)

# c++ shared library
add_library(
  ubiqclient++
  SHARED
  $<TARGET_OBJECTS:c_objects>
  $<TARGET_OBJECTS:cxx_objects>)
set_target_properties(
  ubiqclient++
  PROPERTIES
  VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
target_include_directories(
  ubiqclient++
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(
  ubiqclient++
  curl crypto)
strip_target(ubiqclient++)
install(
  TARGETS ubiqclient++
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
              GROUP_READ GROUP_EXECUTE
              WORLD_READ WORLD_EXECUTE
  COMPONENT runtime)

add_subdirectory(lib)
add_subdirectory(test)
add_subdirectory(examples)

target_include_directories(
  ubiq_sample-common
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(
  ubiq_sample-c
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(
  ubiq_sample-c++
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/examples
  DESTINATION ${CMAKE_INSTALL_DOCDIR}-dev
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE
                   GROUP_READ
                   WORLD_READ
  DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                        GROUP_READ GROUP_EXECUTE
                        WORLD_READ WORLD_EXECUTE
  COMPONENT development)

set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_STRIP_FILES ON)

set(CPACK_GENERATOR DEB)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ubiq Security <support@ubiqsecurity.com>")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "")
set(CPACK_PACKAGE_DESCRIPTION "")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
  "C and C++ client libraries for the Ubiq Platform")

set(CPACK_COMPONENTS_ALL development runtime)

set(CPACK_DEBIAN_DEVELOPMENT_PACKAGE_NAME libubiqclient-dev)
set(CPACK_DEBIAN_DEVELOPMENT_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_DEVELOPMENT_PACKAGE_DEPENDS libubiqclient)
set(CPACK_DEBIAN_DEVELOPMENT_PACKAGE_SECTION libdevel)
set(CPACK_DEBIAN_DEVELOPMENT_DESCRIPTION
  "This package includes support files for C and C++ development")

set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME libubiqclient)
set(CPACK_DEBIAN_RUNTIME_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_RUNTIME_PACKAGE_SECTION libs)
set(CPACK_DEBIAN_RUNTIME_DESCRIPTION
  "This package includes the static and shared libraries")

include(CPack)
