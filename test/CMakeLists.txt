# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT

# Get rid of: warning C4530: C++ exception handler used, but unwind semantics are not enabled. Specify /EHsc
IF (MSVC)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
ENDIF ()

find_package(Threads)
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

IF (CMAKE_VERSION VERSION_LESS "3.23.0")
  Message("GoogleTest found, cmake version too old to verify GMock, look for errors...")
ELSE ()
  IF (NOT TARGET GTest::gmock)
    Message(FATAL_ERROR "GoogleTest found but the GMock component was not found")
  ENDIF()
ENDIF()

# create target to access and use internal cci library
add_library(cciinternal INTERFACE)
target_compile_definitions(cciinternal INTERFACE HAVE_CONFIG_H=1)

target_include_directories(cciinternal
   INTERFACE "${PROJECT_BINARY_DIR}"
             "${PROJECT_BINARY_DIR}/src/lib"
             "${PROJECT_SOURCE_DIR}"
             "${PROJECT_SOURCE_DIR}/src/lib"
             "${PROJECT_SOURCE_DIR}/src/lib/include"
             "${PROJECT_SOURCE_DIR}/include"
)

IF (CI_STATIC)
  target_link_libraries(cciinternal INTERFACE ${PROJECT_NAME}::cci_static)
ELSE ()
  target_link_libraries(cciinternal INTERFACE ${PROJECT_NAME}::cci)
ENDIF ()

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

add_executable(citest ${TESTSOURCES} ${TESTHEADERS})
target_include_directories(citest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
IF (CMAKE_VERSION VERSION_LESS "3.23.0")
  FIND_LIBRARY(LIBGMOCK NAMES gmock PATHS ${GTEST_ROOT} PATH_SUFFIXES lib)
  IF (LIBGMOCK-NOTFOUND)
    MESSAGE(FATAL_ERROR "Could not find Gmock")
  ENDIF ()
  target_link_libraries(citest PRIVATE cciinternal GTest::GTest ${LIBGMOCK})
ELSE ()
  target_link_libraries(citest PRIVATE cciinternal GTest::gmock)
ENDIF()
target_compile_definitions(citest PRIVATE CI_NO_DEPRECATED)

IF (CI_BUILD_CONTAINER_TESTS)
  target_compile_definitions(citest PRIVATE HAVE_USER_NAMESPACE HAVE_UTS_NAMESPACE)
ENDIF ()
# Avoid "fatal error C1041: cannot open program database" due to multiple
# targets trying to use the same PDB.  /FS does NOT resolve this issue.
set_target_properties(citest PROPERTIES COMPILE_PDB_NAME citest.pdb)

add_executable(cifuzz ${FUZZSOURCES})
target_compile_definitions(cifuzz PRIVATE CI_NO_DEPRECATED)
target_link_libraries(cifuzz PRIVATE cciinternal)
# Avoid "fatal error C1041: cannot open program database" due to multiple
# targets trying to use the same PDB.  /FS does NOT resolve this issue.
set_target_properties(cifuzz PROPERTIES COMPILE_PDB_NAME cifuzz.pdb)

add_executable(cifuzzname ${FUZZNAMESOURCES})
target_compile_definitions(cifuzzname PRIVATE CI_NO_DEPRECATED)
target_link_libraries(cifuzzname PRIVATE cciinternal)
# Avoid "fatal error C1041: cannot open program database" due to multiple
# targets trying to use the same PDB.  /FS does NOT resolve this issue.
set_target_properties(cifuzzname PROPERTIES COMPILE_PDB_NAME cifuzzname.pdb)

add_executable(dnsdump ${DUMPSOURCES})
target_compile_definitions(dnsdump PRIVATE CI_NO_DEPRECATED)
target_link_libraries(dnsdump PRIVATE cciinternal)
# Avoid "fatal error C1041: cannot open program database" due to multiple
# targets trying to use the same PDB.  /FS does NOT resolve this issue.
set_target_properties(dnsdump PROPERTIES COMPILE_PDB_NAME dnsdump.pdb)

add_executable(ci_queryloop ${LOOPSOURCES})
target_compile_definitions(ci_queryloop PRIVATE CI_NO_DEPRECATED)
target_link_libraries(ci_queryloop PRIVATE cciinternal)
# Avoid "fatal error C1041: cannot open program database" due to multiple
# targets trying to use the same PDB.  /FS does NOT resolve this issue.
set_target_properties(ci_queryloop PROPERTIES COMPILE_PDB_NAME ci_queryloop.pdb)




# register tests

add_test(NAME citest COMMAND $<TARGET_FILE:citest>)

file(GLOB_RECURSE FUZZINPUT_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/fuzzinput" "fuzzinput/*")
add_test(
  NAME cifuzz
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzzinput"
  COMMAND $<TARGET_FILE:cifuzz> ${FUZZINPUT_FILES}
)

file(GLOB_RECURSE FUZZNAMES_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/fuzznames" "fuzznames/*")
add_test(
  NAME cifuzzname
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzznames"
  COMMAND $<TARGET_FILE:cifuzzname> ${FUZZNAMES_FILES}
)
