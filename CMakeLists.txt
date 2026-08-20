cmake_minimum_required(VERSION 3.16)
project(swsf C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

include(FetchContent)
FetchContent_Declare(
  cgreen
  GIT_REPOSITORY https://github.com/cgreen-devs/cgreen.git
  GIT_TAG 1.6.4
  GIT_SHALLOW TRUE
)
FetchContent_GetProperties(cgreen)
if(NOT cgreen_POPULATED)
  FetchContent_Populate(cgreen)
endif()

# Cgreen's own CMake also builds C++ (cpp_assertions.cpp). Compile the C
# sources only so this C99 project does not need a C++ toolchain.
file(WRITE "${cgreen_BINARY_DIR}/config.h" "/* generated for swsf tests */\n")
file(WRITE "${cgreen_SOURCE_DIR}/gitrevision.h"
  "#define GITREVISION \"1.6.4\"\n")

add_library(cgreen_static STATIC
  ${cgreen_SOURCE_DIR}/src/assertions.c
  ${cgreen_SOURCE_DIR}/src/boxed_double.c
  ${cgreen_SOURCE_DIR}/src/breadcrumb.c
  ${cgreen_SOURCE_DIR}/src/cdash_reporter.c
  ${cgreen_SOURCE_DIR}/src/cgreen_time.c
  ${cgreen_SOURCE_DIR}/src/cgreen_value.c
  ${cgreen_SOURCE_DIR}/src/constraint.c
  ${cgreen_SOURCE_DIR}/src/cute_reporter.c
  ${cgreen_SOURCE_DIR}/src/message_formatting.c
  ${cgreen_SOURCE_DIR}/src/messaging.c
  ${cgreen_SOURCE_DIR}/src/mocks.c
  ${cgreen_SOURCE_DIR}/src/parameters.c
  ${cgreen_SOURCE_DIR}/src/posix_cgreen_pipe.c
  ${cgreen_SOURCE_DIR}/src/posix_cgreen_time.c
  ${cgreen_SOURCE_DIR}/src/posix_runner_platform.c
  ${cgreen_SOURCE_DIR}/src/reporter.c
  ${cgreen_SOURCE_DIR}/src/runner.c
  ${cgreen_SOURCE_DIR}/src/string_comparison.c
  ${cgreen_SOURCE_DIR}/src/suite.c
  ${cgreen_SOURCE_DIR}/src/text_reporter.c
  ${cgreen_SOURCE_DIR}/src/utils.c
  ${cgreen_SOURCE_DIR}/src/vector.c)
target_include_directories(cgreen_static
  PUBLIC ${cgreen_SOURCE_DIR}/include
  PRIVATE ${cgreen_SOURCE_DIR} ${cgreen_SOURCE_DIR}/src ${cgreen_BINARY_DIR})
target_compile_definitions(cgreen_static PRIVATE VERSION="1.6.4")
find_package(Threads REQUIRED)
target_link_libraries(cgreen_static PUBLIC Threads::Threads m)

add_library(swsf src/swsf.c src/utf8.c)
target_include_directories(swsf PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(swsf PRIVATE src)
target_compile_options(swsf PRIVATE -Wall -Wextra -Wpedantic)

add_executable(test_swsf tests/test_swsf.c)
target_link_libraries(test_swsf PRIVATE swsf cgreen_static)
target_compile_options(test_swsf PRIVATE -Wall -Wextra -Wpedantic)

add_executable(hello examples/hello.c)
target_link_libraries(hello PRIVATE swsf)
target_compile_options(hello PRIVATE -Wall -Wextra -Wpedantic)

add_executable(threaded examples/threaded.c)
target_link_libraries(threaded PRIVATE swsf Threads::Threads)
target_compile_options(threaded PRIVATE -Wall -Wextra -Wpedantic)

add_executable(echo_server examples/echo_server.c)
target_link_libraries(echo_server PRIVATE swsf)
target_compile_options(echo_server PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
add_test(NAME unit COMMAND test_swsf)
add_test(NAME hello COMMAND hello)
add_test(NAME threaded COMMAND threaded)
set_tests_properties(threaded PROPERTIES TIMEOUT 15)
add_test(NAME smoke_echo COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/smoke_echo.py)
set_tests_properties(smoke_echo PROPERTIES
  ENVIRONMENT "ECHO_SERVER=$<TARGET_FILE:echo_server>;PORT=19001")

install(TARGETS swsf EXPORT swsfTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/swsf.h DESTINATION include)

option(SWSF_SANITIZE "Build with ASan/UBSan" OFF)
if(SWSF_SANITIZE)
  foreach(tgt swsf test_swsf hello threaded echo_server)
    target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()
