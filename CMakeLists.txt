cmake_minimum_required(VERSION 3.16)
project(sws C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

include(FetchContent)
set(CGREEN_WITH_UNIT_TESTS OFF CACHE BOOL "" FORCE)
set(CGREEN_WITH_XML OFF CACHE BOOL "" FORCE)
set(CGREEN_WITH_LIBXML2 OFF CACHE BOOL "" FORCE)
set(CGREEN_WITH_STATIC_LIBRARY ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  cgreen
  GIT_REPOSITORY https://github.com/cgreen-devs/cgreen.git
  GIT_TAG 1.6.4
  GIT_SHALLOW TRUE
)
FetchContent_GetProperties(cgreen)
if(NOT cgreen_POPULATED)
  FetchContent_Populate(cgreen)
  add_subdirectory(${cgreen_SOURCE_DIR} ${cgreen_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

add_library(sws src/sws.c src/sws_utf8.c)
target_include_directories(sws PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(sws PRIVATE src)
target_compile_options(sws PRIVATE -Wall -Wextra -Wpedantic)

add_executable(test_sws tests/test_sws.c)
target_include_directories(test_sws PRIVATE ${cgreen_SOURCE_DIR}/include)
target_link_libraries(test_sws PRIVATE sws cgreen_static)
target_compile_options(test_sws PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(test_sws PROPERTIES LINKER_LANGUAGE CXX)

add_executable(hello examples/hello.c)
target_link_libraries(hello PRIVATE sws)
target_compile_options(hello PRIVATE -Wall -Wextra -Wpedantic)

add_executable(echo_server examples/echo_server.c)
target_link_libraries(echo_server PRIVATE sws)
target_compile_options(echo_server PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
add_test(NAME unit COMMAND test_sws)
add_test(NAME hello COMMAND hello)
add_test(NAME smoke_echo COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/smoke_echo.py)
set_tests_properties(smoke_echo PROPERTIES
  ENVIRONMENT "ECHO_SERVER=$<TARGET_FILE:echo_server>;PORT=19001")

install(TARGETS sws EXPORT swsTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/sws.h DESTINATION include)

option(SWS_SANITIZE "Build with ASan/UBSan" OFF)
if(SWS_SANITIZE)
  foreach(tgt sws test_sws hello echo_server)
    target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()
