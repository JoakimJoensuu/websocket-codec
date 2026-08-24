cmake_minimum_required(VERSION 3.21)
project(wsc C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BINARY_DIR STREQUAL CMAKE_SOURCE_DIR)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
      "${CMAKE_BINARY_DIR}/compile_commands.json"
      "${CMAKE_SOURCE_DIR}/compile_commands.json")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_library(wsc src/wsc.c)
target_include_directories(wsc PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_options(wsc PRIVATE -Wall -Wextra -Wpedantic)

add_executable(hello examples/hello.c)
target_link_libraries(hello PRIVATE wsc)
target_compile_options(hello PRIVATE -Wall -Wextra -Wpedantic)

add_executable(test_wsc tests/test_wsc.c)
target_link_libraries(test_wsc PRIVATE wsc)
target_compile_options(test_wsc PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
add_test(NAME hello COMMAND hello)
add_test(NAME test_wsc COMMAND test_wsc)

install(TARGETS wsc EXPORT wscTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/wsc.h DESTINATION include)

option(WSC_SANITIZE "Build with ASan/UBSan" OFF)
if(WSC_SANITIZE)
  foreach(tgt wsc hello test_wsc)
    target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()
