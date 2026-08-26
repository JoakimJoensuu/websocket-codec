cmake_minimum_required(VERSION 3.21)
project(wsc LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(CREATE_LINK "${CMAKE_BINARY_DIR}/compile_commands.json"
     "${CMAKE_SOURCE_DIR}/compile_commands.json" SYMBOLIC COPY_ON_ERROR)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_library(wsc_warnings INTERFACE)
target_compile_options(
  wsc_warnings
  INTERFACE -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wformat=2
            -Wmissing-prototypes
            -Wshadow
            -Wstrict-prototypes)

option(WSC_SANITIZE "Build with ASan/UBSan" OFF)
if(WSC_SANITIZE)
  target_compile_options(wsc_warnings INTERFACE -fsanitize=address,undefined
                                                -fno-omit-frame-pointer)
  target_link_options(wsc_warnings INTERFACE -fsanitize=address,undefined)
endif()

add_library(wsc src/wsc.c)
target_include_directories(
  wsc PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
             $<INSTALL_INTERFACE:include>)
target_link_libraries(wsc PRIVATE wsc_warnings)

option(WSC_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(WSC_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})

if(WSC_EXAMPLES)
  add_executable(hello examples/hello.c)
  target_link_libraries(hello PRIVATE wsc wsc_warnings)
endif()

if(WSC_TESTS)
  include(CTest)
  add_executable(test_wsc tests/test_wsc.c)
  target_link_libraries(test_wsc PRIVATE wsc wsc_warnings)
  add_test(NAME test_wsc COMMAND test_wsc)
  if(WSC_EXAMPLES)
    add_test(NAME hello COMMAND hello)
  endif()
endif()

install(TARGETS wsc EXPORT wscTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/wsc.h DESTINATION include)
