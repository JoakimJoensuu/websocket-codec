cmake_minimum_required(VERSION 3.21)
project(swsc C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_library(swsc src/swsc.c src/utf8.c)
target_include_directories(swsc PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(swsc PRIVATE src)
target_compile_options(swsc PRIVATE -Wall -Wextra -Wpedantic)

add_executable(hello examples/hello.c)
target_link_libraries(hello PRIVATE swsc)
target_compile_options(hello PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
add_test(NAME hello COMMAND hello)

install(TARGETS swsc EXPORT swscTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/swsc.h DESTINATION include)

option(SWSC_SANITIZE "Build with ASan/UBSan" OFF)
if(SWSC_SANITIZE)
  foreach(tgt swsc hello)
    target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()
