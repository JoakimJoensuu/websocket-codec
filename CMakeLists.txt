cmake_minimum_required(VERSION 3.16)
project(swsf C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_library(swsf src/swsf.c src/utf8.c)
target_include_directories(swsf PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(swsf PRIVATE src)
target_compile_options(swsf PRIVATE -Wall -Wextra -Wpedantic)

add_executable(hello examples/hello.c)
target_link_libraries(hello PRIVATE swsf)
target_compile_options(hello PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
add_test(NAME hello COMMAND hello)

install(TARGETS swsf EXPORT swsfTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/swsf.h DESTINATION include)

option(SWSF_SANITIZE "Build with ASan/UBSan" OFF)
if(SWSF_SANITIZE)
  foreach(tgt swsf hello)
    target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()
