cmake_minimum_required(VERSION 3.16)
project(wsio C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

add_library(wsio src/wsio.c src/wsio_utf8.c)
target_include_directories(wsio PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(wsio PRIVATE src)

add_executable(test_wsio tests/test_wsio.c)
target_link_libraries(test_wsio PRIVATE wsio)

add_executable(echo_server examples/echo_server.c)
target_link_libraries(echo_server PRIVATE wsio)

include(CTest)
add_test(NAME unit COMMAND test_wsio)
add_test(NAME smoke_echo COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/smoke_echo.py)
set_tests_properties(smoke_echo PROPERTIES
  ENVIRONMENT "ECHO_SERVER=$<TARGET_FILE:echo_server>;PORT=19001")

install(TARGETS wsio EXPORT wsioTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/wsio.h DESTINATION include)

option(WSIO_SANITIZE "Build with ASan/UBSan" OFF)
if(WSIO_SANITIZE)
  target_compile_options(wsio PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(wsio PRIVATE -fsanitize=address,undefined)
  target_compile_options(test_wsio PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(test_wsio PRIVATE -fsanitize=address,undefined)
  target_compile_options(echo_server PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(echo_server PRIVATE -fsanitize=address,undefined)
endif()
