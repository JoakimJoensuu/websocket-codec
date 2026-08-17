cmake_minimum_required(VERSION 3.16)
project(sws C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

add_library(sws src/sws.c src/sws_utf8.c)
target_include_directories(sws PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(sws PRIVATE src)

add_executable(test_sws tests/test_sws.c)
target_link_libraries(test_sws PRIVATE sws)

add_executable(echo_server examples/echo_server.c)
target_link_libraries(echo_server PRIVATE sws)

include(CTest)
add_test(NAME unit COMMAND test_sws)
add_test(NAME smoke_echo COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/smoke_echo.py)
set_tests_properties(smoke_echo PROPERTIES
  ENVIRONMENT "ECHO_SERVER=$<TARGET_FILE:echo_server>;PORT=19001")

install(TARGETS sws EXPORT swsTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
install(FILES include/sws.h DESTINATION include)

option(SWS_SANITIZE "Build with ASan/UBSan" OFF)
if(SWS_SANITIZE)
  target_compile_options(sws PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(sws PRIVATE -fsanitize=address,undefined)
  target_compile_options(test_sws PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(test_sws PRIVATE -fsanitize=address,undefined)
  target_compile_options(echo_server PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(echo_server PRIVATE -fsanitize=address,undefined)
endif()
